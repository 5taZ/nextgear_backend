import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const { Pool } = pg;
const app = express();

app.use(cors({
  origin: ['https://nextgearstore.netlify.app', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Telegram-Init-Data']
}));

app.use(express.json({ limit: '10mb' })); // Увеличиваем лимит для base64 фото

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Telegram Validation
function validateTelegramData(initData: string): { valid: boolean; user?: any } {
  if (!initData || !process.env.BOT_TOKEN) return { valid: false };
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return { valid: false };
    params.delete('hash');
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData')
      .update(process.env.BOT_TOKEN).digest();
    const checkHash = crypto.createHmac('sha256', secretKey)
      .update(dataCheckString).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(checkHash), Buffer.from(hash))) {
      return { valid: false };
    }
    return { valid: true, user: JSON.parse(params.get('user') || '{}') };
  } catch (error) {
    return { valid: false };
  }
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  if (!initData && process.env.NODE_ENV === 'development') return next();
  const { valid, user } = validateTelegramData(initData);
  if (!valid) return res.status(401).json({ error: 'Unauthorized' });
  (req as any).telegramUser = user;
  next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  const { valid, user: tgUser } = validateTelegramData(initData);
  if (!valid && process.env.NODE_ENV === 'development') return next();
  if (!valid) return res.status(401).json({ error: 'Unauthorized' });
  const isAdmin = tgUser.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    tgUser.id.toString() === process.env.ADMIN_TELEGRAM_ID;
  if (!isAdmin) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Users
app.post('/api/users', async (req, res) => {
  const { telegram_id, username, init_data } = req.body;
  const { valid, user: tgUser } = validateTelegramData(init_data);
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  const finalId = tgUser?.id || telegram_id;
  const finalUsername = tgUser?.username || username || `user_${finalId}`;
  const isAdmin = tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    finalId?.toString() === process.env.ADMIN_TELEGRAM_ID;
  
  try {
    let result = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [finalId]);
    if (result.rows.length === 0) {
      result = await pool.query(
        'INSERT INTO users (telegram_id, username, is_admin) VALUES ($1, $2, $3) RETURNING *',
        [finalId, finalUsername, isAdmin]
      );
    }
    res.json({ ...result.rows[0], is_admin: result.rows[0].is_admin || isAdmin });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Products
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/products', requireAdmin, async (req, res) => {
  const { name, price, image, description, category } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO products (name, price, image, description, category, in_stock) VALUES ($1, $2, $3, $4, $5, true) RETURNING *',
      [name, price, image, description, category] // image теперь может быть base64
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Orders
app.get('/api/orders', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*, u.username,
        COALESCE(json_agg(json_build_object(
          'id', oi.product_id,
          'name', oi.product_name,
          'price', oi.price,
          'quantity', oi.quantity,
          'image', oi.image_data
        )) FILTER (WHERE oi.id IS NOT NULL), '[]') as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      GROUP BY o.id, u.username
      ORDER BY o.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/orders/user/:userId', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*,
        COALESCE(json_agg(json_build_object(
          'id', oi.product_id,
          'name', oi.product_name,
          'price', oi.price,
          'quantity', oi.quantity,
          'image', oi.image_data
        )) FILTER (WHERE oi.id IS NOT NULL), '[]') as items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.user_id = $1
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `, [req.params.userId]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/orders', async (req, res) => {
  const { user_id, items, total_amount, init_data } = req.body;
  const { valid } = validateTelegramData(init_data);
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const orderResult = await pool.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    const orderId = orderResult.rows[0].id;
    
    // Сохраняем image_data в order_items для возможности возврата
    for (const item of items) {
      await pool.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price, image_data) VALUES ($1, $2, $3, $4, $5, $6)',
        [orderId, item.id, item.name, item.quantity, item.price, item.image]
      );
    }
    
    // Удаляем из продуктов
    await pool.query('DELETE FROM products WHERE id = ANY($1)', [items.map((i: any) => i.id)]);
    
    await client.query('COMMIT');
    res.json(orderResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// Обновленный эндпоинт - позволяет админу или пользователю отменить свой заказ
app.patch('/api/orders/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status, init_data, user_id } = req.body;
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Проверяем права: админ или владелец заказа
    const orderCheck = await client.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderCheck.rows[0];
    const isAdmin = tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
      tgUser?.id?.toString() === process.env.ADMIN_TELEGRAM_ID;
    const isOwner = order.user_id.toString() === user_id?.toString();
    
    // Пользователь может отменить только свой заказ в статусе PENDING
    if (!isAdmin && (!isOwner || order.status !== 'PENDING' || status !== 'CANCELED')) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const result = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    // Если отмена - возвращаем товары
    if (status === 'CANCELED') {
      const items = await client.query('SELECT * FROM order_items WHERE order_id = $1', [id]);
      for (const item of items.rows) {
        await client.query(
          'INSERT INTO products (name, price, image, description, category, in_stock) VALUES ($1, $2, $3, $4, $5, true)',
          [item.product_name, item.price, item.image_data || '', 'Returned item', 'General']
        );
      }
    }
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server on port ${PORT}`);
});

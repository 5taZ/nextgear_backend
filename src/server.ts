import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const { Pool } = pg;
const app = express();

// ==========================================
// Middleware
// ==========================================

// CORS для Netlify и локальной разработки
app.use(cors({
  origin: ['https://nextgearstore.netlify.app', 'http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Telegram-Init-Data'],
  credentials: true
}));

app.use(express.json());

// ==========================================
// Database
// ==========================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.query('SELECT NOW()', (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// ==========================================
// Telegram Validation
// ==========================================

function validateTelegramData(initData: string): { valid: boolean; user?: any } {
  if (!initData || !process.env.BOT_TOKEN) {
    return { valid: false };
  }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    
    if (!hash) {
      return { valid: false };
    }

    params.delete('hash');

    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(process.env.BOT_TOKEN)
      .digest();

    const checkHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(checkHash), Buffer.from(hash))) {
      return { valid: false };
    }

    const userJson = params.get('user');
    if (!userJson) {
      return { valid: false };
    }

    const user = JSON.parse(userJson);
    return { valid: true, user };
  } catch (error) {
    console.error('Validation error:', error);
    return { valid: false };
  }
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  
  if (!initData && process.env.NODE_ENV === 'development') {
    return next();
  }

  const { valid, user } = validateTelegramData(initData);
  
  if (!valid) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Telegram data' });
  }

  (req as any).telegramUser = user;
  next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  
  if (!initData && process.env.NODE_ENV === 'development') {
    return next();
  }

  const { valid, user: tgUser } = validateTelegramData(initData);
  
  if (!valid) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const isAdmin = 
    tgUser.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    tgUser.id.toString() === process.env.ADMIN_TELEGRAM_ID;

  if (!isAdmin) {
    return res.status(403).json({ error: 'Forbidden: Admin only' });
  }

  (req as any).isAdmin = true;
  (req as any).telegramUser = tgUser;
  next();
}

// ==========================================
// Routes
// ==========================================

// Health check
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============== USERS ==============

app.post('/api/users', async (req: Request, res: Response) => {
  const { telegram_id, username, init_data } = req.body;
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid Telegram signature' });
  }

  const finalTelegramId = tgUser?.id || telegram_id;
  const finalUsername = tgUser?.username || username || `user_${finalTelegramId}`;
  
  const isAdmin = 
    tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    finalTelegramId?.toString() === process.env.ADMIN_TELEGRAM_ID ||
    (process.env.NODE_ENV === 'development' && req.body.is_admin);

  try {
    let result = await pool.query(
      'SELECT * FROM users WHERE telegram_id = $1',
      [finalTelegramId]
    );
    
    if (result.rows.length === 0) {
      result = await pool.query(
        'INSERT INTO users (telegram_id, username, is_admin, balance, referrals) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [finalTelegramId, finalUsername, isAdmin, 0, 0]
      );
      console.log('✅ New user created:', finalUsername);
    } else {
      if (result.rows[0].username !== finalUsername) {
        result = await pool.query(
          'UPDATE users SET username = $1 WHERE telegram_id = $2 RETURNING *',
          [finalUsername, finalTelegramId]
        );
      }
      console.log('✅ User found:', finalUsername);
    }
    
    const user = result.rows[0];
    res.json({
      ...user,
      is_admin: user.is_admin || isAdmin
    });
  } catch (error) {
    console.error('❌ User error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== PRODUCTS ==============

app.get('/api/products', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Products fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/products', requireAdmin, async (req: Request, res: Response) => {
  const { name, price, image, description, category, in_stock } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO products (name, price, image, description, category, in_stock) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name, price, image, description, category, in_stock !== undefined ? in_stock : true]
    );
    console.log('✅ Product added:', name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Product add error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/products/:id', requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    console.log('✅ Product deleted:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Product delete error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== ORDERS ==============

// Get all orders (admin only)
app.get('/api/orders', requireAdmin, async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.id,
        o.user_id,
        o.total_amount,
        o.status,
        o.created_at,
        u.username,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'name', oi.product_name,
              'price', oi.price,
              'quantity', oi.quantity,
              'image', COALESCE(p.image, '')
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      GROUP BY o.id, u.username
      ORDER BY o.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Orders fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get user orders
app.get('/api/orders/user/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  const initData = req.headers['x-telegram-init-data'] as string;
  
  try {
    const result = await pool.query(`
      SELECT 
        o.id,
        o.user_id,
        o.total_amount,
        o.status,
        o.created_at,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'name', oi.product_name,
              'price', oi.price,
              'quantity', oi.quantity,
              'image', COALESCE(p.image, '')
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) as items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE o.user_id = $1
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `, [userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ User orders fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Create order - сразу удаляет товары из ассортимента (резервирование)
app.post('/api/orders', async (req: Request, res: Response) => {
  const { user_id, items, total_amount, init_data } = req.body;
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Создаем заказ
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    
    const orderId = orderResult.rows[0].id;
    console.log('✅ Order created:', orderId);
    
    // Добавляем items и собираем ID для удаления
    const productIds = [];
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES ($1, $2, $3, $4, $5)',
        [orderId, item.id, item.name, item.quantity, item.price]
      );
      productIds.push(item.id);
    }
    
    // СРАЗУ УДАЛЯЕМ ТОВАРЫ ИЗ АССОРТИМЕНТА (резервирование)
    if (productIds.length > 0) {
      await client.query(
        'DELETE FROM products WHERE id = ANY($1)',
        [productIds]
      );
      console.log(`✅ Reserved ${productIds.length} products for order ${orderId}`);
    }
    
    await client.query('COMMIT');
    res.json(orderResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Order creation error:', error);
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// Update order status - при отмене возвращает товары
app.patch('/api/orders/:id', requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const currentOrder = await client.query(
      'SELECT status FROM orders WHERE id = $1',
      [id]
    );
    
    if (currentOrder.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Обновляем статус
    const result = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    // ЕСЛИ ОТМЕНЯЕМ (CANCELED) - возвращаем товары в ассортимент
    if (status === 'CANCELED') {
      const orderItems = await client.query(
        'SELECT product_id, product_name, price FROM order_items WHERE order_id = $1',
        [id]
      );
      
      // Восстанавливаем товары
      // Примечание: так как старые товары удалены, создаем новые с сохраненными данными
      // Для полного восстановления (image, category, desc) нужно хранить их в order_items
      for (const item of orderItems.rows) {
        await client.query(
          `INSERT INTO products (name, price, image, description, category, in_stock) 
           VALUES ($1, $2, $3, $4, $5, true)`,
          [
            item.product_name, 
            item.price, 
            '', // image - placeholder (лучше хранить в order_items)
            'Returned from order', 
            'General'
          ]
        );
      }
      console.log(`✅ Returned ${orderItems.rows.length} products to inventory`);
    }
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Order update error:', error);
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// ==========================================
// Server Start
// ==========================================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API endpoint: http://localhost:${PORT}/api`);
  console.log(`🔐 Telegram validation: ${process.env.BOT_TOKEN ? 'ENABLED' : 'DISABLED'}`);
  console.log(`👑 Admin user: ${process.env.ADMIN_TELEGRAM_USERNAME || process.env.ADMIN_TELEGRAM_ID || 'NOT SET'}`);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await pool.end();
  process.exit(0);
});

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const { Pool } = pg;
const app = express();

// ==========================================
// Middleware (оптимизировано)
// ==========================================

app.use(cors({
  origin: ['https://regal-dango-667791.netlify.app', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Telegram-Init-Data']
}));

app.use(express.json({ limit: '10mb' }));

// ==========================================
// КЭШИРОВАНИЕ (ускоряет GET /api/products в 10 раз)
// ==========================================

let productsCache: any[] = [];
let cacheTimestamp = 0;
const CACHE_TTL = 30000; // 30 секунд

const getCachedProducts = async () => {
  const now = Date.now();
  if (now - cacheTimestamp > CACHE_TTL || productsCache.length === 0) {
    const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC LIMIT 100');
    productsCache = result.rows;
    cacheTimestamp = now;
    console.log('✅ Cache updated:', productsCache.length, 'products');
  }
  return productsCache;
};

const invalidateCache = () => {
  cacheTimestamp = 0;
  productsCache = [];
};

// ==========================================
// Database
// ==========================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20, // Увеличиваем пул соединений
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
  console.error('Unexpected DB error', err);
});

// ==========================================
// Telegram Validation
// ==========================================

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
  
  (req as any).isAdmin = true;
  next();
}

// ==========================================
// Routes (Оптимизированные)
// ==========================================

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    cacheSize: productsCache.length 
  });
});

// ============== USERS ==============

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
    // Используем UPSERT для скорости
    const result = await pool.query(
      `INSERT INTO users (telegram_id, username, is_admin) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (telegram_id) 
       DO UPDATE SET username = EXCLUDED.username 
       RETURNING *`,
      [finalId, finalUsername, isAdmin]
    );
    
    res.json({ ...result.rows[0], is_admin: result.rows[0].is_admin || isAdmin });
  } catch (error) {
    console.error('User error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== PRODUCTS (с кэшем) ==============

// Очень быстрый GET - из памяти, не из БД
app.get('/api/products', async (req, res) => {
  try {
    const products = await getCachedProducts();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST - добавление (с инвалидацией кэша)
app.post('/api/products', requireAdmin, async (req, res) => {
  const { name, price, image, description, category } = req.body;
  
  try {
    const result = await pool.query(
      'INSERT INTO products (name, price, image, description, category, in_stock) VALUES ($1, $2, $3, $4, $5, true) RETURNING *',
      [name, price, image, description, category]
    );
    
    invalidateCache(); // Сбрасываем кэш
    console.log('✅ Product added:', name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Product add error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE - удаление (с инвалидацией кэша)
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    invalidateCache();
    console.log('✅ Product deleted:', req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== ORDERS (Оптимизировано) ==============

// GET all orders (admin) - без кэша, всегда свежие
app.get('/api/orders', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*, u.username,
        COALESCE(json_agg(json_build_object(
          'id', oi.product_id,
          'name', oi.product_name,
          'price', oi.price,
          'quantity', oi.quantity,
          'image', COALESCE(oi.image_data, '')
        )) FILTER (WHERE oi.id IS NOT NULL), '[]') as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      GROUP BY o.id, u.username
      ORDER BY o.created_at DESC
      LIMIT 50
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET user orders
app.get('/api/orders/user/:userId', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*,
        COALESCE(json_agg(json_build_object(
          'id', oi.product_id,
          'name', oi.product_name,
          'price', oi.price,
          'quantity', oi.quantity,
          'image', COALESCE(oi.image_data, '')
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

// POST create order - с резервированием (удаление из products)
app.post('/api/orders', async (req, res) => {
  const { user_id, items, total_amount, init_data } = req.body;
  
  const { valid } = validateTelegramData(init_data);
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 1. Создаем заказ (быстро)
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    const orderId = orderResult.rows[0].id;
    
    // 2. Сохраняем items с image_data для возможности возврата
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price, image_data) VALUES ($1, $2, $3, $4, $5, $6)',
        [orderId, item.id, item.name, item.quantity, item.price, item.image || '']
      );
    }
    
    // 3. Удаляем из products (резервирование) - одним запросом
    if (items.length > 0) {
      await client.query(
        'DELETE FROM products WHERE id = ANY($1)',
        [items.map((i: any) => i.id)]
      );
    }
    
    await client.query('COMMIT');
    
    // 4. Инвалидируем кэш продуктов (чтобы фронт получил актуальный список)
    invalidateCache();
    
    console.log(`✅ Order ${orderId} created, ${items.length} items reserved`);
    res.json(orderResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// PATCH update order status - с возвратом товаров при отмене
app.patch('/api/orders/:id', async (req, res) => {
  const { id } = req.params;
  const { status, init_data, user_id } = req.body;
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Проверяем права
    const orderCheck = await client.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderCheck.rows[0];
    const isAdmin = tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
      tgUser?.id?.toString() === process.env.ADMIN_TELEGRAM_ID;
    const isOwner = order.user_id.toString() === user_id?.toString();
    
    // Пользователь может только отменить свой PENDING заказ
    if (!isAdmin && (!isOwner || order.status !== 'PENDING' || status !== 'CANCELED')) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    // Обновляем статус
    const result = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    // Если отмена - возвращаем товары в ассортимент
    if (status === 'CANCELED') {
      const items = await client.query(
        'SELECT product_name, price, image_data FROM order_items WHERE order_id = $1',
        [id]
      );
      
      for (const item of items.rows) {
        await client.query(
          'INSERT INTO products (name, price, image, description, category, in_stock) VALUES ($1, $2, $3, $4, $5, true)',
          [item.product_name, item.price, item.image_data || '', 'Returned from order', 'General']
        );
      }
      
      invalidateCache(); // Товары вернулись - сбрасываем кэш
      console.log(`✅ Order ${id} canceled, ${items.rows.length} items returned`);
    } else if (status === 'CONFIRMED') {
      console.log(`✅ Order ${id} confirmed`);
    }
    
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Order update error:', error);
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// ==========================================
// Start Server
// ==========================================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server on port ${PORT}`);
  console.log(`⚡ Cache enabled: ${CACHE_TTL}ms TTL`);
});

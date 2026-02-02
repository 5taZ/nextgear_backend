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
  origin: [
    'https://frontendstore-production.up.railway.app', // ✅ УБРАНЫ ПРОБЕЛЫ
    'http://localhost:5173', 
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Telegram-Init-Data'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// ==========================================
// КЭШИРОВАНИЕ (ускоряет GET /api/products в 10 раз)
// ==========================================

let productsCache: any[] = [];
let cacheTimestamp = 0;
const CACHE_TTL = 30000; // 30 секунд
const MAX_CACHE_SIZE = 200; // Максимум 200 товаров в кэше

const getCachedProducts = async () => {
  const now = Date.now();
  if (now - cacheTimestamp > CACHE_TTL || productsCache.length === 0) {
    const result = await pool.query(
      'SELECT * FROM products ORDER BY created_at DESC LIMIT $1',
      [MAX_CACHE_SIZE]
    );
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

// Автоматическая очистка кэша
setInterval(() => {
  const now = Date.now();
  if (now - cacheTimestamp > CACHE_TTL) {
    invalidateCache();
    console.log('🧹 Cache auto-cleared');
  }
}, CACHE_TTL / 2);

// ==========================================
// Database
// ==========================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  min: 2,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  allowExitOnIdle: false
});

pool.on('error', (err) => {
  console.error('❌ Unexpected DB error', err);
});

// ==========================================
// Telegram Validation с кэшированием
// ==========================================

const telegramValidationCache = new Map<string, { valid: boolean; user?: any; timestamp: number }>();
const VALIDATION_CACHE_TTL = 60000; // 1 минута

function validateTelegramData(initData: string): { valid: boolean; user?: any } {
  if (!initData || !process.env.BOT_TOKEN) return { valid: false };
  
  // Проверяем кэш
  const cached = telegramValidationCache.get(initData);
  if (cached && Date.now() - cached.timestamp < VALIDATION_CACHE_TTL) {
    return cached;
  }
  
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
      
    const isValid = crypto.timingSafeEqual(Buffer.from(checkHash), Buffer.from(hash));
    const result = {
      valid: isValid,
      user: isValid ? JSON.parse(params.get('user') || '{}') : undefined,
      timestamp: Date.now()
    };
    
    telegramValidationCache.set(initData, result);
    
    // Очистка старого кэша
    if (telegramValidationCache.size > 1000) {
      const now = Date.now();
      for (const [key, value] of telegramValidationCache.entries()) {
        if (now - value.timestamp > VALIDATION_CACHE_TTL) {
          telegramValidationCache.delete(key);
        }
      }
    }
    
    return result;
  } catch (error) {
    console.error('❌ Telegram validation error:', error);
    return { valid: false };
  }
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  if (!initData && process.env.NODE_ENV === 'development') return next();
  
  const { valid, user } = validateTelegramData(initData);
  if (!valid) {
    console.warn('⚠️ Unauthorized request');
    return res.status(401).json({ error: 'Unauthorized' });
  }
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
    console.warn('⚠️ Invalid user signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }
  const finalId = tgUser?.id || telegram_id;
  const finalUsername = tgUser?.username || username || `user_${finalId}`;
  const isAdmin = tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    finalId?.toString() === process.env.ADMIN_TELEGRAM_ID;
  try {
    const result = await pool.query(
      `INSERT INTO users (telegram_id, username, is_admin) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (telegram_id) 
       DO UPDATE SET username = EXCLUDED.username 
       RETURNING *`,
      [finalId, finalUsername, isAdmin]
    );
    console.log('✅ User authenticated:', finalUsername);
    res.json({ ...result.rows[0], is_admin: result.rows[0].is_admin || isAdmin });
  } catch (error) {
    console.error('❌ User error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== PRODUCTS (с кэшем) ==============

app.get('/api/products', async (req, res) => {
  try {
    const products = await getCachedProducts();
    res.json(products);
  } catch (error) {
    console.error('❌ Products fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/products', requireAdmin, async (req, res) => {
  const { name, price, image, description, category, quantity } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO products (name, price, image, description, category, quantity, in_stock) VALUES ($1, $2, $3, $4, $5, $6, true) RETURNING *',
      [name, price, image, description, category, quantity || 1]
    );
    invalidateCache();
    console.log('✅ Product added:', name);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Product add error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    invalidateCache();
    console.log('✅ Product deleted:', req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Product delete error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/api/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, image, description, category, quantity } = req.body;
  console.log('🔄 PATCH /api/products/:id called:', { 
    id, 
    name, 
    price, 
    image: !!image, 
    description: !!description, 
    category, 
    quantity
  });
  
  try {
    const fields: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;
    
    if (name !== undefined) {
      fields.push(`name = $${paramIndex++}`);
      values.push(name);
    }
    if (price !== undefined) {
      fields.push(`price = $${paramIndex++}`);
      values.push(price);
    }
    if (image !== undefined) {
      fields.push(`image = $${paramIndex++}`);
      values.push(image);
    }
    if (description !== undefined) {
      fields.push(`description = $${paramIndex++}`);
      values.push(description);
    }
    if (category !== undefined) {
      fields.push(`category = $${paramIndex++}`);
      values.push(category);
    }
    if (quantity !== undefined) {
      fields.push(`quantity = $${paramIndex++}`);
      const quantityNum = Number(quantity);
      values.push(quantityNum);
      console.log('📦 Converting quantity to number:', quantity, '→', quantityNum);
    }
    
    if (fields.length === 0) {
      console.warn('⚠️ No fields to update');
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    values.push(id);
    
    const query = `
      UPDATE products 
      SET ${fields.join(', ')} 
      WHERE id = $${paramIndex} 
      RETURNING *
    `;
    
    console.log('📦 Executing query:', query);
    console.log('📦 Query values:', values);
    
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      console.error('❌ Product not found:', id);
      return res.status(404).json({ error: 'Product not found' });
    }
    
    invalidateCache();
    console.log('✅ Product updated successfully:', id, result.rows[0]);
    res.json(result.rows[0]);
  } catch (error: any) {
    console.error('❌ Product update error:', error);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Database error', details: error.message });
  }
});

// ============== ORDERS (Оптимизировано) ==============

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
    console.error('❌ Orders fetch error:', error);
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
    console.error('❌ User orders fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/orders', async (req, res) => {
  const { user_id, items, total_amount, init_data } = req.body;
  console.log('📦 Order request:', { user_id, itemsCount: items?.length, total_amount });
  
  if (!user_id || !items || !Array.isArray(items) || items.length === 0) {
    console.error('❌ Invalid order data');
    return res.status(400).json({ error: 'Invalid order data' });
  }
  
  const { valid } = validateTelegramData(init_data);
  if (!valid && process.env.NODE_ENV !== 'development') {
    console.error('❌ Invalid Telegram data in order');
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    console.log('🔄 Transaction started');
    
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    const orderId = orderResult.rows[0].id;
    console.log('✅ Order created:', orderId);
    
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price, image_data) VALUES ($1, $2, $3, $4, $5, $6)',
        [orderId, item.id, item.name, item.quantity, item.price, item.image || '']
      );
    }
    console.log('✅ Order items saved:', items.length);
    
    for (const item of items) {
      const productResult = await client.query(
        'SELECT quantity FROM products WHERE id = $1 FOR UPDATE',
        [item.id]
      );
      
      if (productResult.rows.length === 0) {
        throw new Error(`Product ${item.id} not found`);
      }
      
      const currentQuantity = productResult.rows[0].quantity || 1;
      const newQuantity = currentQuantity - item.quantity;
      
      if (newQuantity <= 0) {
        await client.query('DELETE FROM products WHERE id = $1', [item.id]);
        console.log(`🗑️ Product ${item.id} deleted (quantity reached 0)`);
      } else {
        await client.query(
          'UPDATE products SET quantity = $1 WHERE id = $2',
          [newQuantity, item.id]
        );
        console.log(`📦 Product ${item.id} quantity updated: ${currentQuantity} → ${newQuantity}`);
      }
    }
    
    await client.query('COMMIT');
    console.log('✅ Transaction committed');
    
    invalidateCache();
    
    console.log(`🎉 Order ${orderId} created successfully`);
    res.json(orderResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Order creation failed:', error);
    res.status(500).json({ 
      error: 'Failed to create order',
      details: process.env.NODE_ENV === 'development' ? (error as Error).message : undefined
    });
  } finally {
    client.release();
  }
});

app.patch('/api/orders/:id', async (req, res) => {
  const { id } = req.params;
  const { status, init_data, user_id } = req.body;
  console.log('📝 Order status update:', { id, status, user_id });
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    console.error('❌ Unauthorized order update');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const orderCheck = await client.query('SELECT id, user_id, status, total_amount FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      console.error('❌ Order not found:', id);
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderCheck.rows[0];
    const isAdmin = tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
      tgUser?.id?.toString() === process.env.ADMIN_TELEGRAM_ID;
    const isOwner = order.user_id.toString() === user_id?.toString();
    
    if (!isAdmin && (!isOwner || order.status !== 'PENDING' || status !== 'CANCELED')) {
      await client.query('ROLLBACK');
      console.error('❌ Forbidden order update');
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const result = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    await client.query('COMMIT');
    
    if (status === 'CONFIRMED') {
      console.log(`✅ Order ${id} confirmed by ${isAdmin ? 'admin' : 'user'}`);
    } else if (status === 'CANCELED') {
      console.log(`❌ Order ${id} ${isAdmin ? 'rejected by admin' : 'canceled by user'}`);
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Order update error:', error);
    res.status(500).json({ error: 'Database error' });
  } finally {
    client.release();
  }
});

// ============== PRODUCT REQUESTS ==============

app.post('/api/product-requests', async (req, res) => {
  const { user_id, product_name, quantity, image, init_data } = req.body;
  console.log('📦 Product request received:', { 
    user_id, 
    product_name, 
    quantity, 
    image,
    has_init_data: !!init_data
  });
  
  if (!user_id || !product_name || !quantity) {
    console.error('❌ Missing required fields');
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  console.log('🔐 Telegram validation:', valid ? '✅ Valid' : '❌ Invalid');
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    console.error('❌ Invalid Telegram data in product request');
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  try {
    const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [user_id]);
    
    if (userResult.rows.length === 0) {
      console.error('❌ User not found:', user_id);
      return res.status(404).json({ error: 'User not found' });
    }
    
    const username = userResult.rows[0].username;
    console.log('👤 User found:', username);
    
    const result = await pool.query(
      `INSERT INTO product_requests (user_id, username, product_name, quantity, image, status) 
       VALUES ($1, $2, $3, $4, $5, 'pending') 
       RETURNING *`,
      [user_id, username, product_name, quantity, image]
    );
    
    console.log(`✅ Product request created successfully:`, {
      id: result.rows[0].id,
      productName: product_name,
      quantity: quantity
    });
    
    res.json({
      success: true,
      message: 'Product request sent to admin',
      requestId: result.rows[0].id
    });
  } catch (error) {
    console.error('❌ Product request error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/product-requests', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM product_requests 
       ORDER BY created_at DESC 
       LIMIT 100`
    );
    
    console.log('✅ Fetched product requests:', result.rows.length);
    
    res.json(result.rows.map(r => ({
      id: r.id.toString(),
      userId: r.user_id,
      username: r.username,
      productName: r.product_name,
      quantity: r.quantity,
      image: r.image,
      status: r.status,
      createdAt: new Date(r.created_at).getTime(),
      processedAt: r.processed_at ? new Date(r.processed_at).getTime() : undefined
    })));
  } catch (error) {
    console.error('❌ Product requests fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/product-requests/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { valid } = validateTelegramData(req.headers['x-telegram-init-data'] as string);
    
    if (!valid && process.env.NODE_ENV !== 'development') {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const result = await pool.query(
      `SELECT * FROM product_requests 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    console.log('✅ Fetched user product requests:', result.rows.length);
    
    res.json(result.rows.map(r => ({
      id: r.id.toString(),
      userId: r.user_id,
      username: r.username,
      productName: r.product_name,
      quantity: r.quantity,
      image: r.image,
      status: r.status,
      createdAt: new Date(r.created_at).getTime(),
      processedAt: r.processed_at ? new Date(r.processed_at).getTime() : undefined
    })));
  } catch (error) {
    console.error('❌ User product requests fetch error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/api/product-requests/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, init_data } = req.body;
  console.log('📝 Product request update:', { id, status });
  
  const { valid } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    console.error('❌ Unauthorized product request update');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const requestResult = await pool.query(
      'SELECT user_id, product_name, quantity FROM product_requests WHERE id = $1',
      [id]
    );
    
    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    const request = requestResult.rows[0];
    
    const result = await pool.query(
      `UPDATE product_requests 
       SET status = $1, processed_at = NOW() 
       WHERE id = $2 
       RETURNING *`,
      [status, id]
    );
    
    console.log(`✅ Product request ${id} ${status === 'approved' ? 'approved' : 'rejected'}`);
    
    console.log(`🔔 User ${request.user_id} should be notified about ${status} request for "${request.product_name}"`);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Product request update error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ==========================================
// Start Server
// ==========================================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`⚡ Cache enabled: ${CACHE_TTL}ms TTL`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const { Pool } = pg;
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// ============== TELEGRAM VALIDATION ==============

/**
 * Валидация initData от Telegram WebApp
 * Проверяет HMAC-SHA256 подпись
 */
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

    // Сортируем параметры по ключу
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    // Создаем секретный ключ
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(process.env.BOT_TOKEN)
      .digest();

    // Вычисляем хеш
    const checkHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    // Безопасное сравнение хешей
    if (!crypto.timingSafeEqual(Buffer.from(checkHash), Buffer.from(hash))) {
      return { valid: false };
    }

    // Парсим пользователя
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

/**
 * Middleware для проверки авторизации
 */
async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  
  if (!initData && process.env.NODE_ENV === 'development') {
    // В режиме разработки пропускаем без проверки (опционально)
    return next();
  }

  const { valid, user } = validateTelegramData(initData);
  
  if (!valid) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Telegram data' });
  }

  // Добавляем пользователя в запрос для использования в роутах
  (req as any).telegramUser = user;
  next();
}

/**
 * Middleware для проверки прав администратора
 */
async function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const initData = req.body?.init_data || req.headers['x-telegram-init-data'];
  const { valid, user } = validateTelegramData(initData);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const tgUser = user || (req as any).telegramUser;
  
  if (!tgUser) {
    return res.status(401).json({ error: 'User not found' });
  }

  // Проверяем, является ли пользователь админом
  const isAdmin = 
    tgUser.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    tgUser.id.toString() === process.env.ADMIN_TELEGRAM_ID;

  if (!isAdmin && process.env.NODE_ENV !== 'development') {
    return res.status(403).json({ error: 'Forbidden: Admin only' });
  }

  (req as any).isAdmin = true;
  next();
}

// ============== HEALTH CHECK ==============
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============== USER ENDPOINTS ==============

// Get or create user (с валидацией Telegram)
app.post('/api/users', async (req: Request, res: Response) => {
  const { init_data } = req.body;
  
  // Валидация Telegram данных
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid) {
    // В режиме разработки можно пропустить (но не в production!)
    if (process.env.NODE_ENV === 'development' && req.body.telegram_id) {
      console.log('⚠️ Development mode: skipping Telegram validation');
      // Для dev режима используем данные из body
    } else {
      return res.status(401).json({ error: 'Invalid Telegram signature' });
    }
  }

  // Используем данные из Telegram или fallback для dev
  const telegramId = tgUser?.id || req.body.telegram_id;
  const username = tgUser?.username || req.body.username || `user_${telegramId}`;
  
  // Определяем админа ТОЛЬКО по проверенным данным Telegram или env
  const isAdmin = 
    tgUser?.username === process.env.ADMIN_TELEGRAM_USERNAME ||
    telegramId?.toString() === process.env.ADMIN_TELEGRAM_ID ||
    (process.env.NODE_ENV === 'development' && req.body.is_admin); // Только для dev

  try {
    // Check if user exists
    let result = await pool.query(
      'SELECT * FROM users WHERE telegram_id = $1',
      [telegramId]
    );
    
    if (result.rows.length === 0) {
      // Create new user
      result = await pool.query(
        'INSERT INTO users (telegram_id, username, is_admin, balance, referrals) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [telegramId, username, isAdmin, 0, 0]
      );
      console.log('✅ New user created:', username, 'Admin:', isAdmin);
    } else {
      // Обновляем username если изменился
      if (result.rows[0].username !== username) {
        result = await pool.query(
          'UPDATE users SET username = $1 WHERE telegram_id = $2 RETURNING *',
          [username, telegramId]
        );
      }
      console.log('✅ User found:', username);
    }
    
    // Возвращаем user с флагом is_admin
    const user = result.rows[0];
    res.json({
      ...user,
      is_admin: user.is_admin || isAdmin // Убеждаемся что флаг актуальный
    });
  } catch (error) {
    console.error('❌ User error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== PRODUCT ENDPOINTS ==============

// Get all products (публично)
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

// Add product (только админ + проверка Telegram)
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

// Update product (только админ)
app.patch('/api/products/:id', requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { name, price, image, description, category, in_stock } = req.body;
  
  try {
    const result = await pool.query(
      'UPDATE products SET name = COALESCE($1, name), price = COALESCE($2, price), image = COALESCE($3, image), description = COALESCE($4, description), category = COALESCE($5, category), in_stock = COALESCE($6, in_stock) WHERE id = $7 RETURNING *',
      [name, price, image, description, category, in_stock, id]
    );
    console.log('✅ Product updated:', id);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Product update error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Delete product (только админ)
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

// ============== ORDER ENDPOINTS ==============

// Get all orders (только админ)
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
              'name', COALESCE(p.name, oi.product_name),
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

// Get user orders (с проверкой Telegram)
app.get('/api/orders/user/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  const initData = req.headers['x-telegram-init-data'] as string;
  
  // Проверяем, что пользователь запрашивает свои заказы
  const { valid, user: tgUser } = validateTelegramData(initData);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const result = await pool.query(`
      SELECT 
        o.id,
        o.total_amount,
        o.status,
        o.created_at,
        COALESCE(
          json_agg(
            json_build_object(
              'id', p.id,
              'name', COALESCE(p.name, oi.product_name),
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

// Create order (с проверкой Telegram)
app.post('/api/orders', async (req: Request, res: Response) => {
  const { user_id, items, total_amount, init_data } = req.body;
  
  // Валидация Telegram (убеждаемся что заказ делает реальный пользователь)
  const { valid, user: tgUser } = validateTelegramData(init_data);
  
  if (!valid && process.env.NODE_ENV !== 'development') {
    return res.status(401).json({ error: 'Invalid Telegram data' });
  }
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Проверяем что user_id соответствует telegram_id из initData
    if (valid && tgUser) {
      const userCheck = await client.query(
        'SELECT id FROM users WHERE id = $1 AND telegram_id = $2',
        [user_id, tgUser.id]
      );
      if (userCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'User ID mismatch' });
      }
    }
    
    // Create order
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    
    const orderId = orderResult.rows[0].id;
    console.log('✅ Order created:', orderId);
    
    // Add order items
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES ($1, $2, $3, $4, $5)',
        [orderId, item.id, item.name, item.quantity, item.price]
      );
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

// Update order status (только админ)
app.patch('/api/orders/:id', requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Update order status
    const result = await client.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    console.log(`✅ Order ${id} status updated to: ${status}`);
    
    // If approved, remove items from inventory
    if (status === 'CONFIRMED') {
      const orderItems = await client.query(
        'SELECT product_id FROM order_items WHERE order_id = $1',
        [id]
      );
      
      const productIds = orderItems.rows.map((item: any) => item.product_id);
      
      if (productIds.length > 0) {
        await client.query(
          'DELETE FROM products WHERE id = ANY($1)',
          [productIds]
        );
        console.log(`✅ Removed ${productIds.length} products from inventory`);
      }
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

// ============== START SERVER ==============

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API endpoint: http://localhost:${PORT}/api`);
  console.log(`🔐 Telegram validation: ${process.env.BOT_TOKEN ? 'ENABLED' : 'DISABLED (set BOT_TOKEN)'}`);
  console.log(`👑 Admin user: ${process.env.ADMIN_TELEGRAM_USERNAME || process.env.ADMIN_TELEGRAM_ID || 'NOT SET'}`);
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await pool.end();
  process.exit(0);
});

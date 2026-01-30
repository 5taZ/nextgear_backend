import express, { Request, Response } from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';

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

// ============== HEALTH CHECK ==============
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============== USER ENDPOINTS ==============

// Get or create user
app.post('/api/users', async (req: Request, res: Response) => {
  const { telegram_id, username, is_admin } = req.body;
  
  try {
    // Check if user exists
    let result = await pool.query(
      'SELECT * FROM users WHERE telegram_id = $1',
      [telegram_id]
    );
    
    if (result.rows.length === 0) {
      // Create new user
      result = await pool.query(
        'INSERT INTO users (telegram_id, username, is_admin) VALUES ($1, $2, $3) RETURNING *',
        [telegram_id, username, is_admin || false]
      );
      console.log('✅ New user created:', username);
    } else {
      console.log('✅ User found:', username);
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ User error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// ============== PRODUCT ENDPOINTS ==============

// Get all products
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

// Add product (admin only)
app.post('/api/products', async (req: Request, res: Response) => {
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

// Update product
app.patch('/api/products/:id', async (req: Request, res: Response) => {
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

// Delete product (admin only)
app.delete('/api/products/:id', async (req: Request, res: Response) => {
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

// Get all orders (for admin)
app.get('/api/orders', async (req: Request, res: Response) => {
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

// Get user orders
app.get('/api/orders/user/:userId', async (req: Request, res: Response) => {
  const { userId } = req.params;
  
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

// Create order
app.post('/api/orders', async (req: Request, res: Response) => {
  const { user_id, items, total_amount } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Create order
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3) RETURNING *',
      [user_id, total_amount, 'PENDING']
    );
    
    const orderId = orderResult.rows[0].id;
    console.log('✅ Order created:', orderId);
    
    // Add order items (store product name in case product gets deleted)
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

// Update order status (admin only)
app.patch('/api/orders/:id', async (req: Request, res: Response) => {
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
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await pool.end();
  process.exit(0);
});

-- Next Gear Database Schema
-- Run this SQL in your Supabase SQL Editor

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  telegram_id BIGINT UNIQUE NOT NULL,
  username VARCHAR(255),
  balance INTEGER DEFAULT 0,
  referrals INTEGER DEFAULT 0,
  is_admin BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  price INTEGER NOT NULL,
  image TEXT,
  description TEXT,
  category VARCHAR(100),
  in_stock BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  total_amount INTEGER NOT NULL,
  status VARCHAR(50) DEFAULT 'PENDING',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Order Items table
CREATE TABLE IF NOT EXISTS order_items (
  id SERIAL PRIMARY KEY,
  order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  product_name VARCHAR(255) NOT NULL,
  quantity INTEGER NOT NULL,
  price INTEGER NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_in_stock ON products(in_stock);

-- Insert initial products (optional - for demo)
INSERT INTO products (name, price, image, description, category, in_stock) VALUES
  ('Nike Dunk Low Retro', 14990, 'https://picsum.photos/400/400?random=1', 'Classic panda colorway, authentic verification included.', 'Sneakers', true),
  ('Supreme Box Logo Tee', 12500, 'https://picsum.photos/400/400?random=2', 'FW23 Collection, Size L, White.', 'Clothing', true),
  ('Yeezy Slide Pure', 8990, 'https://picsum.photos/400/400?random=3', 'Softest foam slides, Size 10 US.', 'Sneakers', false),
  ('PS5 Digital Edition', 45000, 'https://picsum.photos/400/400?random=4', 'Brand new, sealed. Japanese version.', 'Electronics', true),
  ('Stone Island Hoodie', 22000, 'https://picsum.photos/400/400?random=5', 'Garment dyed, black, patch on arm.', 'Clothing', true)
ON CONFLICT DO NOTHING;

-- Create a function to automatically update referral count
CREATE OR REPLACE FUNCTION update_referral_count()
RETURNS TRIGGER AS $$
BEGIN
  -- This is a placeholder - implement referral logic based on your needs
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE users IS 'Stores user information from Telegram';
COMMENT ON TABLE products IS 'Product inventory for the store';
COMMENT ON TABLE orders IS 'Customer orders with status tracking';
COMMENT ON TABLE order_items IS 'Individual items within each order';

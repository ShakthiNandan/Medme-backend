// server.js
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Enable CORS to allow requests from your React app
app.use(cors());

// Parse JSON bodies
app.use(bodyParser.json());

// Create a PostgreSQL connection pool with retry logic
const createPool = () => {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
  });

  return pool;
};

let pool = createPool();

// Test database connection
const testConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('Database connection successful');
    client.release();
  } catch (err) {
    console.error('Database connection failed:', err);
    // Attempt to recreate the pool
    pool = createPool();
  }
};

// Test connection on startup
testConnection();

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Debug logging
  console.log('Login attempt for user:', username);
  console.log('Request body:', req.body);
  
  if (!password) {
    console.error('No password provided in request');
    return res.status(400).json({ message: 'Password is required' });
  }
  
  try {
    // Find user by username
    const result = await pool.query('SELECT * FROM users WHERE name = $1', [username]);
    if (result.rows.length === 0) {
      console.error('User not found:', username);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    console.log('Found user:', { id: user.id, username: user.name });
    
    if (!user.password_hash) {
      console.error('No password hash found for user:', username);
      return res.status(500).json({ message: 'User account error - no password hash' });
    }
    
    // Debug log lengths to help diagnose issues
    console.log('Password length:', password.length);
    console.log('Hash length:', user.password_hash.length);
    
    // Compare password with stored hashed password
    console.log('Attempting bcrypt compare...');
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    // Generate a JWT token
    const token = jwt.sign(
      { id: user.id, username: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log('DATABASE_URL:', process.env.DATABASE_URL);
});

/**
 * POST /forgot-password/check
 * Checks if user exists and if admin code is correct.
 */
app.post('/forgot-password/check', async (req, res) => {
  const { username, adminCode } = req.body;

  try {
    // Check if user exists
    const result = await pool.query('SELECT * FROM users WHERE name = $1', [username]);
    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Username doesn't exist" });
    }

    // Check admin code
    if (adminCode !== '667') {
      return res.json({ success: false, message: 'Wrong admin code' });
    }

    // If both checks pass
    return res.json({ success: true, message: 'User found, admin code verified.' });
  } catch (error) {
    console.error('Error during forgot-password check:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

/**
 * POST /forgot-password/reset
 * Resets the user's password if the username exists and admin code is correct.
 */
app.post('/forgot-password/reset', async (req, res) => {
  const { username, adminCode, newPassword } = req.body;

  try {
    // Check if user exists
    const result = await pool.query('SELECT * FROM users WHERE name = $1', [username]);
    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Username doesn't exist" });
    }

    // Check admin code
    if (adminCode !== '667') {
      return res.json({ success: false, message: 'Wrong admin code' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    await pool.query('UPDATE users SET password_hash = $1 WHERE name = $2', [hashedPassword, username]);

    return res.json({ success: true, message: 'Password updated successfully!' });
  } catch (error) {
    console.error('Error during forgot-password reset:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
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

// Create a PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Find user by username
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const user = result.rows[0];
    // Compare password with stored hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    // Generate a JWT token (set JWT_SECRET in .env)
    const token = jwt.sign(
      { id: user.id, username: user.username },
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
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
require('dotenv').config();
console.log('DATABASE_URL:', process.env.DATABASE_URL);
console.log('PORT:', process.env.PORT);
// server.js
// ... Your existing /login route here ...

/**
 * POST /forgot-password/check
 * Checks if user exists and if admin code is correct.
 */
app.post('/forgot-password/check', async (req, res) => {
  const { username, adminCode } = req.body;

  try {
    // Check if user exists
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
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
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
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
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPassword, username]);

    return res.json({ success: true, message: 'Password updated successfully!' });
  } catch (error) {
    console.error('Error during forgot-password reset:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});
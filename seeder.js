const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function seedUser() {
  const username = 'Shakthi';
  const plaintextPassword = 'sss'; // the plaintext you want to hash

  // Hash the password
  const hashedPassword = await bcrypt.hash(plaintextPassword, 10);

  // Insert into DB
  const query = 'INSERT INTO users (username, password) VALUES ($1, $2)';
  const values = [username, hashedPassword];

  try {
    await pool.query(query, values);
    console.log('User inserted with hashed password');
  } catch (err) {
    console.error('Error inserting user:', err);
  }
}

seedUser();

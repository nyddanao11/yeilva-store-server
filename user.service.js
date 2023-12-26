const { pool } = require('./server');

async function getUserByEmail(userEmail) {
  try {
    const query = 'SELECT firstname, lastname, email FROM users WHERE email = $1';
    const result = await pool.query(query, [userEmail]);

    if (result.rows.length === 0) {
      return null; // Return null when the user is not found
    }

    const user = result.rows[0];
    return user;
  } catch (error) {
    console.error('Error executing SQL query:', error);
    throw error;
  }
}

module.exports = { getUserByEmail };

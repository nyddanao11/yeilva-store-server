// routes/checkAuth.js

const express = require('express');
const authenticateJWT = require('../middleware/authenticateJWT');

const router = express.Router();

router.get('/', authenticateJWT, (req, res) => {
  // Access the user information in req.user
  res.json({ message: 'Authentication successful', user: req.user });
  console.log('Authentication successful');
});

module.exports = router;

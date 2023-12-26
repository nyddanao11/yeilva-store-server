// middleware/authenticateJWT.js

const jwt = require('jsonwebtoken');
const { ACCESS_TOKEN_SECRET } = process.env;

function authenticateJWT(req, res, next) {
  const token = req.cookies.jwtToken;

  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.sendStatus(403);
    }

    req.user = user;
    console.log('User authenticated:', user);
    next();
  });
}




module.exports = authenticateJWT;

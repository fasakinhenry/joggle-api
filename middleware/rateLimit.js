const rateLimit = require('express-rate-limit');
const logger = require('../config/logger');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 50 : 1000, // 50 requests in prod
  message: 'Too many requests, please try again later.',
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  },
});

module.exports = { authLimiter };

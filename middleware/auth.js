const jwt = require('jsonwebtoken');
const logger = require('../config/logger');

const ensureAuthenticated = async (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  logger.warn('Unauthorized access attempt');
  res.status(401).json({ error: 'Unauthorized' });
};

module.exports = { ensureAuthenticated };

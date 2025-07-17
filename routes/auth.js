const express = require('express');
const passport = require('passport');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../config/email');
const { authLimiter } = require('../middleware/rateLimit');
const { ensureAuthenticated } = require('../middleware/auth');
const User = require('../models/User');
const logger = require('../config/logger');

const router = express.Router();

// Validation middleware
const validateSignup = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('username').trim().notEmpty(),
];

const validateLogin = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
];

const validatePasswordReset = [
  body('email').isEmail().normalizeEmail(),
];

const validatePasswordResetConfirm = [
  body('token').notEmpty(),
  body('newPassword').isLength({ min: 8 }),
];

// Signup
router.post('/signup', authLimiter, validateSignup, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Signup validation failed', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, username } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warn(`Signup attempt with existing email: ${email}`);
      return res.status(400).json({ error: 'Email already exists' });
    }

    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const user = new User({ email, password, username, verificationToken });
    await user.save();

    const verificationUrl = `${process.env.BACKEND_URL}/api/auth/verify-email?token=${verificationToken}`;
    await sendEmail(
      email,
      'Verify Your Email',
      `<p>Please verify your email by clicking <a href="${verificationUrl}">here</a>.</p>`
    );

    res.status(201).json({ message: 'User created, verification email sent' });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify Email
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email: decoded.email, verificationToken: token });

    if (!user) {
      logger.warn('Invalid or expired verification token');
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    req.login(user, (err) => {
      if (err) {
        logger.error('Login after verification failed:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.redirect(`${process.env.FRONTEND_URL}/launchpad`);
    });
  } catch (error) {
    logger.error('Verify email error:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// Login
router.post('/login', authLimiter, validateLogin, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      logger.error('Login error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    if (!user) {
      logger.warn('Login failed:', info.message);
      return res.status(401).json({ error: info.message });
    }

    req.login(user, (err) => {
      if (err) {
        logger.error('Session login error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.json({ message: 'Login successful', user: { email: user.email, username: user.username } });
    });
  })(req, res, next);
});

// OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URL}/auth/signin?error=auth_failed` }), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/launchpad`);
});

router.get('/facebook', passport.authenticate('facebook', { scope: ['email'] }));
router.get('/facebook/callback', passport.authenticate('facebook', { failureRedirect: `${process.env.FRONTEND_URL}/auth/signin?error=auth_failed` }), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/launchpad`);
});

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/github/callback', passport.authenticate('github', { failureRedirect: `${process.env.FRONTEND_URL}/auth/signin?error=auth_failed` }), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/launchpad`);
});

router.get('/linkedin', passport.authenticate('linkedin', { scope: ['r_emailaddress', 'r_liteprofile'] }));
router.get('/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: `${process.env.FRONTEND_URL}/auth/signin?error=auth_failed` }), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/launchpad`);
});

// Password Reset Request
router.post('/password-reset', authLimiter, validatePasswordReset, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Password reset validation failed', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`Password reset requested for non-existent email: ${email}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password?token=${resetToken}`;
    await sendEmail(
      email,
      'Password Reset Request',
      `<p>Reset your password by clicking <a href="${resetUrl}">here</a>. Link expires in 1 hour.</p>`
    );

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    logger.error('Password reset error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Password Reset Confirm
router.post('/password-reset/confirm', authLimiter, validatePasswordResetConfirm, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Password reset confirm validation failed', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({
      email: decoded.email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      logger.warn('Invalid or expired password reset token');
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    logger.error('Password reset confirm error:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// Logout
router.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      logger.error('Logout error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    req.session.destroy((err) => {
      if (err) {
        logger.error('Session destroy error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      res.clearCookie('connect.sid');
      res.json({ message: 'Logout successful' });
    });
  });
});

// Delete Account
router.delete('/account', ensureAuthenticated, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);
    req.logout((err) => {
      if (err) {
        logger.error('Logout after account deletion error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      req.session.destroy((err) => {
        if (err) {
          logger.error('Session destroy after account deletion error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Account deleted successfully' });
      });
    });
  } catch (error) {
    logger.error('Account deletion error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get User
router.get('/user', ensureAuthenticated, (req, res) => {
  const { email, username, isVerified, socialProfiles, badges, languages } = req.user;
  res.json({ email, username, isVerified, socialProfiles, badges, languages });
});

// Health Check
router.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

module.exports = router;

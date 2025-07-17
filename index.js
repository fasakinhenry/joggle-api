const express = require('express');
const cors = require('cors');
const { connectDB } = require('./config/db');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Centralized error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error:
      process.env.NODE_ENV === 'production'
        ? 'Internal Server Error'
        : err.message,
  });
});

// Connect to MongoDB
connectDB();

// Routes
app.use('/api/auth', require('./routes/auth2'));

// Not found route
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

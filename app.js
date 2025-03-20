const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const userRoutes = require('./routes/userRoutes');
const logger = require('./logger');

// Load environment variables from .env file
dotenv.config();

const app = express();

// Middleware
app.use(cors()); // Enable Cross-Origin Request Sharing
app.use(express.json()); // Parse incoming JSON requests (No need for body-parser)

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Database connected successfully');
  })
  .catch((error) => {
    console.error('Database connection error:', error.message);
  });

  // Log all incoming requests
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.originalUrl} - ${req.ip}`);
  next();
});


// Routes
app.use('/api/users', userRoutes);

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  // Use logger to log error details
  logger.error(`${err.message} - ${req.method} ${req.originalUrl} - ${req.ip}`);

  // Determine the status code (default to 500 if not provided)
  const statusCode = err.status || 500;

  // Prepare the error response
  const response = {
    error: {
      message: err.message || 'Something went wrong!',
      status: statusCode,
    },
  };

  // For mongoose validation errors or any other validation-related errors
  if (err.name === 'ValidationError') {
    response.error.details = err.errors; // Add validation error details
  }

  // Send the response
  res.status(statusCode).json(response);
});


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


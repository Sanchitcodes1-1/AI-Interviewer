const jwt = require('jsonwebtoken');
const logger = require('../logger'); // Import the logger

// Middleware to authenticate and verify JWT token
const authenticateToken = (req, res, next) => {
    // Get the token from Authorization header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    // If no token, return 401 Unauthorized error
    if (!token) {
        logger.warn(`Unauthorized access attempt - ${req.method} ${req.originalUrl} - ${req.ip}`);
        return res.status(401).json({ error: 'Access denied, no token provided' });
    }

    try {
        // Verify the token and decode the payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach user info(id, email) to the request object
        req.user = decoded; // Now accessible in other routes

        logger.info(`Token verified for user ${decoded.id} - ${req.method} ${req.originalUrl}`);
        next();
    } catch (error) {
        logger.error(`Invalid/Expired token - ${req.method} ${req.originalUrl} - ${req.ip}`);
        return res.status(400).json({ error: 'Invalid or expired token' });
    }
};

module.exports = authenticateToken;

// backend/middleware/errorHandler.js

const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
    logger.error('Error occurred:', {
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip
    });

    // Don't expose internal errors in production
    if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({
            error: 'Internal server error'
        });
    }

    // In development, show more details
    res.status(err.status || 500).json({
        error: err.message,
        stack: err.stack,
        path: req.path
    });
};

module.exports = errorHandler;
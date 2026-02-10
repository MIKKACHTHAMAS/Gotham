// backend/middleware/security.js

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
    // Sanitize all string fields in body
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                req.body[key] = validator.escape(req.body[key].trim());
            }
        });
    }
    
    // Sanitize query parameters
    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === 'string') {
                req.query[key] = validator.escape(req.query[key].trim());
            }
        });
    }
    
    next();
};

// XSS protection headers
const xssProtection = (req, res, next) => {
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
};

// Prevent parameter pollution
const preventParameterPollution = (req, res, next) => {
    const queryKeys = Object.keys(req.query);
    const uniqueKeys = [...new Set(queryKeys)];
    
    if (queryKeys.length !== uniqueKeys.length) {
        return res.status(400).json({
            error: 'Duplicate query parameters detected'
        });
    }
    
    next();
};

module.exports = {
    sanitizeInput,
    xssProtection,
    preventParameterPollution
};
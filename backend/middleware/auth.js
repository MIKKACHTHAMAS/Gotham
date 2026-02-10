// backend/middleware/auth.js

const jwt = require('jsonwebtoken');
const { query } = require('../config/database');
const logger = require('../utils/logger');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        
        // Check if user exists and is active
        const userResult = await query(
            'SELECT id, username, email, role, is_active FROM users WHERE id = $1',
            [decoded.userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        if (!userResult.rows[0].is_active) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }

        req.user = userResult.rows[0];
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        logger.error('Authentication error:', error);
        return res.status(403).json({ error: 'Invalid token' });
    }
};

const authorizeRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Insufficient permissions' 
            });
        }

        next();
    };
};

// Rate limiting for authentication attempts
const trackLoginAttempts = async (req, res, next) => {
    const { email } = req.body;
    
    try {
        const result = await query(
            'SELECT login_attempts, locked_until FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            
            // Check if account is locked
            if (user.locked_until && user.locked_until > new Date()) {
                return res.status(423).json({
                    error: 'Account is temporarily locked. Please try again later.'
                });
            }
        }
        
        next();
    } catch (error) {
        logger.error('Login attempt tracking error:', error);
        next();
    }
};

module.exports = {
    authenticateToken,
    authorizeRole,
    trackLoginAttempts
};
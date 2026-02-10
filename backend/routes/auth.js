// backend/routes/auth.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { query } = require('../config/database');
const logger = require('../utils/logger');
const {
    validateRegistration,
    validateLogin,
    validatePasswordReset,
    handleValidationErrors
} = require('../validators/auth');
const { trackLoginAttempts } = require('../middleware/auth');
const { sendPasswordResetEmail } = require('../utils/email');

// Register
router.post('/register', validateRegistration, handleValidationErrors, async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;

        // Check if user already exists
        const existingUser = await query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                error: 'User with this email or username already exists'
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS));

        // Create user
        const result = await query(
            `INSERT INTO users (username, email, password_hash, full_name) 
             VALUES ($1, $2, $3, $4) 
             RETURNING id, username, email, full_name, role, created_at`,
            [username, email, passwordHash, fullName || null]
        );

        const user = result.rows[0];

        // Generate tokens
        const accessToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
        );

        const refreshToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
        );

        // Hash and store refresh token
        const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        await query(
            `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
             VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.id, refreshTokenHash]
        );

        // Set tokens in HTTP-only cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // Log activity
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [user.id, 'register', req.ip, req.headers['user-agent']]
        );

        res.status(201).json({
            message: 'Registration successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name,
                role: user.role
            }
        });

    } catch (error) {
        logger.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
router.post('/login', validateLogin, handleValidationErrors, trackLoginAttempts, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Get user with password hash
        const result = await query(
            `SELECT id, username, email, password_hash, role, is_active, 
                    login_attempts, locked_until 
             FROM users WHERE email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Check if account is locked
        if (user.locked_until && user.locked_until > new Date()) {
            return res.status(423).json({
                error: 'Account is temporarily locked. Please try again later.'
            });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            // Increment failed login attempts
            const newAttempts = user.login_attempts + 1;
            let lockUpdate = '';
            let lockParams = [];

            if (newAttempts >= 5) {
                lockUpdate = ', locked_until = NOW() + INTERVAL \'30 minutes\'';
            }

            await query(
                `UPDATE users SET login_attempts = $1 ${lockUpdate} WHERE id = $2`,
                [newAttempts, user.id]
            );

            // Log failed attempt
            await query(
                `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
                 VALUES ($1, $2, $3, $4)`,
                [user.id, 'failed_login', req.ip, req.headers['user-agent']]
            );

            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Reset login attempts on successful login
        await query(
            'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
            [user.id]
        );

        // Generate tokens
        const accessToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
        );

        const refreshToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
        );

        // Hash and store refresh token
        const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        await query(
            `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) 
             VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.id, refreshTokenHash]
        );

        // Set tokens in HTTP-only cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Log successful login
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [user.id, 'login', req.ip, req.headers['user-agent']]
        );

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Refresh token
router.post('/refresh', async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ error: 'Refresh token required' });
        }

        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        // Check if refresh token exists and is not revoked
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        const tokenResult = await query(
            `SELECT * FROM refresh_tokens 
             WHERE token_hash = $1 AND user_id = $2 AND revoked = false AND expires_at > NOW()`,
            [tokenHash, decoded.userId]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        // Generate new access token
        const accessToken = jwt.sign(
            { userId: decoded.userId },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
        );

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000
        });

        res.json({ message: 'Token refreshed' });

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Refresh token expired' });
        }
        logger.error('Token refresh error:', error);
        res.status(403).json({ error: 'Invalid refresh token' });
    }
});

// Logout
router.post('/logout', async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {
            // Revoke refresh token
            const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
            await query(
                'UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1',
                [tokenHash]
            );
        }

        // Clear cookies
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        // Log activity
        if (req.user) {
            await query(
                `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
                 VALUES ($1, $2, $3, $4)`,
                [req.user.id, 'logout', req.ip, req.headers['user-agent']]
            );
        }

        res.json({ message: 'Logout successful' });

    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Forgot password request
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const userResult = await query(
            'SELECT id, email FROM users WHERE email = $1 AND is_active = true',
            [email]
        );

        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            
            // Generate reset token
            const resetToken = crypto.randomBytes(32).toString('hex');
            const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
            const expiresAt = new Date(Date.now() + 3600000); // 1 hour

            // Store token
            await query(
                `INSERT INTO password_resets (user_id, token_hash, expires_at) 
                 VALUES ($1, $2, $3)`,
                [user.id, tokenHash, expiresAt]
            );

            // Send email
            await sendPasswordResetEmail(user.email, resetToken);

            // Log activity
            await query(
                `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
                 VALUES ($1, $2, $3, $4)`,
                [user.id, 'password_reset_request', req.ip, req.headers['user-agent']]
            );
        }

        // Always return success to prevent email enumeration
        res.json({ 
            message: 'If an account exists with this email, you will receive password reset instructions.' 
        });

    } catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({ error: 'Password reset request failed' });
    }
});

// Reset password
router.post('/reset-password/:token', validatePasswordReset, handleValidationErrors, async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Hash token to compare with stored hash
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Find valid reset token
        const resetResult = await query(
            `SELECT pr.user_id, pr.expires_at, u.is_active 
             FROM password_resets pr 
             JOIN users u ON pr.user_id = u.id 
             WHERE pr.token_hash = $1 AND pr.used = false AND pr.expires_at > NOW()`,
            [tokenHash]
        );

        if (resetResult.rows.length === 0) {
            return res.status(400).json({ 
                error: 'Invalid or expired reset token' 
            });
        }

        const { user_id, expires_at } = resetResult.rows[0];

        // Check if token is expired
        if (expires_at < new Date()) {
            await query(
                'UPDATE password_resets SET used = true WHERE token_hash = $1',
                [tokenHash]
            );
            return res.status(400).json({ error: 'Reset token has expired' });
        }

        // Hash new password
        const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS));

        // Update password
        await query(
            'UPDATE users SET password_hash = $1, login_attempts = 0, locked_until = NULL WHERE id = $2',
            [passwordHash, user_id]
        );

        // Mark token as used
        await query(
            'UPDATE password_resets SET used = true WHERE token_hash = $1',
            [tokenHash]
        );

        // Revoke all refresh tokens for security
        await query(
            'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1',
            [user_id]
        );

        // Log activity
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [user_id, 'password_reset', req.ip, req.headers['user-agent']]
        );

        res.json({ message: 'Password reset successful' });

    } catch (error) {
        logger.error('Password reset error:', error);
        res.status(500).json({ error: 'Password reset failed' });
    }
});

module.exports = router;
// backend/routes/users.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { authenticateToken, authorizeRole } = require('../middleware/auth');
const { validateProfileUpdate, handleValidationErrors } = require('../validators/auth');
const { query } = require('../config/database');
const logger = require('../utils/logger');

// Get current user profile
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const result = await query(
            `SELECT id, username, email, full_name, avatar_url, role, 
                    is_verified, created_at, updated_at 
             FROM users WHERE id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: result.rows[0] });
    } catch (error) {
        logger.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update profile
router.put('/profile', authenticateToken, validateProfileUpdate, handleValidationErrors, async (req, res) => {
    try {
        const { username, fullName } = req.body;
        const updates = [];
        const params = [];
        let paramCount = 1;

        // Build dynamic update query
        if (username !== undefined) {
            // Check if username is available
            const existingUser = await query(
                'SELECT id FROM users WHERE username = $1 AND id != $2',
                [username, req.user.id]
            );

            if (existingUser.rows.length > 0) {
                return res.status(409).json({ error: 'Username already taken' });
            }

            updates.push(`username = $${paramCount}`);
            params.push(username);
            paramCount++;
        }

        if (fullName !== undefined) {
            updates.push(`full_name = $${paramCount}`);
            params.push(fullName);
            paramCount++;
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No updates provided' });
        }

        // Add user ID as last parameter
        params.push(req.user.id);

        const updateQuery = `
            UPDATE users 
            SET ${updates.join(', ')} 
            WHERE id = $${paramCount} 
            RETURNING id, username, email, full_name, avatar_url, role, updated_at
        `;

        const result = await query(updateQuery, params);

        // Log activity
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, 'profile_update', req.ip, req.headers['user-agent']]
        );

        res.json({
            message: 'Profile updated successfully',
            user: result.rows[0]
        });

    } catch (error) {
        logger.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Change password
router.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new password required' });
        }

        if (newPassword.length < 12) {
            return res.status(400).json({ 
                error: 'New password must be at least 12 characters' 
            });
        }

        // Get current password hash
        const userResult = await query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isValid = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const newPasswordHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS));

        // Update password
        await query(
            'UPDATE users SET password_hash = $1 WHERE id = $2',
            [newPasswordHash, req.user.id]
        );

        // Revoke all refresh tokens for security
        await query(
            'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1',
            [req.user.id]
        );

        // Log activity
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, 'password_change', req.ip, req.headers['user-agent']]
        );

        res.json({ message: 'Password changed successfully' });

    } catch (error) {
        logger.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Delete account (soft delete)
router.delete('/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password required for account deletion' });
        }

        // Get current password hash
        const userResult = await query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify password
        const isValid = await bcrypt.compare(password, userResult.rows[0].password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Password is incorrect' });
        }

        // Soft delete user
        await query(
            'UPDATE users SET is_active = false WHERE id = $1',
            [req.user.id]
        );

        // Revoke all tokens
        await query(
            'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1',
            [req.user.id]
        );

        // Clear cookies
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        // Log activity
        await query(
            `INSERT INTO user_activity (user_id, activity_type, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, 'account_deletion', req.ip, req.headers['user-agent']]
        );

        res.json({ message: 'Account deleted successfully' });

    } catch (error) {
        logger.error('Delete account error:', error);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// Admin: Get all users (admin only)
router.get('/', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        const result = await query(
            `SELECT id, username, email, full_name, role, is_active, is_verified, 
                    created_at, updated_at, last_login 
             FROM users 
             ORDER BY created_at DESC 
             LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        const countResult = await query('SELECT COUNT(*) FROM users');
        const total = parseInt(countResult.rows[0].count);

        res.json({
            users: result.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        logger.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

module.exports = router;
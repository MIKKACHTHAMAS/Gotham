// backend/routes/contact.js

const express = require('express');
const router = express.Router();
const { validateContact, handleValidationErrors } = require('../validators/auth');
const { query } = require('../config/database');
const logger = require('../utils/logger');

// Submit contact form
router.post('/', validateContact, handleValidationErrors, async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;

        // Save to database
        const result = await query(
            `INSERT INTO contact_submissions (name, email, subject, message) 
             VALUES ($1, $2, $3, $4) 
             RETURNING id, created_at`,
            [name, email, subject, message]
        );

        // In a real application, send email notification here
        // await sendContactNotification(name, email, subject, message);

        res.status(201).json({
            message: 'Contact form submitted successfully',
            submission: result.rows[0]
        });

    } catch (error) {
        logger.error('Contact form error:', error);
        res.status(500).json({ error: 'Failed to submit contact form' });
    }
});

// Get contact submissions (admin only - requires authentication)
// router.get('/', authenticateToken, authorizeRole('admin'), async (req, res) => {
//     // Implementation for admin to view submissions
// });

module.exports = router;
const nodemailer = require('nodemailer');
const logger = require('./logger');

// Create transporter
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_PORT === '465',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Verify transporter
transporter.verify((error) => {
    if (error) {
        logger.error('SMTP connection error:', error);
    } else {
        logger.info('SMTP server is ready to send emails');
    }
});

async function sendPasswordResetEmail(email, resetToken) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}`;
    
    const mailOptions = {
        from: `"Comic Secure" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Reset Your Comic Secure Password',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #080808; color: #ffffff; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #AE8875; padding: 20px; text-align: center; }
                    .content { background-color: #515155; padding: 30px; }
                    .button { display: inline-block; background-color: #AE8875; color: #080808; 
                             padding: 12px 24px; text-decoration: none; font-weight: bold; 
                             border-radius: 5px; margin: 20px 0; }
                    .footer { text-align: center; color: #7F8086; font-size: 12px; margin-top: 30px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🦸 Comic Secure</h1>
                    </div>
                    <div class="content">
                        <h2>Password Reset Request</h2>
                        <p>Hello Hero!</p>
                        <p>We received a request to reset your password for your Comic Secure account.</p>
                        <p>Click the button below to reset your password:</p>
                        <a href="${resetUrl}" class="button">Reset Password</a>
                        <p>This link will expire in 1 hour for security reasons.</p>
                        <p>If you didn't request this password reset, you can safely ignore this email.</p>
                        <p>Stay secure,<br>The Comic Secure Team</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Comic Secure. All rights reserved.</p>
                        <p>This is an automated message, please do not reply.</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        logger.info(`Password reset email sent to ${email}`);
        return true;
    } catch (error) {
        logger.error('Failed to send password reset email:', error);
        throw new Error('Failed to send reset email');
    }
}

async function sendWelcomeEmail(email, username) {
    const mailOptions = {
        from: `"Comic Secure" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Welcome to Comic Secure, Hero! 🦸',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #080808; color: #ffffff; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #AE8875; padding: 20px; text-align: center; }
                    .content { background-color: #515155; padding: 30px; }
                    .features { margin: 20px 0; }
                    .feature { margin: 10px 0; padding: 10px; background-color: rgba(8, 8, 8, 0.3); }
                    .footer { text-align: center; color: #7F8086; font-size: 12px; margin-top: 30px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🦸 Welcome to Comic Secure, ${username}!</h1>
                    </div>
                    <div class="content">
                        <p>Congratulations, Hero! You've just joined the most secure league in the digital universe.</p>
                        
                        <div class="features">
                            <h3>Your New Superpowers:</h3>
                            <div class="feature">🔒 Military-grade encryption</div>
                            <div class="feature">🛡️ Real-time threat protection</div>
                            <div class="feature">⚡ Lightning-fast performance</div>
                            <div class="feature">🌐 Cross-platform security</div>
                        </div>
                        
                        <p>Get started by exploring your dashboard and customizing your security settings.</p>
                        <p>Need help? Our hero support squad is available 24/7.</p>
                        <p>Stay vigilant, stay secure!<br>The Comic Secure Team</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Comic Secure. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        logger.info(`Welcome email sent to ${email}`);
        return true;
    } catch (error) {
        logger.error('Failed to send welcome email:', error);
        // Don't throw error for welcome email
        return false;
    }
}

module.exports = {
    sendPasswordResetEmail,
    sendWelcomeEmail
};
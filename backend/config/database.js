// backend/config/database.js

const { Pool } = require('pg');
const logger = require('../utils/logger');

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Log connection events
pool.on('connect', () => {
    logger.info('Database connected successfully');
});

pool.on('error', (err) => {
    logger.error('Unexpected database error:', err);
    process.exit(-1);
});

// Test connection
const connect = async () => {
    try {
        await pool.query('SELECT NOW()');
        logger.info('Database connection test successful');
        return true;
    } catch (error) {
        logger.error('Database connection test failed:', error);
        throw error;
    }
};

// Query helper with error handling
const query = async (text, params) => {
    const start = Date.now();
    try {
        const res = await pool.query(text, params);
        const duration = Date.now() - start;
        logger.debug(`Query executed in ${duration}ms: ${text.substring(0, 100)}...`);
        return res;
    } catch (error) {
        logger.error(`Query error: ${text.substring(0, 100)}...`, error);
        throw error;
    }
};

module.exports = {
    pool,
    connect,
    query
};
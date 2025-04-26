-- D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\database\schema.sql

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS fraud_detection_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Use the newly created database
USE fraud_detection_db;

-- Create the users table with the username column
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL, -- This is the correct definition
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the analysis_history table
CREATE TABLE IF NOT EXISTS analysis_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    item_type VARCHAR(50) NOT NULL, -- 'url' or 'qr'
    item_data TEXT NOT NULL,       -- The URL string or QR code content/filename
    analysis_result JSON,          -- Store the analysis result as JSON
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index on user_id for faster history retrieval
CREATE INDEX idx_user_id ON analysis_history (user_id);

-- You might want to add more indexes later for performance
-- Example: Index on item_type if you frequently filter by type
-- CREATE INDEX idx_item_type ON analysis_history (item_type);

-- Example: Index on analyzed_at if you frequently filter by date range
-- CREATE INDEX idx_analyzed_at ON analysis_history (analyzed_at);

-- Example: Full-text index on item_data if you implement text search (requires specific MySQL configuration)
-- CREATE FULLTEXT INDEX ft_item_data ON analysis_history (item_data);
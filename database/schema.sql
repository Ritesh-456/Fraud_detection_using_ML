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
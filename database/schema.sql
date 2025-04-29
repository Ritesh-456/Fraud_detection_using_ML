-- D:\Projects\Fraud Detection using ML\Fraud_detection_using_ML\database\schema.sql

-- This script creates the necessary database and tables for the Fraud Detection System.
-- It is designed for a MySQL database.

-- Create the database if it does not already exist.
-- Specify character set and collation for proper handling of text data.
CREATE DATABASE IF NOT EXISTS fraud_detection_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Switch to using the newly created database.
USE fraud_detection_db;

-- Create the 'users' table if it does not already exist.
-- Stores user authentication and identification information.
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,          -- Unique auto-incrementing user ID (Primary Key)
    email VARCHAR(255) UNIQUE NOT NULL,         -- User's email address (must be unique, cannot be null)
    username VARCHAR(255) UNIQUE NOT NULL,      -- User's chosen username (must be unique, cannot be null)
    password_hash VARCHAR(255) NOT NULL,        -- Hashed password string (cannot be null)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Timestamp when the user was created (defaults to current time)
);

-- Create the 'analysis_history' table if it does not already exist.
-- Stores the history of analysis requests and their results for each user.
CREATE TABLE IF NOT EXISTS analysis_history (
    id INT AUTO_INCREMENT PRIMARY KEY,          -- Unique auto-incrementing history item ID (Primary Key)
    user_id INT,                                -- ID of the user who performed the analysis
    item_type VARCHAR(50) NOT NULL,             -- Type of item analyzed (e.g., 'url', 'qr')
    item_data TEXT NOT NULL,                    -- The actual data that was analyzed (e.g., the URL string, decoded QR content)
    analysis_result JSON,                       -- The analysis result stored as a JSON document
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Timestamp when the analysis was performed

    -- Define a foreign key constraint linking analysis history items to users.
    -- ON DELETE CASCADE means if a user is deleted, all their associated history items are also automatically deleted.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add an index on the 'user_id' column in the 'analysis_history' table.
-- This significantly speeds up queries that filter history by user ID (e.g., fetching a user's history).
CREATE INDEX idx_user_id ON analysis_history (user_id);

-- Optional: Add more indexes for performance based on common query patterns.
-- These can be added later if performance profiling shows bottlenecks.
-- Example: Index on 'item_type' if you frequently filter history by type.
-- CREATE INDEX idx_item_type ON analysis_history (item_type);

-- Example: Index on 'analyzed_at' if you frequently query history within date ranges.
-- CREATE INDEX idx_analyzed_at ON analysis_history (analyzed_at);

-- Example: Full-text index on 'item_data' if you implement text search functionality.
-- Note: Full-text indexing requires specific MySQL configuration and engine (e.g., MyISAM or InnoDB with specific settings).
-- CREATE FULLTEXT INDEX ft_item_data ON analysis_history (item_data);
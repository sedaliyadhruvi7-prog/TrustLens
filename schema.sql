CREATE DATABASE IF NOT EXISTS trustlens;
USE trustlens;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  reference_id VARCHAR(20) NOT NULL UNIQUE,
  user_id INT, -- NULL for guest scans
  scan_type ENUM('message', 'url', 'job') NOT NULL,
  content TEXT NOT NULL,
  risk_score INT NOT NULL,
  risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  findings JSON NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE community_reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  category VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  status ENUM('pending', 'reviewing', 'approved', 'rejected') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_progress (
  user_id INT PRIMARY KEY,
  points INT DEFAULT 0,
  quizzes_completed INT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
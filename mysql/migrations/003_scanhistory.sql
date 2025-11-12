-- Migration: 003_scanhistory.sql
-- Description: Create ScanHistory table for tracking scan executions
-- Date: 2025-10-23

CREATE TABLE IF NOT EXISTS ScanHistory (
    -- Primary identification
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Scan details
    repo_postfix VARCHAR(512) NOT NULL,
    branch VARCHAR(255) NOT NULL,
    commit VARCHAR(64),

    -- Scan metadata
    scanner_type VARCHAR(50),         -- 'SAST', 'OSS', 'Secrets'
    scanner_name VARCHAR(100),        -- 'Semgrep', 'FOSSA', 'Trufflehog'
    scan_mode VARCHAR(50),            -- 'API', 'CLI'

    -- Results
    total_findings INT DEFAULT 0,
    new_findings INT DEFAULT 0,
    updated_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,

    -- Status
    status VARCHAR(50),               -- 'SUCCESS', 'FAILED', 'PARTIAL'
    error_message TEXT,

    -- Performance
    duration_seconds FLOAT,

    -- Timestamps
    started_at TIMESTAMP,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Indexes
    INDEX idx_repo_branch (repo_postfix, branch),
    INDEX idx_scanner (scanner_type),
    INDEX idx_scanner_name (scanner_name),
    INDEX idx_status (status),
    INDEX idx_completed (completed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migration: 001_ctsvuln.sql
-- Description: Create CtsVuln table for vulnerability tracking
-- Date: 2025-10-23

CREATE TABLE IF NOT EXISTS CtsVuln (
    -- Primary identification
    id INT AUTO_INCREMENT PRIMARY KEY,
    primary_unique_key VARCHAR(512) UNIQUE NOT NULL,

    -- Vulnerability details
    ticket_name VARCHAR(512),
    severity VARCHAR(20),
    description TEXT,
    component VARCHAR(100),  -- 'OSS', 'SAST', 'Secrets'

    -- Source information
    source VARCHAR(100),     -- 'ProdSec', 'Community'
    origin_ref VARCHAR(512), -- Link to vulnerability details
    origin_path TEXT,        -- Comma-separated affected files

    -- Repository context
    postfix VARCHAR(512),    -- Repository identifier (org/repo)
    branch VARCHAR(255),
    commit VARCHAR(64),

    -- Version information
    remediation_version VARCHAR(100),
    affects_version VARCHAR(100),

    -- Ownership
    owner VARCHAR(255),
    productArea VARCHAR(100),
    mission_team VARCHAR(100),

    -- Metadata
    labels TEXT,             -- Comma-separated
    cves TEXT,               -- Comma-separated CVE IDs
    cwes TEXT,               -- Comma-separated CWE IDs

    -- Status tracking
    status VARCHAR(50) DEFAULT 'CREATED',      -- 'CREATED', 'UPDATED', 'RESOLVED'
    resolution VARCHAR(255),
    ticket_readiness TINYINT DEFAULT 0,
    jira_ticket VARCHAR(255),
    due_date DATE,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    INDEX idx_repo_branch (postfix, branch),
    INDEX idx_severity (severity),
    INDEX idx_component (component),
    INDEX idx_owner (owner),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_last_activity_at (last_activity_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migration: 002_ownership.sql
-- Description: Create OwnershipReference table for repository ownership mapping
-- Date: 2025-10-23

CREATE TABLE IF NOT EXISTS OwnershipReference (
    -- Primary identification
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Repository identification
    repo_url VARCHAR(512) NOT NULL,
    repo_postfix VARCHAR(512) NOT NULL,
    branch VARCHAR(255),

    -- Ownership details
    owner_type VARCHAR(50),           -- 'user', 'team', 'group'
    owner_identifier VARCHAR(255),    -- Email, username, or group name

    -- Metadata
    preferred_assignee_strategy VARCHAR(50), -- 'assignee', 'recent_committer', 'codeowners'
    jira_labels TEXT,                 -- Comma-separated
    jira_watchers TEXT,               -- Comma-separated email addresses
    product_area VARCHAR(100),
    mission_team VARCHAR(100),
    o11y_program_team VARCHAR(100),

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Indexes
    UNIQUE KEY idx_repo_branch (repo_postfix, branch),
    INDEX idx_owner (owner_identifier),
    INDEX idx_repo_url (repo_url),
    INDEX idx_owner_type (owner_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

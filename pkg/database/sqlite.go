package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteDB implements DB interface for SQLite
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLite creates a new SQLite database connection
func NewSQLite(cfg Config) (*SQLiteDB, error) {
	dbPath := cfg.FilePath
	if dbPath == "" {
		// Default to ~/.securelens/securelens.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, ".securelens", "securelens.db")
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	slog.Info("Opening SQLite database", "path", dbPath)

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	sqliteDB := &SQLiteDB{db: db}

	// Run migrations
	if err := sqliteDB.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return sqliteDB, nil
}

// migrate creates the database schema
func (s *SQLiteDB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS repositories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		provider TEXT NOT NULL,
		name TEXT NOT NULL,
		full_name TEXT NOT NULL,
		url TEXT,
		clone_url TEXT,
		is_private INTEGER DEFAULT 0,
		language TEXT,
		description TEXT,
		source TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(provider, full_name)
	);

	CREATE INDEX IF NOT EXISTS idx_repos_provider ON repositories(provider);
	CREATE INDEX IF NOT EXISTS idx_repos_source ON repositories(source);
	CREATE INDEX IF NOT EXISTS idx_repos_full_name ON repositories(full_name);

	CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		branch TEXT,
		commit_hash TEXT,
		status TEXT DEFAULT 'pending',
		scan_mode TEXT,
		scanners TEXT,
		results_json TEXT,
		error_msg TEXT,
		started_at DATETIME,
		completed_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_scans_repo ON scan_results(repository_id);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_results(status);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repository_id INTEGER NOT NULL,
		scan_result_id INTEGER,
		scanner TEXT NOT NULL,
		rule_id TEXT,
		severity TEXT,
		title TEXT,
		description TEXT,
		file_path TEXT,
		line_start INTEGER,
		line_end INTEGER,
		fingerprint TEXT UNIQUE,
		first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'open',
		ticket_id TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
		FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repository_id);
	CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection
func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// Ping checks the database connection
func (s *SQLiteDB) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// CreateRepository creates a new repository record
func (s *SQLiteDB) CreateRepository(ctx context.Context, repo *Repository) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO repositories (provider, name, full_name, url, clone_url, is_private, language, description, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, repo.Provider, repo.Name, repo.FullName, repo.URL, repo.CloneURL, repo.IsPrivate, repo.Language, repo.Description, repo.Source)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	repo.ID = id
	return nil
}

// GetRepository retrieves a repository by ID
func (s *SQLiteDB) GetRepository(ctx context.Context, id int64) (*Repository, error) {
	repo := &Repository{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, provider, name, full_name, url, clone_url, is_private, language, description, source, created_at, updated_at
		FROM repositories WHERE id = ?
	`, id).Scan(&repo.ID, &repo.Provider, &repo.Name, &repo.FullName, &repo.URL, &repo.CloneURL,
		&repo.IsPrivate, &repo.Language, &repo.Description, &repo.Source, &repo.CreatedAt, &repo.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return repo, err
}

// GetRepositoryByFullName retrieves a repository by provider and full name
func (s *SQLiteDB) GetRepositoryByFullName(ctx context.Context, provider, fullName string) (*Repository, error) {
	repo := &Repository{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, provider, name, full_name, url, clone_url, is_private, language, description, source, created_at, updated_at
		FROM repositories WHERE provider = ? AND full_name = ?
	`, provider, fullName).Scan(&repo.ID, &repo.Provider, &repo.Name, &repo.FullName, &repo.URL, &repo.CloneURL,
		&repo.IsPrivate, &repo.Language, &repo.Description, &repo.Source, &repo.CreatedAt, &repo.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return repo, err
}

// ListRepositories retrieves repositories with optional filtering
func (s *SQLiteDB) ListRepositories(ctx context.Context, opts ListRepositoriesOptions) ([]Repository, error) {
	query := "SELECT id, provider, name, full_name, url, clone_url, is_private, language, description, source, created_at, updated_at FROM repositories WHERE 1=1"
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Source != "" {
		query += " AND source = ?"
		args = append(args, opts.Source)
	}
	if opts.Search != "" {
		query += " AND (full_name LIKE ? OR name LIKE ? OR description LIKE ?)"
		searchTerm := "%" + opts.Search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	query += " ORDER BY updated_at DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var repos []Repository
	for rows.Next() {
		var repo Repository
		if err := rows.Scan(&repo.ID, &repo.Provider, &repo.Name, &repo.FullName, &repo.URL, &repo.CloneURL,
			&repo.IsPrivate, &repo.Language, &repo.Description, &repo.Source, &repo.CreatedAt, &repo.UpdatedAt); err != nil {
			return nil, err
		}
		repos = append(repos, repo)
	}
	return repos, rows.Err()
}

// UpsertRepository creates or updates a repository
func (s *SQLiteDB) UpsertRepository(ctx context.Context, repo *Repository) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO repositories (provider, name, full_name, url, clone_url, is_private, language, description, source, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(provider, full_name) DO UPDATE SET
			name = excluded.name,
			url = excluded.url,
			clone_url = excluded.clone_url,
			is_private = excluded.is_private,
			language = excluded.language,
			description = excluded.description,
			source = excluded.source,
			updated_at = CURRENT_TIMESTAMP
	`, repo.Provider, repo.Name, repo.FullName, repo.URL, repo.CloneURL, repo.IsPrivate, repo.Language, repo.Description, repo.Source)
	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	if id > 0 {
		repo.ID = id
	}
	return nil
}

// DeleteRepository deletes a repository
func (s *SQLiteDB) DeleteRepository(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM repositories WHERE id = ?", id)
	return err
}

// CreateScanResult creates a new scan result
func (s *SQLiteDB) CreateScanResult(ctx context.Context, result *ScanResult) error {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_results (repository_id, branch, commit_hash, status, scan_mode, scanners, results_json, error_msg, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, result.RepositoryID, result.Branch, result.Commit, result.Status, result.ScanMode, result.Scanners, result.ResultsJSON, result.ErrorMsg, result.StartedAt)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	result.ID = id
	return nil
}

// GetScanResult retrieves a scan result by ID
func (s *SQLiteDB) GetScanResult(ctx context.Context, id int64) (*ScanResult, error) {
	result := &ScanResult{}
	var completedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, repository_id, branch, commit_hash, status, scan_mode, scanners, results_json, error_msg, started_at, completed_at, created_at
		FROM scan_results WHERE id = ?
	`, id).Scan(&result.ID, &result.RepositoryID, &result.Branch, &result.Commit, &result.Status,
		&result.ScanMode, &result.Scanners, &result.ResultsJSON, &result.ErrorMsg, &result.StartedAt, &completedAt, &result.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if completedAt.Valid {
		result.CompletedAt = completedAt.Time
	}
	return result, err
}

// GetLatestScanResult gets the most recent scan result for a repo/branch
func (s *SQLiteDB) GetLatestScanResult(ctx context.Context, repositoryID int64, branch string) (*ScanResult, error) {
	result := &ScanResult{}
	var completedAt sql.NullTime
	query := "SELECT id, repository_id, branch, commit_hash, status, scan_mode, scanners, results_json, error_msg, started_at, completed_at, created_at FROM scan_results WHERE repository_id = ?"
	args := []interface{}{repositoryID}

	if branch != "" {
		query += " AND branch = ?"
		args = append(args, branch)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.ID, &result.RepositoryID, &result.Branch, &result.Commit, &result.Status,
		&result.ScanMode, &result.Scanners, &result.ResultsJSON, &result.ErrorMsg, &result.StartedAt, &completedAt, &result.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if completedAt.Valid {
		result.CompletedAt = completedAt.Time
	}
	return result, err
}

// ListScanResults lists scan results with filtering
func (s *SQLiteDB) ListScanResults(ctx context.Context, opts ListScanResultsOptions) ([]ScanResult, error) {
	query := "SELECT id, repository_id, branch, commit_hash, status, scan_mode, scanners, results_json, error_msg, started_at, completed_at, created_at FROM scan_results WHERE 1=1"
	args := []interface{}{}

	if opts.RepositoryID > 0 {
		query += " AND repository_id = ?"
		args = append(args, opts.RepositoryID)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []ScanResult
	for rows.Next() {
		var result ScanResult
		var completedAt sql.NullTime
		if err := rows.Scan(&result.ID, &result.RepositoryID, &result.Branch, &result.Commit, &result.Status,
			&result.ScanMode, &result.Scanners, &result.ResultsJSON, &result.ErrorMsg, &result.StartedAt, &completedAt, &result.CreatedAt); err != nil {
			return nil, err
		}
		if completedAt.Valid {
			result.CompletedAt = completedAt.Time
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

// UpdateScanResult updates a scan result
func (s *SQLiteDB) UpdateScanResult(ctx context.Context, result *ScanResult) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scan_results SET status = ?, results_json = ?, error_msg = ?, completed_at = ?
		WHERE id = ?
	`, result.Status, result.ResultsJSON, result.ErrorMsg, time.Now(), result.ID)
	return err
}

// CreateFinding creates a new finding
func (s *SQLiteDB) CreateFinding(ctx context.Context, finding *Finding) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (repository_id, scan_result_id, scanner, rule_id, severity, title, description, file_path, line_start, line_end, fingerprint, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, finding.RepositoryID, finding.ScanResultID, finding.Scanner, finding.RuleID, finding.Severity,
		finding.Title, finding.Description, finding.FilePath, finding.LineStart, finding.LineEnd, finding.Fingerprint, finding.Status)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	finding.ID = id
	return nil
}

// GetFinding retrieves a finding by ID
func (s *SQLiteDB) GetFinding(ctx context.Context, id int64) (*Finding, error) {
	finding := &Finding{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, repository_id, scan_result_id, scanner, rule_id, severity, title, description, file_path, line_start, line_end, fingerprint, first_seen_at, last_seen_at, status, ticket_id, created_at, updated_at
		FROM findings WHERE id = ?
	`, id).Scan(&finding.ID, &finding.RepositoryID, &finding.ScanResultID, &finding.Scanner, &finding.RuleID,
		&finding.Severity, &finding.Title, &finding.Description, &finding.FilePath, &finding.LineStart,
		&finding.LineEnd, &finding.Fingerprint, &finding.FirstSeenAt, &finding.LastSeenAt, &finding.Status,
		&finding.TicketID, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return finding, err
}

// GetFindingByFingerprint retrieves a finding by fingerprint (for deduplication)
func (s *SQLiteDB) GetFindingByFingerprint(ctx context.Context, fingerprint string) (*Finding, error) {
	finding := &Finding{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, repository_id, scan_result_id, scanner, rule_id, severity, title, description, file_path, line_start, line_end, fingerprint, first_seen_at, last_seen_at, status, ticket_id, created_at, updated_at
		FROM findings WHERE fingerprint = ?
	`, fingerprint).Scan(&finding.ID, &finding.RepositoryID, &finding.ScanResultID, &finding.Scanner, &finding.RuleID,
		&finding.Severity, &finding.Title, &finding.Description, &finding.FilePath, &finding.LineStart,
		&finding.LineEnd, &finding.Fingerprint, &finding.FirstSeenAt, &finding.LastSeenAt, &finding.Status,
		&finding.TicketID, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return finding, err
}

// ListFindings lists findings with filtering
func (s *SQLiteDB) ListFindings(ctx context.Context, opts ListFindingsOptions) ([]Finding, error) {
	query := `SELECT id, repository_id, scan_result_id, scanner, rule_id, severity, title, description,
		file_path, line_start, line_end, fingerprint, first_seen_at, last_seen_at, status, ticket_id, created_at, updated_at
		FROM findings WHERE 1=1`
	args := []interface{}{}

	if opts.RepositoryID > 0 {
		query += " AND repository_id = ?"
		args = append(args, opts.RepositoryID)
	}
	if opts.ScanResultID > 0 {
		query += " AND scan_result_id = ?"
		args = append(args, opts.ScanResultID)
	}
	if opts.Scanner != "" {
		query += " AND scanner = ?"
		args = append(args, opts.Scanner)
	}
	if opts.Severity != "" {
		query += " AND severity = ?"
		args = append(args, opts.Severity)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}

	query += " ORDER BY last_seen_at DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.RepositoryID, &f.ScanResultID, &f.Scanner, &f.RuleID, &f.Severity,
			&f.Title, &f.Description, &f.FilePath, &f.LineStart, &f.LineEnd, &f.Fingerprint,
			&f.FirstSeenAt, &f.LastSeenAt, &f.Status, &f.TicketID, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpsertFinding creates or updates a finding (deduplication by fingerprint)
func (s *SQLiteDB) UpsertFinding(ctx context.Context, finding *Finding) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (repository_id, scan_result_id, scanner, rule_id, severity, title, description, file_path, line_start, line_end, fingerprint, status, last_seen_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(fingerprint) DO UPDATE SET
			scan_result_id = excluded.scan_result_id,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, finding.RepositoryID, finding.ScanResultID, finding.Scanner, finding.RuleID, finding.Severity,
		finding.Title, finding.Description, finding.FilePath, finding.LineStart, finding.LineEnd, finding.Fingerprint, finding.Status)
	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	if id > 0 {
		finding.ID = id
	}
	return nil
}

// UpdateFindingStatus updates the status and ticket ID of a finding
func (s *SQLiteDB) UpdateFindingStatus(ctx context.Context, id int64, status, ticketID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE findings SET status = ?, ticket_id = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, ticketID, id)
	return err
}

// GetRepositoryCount returns the total count of repositories
func (s *SQLiteDB) GetRepositoryCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM repositories").Scan(&count)
	return count, err
}

// GetFindingCountBySeverity returns finding counts grouped by severity
func (s *SQLiteDB) GetFindingCountBySeverity(ctx context.Context, repositoryID int64) (map[string]int64, error) {
	query := "SELECT severity, COUNT(*) FROM findings WHERE status = 'open'"
	args := []interface{}{}

	if repositoryID > 0 {
		query += " AND repository_id = ?"
		args = append(args, repositoryID)
	}
	query += " GROUP BY severity"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[strings.ToUpper(severity)] = count
	}
	return counts, rows.Err()
}

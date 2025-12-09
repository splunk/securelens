package database

import (
	"context"
	"time"
)

// Repository represents a cached repository
type Repository struct {
	ID          int64     `json:"id" db:"id"`
	Provider    string    `json:"provider" db:"provider"`
	Name        string    `json:"name" db:"name"`
	FullName    string    `json:"full_name" db:"full_name"`
	URL         string    `json:"url" db:"url"`
	CloneURL    string    `json:"clone_url" db:"clone_url"`
	IsPrivate   bool      `json:"is_private" db:"is_private"`
	Language    string    `json:"language" db:"language"`
	Description string    `json:"description" db:"description"`
	Source      string    `json:"source" db:"source"` // Config source name
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ScanResult represents a cached scan result
type ScanResult struct {
	ID           int64     `json:"id" db:"id"`
	RepositoryID int64     `json:"repository_id" db:"repository_id"`
	Branch       string    `json:"branch" db:"branch"`
	Commit       string    `json:"commit" db:"commit"`
	Status       string    `json:"status" db:"status"` // pending, running, completed, failed
	ScanMode     string    `json:"scan_mode" db:"scan_mode"`
	Scanners     string    `json:"scanners" db:"scanners"` // JSON array of scanner names
	ResultsJSON  string    `json:"results_json" db:"results_json"`
	ErrorMsg     string    `json:"error_msg" db:"error_msg"`
	StartedAt    time.Time `json:"started_at" db:"started_at"`
	CompletedAt  time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// Finding represents a deduplicated vulnerability finding
type Finding struct {
	ID           int64     `json:"id" db:"id"`
	RepositoryID int64     `json:"repository_id" db:"repository_id"`
	ScanResultID int64     `json:"scan_result_id" db:"scan_result_id"`
	Scanner      string    `json:"scanner" db:"scanner"`
	RuleID       string    `json:"rule_id" db:"rule_id"`
	Severity     string    `json:"severity" db:"severity"`
	Title        string    `json:"title" db:"title"`
	Description  string    `json:"description" db:"description"`
	FilePath     string    `json:"file_path" db:"file_path"`
	LineStart    int       `json:"line_start" db:"line_start"`
	LineEnd      int       `json:"line_end" db:"line_end"`
	Fingerprint  string    `json:"fingerprint" db:"fingerprint"` // Hash for deduplication
	FirstSeenAt  time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at" db:"last_seen_at"`
	Status       string    `json:"status" db:"status"` // open, resolved, ignored, ticketed
	TicketID     string    `json:"ticket_id" db:"ticket_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// DB is the interface for database operations
type DB interface {
	// Connection management
	Close() error
	Ping(ctx context.Context) error

	// Repository operations
	CreateRepository(ctx context.Context, repo *Repository) error
	GetRepository(ctx context.Context, id int64) (*Repository, error)
	GetRepositoryByFullName(ctx context.Context, provider, fullName string) (*Repository, error)
	ListRepositories(ctx context.Context, opts ListRepositoriesOptions) ([]Repository, error)
	UpsertRepository(ctx context.Context, repo *Repository) error
	DeleteRepository(ctx context.Context, id int64) error

	// Scan result operations
	CreateScanResult(ctx context.Context, result *ScanResult) error
	GetScanResult(ctx context.Context, id int64) (*ScanResult, error)
	GetLatestScanResult(ctx context.Context, repositoryID int64, branch string) (*ScanResult, error)
	ListScanResults(ctx context.Context, opts ListScanResultsOptions) ([]ScanResult, error)
	UpdateScanResult(ctx context.Context, result *ScanResult) error

	// Finding operations
	CreateFinding(ctx context.Context, finding *Finding) error
	GetFinding(ctx context.Context, id int64) (*Finding, error)
	GetFindingByFingerprint(ctx context.Context, fingerprint string) (*Finding, error)
	ListFindings(ctx context.Context, opts ListFindingsOptions) ([]Finding, error)
	UpsertFinding(ctx context.Context, finding *Finding) error
	UpdateFindingStatus(ctx context.Context, id int64, status, ticketID string) error

	// Statistics
	GetRepositoryCount(ctx context.Context) (int64, error)
	GetFindingCountBySeverity(ctx context.Context, repositoryID int64) (map[string]int64, error)
}

// ListRepositoriesOptions for filtering repository queries
type ListRepositoriesOptions struct {
	Provider string
	Source   string
	Search   string // Substring search in name/full_name
	Limit    int
	Offset   int
}

// ListScanResultsOptions for filtering scan result queries
type ListScanResultsOptions struct {
	RepositoryID int64
	Branch       string
	Status       string
	Limit        int
	Offset       int
}

// ListFindingsOptions for filtering finding queries
type ListFindingsOptions struct {
	RepositoryID int64
	ScanResultID int64
	Scanner      string
	Severity     string
	Status       string
	Limit        int
	Offset       int
}

// Config holds database configuration
type Config struct {
	Driver   string `yaml:"driver"`   // sqlite, mysql
	DSN      string `yaml:"dsn"`      // Data source name
	FilePath string `yaml:"filepath"` // For SQLite: path to db file
	Host     string `yaml:"host"`     // For MySQL
	Port     int    `yaml:"port"`     // For MySQL
	Database string `yaml:"database"` // For MySQL
	Username string `yaml:"username"` // For MySQL
	Password string `yaml:"password"` // For MySQL
}

// New creates a new database connection based on config
func New(cfg Config) (DB, error) {
	switch cfg.Driver {
	case "sqlite", "sqlite3", "":
		return NewSQLite(cfg)
	case "mysql":
		return NewMySQL(cfg)
	default:
		return NewSQLite(cfg) // Default to SQLite
	}
}

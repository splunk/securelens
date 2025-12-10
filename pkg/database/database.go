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

// ============================================================================
// Vulnerability Finding Tables - Scanner-specific with unique primary keys
// ============================================================================

// SCAFinding represents a Software Composition Analysis finding (Trivy)
// Primary Key: provider:repo:branch:commit:package:version
//
// Lifecycle:
// - NEW: Insert with status='open'
// - EXISTING: Update fields (preserve jira_ticket, first_seen_at)
// - FIXED: When a new scan doesn't include this finding, mark status='fixed', set fixed_in_commit
type SCAFinding struct {
	ID               int64     `json:"id" db:"id"`
	PrimaryUniqueKey string    `json:"primary_unique_key" db:"primary_unique_key"` // provider:repo:branch:commit:package:version
	Provider         string    `json:"provider" db:"provider"`                     // github, gitlab, bitbucket
	Repository       string    `json:"repository" db:"repository"`                 // full repo name (owner/repo)
	Branch           string    `json:"branch" db:"branch"`
	Commit           string    `json:"commit" db:"commit"`
	Package          string    `json:"package" db:"package"`             // vulnerable package name
	InstalledVersion string    `json:"installed_version" db:"installed_version"`
	FixedVersion     string    `json:"fixed_version" db:"fixed_version"` // remediation version
	Severity         string    `json:"severity" db:"severity"`           // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	VulnerabilityID  string    `json:"vulnerability_id" db:"vulnerability_id"` // CVE-XXXX-XXXX
	Title            string    `json:"title" db:"title"`
	Description      string    `json:"description" db:"description"`
	CVEs             string    `json:"cves" db:"cves"`                 // JSON array of CVE IDs
	CWEs             string    `json:"cwes" db:"cwes"`                 // JSON array of CWE IDs
	PkgPath          string    `json:"pkg_path" db:"pkg_path"`         // Path to the manifest file
	DataSource       string    `json:"data_source" db:"data_source"`   // Source of vulnerability data
	Status           string    `json:"status" db:"status"`             // open, fixed, ignored, ticketed
	JiraTicket       string    `json:"jira_ticket" db:"jira_ticket"`   // JIRA ticket URL/ID if created
	FixedInCommit    string    `json:"fixed_in_commit" db:"fixed_in_commit"` // Commit where this was fixed (when status=fixed)
	FixedAt          time.Time `json:"fixed_at" db:"fixed_at"`               // When this was marked fixed
	FirstSeenAt      time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// SCAFindingKey returns the key used for matching across commits (without commit in key)
// This is used to determine if a finding was fixed between commits
func (f *SCAFinding) SCAFindingKey() string {
	return f.Provider + ":" + f.Repository + ":" + f.Branch + ":" + f.Package + ":" + f.InstalledVersion
}

// SASTFinding represents a SAST finding (Semgrep/OpenGrep)
// Primary Key: provider:repo:branch:commit:check_id:fingerprint
// Note: Semgrep and OpenGrep share the same table as they have identical output formats
//
// Lifecycle:
// - NEW: Insert with status='open'
// - EXISTING: Update fields (preserve jira_ticket, first_seen_at)
// - FIXED: When a new scan doesn't include this finding, mark status='fixed', set fixed_in_commit
type SASTFinding struct {
	ID               int64     `json:"id" db:"id"`
	PrimaryUniqueKey string    `json:"primary_unique_key" db:"primary_unique_key"` // provider:repo:branch:commit:check_id:fingerprint
	Provider         string    `json:"provider" db:"provider"`                     // github, gitlab, bitbucket
	Repository       string    `json:"repository" db:"repository"`                 // full repo name (owner/repo)
	Branch           string    `json:"branch" db:"branch"`
	Commit           string    `json:"commit" db:"commit"`
	Scanner          string    `json:"scanner" db:"scanner"`             // semgrep or opengrep
	CheckID          string    `json:"check_id" db:"check_id"`           // Rule/check identifier
	Severity         string    `json:"severity" db:"severity"`           // ERROR, WARNING, INFO
	Message          string    `json:"message" db:"message"`             // Finding message
	FilePath         string    `json:"file_path" db:"file_path"`
	LineStart        int       `json:"line_start" db:"line_start"`
	LineEnd          int       `json:"line_end" db:"line_end"`
	ColStart         int       `json:"col_start" db:"col_start"`
	ColEnd           int       `json:"col_end" db:"col_end"`
	Fingerprint      string    `json:"fingerprint" db:"fingerprint"`     // Hash of code snippet for dedup
	Category         string    `json:"category" db:"category"`           // security, correctness, performance, etc.
	Subcategory      string    `json:"subcategory" db:"subcategory"`     // More specific classification
	CWEs             string    `json:"cwes" db:"cwes"`                   // JSON array of CWE IDs
	OWASP            string    `json:"owasp" db:"owasp"`                 // OWASP classification
	Confidence       string    `json:"confidence" db:"confidence"`       // HIGH, MEDIUM, LOW
	Metadata         string    `json:"metadata" db:"metadata"`           // JSON blob for extra scanner metadata
	Status           string    `json:"status" db:"status"`               // open, fixed, ignored, ticketed
	JiraTicket       string    `json:"jira_ticket" db:"jira_ticket"`     // JIRA ticket URL/ID if created
	FixedInCommit    string    `json:"fixed_in_commit" db:"fixed_in_commit"` // Commit where this was fixed
	FixedAt          time.Time `json:"fixed_at" db:"fixed_at"`               // When this was marked fixed
	FirstSeenAt      time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// SASTFindingKey returns the key used for matching across commits (without commit in key)
// This is used to determine if a finding was fixed between commits
func (f *SASTFinding) SASTFindingKey() string {
	return f.Provider + ":" + f.Repository + ":" + f.Branch + ":" + f.CheckID + ":" + f.Fingerprint
}

// SecretsFinding represents a secrets/credentials finding (TruffleHog)
// Primary Key: provider:repo:branch:commit:credential_hash:location_hash
//
// Lifecycle:
// - NEW: Insert with status='open'
// - EXISTING: Update fields (preserve jira_ticket, first_seen_at)
// - FIXED: When a new scan doesn't include this finding, mark status='fixed', set fixed_in_commit
type SecretsFinding struct {
	ID               int64     `json:"id" db:"id"`
	PrimaryUniqueKey string    `json:"primary_unique_key" db:"primary_unique_key"` // provider:repo:branch:commit:credential_hash:location_hash
	Provider         string    `json:"provider" db:"provider"`                     // github, gitlab, bitbucket
	Repository       string    `json:"repository" db:"repository"`                 // full repo name (owner/repo)
	Branch           string    `json:"branch" db:"branch"`
	Commit           string    `json:"commit" db:"commit"`
	DetectorName     string    `json:"detector_name" db:"detector_name"`           // AWS, GitHub, etc.
	DetectorType     string    `json:"detector_type" db:"detector_type"`           // Detector type code
	Verified         bool      `json:"verified" db:"verified"`                     // Whether the secret was verified
	CredentialHash   string    `json:"credential_hash" db:"credential_hash"`       // Hash of the credential (not the credential itself!)
	LocationHash     string    `json:"location_hash" db:"location_hash"`           // Hash of file + line location
	FilePath         string    `json:"file_path" db:"file_path"`
	LineNumber       int       `json:"line_number" db:"line_number"`
	Severity         string    `json:"severity" db:"severity"`                     // Based on detector type and verification
	RawMetadata      string    `json:"raw_metadata" db:"raw_metadata"`             // JSON blob of extra metadata (redacted)
	Status           string    `json:"status" db:"status"`                         // open, fixed, ignored, ticketed
	JiraTicket       string    `json:"jira_ticket" db:"jira_ticket"`               // JIRA ticket URL/ID if created
	FixedInCommit    string    `json:"fixed_in_commit" db:"fixed_in_commit"`       // Commit where this was fixed
	FixedAt          time.Time `json:"fixed_at" db:"fixed_at"`                     // When this was marked fixed
	FirstSeenAt      time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// SecretsFindingKey returns the key used for matching across commits (without commit in key)
// This is used to determine if a finding was fixed between commits
func (f *SecretsFinding) SecretsFindingKey() string {
	return f.Provider + ":" + f.Repository + ":" + f.Branch + ":" + f.CredentialHash + ":" + f.LocationHash
}

// LicenseFinding represents a license detected in a package (Trivy)
// Primary Key: provider:repo:branch:commit:package:version:license
//
// Lifecycle:
// - NEW: Insert with status='open'
// - EXISTING: Update fields (preserve first_seen_at)
type LicenseFinding struct {
	ID               int64     `json:"id" db:"id"`
	PrimaryUniqueKey string    `json:"primary_unique_key" db:"primary_unique_key"` // provider:repo:branch:commit:package:version:license
	Provider         string    `json:"provider" db:"provider"`                     // github, gitlab, bitbucket
	Repository       string    `json:"repository" db:"repository"`                 // full repo name (owner/repo)
	Branch           string    `json:"branch" db:"branch"`
	Commit           string    `json:"commit" db:"commit"`
	Package          string    `json:"package" db:"package"`           // package name
	Version          string    `json:"version" db:"version"`           // package version
	License          string    `json:"license" db:"license"`           // license name (e.g., MIT, Apache-2.0)
	Classification   string    `json:"classification" db:"classification"` // restricted, reciprocal, permissive, unknown
	PkgPath          string    `json:"pkg_path" db:"pkg_path"`         // Path to the manifest file (Target)
	PkgType          string    `json:"pkg_type" db:"pkg_type"`         // Type of package (gomod, npm, etc.)
	Severity         string    `json:"severity" db:"severity"`         // HIGH for restricted, MEDIUM for reciprocal, LOW for permissive
	Status           string    `json:"status" db:"status"`             // open, acknowledged, ignored
	JiraTicket       string    `json:"jira_ticket" db:"jira_ticket"`   // JIRA ticket URL/ID if created
	FirstSeenAt      time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// LicenseFindingKey returns the key used for matching across commits (without commit in key)
func (f *LicenseFinding) LicenseFindingKey() string {
	return f.Provider + ":" + f.Repository + ":" + f.Branch + ":" + f.Package + ":" + f.Version + ":" + f.License
}

// JiraTicketAttribution tracks Jira tickets associated with findings
// This is a future table for ownership attribution
type JiraTicketAttribution struct {
	ID               int64     `json:"id" db:"id"`
	JiraTicket       string    `json:"jira_ticket" db:"jira_ticket"`               // JIRA ticket URL/ID
	TicketKey        string    `json:"ticket_key" db:"ticket_key"`                 // e.g., VULN-1234
	FindingType      string    `json:"finding_type" db:"finding_type"`             // sca, sast, secrets
	FindingKey       string    `json:"finding_key" db:"finding_key"`               // primary_unique_key of the finding
	TicketStatus     string    `json:"ticket_status" db:"ticket_status"`           // Open, In Progress, Resolved, etc.
	TicketResolution string    `json:"ticket_resolution" db:"ticket_resolution"`   // Fixed, Won't Fix, etc.
	Assignee         string    `json:"assignee" db:"assignee"`
	DueDate          time.Time `json:"due_date" db:"due_date"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// ============================================================================
// Scan Job Tracking - Tracks scan progress for provider:repo:branch:commit
// ============================================================================

// ScanJob represents a scan job for a specific repo/branch/commit combination
// Primary Key: provider:repo:branch:commit
type ScanJob struct {
	ID               int64     `json:"id" db:"id"`
	PrimaryUniqueKey string    `json:"primary_unique_key" db:"primary_unique_key"` // provider:repo:branch:commit
	Provider         string    `json:"provider" db:"provider"`                     // github, gitlab, bitbucket
	Repository       string    `json:"repository" db:"repository"`                 // full repo name (owner/repo)
	Branch           string    `json:"branch" db:"branch"`
	Commit           string    `json:"commit" db:"commit"`
	Status           string    `json:"status" db:"status"`                         // pending, running, completed, failed, partial
	ScanMode         string    `json:"scan_mode" db:"scan_mode"`                   // standalone, remote
	ErrorMessage     string    `json:"error_message" db:"error_message"`           // Overall error message if failed
	ReportPath       string    `json:"report_path" db:"report_path"`               // Path to the combined report file
	StartedAt        time.Time `json:"started_at" db:"started_at"`
	CompletedAt      time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// ScanJobScanner tracks individual scanner status within a ScanJob
// This allows flexible addition/removal of scanners (trivy, semgrep, opengrep, trufflehog, syft, grype, etc.)
type ScanJobScanner struct {
	ID            int64     `json:"id" db:"id"`
	ScanJobID     int64     `json:"scan_job_id" db:"scan_job_id"`           // FK to ScanJob
	ScannerName   string    `json:"scanner_name" db:"scanner_name"`         // trivy, semgrep, opengrep, trufflehog, syft, grype, etc.
	ScannerType   string    `json:"scanner_type" db:"scanner_type"`         // sca, sast, secrets
	Status        string    `json:"status" db:"status"`                     // pending, running, completed, failed, skipped
	FindingsCount int       `json:"findings_count" db:"findings_count"`     // Number of findings from this scanner
	ErrorMessage  string    `json:"error_message" db:"error_message"`       // Scanner-specific error message
	OutputPath    string    `json:"output_path" db:"output_path"`           // Path to raw scanner output file
	Duration      int64     `json:"duration" db:"duration"`                 // Duration in milliseconds
	StartedAt     time.Time `json:"started_at" db:"started_at"`
	CompletedAt   time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// DB is the interface for database operations
type DB interface {
	// Connection management
	Close() error
	Ping(ctx context.Context) error

	// Repository operations (cache for provider APIs)
	CreateRepository(ctx context.Context, repo *Repository) error
	GetRepository(ctx context.Context, id int64) (*Repository, error)
	GetRepositoryByFullName(ctx context.Context, provider, fullName string) (*Repository, error)
	ListRepositories(ctx context.Context, opts ListRepositoriesOptions) ([]Repository, error)
	UpsertRepository(ctx context.Context, repo *Repository) error
	DeleteRepository(ctx context.Context, id int64) error

	// Scan result operations (legacy - kept for backwards compatibility)
	CreateScanResult(ctx context.Context, result *ScanResult) error
	GetScanResult(ctx context.Context, id int64) (*ScanResult, error)
	GetLatestScanResult(ctx context.Context, repositoryID int64, branch string) (*ScanResult, error)
	ListScanResults(ctx context.Context, opts ListScanResultsOptions) ([]ScanResult, error)
	UpdateScanResult(ctx context.Context, result *ScanResult) error

	// Finding operations (legacy - kept for backwards compatibility)
	CreateFinding(ctx context.Context, finding *Finding) error
	GetFinding(ctx context.Context, id int64) (*Finding, error)
	GetFindingByFingerprint(ctx context.Context, fingerprint string) (*Finding, error)
	ListFindings(ctx context.Context, opts ListFindingsOptions) ([]Finding, error)
	UpsertFinding(ctx context.Context, finding *Finding) error
	UpdateFindingStatus(ctx context.Context, id int64, status, ticketID string) error

	// Statistics
	GetRepositoryCount(ctx context.Context) (int64, error)
	GetFindingCountBySeverity(ctx context.Context, repositoryID int64) (map[string]int64, error)

	// ============================================================================
	// New Vulnerability Finding Operations
	// ============================================================================

	// SCA Finding operations (Trivy, future: Syft, Grype)
	UpsertSCAFinding(ctx context.Context, finding *SCAFinding) error
	GetSCAFinding(ctx context.Context, primaryKey string) (*SCAFinding, error)
	ListSCAFindings(ctx context.Context, opts ListSCAFindingsOptions) ([]SCAFinding, error)
	UpdateSCAFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error
	GetLatestSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error)
	GetOpenSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error) // For fix detection
	MarkSCAFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error

	// SAST Finding operations (Semgrep, OpenGrep)
	UpsertSASTFinding(ctx context.Context, finding *SASTFinding) error
	GetSASTFinding(ctx context.Context, primaryKey string) (*SASTFinding, error)
	ListSASTFindings(ctx context.Context, opts ListSASTFindingsOptions) ([]SASTFinding, error)
	UpdateSASTFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error
	GetLatestSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error)
	GetOpenSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error) // For fix detection
	MarkSASTFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error

	// Secrets Finding operations (TruffleHog)
	UpsertSecretsFinding(ctx context.Context, finding *SecretsFinding) error
	GetSecretsFinding(ctx context.Context, primaryKey string) (*SecretsFinding, error)
	ListSecretsFindings(ctx context.Context, opts ListSecretsFindingsOptions) ([]SecretsFinding, error)
	UpdateSecretsFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error
	GetLatestSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error)
	GetOpenSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error) // For fix detection
	MarkSecretsFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error

	// License Finding operations (Trivy)
	UpsertLicenseFinding(ctx context.Context, finding *LicenseFinding) error
	GetLicenseFinding(ctx context.Context, primaryKey string) (*LicenseFinding, error)
	ListLicenseFindings(ctx context.Context, opts ListLicenseFindingsOptions) ([]LicenseFinding, error)
	UpdateLicenseFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error
	GetLatestLicenseFindings(ctx context.Context, provider, repo, branch string) ([]LicenseFinding, error)

	// Scan Job operations
	CreateScanJob(ctx context.Context, job *ScanJob) error
	GetScanJob(ctx context.Context, primaryKey string) (*ScanJob, error)
	GetScanJobByID(ctx context.Context, id int64) (*ScanJob, error)
	ListScanJobs(ctx context.Context, opts ListScanJobsOptions) ([]ScanJob, error)
	UpdateScanJob(ctx context.Context, job *ScanJob) error
	GetLatestScanJob(ctx context.Context, provider, repo, branch string) (*ScanJob, error)

	// Scan Job Scanner operations (per-scanner status within a job)
	CreateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error
	GetScanJobScanners(ctx context.Context, scanJobID int64) ([]ScanJobScanner, error)
	UpdateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error

	// Jira Ticket Attribution operations (for future use)
	UpsertJiraTicketAttribution(ctx context.Context, attr *JiraTicketAttribution) error
	GetJiraTicketAttribution(ctx context.Context, ticketKey string) (*JiraTicketAttribution, error)
	ListJiraTicketsByFinding(ctx context.Context, findingType, findingKey string) ([]JiraTicketAttribution, error)
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

// ============================================================================
// New List Options for Vulnerability Tables
// ============================================================================

// ListSCAFindingsOptions for filtering SCA (Trivy) findings
type ListSCAFindingsOptions struct {
	Provider        string
	Repository      string
	Branch          string
	Commit          string
	Package         string
	Severity        string
	Status          string
	VulnerabilityID string // Filter by CVE
	Limit           int
	Offset          int
}

// ListSASTFindingsOptions for filtering SAST (Semgrep/OpenGrep) findings
type ListSASTFindingsOptions struct {
	Provider   string
	Repository string
	Branch     string
	Commit     string
	Scanner    string // semgrep or opengrep
	CheckID    string
	Severity   string
	Status     string
	Category   string
	Limit      int
	Offset     int
}

// ListSecretsFindingsOptions for filtering Secrets (TruffleHog) findings
type ListSecretsFindingsOptions struct {
	Provider     string
	Repository   string
	Branch       string
	Commit       string
	DetectorName string
	Verified     *bool // Pointer to allow nil (any), true (verified only), false (unverified only)
	Severity     string
	Status       string
	Limit        int
	Offset       int
}

// ListLicenseFindingsOptions for filtering License (Trivy) findings
type ListLicenseFindingsOptions struct {
	Provider       string
	Repository     string
	Branch         string
	Commit         string
	Package        string
	License        string
	Classification string // restricted, reciprocal, permissive, unknown
	Severity       string
	Status         string
	Limit          int
	Offset         int
}

// ListScanJobsOptions for filtering scan jobs
type ListScanJobsOptions struct {
	Provider   string
	Repository string
	Branch     string
	Status     string // pending, running, completed, failed, partial
	ScanMode   string // standalone, remote
	Limit      int
	Offset     int
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

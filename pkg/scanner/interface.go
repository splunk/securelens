package scanner

import (
	"context"
	"time"
)

// ScannerType represents the type of security scanner
type ScannerType int

const (
	SAST ScannerType = iota
	OSS
	Secrets
	Container
)

func (s ScannerType) String() string {
	return [...]string{"SAST", "OSS", "Secrets", "Container"}[s]
}

// Scanner is the interface that all security scanners must implement
type Scanner interface {
	// Scan performs a security scan on the given repository path
	Scan(ctx context.Context, repoPath string, opts ScanOptions) (*ScanResult, error)

	// Name returns the name of the scanner (e.g., "Semgrep", "FOSSA")
	Name() string

	// Type returns the type of scanner
	Type() ScannerType
}

// ScanOptions contains configuration options for a scan
type ScanOptions struct {
	Branch    string
	Commit    string
	Timeout   time.Duration
	Config    map[string]interface{}
	RepoURL   string
	RepoOwner string
}

// ScanResult contains the results of a security scan
type ScanResult struct {
	ScannerName string
	ScannerType ScannerType
	StartTime   time.Time
	EndTime     time.Time
	Status      string // "SUCCESS", "FAILED", "PARTIAL"
	Error       error

	Vulnerabilities []Vulnerability
	Summary         ScanSummary
}

// Vulnerability represents a single vulnerability finding
type Vulnerability struct {
	// Identification
	PrimaryKey  string
	TicketName  string
	Description string

	// Classification
	Severity  string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Component string // "OSS", "SAST", "Secrets"
	Source    string // "ProdSec", "Community"

	// Location
	OriginPath string
	OriginRef  string

	// Repository context
	Postfix string // repo identifier (org/repo)
	Branch  string
	Commit  string

	// Version information
	RemediationVersion string
	AffectsVersion     string

	// Metadata
	Labels []string
	CVEs   []string
	CWEs   []string

	// Additional data (scanner-specific)
	RawData map[string]interface{}
}

// ScanSummary provides aggregate statistics about scan results
type ScanSummary struct {
	TotalFindings    int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	DurationSeconds  float64
	ScannedFileCount int
}

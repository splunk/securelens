package ui

import (
	"github.com/splunk/securelens/cli/scan"
)

// ViewType represents the current view in the TUI
type ViewType int

const (
	ViewHome ViewType = iota
	ViewRepos
	ViewBranchSelect // Branch selection before scanning
	ViewScan
	ViewResults
	ViewVulnsDb  // Vulnerability database browser
	ViewLicenses // License findings browser
	ViewWizard
)

// ReportBrowserLevel represents the navigation level in the report browser
type ReportBrowserLevel int

const (
	ReportLevelOwner ReportBrowserLevel = iota
	ReportLevelRepo
	ReportLevelBranch
	ReportLevelCommit
	ReportLevelReport
)

func (v ViewType) String() string {
	return [...]string{"Home", "Repositories", "Branch Select", "Scanning", "Results", "VulnsDb", "Licenses", "Setup"}[v]
}

// Custom messages for the TUI

// WindowSizeMsg is sent when the terminal is resized
type WindowSizeMsg struct {
	Width  int
	Height int
}

// ChangeViewMsg requests a view change
type ChangeViewMsg struct {
	View ViewType
}

// ErrorMsg represents an error
type ErrorMsg struct {
	Err error
}

func (e ErrorMsg) Error() string {
	return e.Err.Error()
}

// StatusMsg represents a status update
type StatusMsg string

// ReposLoadedMsg is sent when repositories are loaded
type ReposLoadedMsg struct {
	Repos        []scan.DiscoveredRepository
	Limit        int    // The limit that was requested (for pagination tracking)
	Provider     string // The provider filter used ("" for all)
	FromDatabase bool   // True if loaded from SQLite, false if from API
}

// ReposLoadingMsg indicates repos are being loaded
type ReposLoadingMsg struct{}

// ScanStartMsg starts a scan
type ScanStartMsg struct {
	Repos []scan.DiscoveredRepository
}

// ScanProgressMsg reports scan progress
type ScanProgressMsg struct {
	RepoIndex     int
	RepoName      string
	Scanner       string
	Status        string // "running", "complete", "error"
	Message       string
	FindingsCount int
}

// ScanCompleteMsg indicates scan completion
type ScanCompleteMsg struct {
	Report *scan.ScanReport
	Error  error
}

// BulkScanCompleteMsg indicates all bulk scans complete
type BulkScanCompleteMsg struct {
	Reports []*scan.ScanReport
	Errors  []error
}

// ReportLoadedMsg is sent when a report is loaded
type ReportLoadedMsg struct {
	Report *scan.ScanReport
}

// ConfigSavedMsg indicates config was saved
type ConfigSavedMsg struct {
	Path string
}

// ProviderTestMsg is result of testing a provider connection
type ProviderTestMsg struct {
	Provider string
	Success  bool
	Message  string
}

// ReportBrowserItem represents an item in the report browser
type ReportBrowserItem struct {
	Name     string // Display name (owner, repo, branch, commit, or report filename)
	Path     string // Full path to this level
	IsDir    bool   // True if this is a directory (not a report file)
	Children int    // Number of children (for directories)
}

// ReportBrowserLoadedMsg is sent when report browser items are loaded
type ReportBrowserLoadedMsg struct {
	Level ReportBrowserLevel
	Items []ReportBrowserItem
	Path  string // Current path being browsed
}

// ReportDetailLoadedMsg is sent when a report is loaded for viewing
type ReportDetailLoadedMsg struct {
	Report *scan.ScanReport
	Path   string
}

// BranchesLoadedMsg is sent when branches are loaded for a repository
type BranchesLoadedMsg struct {
	Repo     scan.DiscoveredRepository
	Branches []string
	Error    error
}

// ScanStatus represents the status of a scan job
type ScanStatus string

const (
	ScanStatusPending  ScanStatus = "pending"
	ScanStatusRunning  ScanStatus = "running"
	ScanStatusComplete ScanStatus = "complete"
	ScanStatusError    ScanStatus = "error"
)

// ScanItem represents a single scan job (repo + branch combination)
type ScanItem struct {
	Repo       scan.DiscoveredRepository
	Branch     string
	Status     ScanStatus
	ReportPath string // Path to saved report (when complete)
	Error      string // Error message (when failed)
}

// SearchResultsMsg is sent when search results are loaded
type SearchResultsMsg struct {
	Query string
	Repos []scan.DiscoveredRepository
	Error error
}

// ScanLogMsg is sent when a scanner produces output
type ScanLogMsg struct {
	Message string
}

// ============================================================================
// VulnsDb View Messages
// ============================================================================

// VulnType represents the type of vulnerability (scanner source)
type VulnType int

const (
	VulnTypeSCA     VulnType = iota // Trivy - Software Composition Analysis
	VulnTypeSAST                    // OpenGrep/Semgrep - Static Analysis
	VulnTypeSecrets                 // TruffleHog - Secrets Detection
)

func (v VulnType) String() string {
	return [...]string{"SCA (Trivy)", "SAST (OpenGrep)", "Secrets (TruffleHog)"}[v]
}

func (v VulnType) ShortString() string {
	return [...]string{"SCA", "SAST", "Secrets"}[v]
}

// VulnSortField represents sortable fields
type VulnSortField int

const (
	VulnSortSeverity VulnSortField = iota
	VulnSortRepo
	VulnSortDate
	VulnSortStatus
)

func (s VulnSortField) String() string {
	return [...]string{"Severity", "Repository", "Date", "Status"}[s]
}

// VulnsLoadedMsg is sent when vulnerabilities are loaded from the database
type VulnsLoadedMsg struct {
	VulnType   VulnType
	SCAItems   []SCAVulnItem
	SASTItems  []SASTVulnItem
	SecretItems []SecretsVulnItem
	Total      int
	Error      error
}

// SCAVulnItem represents an SCA finding for display
type SCAVulnItem struct {
	ID              int64
	PrimaryKey      string
	Provider        string
	Repository      string
	Branch          string
	Commit          string
	Package         string
	Version         string
	VulnerabilityID string
	Severity        string
	Title           string
	Status          string
	JiraTicket      string
	FirstSeen       string
	LastSeen        string
}

// SASTVulnItem represents a SAST finding for display
type SASTVulnItem struct {
	ID         int64
	PrimaryKey string
	Provider   string
	Repository string
	Branch     string
	Commit     string
	Scanner    string
	CheckID    string
	Severity   string
	Message    string
	FilePath   string
	Line       int
	Status     string
	JiraTicket string
	FirstSeen  string
	LastSeen   string
}

// SecretsVulnItem represents a secrets finding for display
type SecretsVulnItem struct {
	ID           int64
	PrimaryKey   string
	Provider     string
	Repository   string
	Branch       string
	Commit       string
	DetectorName string
	Verified     bool
	FilePath     string
	Line         int
	Severity     string
	Status       string
	JiraTicket   string
	FirstSeen    string
	LastSeen     string
}

// LicenseVulnItem represents a license finding for display
type LicenseVulnItem struct {
	ID             int64
	PrimaryKey     string
	Provider       string
	Repository     string
	Branch         string
	Commit         string
	Package        string
	Version        string
	License        string
	Classification string // restricted, reciprocal, permissive, unknown
	PkgPath        string
	PkgType        string
	Severity       string
	Status         string
	JiraTicket     string
	FirstSeen      string
	LastSeen       string
}

// LicensesLoadedMsg is sent when license findings are loaded from the database
type LicensesLoadedMsg struct {
	Items []LicenseVulnItem
	Total int
	Error error
}

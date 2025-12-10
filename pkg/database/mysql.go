package database

import (
	"context"
	"fmt"
)

// MySQLDB implements DB interface for MySQL
type MySQLDB struct {
	// Will be implemented when MySQL support is needed
}

// NewMySQL creates a new MySQL database connection
func NewMySQL(cfg Config) (*MySQLDB, error) {
	return nil, fmt.Errorf("MySQL support not yet implemented - use SQLite for now")
}

// Stub implementations - will be filled in when MySQL is needed

func (m *MySQLDB) Close() error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) Ping(ctx context.Context) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) CreateRepository(ctx context.Context, repo *Repository) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetRepository(ctx context.Context, id int64) (*Repository, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetRepositoryByFullName(ctx context.Context, provider, fullName string) (*Repository, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListRepositories(ctx context.Context, opts ListRepositoriesOptions) ([]Repository, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpsertRepository(ctx context.Context, repo *Repository) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) DeleteRepository(ctx context.Context, id int64) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) CreateScanResult(ctx context.Context, result *ScanResult) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetScanResult(ctx context.Context, id int64) (*ScanResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestScanResult(ctx context.Context, repositoryID int64, branch string) (*ScanResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListScanResults(ctx context.Context, opts ListScanResultsOptions) ([]ScanResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateScanResult(ctx context.Context, result *ScanResult) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) CreateFinding(ctx context.Context, finding *Finding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetFinding(ctx context.Context, id int64) (*Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetFindingByFingerprint(ctx context.Context, fingerprint string) (*Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListFindings(ctx context.Context, opts ListFindingsOptions) ([]Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpsertFinding(ctx context.Context, finding *Finding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateFindingStatus(ctx context.Context, id int64, status, ticketID string) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetRepositoryCount(ctx context.Context) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetFindingCountBySeverity(ctx context.Context, repositoryID int64) (map[string]int64, error) {
	return nil, fmt.Errorf("not implemented")
}

// ============================================================================
// SCA Finding Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) UpsertSCAFinding(ctx context.Context, finding *SCAFinding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetSCAFinding(ctx context.Context, primaryKey string) (*SCAFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListSCAFindings(ctx context.Context, opts ListSCAFindingsOptions) ([]SCAFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateSCAFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetOpenSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) MarkSCAFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	return fmt.Errorf("not implemented")
}

// ============================================================================
// SAST Finding Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) UpsertSASTFinding(ctx context.Context, finding *SASTFinding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetSASTFinding(ctx context.Context, primaryKey string) (*SASTFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListSASTFindings(ctx context.Context, opts ListSASTFindingsOptions) ([]SASTFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateSASTFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetOpenSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) MarkSASTFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	return fmt.Errorf("not implemented")
}

// ============================================================================
// Secrets Finding Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) UpsertSecretsFinding(ctx context.Context, finding *SecretsFinding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetSecretsFinding(ctx context.Context, primaryKey string) (*SecretsFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListSecretsFindings(ctx context.Context, opts ListSecretsFindingsOptions) ([]SecretsFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateSecretsFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetOpenSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) MarkSecretsFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	return fmt.Errorf("not implemented")
}

// ============================================================================
// Scan Job Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) CreateScanJob(ctx context.Context, job *ScanJob) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetScanJob(ctx context.Context, primaryKey string) (*ScanJob, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetScanJobByID(ctx context.Context, id int64) (*ScanJob, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListScanJobs(ctx context.Context, opts ListScanJobsOptions) ([]ScanJob, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateScanJob(ctx context.Context, job *ScanJob) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestScanJob(ctx context.Context, provider, repo, branch string) (*ScanJob, error) {
	return nil, fmt.Errorf("not implemented")
}

// ============================================================================
// Scan Job Scanner Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) CreateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetScanJobScanners(ctx context.Context, scanJobID int64) ([]ScanJobScanner, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error {
	return fmt.Errorf("not implemented")
}

// ============================================================================
// Jira Ticket Attribution Operations - MySQL stubs
// ============================================================================

func (m *MySQLDB) UpsertJiraTicketAttribution(ctx context.Context, attr *JiraTicketAttribution) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetJiraTicketAttribution(ctx context.Context, ticketKey string) (*JiraTicketAttribution, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListJiraTicketsByFinding(ctx context.Context, findingType, findingKey string) ([]JiraTicketAttribution, error) {
	return nil, fmt.Errorf("not implemented")
}

// License Finding Operations

func (m *MySQLDB) UpsertLicenseFinding(ctx context.Context, finding *LicenseFinding) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLicenseFinding(ctx context.Context, primaryKey string) (*LicenseFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) ListLicenseFindings(ctx context.Context, opts ListLicenseFindingsOptions) ([]LicenseFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MySQLDB) UpdateLicenseFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	return fmt.Errorf("not implemented")
}

func (m *MySQLDB) GetLatestLicenseFindings(ctx context.Context, provider, repo, branch string) ([]LicenseFinding, error) {
	return nil, fmt.Errorf("not implemented")
}

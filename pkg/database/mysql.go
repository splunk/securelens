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

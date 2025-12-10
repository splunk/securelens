package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ============================================================================
// SCA Finding Operations (Trivy, future: Syft, Grype)
// ============================================================================

// UpsertSCAFinding creates or updates an SCA finding
// On conflict, it updates fields but preserves jira_ticket and first_seen_at
func (s *SQLiteDB) UpsertSCAFinding(ctx context.Context, finding *SCAFinding) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sca_findings (
			primary_unique_key, provider, repository, branch, commit_hash, package,
			installed_version, fixed_version, severity, vulnerability_id, title,
			description, cves, cwes, pkg_path, data_source, status, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(primary_unique_key) DO UPDATE SET
			installed_version = excluded.installed_version,
			fixed_version = excluded.fixed_version,
			severity = excluded.severity,
			title = excluded.title,
			description = excluded.description,
			cves = excluded.cves,
			cwes = excluded.cwes,
			pkg_path = excluded.pkg_path,
			data_source = excluded.data_source,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, finding.PrimaryUniqueKey, finding.Provider, finding.Repository, finding.Branch,
		finding.Commit, finding.Package, finding.InstalledVersion, finding.FixedVersion,
		finding.Severity, finding.VulnerabilityID, finding.Title, finding.Description,
		finding.CVEs, finding.CWEs, finding.PkgPath, finding.DataSource, finding.Status)
	return err
}

// GetSCAFinding retrieves an SCA finding by primary key
func (s *SQLiteDB) GetSCAFinding(ctx context.Context, primaryKey string) (*SCAFinding, error) {
	finding := &SCAFinding{}
	var fixedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash, package,
			installed_version, fixed_version, severity, vulnerability_id, title, description,
			cves, cwes, pkg_path, data_source, status, jira_ticket, fixed_in_commit, fixed_at,
			first_seen_at, last_seen_at, created_at, updated_at
		FROM sca_findings WHERE primary_unique_key = ?
	`, primaryKey).Scan(&finding.ID, &finding.PrimaryUniqueKey, &finding.Provider,
		&finding.Repository, &finding.Branch, &finding.Commit, &finding.Package,
		&finding.InstalledVersion, &finding.FixedVersion, &finding.Severity,
		&finding.VulnerabilityID, &finding.Title, &finding.Description,
		&finding.CVEs, &finding.CWEs, &finding.PkgPath, &finding.DataSource,
		&finding.Status, &finding.JiraTicket, &finding.FixedInCommit, &fixedAt,
		&finding.FirstSeenAt, &finding.LastSeenAt, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if fixedAt.Valid {
		finding.FixedAt = fixedAt.Time
	}
	return finding, err
}

// ListSCAFindings retrieves SCA findings with filtering
func (s *SQLiteDB) ListSCAFindings(ctx context.Context, opts ListSCAFindingsOptions) ([]SCAFinding, error) {
	query := `SELECT id, primary_unique_key, provider, repository, branch, commit_hash, package,
		installed_version, fixed_version, severity, vulnerability_id, title, description,
		cves, cwes, pkg_path, data_source, status, jira_ticket, fixed_in_commit, fixed_at,
		first_seen_at, last_seen_at, created_at, updated_at FROM sca_findings WHERE 1=1`
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Repository != "" {
		query += " AND repository = ?"
		args = append(args, opts.Repository)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Commit != "" {
		query += " AND commit_hash = ?"
		args = append(args, opts.Commit)
	}
	if opts.Package != "" {
		query += " AND package LIKE ?"
		args = append(args, "%"+opts.Package+"%")
	}
	if opts.Severity != "" {
		query += " AND severity = ?"
		args = append(args, opts.Severity)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.VulnerabilityID != "" {
		query += " AND vulnerability_id = ?"
		args = append(args, opts.VulnerabilityID)
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

	var findings []SCAFinding
	for rows.Next() {
		var f SCAFinding
		var fixedAt sql.NullTime
		var jiraTicket, fixedInCommit, installedVersion, fixedVersion sql.NullString
		var severity, vulnID, title, description, cves, cwes, pkgPath, dataSource sql.NullString
		if err := rows.Scan(&f.ID, &f.PrimaryUniqueKey, &f.Provider, &f.Repository,
			&f.Branch, &f.Commit, &f.Package, &installedVersion, &fixedVersion,
			&severity, &vulnID, &title, &description, &cves,
			&cwes, &pkgPath, &dataSource, &f.Status, &jiraTicket,
			&fixedInCommit, &fixedAt, &f.FirstSeenAt, &f.LastSeenAt,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		if fixedAt.Valid {
			f.FixedAt = fixedAt.Time
		}
		f.JiraTicket = jiraTicket.String
		f.FixedInCommit = fixedInCommit.String
		f.InstalledVersion = installedVersion.String
		f.FixedVersion = fixedVersion.String
		f.Severity = severity.String
		f.VulnerabilityID = vulnID.String
		f.Title = title.String
		f.Description = description.String
		f.CVEs = cves.String
		f.CWEs = cwes.String
		f.PkgPath = pkgPath.String
		f.DataSource = dataSource.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpdateSCAFindingStatus updates the status and jira ticket of an SCA finding
func (s *SQLiteDB) UpdateSCAFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sca_findings SET status = ?, jira_ticket = ?, updated_at = CURRENT_TIMESTAMP
		WHERE primary_unique_key = ?
	`, status, jiraTicket, primaryKey)
	return err
}

// GetLatestSCAFindings gets the most recent SCA findings for a repo/branch
func (s *SQLiteDB) GetLatestSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error) {
	return s.ListSCAFindings(ctx, ListSCAFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Limit:      1000,
	})
}

// GetOpenSCAFindings gets all open SCA findings for a repo/branch (for fix detection)
func (s *SQLiteDB) GetOpenSCAFindings(ctx context.Context, provider, repo, branch string) ([]SCAFinding, error) {
	return s.ListSCAFindings(ctx, ListSCAFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Status:     "open",
		Limit:      10000,
	})
}

// MarkSCAFindingsFixed marks findings as fixed when they're no longer present in a scan
func (s *SQLiteDB) MarkSCAFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	if len(findingKeys) == 0 {
		return nil
	}

	// Build the query with placeholders
	query := `UPDATE sca_findings SET status = 'fixed', fixed_in_commit = ?, fixed_at = ?,
		updated_at = CURRENT_TIMESTAMP WHERE provider = ? AND repository = ? AND branch = ?
		AND status = 'open' AND primary_unique_key NOT IN (`
	args := []interface{}{fixedInCommit, time.Now(), provider, repo, branch}

	for i, key := range findingKeys {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, key)
	}
	query += ")"

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// ============================================================================
// SAST Finding Operations (Semgrep, OpenGrep)
// ============================================================================

// UpsertSASTFinding creates or updates a SAST finding
func (s *SQLiteDB) UpsertSASTFinding(ctx context.Context, finding *SASTFinding) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sast_findings (
			primary_unique_key, provider, repository, branch, commit_hash, scanner,
			check_id, severity, message, file_path, line_start, line_end, col_start,
			col_end, fingerprint, category, subcategory, cwes, owasp, confidence,
			metadata, status, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(primary_unique_key) DO UPDATE SET
			severity = excluded.severity,
			message = excluded.message,
			file_path = excluded.file_path,
			line_start = excluded.line_start,
			line_end = excluded.line_end,
			col_start = excluded.col_start,
			col_end = excluded.col_end,
			category = excluded.category,
			subcategory = excluded.subcategory,
			cwes = excluded.cwes,
			owasp = excluded.owasp,
			confidence = excluded.confidence,
			metadata = excluded.metadata,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, finding.PrimaryUniqueKey, finding.Provider, finding.Repository, finding.Branch,
		finding.Commit, finding.Scanner, finding.CheckID, finding.Severity, finding.Message,
		finding.FilePath, finding.LineStart, finding.LineEnd, finding.ColStart, finding.ColEnd,
		finding.Fingerprint, finding.Category, finding.Subcategory, finding.CWEs, finding.OWASP,
		finding.Confidence, finding.Metadata, finding.Status)
	return err
}

// GetSASTFinding retrieves a SAST finding by primary key
func (s *SQLiteDB) GetSASTFinding(ctx context.Context, primaryKey string) (*SASTFinding, error) {
	finding := &SASTFinding{}
	var fixedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash, scanner,
			check_id, severity, message, file_path, line_start, line_end, col_start, col_end,
			fingerprint, category, subcategory, cwes, owasp, confidence, metadata,
			status, jira_ticket, fixed_in_commit, fixed_at, first_seen_at, last_seen_at,
			created_at, updated_at
		FROM sast_findings WHERE primary_unique_key = ?
	`, primaryKey).Scan(&finding.ID, &finding.PrimaryUniqueKey, &finding.Provider,
		&finding.Repository, &finding.Branch, &finding.Commit, &finding.Scanner,
		&finding.CheckID, &finding.Severity, &finding.Message, &finding.FilePath,
		&finding.LineStart, &finding.LineEnd, &finding.ColStart, &finding.ColEnd,
		&finding.Fingerprint, &finding.Category, &finding.Subcategory, &finding.CWEs,
		&finding.OWASP, &finding.Confidence, &finding.Metadata, &finding.Status,
		&finding.JiraTicket, &finding.FixedInCommit, &fixedAt, &finding.FirstSeenAt,
		&finding.LastSeenAt, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if fixedAt.Valid {
		finding.FixedAt = fixedAt.Time
	}
	return finding, err
}

// ListSASTFindings retrieves SAST findings with filtering
func (s *SQLiteDB) ListSASTFindings(ctx context.Context, opts ListSASTFindingsOptions) ([]SASTFinding, error) {
	query := `SELECT id, primary_unique_key, provider, repository, branch, commit_hash, scanner,
		check_id, severity, message, file_path, line_start, line_end, col_start, col_end,
		fingerprint, category, subcategory, cwes, owasp, confidence, metadata,
		status, jira_ticket, fixed_in_commit, fixed_at, first_seen_at, last_seen_at,
		created_at, updated_at FROM sast_findings WHERE 1=1`
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Repository != "" {
		query += " AND repository = ?"
		args = append(args, opts.Repository)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Commit != "" {
		query += " AND commit_hash = ?"
		args = append(args, opts.Commit)
	}
	if opts.Scanner != "" {
		query += " AND scanner = ?"
		args = append(args, opts.Scanner)
	}
	if opts.CheckID != "" {
		query += " AND check_id = ?"
		args = append(args, opts.CheckID)
	}
	if opts.Severity != "" {
		query += " AND severity = ?"
		args = append(args, opts.Severity)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.Category != "" {
		query += " AND category = ?"
		args = append(args, opts.Category)
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

	var findings []SASTFinding
	for rows.Next() {
		var f SASTFinding
		var fixedAt sql.NullTime
		var severity, message, fingerprint, category, subcategory sql.NullString
		var cwes, owasp, confidence, metadata, jiraTicket, fixedInCommit sql.NullString
		if err := rows.Scan(&f.ID, &f.PrimaryUniqueKey, &f.Provider, &f.Repository,
			&f.Branch, &f.Commit, &f.Scanner, &f.CheckID, &severity, &message,
			&f.FilePath, &f.LineStart, &f.LineEnd, &f.ColStart, &f.ColEnd,
			&fingerprint, &category, &subcategory, &cwes, &owasp,
			&confidence, &metadata, &f.Status, &jiraTicket, &fixedInCommit,
			&fixedAt, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		if fixedAt.Valid {
			f.FixedAt = fixedAt.Time
		}
		f.Severity = severity.String
		f.Message = message.String
		f.Fingerprint = fingerprint.String
		f.Category = category.String
		f.Subcategory = subcategory.String
		f.CWEs = cwes.String
		f.OWASP = owasp.String
		f.Confidence = confidence.String
		f.Metadata = metadata.String
		f.JiraTicket = jiraTicket.String
		f.FixedInCommit = fixedInCommit.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpdateSASTFindingStatus updates the status and jira ticket of a SAST finding
func (s *SQLiteDB) UpdateSASTFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sast_findings SET status = ?, jira_ticket = ?, updated_at = CURRENT_TIMESTAMP
		WHERE primary_unique_key = ?
	`, status, jiraTicket, primaryKey)
	return err
}

// GetLatestSASTFindings gets the most recent SAST findings for a repo/branch
func (s *SQLiteDB) GetLatestSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error) {
	return s.ListSASTFindings(ctx, ListSASTFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Limit:      1000,
	})
}

// GetOpenSASTFindings gets all open SAST findings for a repo/branch (for fix detection)
func (s *SQLiteDB) GetOpenSASTFindings(ctx context.Context, provider, repo, branch string) ([]SASTFinding, error) {
	return s.ListSASTFindings(ctx, ListSASTFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Status:     "open",
		Limit:      10000,
	})
}

// MarkSASTFindingsFixed marks findings as fixed when they're no longer present in a scan
func (s *SQLiteDB) MarkSASTFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	if len(findingKeys) == 0 {
		return nil
	}

	query := `UPDATE sast_findings SET status = 'fixed', fixed_in_commit = ?, fixed_at = ?,
		updated_at = CURRENT_TIMESTAMP WHERE provider = ? AND repository = ? AND branch = ?
		AND status = 'open' AND primary_unique_key NOT IN (`
	args := []interface{}{fixedInCommit, time.Now(), provider, repo, branch}

	for i, key := range findingKeys {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, key)
	}
	query += ")"

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// ============================================================================
// Secrets Finding Operations (TruffleHog)
// ============================================================================

// UpsertSecretsFinding creates or updates a secrets finding
func (s *SQLiteDB) UpsertSecretsFinding(ctx context.Context, finding *SecretsFinding) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO secrets_findings (
			primary_unique_key, provider, repository, branch, commit_hash,
			detector_name, detector_type, verified, credential_hash, location_hash,
			file_path, line_number, severity, raw_metadata, status, last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(primary_unique_key) DO UPDATE SET
			verified = excluded.verified,
			severity = excluded.severity,
			raw_metadata = excluded.raw_metadata,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, finding.PrimaryUniqueKey, finding.Provider, finding.Repository, finding.Branch,
		finding.Commit, finding.DetectorName, finding.DetectorType, finding.Verified,
		finding.CredentialHash, finding.LocationHash, finding.FilePath, finding.LineNumber,
		finding.Severity, finding.RawMetadata, finding.Status)
	return err
}

// GetSecretsFinding retrieves a secrets finding by primary key
func (s *SQLiteDB) GetSecretsFinding(ctx context.Context, primaryKey string) (*SecretsFinding, error) {
	finding := &SecretsFinding{}
	var fixedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash,
			detector_name, detector_type, verified, credential_hash, location_hash,
			file_path, line_number, severity, raw_metadata, status, jira_ticket,
			fixed_in_commit, fixed_at, first_seen_at, last_seen_at, created_at, updated_at
		FROM secrets_findings WHERE primary_unique_key = ?
	`, primaryKey).Scan(&finding.ID, &finding.PrimaryUniqueKey, &finding.Provider,
		&finding.Repository, &finding.Branch, &finding.Commit, &finding.DetectorName,
		&finding.DetectorType, &finding.Verified, &finding.CredentialHash,
		&finding.LocationHash, &finding.FilePath, &finding.LineNumber, &finding.Severity,
		&finding.RawMetadata, &finding.Status, &finding.JiraTicket, &finding.FixedInCommit,
		&fixedAt, &finding.FirstSeenAt, &finding.LastSeenAt, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if fixedAt.Valid {
		finding.FixedAt = fixedAt.Time
	}
	return finding, err
}

// ListSecretsFindings retrieves secrets findings with filtering
func (s *SQLiteDB) ListSecretsFindings(ctx context.Context, opts ListSecretsFindingsOptions) ([]SecretsFinding, error) {
	query := `SELECT id, primary_unique_key, provider, repository, branch, commit_hash,
		detector_name, detector_type, verified, credential_hash, location_hash,
		file_path, line_number, severity, raw_metadata, status, jira_ticket,
		fixed_in_commit, fixed_at, first_seen_at, last_seen_at, created_at, updated_at
		FROM secrets_findings WHERE 1=1`
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Repository != "" {
		query += " AND repository = ?"
		args = append(args, opts.Repository)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Commit != "" {
		query += " AND commit_hash = ?"
		args = append(args, opts.Commit)
	}
	if opts.DetectorName != "" {
		query += " AND detector_name = ?"
		args = append(args, opts.DetectorName)
	}
	if opts.Verified != nil {
		query += " AND verified = ?"
		if *opts.Verified {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
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

	var findings []SecretsFinding
	for rows.Next() {
		var f SecretsFinding
		var fixedAt sql.NullTime
		var detectorType, severity, rawMetadata, jiraTicket, fixedInCommit sql.NullString
		if err := rows.Scan(&f.ID, &f.PrimaryUniqueKey, &f.Provider, &f.Repository,
			&f.Branch, &f.Commit, &f.DetectorName, &detectorType, &f.Verified,
			&f.CredentialHash, &f.LocationHash, &f.FilePath, &f.LineNumber,
			&severity, &rawMetadata, &f.Status, &jiraTicket, &fixedInCommit,
			&fixedAt, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		if fixedAt.Valid {
			f.FixedAt = fixedAt.Time
		}
		f.DetectorType = detectorType.String
		f.Severity = severity.String
		f.RawMetadata = rawMetadata.String
		f.JiraTicket = jiraTicket.String
		f.FixedInCommit = fixedInCommit.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpdateSecretsFindingStatus updates the status and jira ticket of a secrets finding
func (s *SQLiteDB) UpdateSecretsFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE secrets_findings SET status = ?, jira_ticket = ?, updated_at = CURRENT_TIMESTAMP
		WHERE primary_unique_key = ?
	`, status, jiraTicket, primaryKey)
	return err
}

// GetLatestSecretsFindings gets the most recent secrets findings for a repo/branch
func (s *SQLiteDB) GetLatestSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error) {
	return s.ListSecretsFindings(ctx, ListSecretsFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Limit:      1000,
	})
}

// GetOpenSecretsFindings gets all open secrets findings for a repo/branch (for fix detection)
func (s *SQLiteDB) GetOpenSecretsFindings(ctx context.Context, provider, repo, branch string) ([]SecretsFinding, error) {
	return s.ListSecretsFindings(ctx, ListSecretsFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Status:     "open",
		Limit:      10000,
	})
}

// MarkSecretsFindingsFixed marks findings as fixed when they're no longer present in a scan
func (s *SQLiteDB) MarkSecretsFindingsFixed(ctx context.Context, provider, repo, branch, fixedInCommit string, findingKeys []string) error {
	if len(findingKeys) == 0 {
		return nil
	}

	query := `UPDATE secrets_findings SET status = 'fixed', fixed_in_commit = ?, fixed_at = ?,
		updated_at = CURRENT_TIMESTAMP WHERE provider = ? AND repository = ? AND branch = ?
		AND status = 'open' AND primary_unique_key NOT IN (`
	args := []interface{}{fixedInCommit, time.Now(), provider, repo, branch}

	for i, key := range findingKeys {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, key)
	}
	query += ")"

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

// ============================================================================
// Scan Job Operations
// ============================================================================

// CreateScanJob creates a new scan job
func (s *SQLiteDB) CreateScanJob(ctx context.Context, job *ScanJob) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_jobs (
			primary_unique_key, provider, repository, branch, commit_hash,
			status, scan_mode, error_message, report_path, started_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, job.PrimaryUniqueKey, job.Provider, job.Repository, job.Branch, job.Commit,
		job.Status, job.ScanMode, job.ErrorMessage, job.ReportPath, job.StartedAt)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	job.ID = id
	return nil
}

// GetScanJob retrieves a scan job by primary key
func (s *SQLiteDB) GetScanJob(ctx context.Context, primaryKey string) (*ScanJob, error) {
	job := &ScanJob{}
	var startedAt, completedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash,
			status, scan_mode, error_message, report_path, started_at, completed_at,
			created_at, updated_at
		FROM scan_jobs WHERE primary_unique_key = ?
	`, primaryKey).Scan(&job.ID, &job.PrimaryUniqueKey, &job.Provider, &job.Repository,
		&job.Branch, &job.Commit, &job.Status, &job.ScanMode, &job.ErrorMessage,
		&job.ReportPath, &startedAt, &completedAt, &job.CreatedAt, &job.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if startedAt.Valid {
		job.StartedAt = startedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = completedAt.Time
	}
	return job, err
}

// GetScanJobByID retrieves a scan job by ID
func (s *SQLiteDB) GetScanJobByID(ctx context.Context, id int64) (*ScanJob, error) {
	job := &ScanJob{}
	var startedAt, completedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash,
			status, scan_mode, error_message, report_path, started_at, completed_at,
			created_at, updated_at
		FROM scan_jobs WHERE id = ?
	`, id).Scan(&job.ID, &job.PrimaryUniqueKey, &job.Provider, &job.Repository,
		&job.Branch, &job.Commit, &job.Status, &job.ScanMode, &job.ErrorMessage,
		&job.ReportPath, &startedAt, &completedAt, &job.CreatedAt, &job.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if startedAt.Valid {
		job.StartedAt = startedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = completedAt.Time
	}
	return job, err
}

// ListScanJobs retrieves scan jobs with filtering
func (s *SQLiteDB) ListScanJobs(ctx context.Context, opts ListScanJobsOptions) ([]ScanJob, error) {
	query := `SELECT id, primary_unique_key, provider, repository, branch, commit_hash,
		status, scan_mode, error_message, report_path, started_at, completed_at,
		created_at, updated_at FROM scan_jobs WHERE 1=1`
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Repository != "" {
		query += " AND repository = ?"
		args = append(args, opts.Repository)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.ScanMode != "" {
		query += " AND scan_mode = ?"
		args = append(args, opts.ScanMode)
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

	var jobs []ScanJob
	for rows.Next() {
		var j ScanJob
		var startedAt, completedAt sql.NullTime
		if err := rows.Scan(&j.ID, &j.PrimaryUniqueKey, &j.Provider, &j.Repository,
			&j.Branch, &j.Commit, &j.Status, &j.ScanMode, &j.ErrorMessage,
			&j.ReportPath, &startedAt, &completedAt, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		if startedAt.Valid {
			j.StartedAt = startedAt.Time
		}
		if completedAt.Valid {
			j.CompletedAt = completedAt.Time
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// UpdateScanJob updates a scan job
func (s *SQLiteDB) UpdateScanJob(ctx context.Context, job *ScanJob) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scan_jobs SET status = ?, error_message = ?, report_path = ?,
			completed_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, job.Status, job.ErrorMessage, job.ReportPath, job.CompletedAt, job.ID)
	return err
}

// GetLatestScanJob gets the most recent scan job for a repo/branch
func (s *SQLiteDB) GetLatestScanJob(ctx context.Context, provider, repo, branch string) (*ScanJob, error) {
	jobs, err := s.ListScanJobs(ctx, ListScanJobsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Limit:      1,
	})
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, nil
	}
	return &jobs[0], nil
}

// ============================================================================
// Scan Job Scanner Operations
// ============================================================================

// CreateScanJobScanner creates a scanner entry for a scan job
func (s *SQLiteDB) CreateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_job_scanners (
			scan_job_id, scanner_name, scanner_type, status, findings_count,
			error_message, output_path, duration, started_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scanner.ScanJobID, scanner.ScannerName, scanner.ScannerType, scanner.Status,
		scanner.FindingsCount, scanner.ErrorMessage, scanner.OutputPath,
		scanner.Duration, scanner.StartedAt)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	scanner.ID = id
	return nil
}

// GetScanJobScanners retrieves all scanners for a scan job
func (s *SQLiteDB) GetScanJobScanners(ctx context.Context, scanJobID int64) ([]ScanJobScanner, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_job_id, scanner_name, scanner_type, status, findings_count,
			error_message, output_path, duration, started_at, completed_at,
			created_at, updated_at
		FROM scan_job_scanners WHERE scan_job_id = ?
	`, scanJobID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var scanners []ScanJobScanner
	for rows.Next() {
		var sc ScanJobScanner
		var startedAt, completedAt sql.NullTime
		if err := rows.Scan(&sc.ID, &sc.ScanJobID, &sc.ScannerName, &sc.ScannerType,
			&sc.Status, &sc.FindingsCount, &sc.ErrorMessage, &sc.OutputPath,
			&sc.Duration, &startedAt, &completedAt, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
			return nil, err
		}
		if startedAt.Valid {
			sc.StartedAt = startedAt.Time
		}
		if completedAt.Valid {
			sc.CompletedAt = completedAt.Time
		}
		scanners = append(scanners, sc)
	}
	return scanners, rows.Err()
}

// UpdateScanJobScanner updates a scanner's status within a scan job
func (s *SQLiteDB) UpdateScanJobScanner(ctx context.Context, scanner *ScanJobScanner) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scan_job_scanners SET status = ?, findings_count = ?, error_message = ?,
			output_path = ?, duration = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, scanner.Status, scanner.FindingsCount, scanner.ErrorMessage,
		scanner.OutputPath, scanner.Duration, scanner.CompletedAt, scanner.ID)
	return err
}

// ============================================================================
// Jira Ticket Attribution Operations
// ============================================================================

// UpsertJiraTicketAttribution creates or updates a Jira ticket attribution
func (s *SQLiteDB) UpsertJiraTicketAttribution(ctx context.Context, attr *JiraTicketAttribution) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO jira_ticket_attributions (
			jira_ticket, ticket_key, finding_type, finding_key, ticket_status,
			ticket_resolution, assignee, due_date
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ticket_key) DO UPDATE SET
			ticket_status = excluded.ticket_status,
			ticket_resolution = excluded.ticket_resolution,
			assignee = excluded.assignee,
			due_date = excluded.due_date,
			updated_at = CURRENT_TIMESTAMP
	`, attr.JiraTicket, attr.TicketKey, attr.FindingType, attr.FindingKey,
		attr.TicketStatus, attr.TicketResolution, attr.Assignee, attr.DueDate)
	return err
}

// GetJiraTicketAttribution retrieves a Jira ticket attribution by ticket key
func (s *SQLiteDB) GetJiraTicketAttribution(ctx context.Context, ticketKey string) (*JiraTicketAttribution, error) {
	attr := &JiraTicketAttribution{}
	var dueDate sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, jira_ticket, ticket_key, finding_type, finding_key,
			ticket_status, ticket_resolution, assignee, due_date, created_at, updated_at
		FROM jira_ticket_attributions WHERE ticket_key = ?
	`, ticketKey).Scan(&attr.ID, &attr.JiraTicket, &attr.TicketKey, &attr.FindingType,
		&attr.FindingKey, &attr.TicketStatus, &attr.TicketResolution, &attr.Assignee,
		&dueDate, &attr.CreatedAt, &attr.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if dueDate.Valid {
		attr.DueDate = dueDate.Time
	}
	return attr, err
}

// ListJiraTicketsByFinding retrieves all Jira tickets for a specific finding
func (s *SQLiteDB) ListJiraTicketsByFinding(ctx context.Context, findingType, findingKey string) ([]JiraTicketAttribution, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, jira_ticket, ticket_key, finding_type, finding_key,
			ticket_status, ticket_resolution, assignee, due_date, created_at, updated_at
		FROM jira_ticket_attributions WHERE finding_type = ? AND finding_key = ?
	`, findingType, findingKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var attrs []JiraTicketAttribution
	for rows.Next() {
		var a JiraTicketAttribution
		var dueDate sql.NullTime
		if err := rows.Scan(&a.ID, &a.JiraTicket, &a.TicketKey, &a.FindingType,
			&a.FindingKey, &a.TicketStatus, &a.TicketResolution, &a.Assignee,
			&dueDate, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		if dueDate.Valid {
			a.DueDate = dueDate.Time
		}
		attrs = append(attrs, a)
	}
	return attrs, rows.Err()
}

// ============================================================================
// Helper Functions for Primary Key Generation
// ============================================================================

// GenerateSCAPrimaryKey generates the primary unique key for an SCA finding
func GenerateSCAPrimaryKey(provider, repo, branch, commit, pkg, version string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", provider, repo, branch, commit, pkg, version)
}

// GenerateSASTPrimaryKey generates the primary unique key for a SAST finding
func GenerateSASTPrimaryKey(provider, repo, branch, commit, checkID, fingerprint string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", provider, repo, branch, commit, checkID, fingerprint)
}

// GenerateSecretsPrimaryKey generates the primary unique key for a secrets finding
func GenerateSecretsPrimaryKey(provider, repo, branch, commit, credHash, locHash string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", provider, repo, branch, commit, credHash, locHash)
}

// GenerateScanJobPrimaryKey generates the primary unique key for a scan job
func GenerateScanJobPrimaryKey(provider, repo, branch, commit string) string {
	return fmt.Sprintf("%s:%s:%s:%s", provider, repo, branch, commit)
}

// GenerateLicensePrimaryKey generates the primary unique key for a license finding
func GenerateLicensePrimaryKey(provider, repo, branch, commit, pkg, version, license string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s", provider, repo, branch, commit, pkg, version, license)
}

// ============================================================================
// License Finding Operations (Trivy)
// ============================================================================

// UpsertLicenseFinding creates or updates a license finding
// On conflict, it updates fields but preserves first_seen_at
func (s *SQLiteDB) UpsertLicenseFinding(ctx context.Context, finding *LicenseFinding) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO license_findings (
			primary_unique_key, provider, repository, branch, commit_hash, package,
			version, license, classification, pkg_path, pkg_type, severity, status,
			last_seen_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(primary_unique_key) DO UPDATE SET
			classification = excluded.classification,
			pkg_path = excluded.pkg_path,
			pkg_type = excluded.pkg_type,
			severity = excluded.severity,
			last_seen_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
	`, finding.PrimaryUniqueKey, finding.Provider, finding.Repository, finding.Branch,
		finding.Commit, finding.Package, finding.Version, finding.License,
		finding.Classification, finding.PkgPath, finding.PkgType, finding.Severity, finding.Status)
	return err
}

// GetLicenseFinding retrieves a license finding by primary key
func (s *SQLiteDB) GetLicenseFinding(ctx context.Context, primaryKey string) (*LicenseFinding, error) {
	finding := &LicenseFinding{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, primary_unique_key, provider, repository, branch, commit_hash, package,
			version, license, classification, pkg_path, pkg_type, severity, status, jira_ticket,
			first_seen_at, last_seen_at, created_at, updated_at
		FROM license_findings WHERE primary_unique_key = ?
	`, primaryKey).Scan(&finding.ID, &finding.PrimaryUniqueKey, &finding.Provider,
		&finding.Repository, &finding.Branch, &finding.Commit, &finding.Package,
		&finding.Version, &finding.License, &finding.Classification, &finding.PkgPath,
		&finding.PkgType, &finding.Severity, &finding.Status, &finding.JiraTicket,
		&finding.FirstSeenAt, &finding.LastSeenAt, &finding.CreatedAt, &finding.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return finding, err
}

// ListLicenseFindings retrieves license findings with filtering
func (s *SQLiteDB) ListLicenseFindings(ctx context.Context, opts ListLicenseFindingsOptions) ([]LicenseFinding, error) {
	query := `SELECT id, primary_unique_key, provider, repository, branch, commit_hash, package,
		version, license, classification, pkg_path, pkg_type, severity, status, jira_ticket,
		first_seen_at, last_seen_at, created_at, updated_at FROM license_findings WHERE 1=1`
	args := []interface{}{}

	if opts.Provider != "" {
		query += " AND provider = ?"
		args = append(args, opts.Provider)
	}
	if opts.Repository != "" {
		query += " AND repository = ?"
		args = append(args, opts.Repository)
	}
	if opts.Branch != "" {
		query += " AND branch = ?"
		args = append(args, opts.Branch)
	}
	if opts.Commit != "" {
		query += " AND commit_hash = ?"
		args = append(args, opts.Commit)
	}
	if opts.Package != "" {
		query += " AND package LIKE ?"
		args = append(args, "%"+opts.Package+"%")
	}
	if opts.License != "" {
		query += " AND license LIKE ?"
		args = append(args, "%"+opts.License+"%")
	}
	if opts.Classification != "" {
		query += " AND classification = ?"
		args = append(args, opts.Classification)
	}
	if opts.Severity != "" {
		query += " AND severity = ?"
		args = append(args, opts.Severity)
	}
	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []LicenseFinding
	for rows.Next() {
		var f LicenseFinding
		var version, classification, pkgPath, pkgType, severity, jiraTicket sql.NullString
		if err := rows.Scan(&f.ID, &f.PrimaryUniqueKey, &f.Provider, &f.Repository,
			&f.Branch, &f.Commit, &f.Package, &version, &f.License,
			&classification, &pkgPath, &pkgType, &severity, &f.Status,
			&jiraTicket, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		f.Version = version.String
		f.Classification = classification.String
		f.PkgPath = pkgPath.String
		f.PkgType = pkgType.String
		f.Severity = severity.String
		f.JiraTicket = jiraTicket.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpdateLicenseFindingStatus updates the status and optional jira ticket for a license finding
func (s *SQLiteDB) UpdateLicenseFindingStatus(ctx context.Context, primaryKey, status, jiraTicket string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE license_findings SET status = ?, jira_ticket = ?, updated_at = CURRENT_TIMESTAMP
		WHERE primary_unique_key = ?
	`, status, jiraTicket, primaryKey)
	return err
}

// GetLatestLicenseFindings gets the most recent license findings for a repo/branch
func (s *SQLiteDB) GetLatestLicenseFindings(ctx context.Context, provider, repo, branch string) ([]LicenseFinding, error) {
	return s.ListLicenseFindings(ctx, ListLicenseFindingsOptions{
		Provider:   provider,
		Repository: repo,
		Branch:     branch,
		Limit:      1000,
	})
}

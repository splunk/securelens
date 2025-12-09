package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/splunk/securelens/pkg/scanner"
	"github.com/splunk/securelens/pkg/srs"
)

// TrivyScanner implements the Scanner interface for Trivy vulnerability scanning
type TrivyScanner struct {
	config map[string]interface{}
}

// NewTrivyScanner creates a new Trivy scanner instance
func NewTrivyScanner(config map[string]interface{}) *TrivyScanner {
	return &TrivyScanner{
		config: config,
	}
}

// Name returns the scanner name
func (t *TrivyScanner) Name() string {
	return "Trivy"
}

// Type returns the scanner type
func (t *TrivyScanner) Type() scanner.ScannerType {
	return scanner.OSS
}

// IsAvailable checks if the trivy binary is available on the system
func (t *TrivyScanner) IsAvailable() (bool, string) {
	path, err := exec.LookPath("trivy")
	if err != nil {
		return false, fmt.Sprintf("trivy binary not found in PATH: %v", err)
	}
	return true, fmt.Sprintf("trivy found at: %s", path)
}

// Scan executes a Trivy scan on the given repository
func (t *TrivyScanner) Scan(ctx context.Context, repoPath string, opts scanner.ScanOptions) (*scanner.ScanResult, error) {
	startTime := time.Now()

	slog.Info("Starting Trivy scan",
		"repoPath", repoPath,
		"branch", opts.Branch,
		"commit", opts.Commit,
	)

	// Check if trivy is available
	available, message := t.IsAvailable()
	if !available {
		slog.Error("Trivy scanner not available", "error", message)
		return &scanner.ScanResult{
			ScannerName:     t.Name(),
			ScannerType:     t.Type(),
			StartTime:       startTime,
			EndTime:         time.Now(),
			Status:          "FAILED",
			Error:           fmt.Errorf("%s", message),
			Vulnerabilities: []scanner.Vulnerability{},
			Summary:         scanner.ScanSummary{},
		}, fmt.Errorf("%s", message)
	}

	slog.Info("Trivy binary check passed", "message", message)

	// Execute trivy scan
	cmd := exec.CommandContext(ctx, "trivy", "fs", repoPath,
		"--format", "json",
		"--scanners", "vuln,secret,misconfig")

	slog.Info("Executing trivy command",
		"command", cmd.String(),
		"repoPath", repoPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("Trivy scan execution failed",
			"error", err,
			"output", string(output),
		)
		return &scanner.ScanResult{
			ScannerName:     t.Name(),
			ScannerType:     t.Type(),
			StartTime:       startTime,
			EndTime:         time.Now(),
			Status:          "FAILED",
			Error:           fmt.Errorf("trivy execution failed: %w", err),
			Vulnerabilities: []scanner.Vulnerability{},
			Summary:         scanner.ScanSummary{},
		}, fmt.Errorf("trivy execution failed: %w", err)
	}

	slog.Info("Trivy command executed successfully",
		"outputSize", len(output),
	)

	// Parse Trivy JSON output into SRS-compatible format
	var trivyRawData srs.TrivyRawData
	if err := json.Unmarshal(output, &trivyRawData); err != nil {
		slog.Error("Failed to parse Trivy JSON output",
			"error", err,
			"output", string(output[:min(len(output), 500)]),
		)
		return &scanner.ScanResult{
			ScannerName:     t.Name(),
			ScannerType:     t.Type(),
			StartTime:       startTime,
			EndTime:         time.Now(),
			Status:          "FAILED",
			Error:           fmt.Errorf("failed to parse trivy output: %w", err),
			Vulnerabilities: []scanner.Vulnerability{},
			Summary:         scanner.ScanSummary{},
		}, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	slog.Info("Trivy JSON parsed successfully",
		"resultCount", len(trivyRawData.Results),
	)

	// Convert Trivy results to scanner.Vulnerability format
	vulnerabilities, summary := t.convertTrivyResults(&trivyRawData, opts)

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()
	summary.DurationSeconds = duration

	slog.Info("Trivy scan completed successfully",
		"repoPath", repoPath,
		"totalFindings", summary.TotalFindings,
		"criticalCount", summary.CriticalCount,
		"highCount", summary.HighCount,
		"mediumCount", summary.MediumCount,
		"lowCount", summary.LowCount,
		"durationSeconds", duration,
	)

	return &scanner.ScanResult{
		ScannerName:     t.Name(),
		ScannerType:     t.Type(),
		StartTime:       startTime,
		EndTime:         endTime,
		Status:          "SUCCESS",
		Error:           nil,
		Vulnerabilities: vulnerabilities,
		Summary:         summary,
	}, nil
}

// convertTrivyResults converts Trivy raw data to scanner.Vulnerability format
func (t *TrivyScanner) convertTrivyResults(rawData *srs.TrivyRawData, opts scanner.ScanOptions) ([]scanner.Vulnerability, scanner.ScanSummary) {
	var vulnerabilities []scanner.Vulnerability
	summary := scanner.ScanSummary{}

	// Determine the postfix (repo identifier)
	postfix := ""
	if opts.RepoOwner != "" && opts.RepoURL != "" {
		// Extract repo name from URL
		parts := strings.Split(strings.TrimSuffix(opts.RepoURL, ".git"), "/")
		if len(parts) > 0 {
			repoName := parts[len(parts)-1]
			postfix = fmt.Sprintf("%s/%s", opts.RepoOwner, repoName)
		}
	}

	// Process each result target (e.g., different lock files, manifests)
	for _, result := range rawData.Results {
		slog.Debug("Processing Trivy result",
			"target", result.Target,
			"type", result.Type,
			"vulnCount", len(result.Vulnerabilities),
			"pkgCount", len(result.Packages),
		)

		// Process vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			severity := normalizeSeverity(vuln.Severity)

			// Generate a unique primary key for this vulnerability
			// Format: {vuln_id}:{pkg_name}:{pkg_version}:{postfix}:{branch}
			primaryKey := generatePrimaryKey(
				vuln.VulnerabilityID,
				vuln.PkgName,
				vuln.InstalledVersion,
				postfix,
				opts.Branch,
			)

			// Extract CVEs and CWEs
			cves := extractCVEs(vuln.VulnerabilityID, vuln.References)
			cwes := vuln.CweIDs

			// Build raw data map for additional information
			rawDataMap := map[string]interface{}{
				"target":            result.Target,
				"type":              result.Type,
				"class":             result.Class,
				"installed_version": vuln.InstalledVersion,
				"fixed_version":     vuln.FixedVersion,
				"primary_url":       vuln.PrimaryURL,
				"references":        vuln.References,
				"cvss":              vuln.CVSS,
				"status":            vuln.Status,
				"published_date":    vuln.PublishedDate,
				"last_modified":     vuln.LastModifiedDate,
				"title":             vuln.Title,
			}

			vulnerability := scanner.Vulnerability{
				PrimaryKey:  primaryKey,
				TicketName:  vuln.VulnerabilityID,
				Description: vuln.Description,

				Severity:  severity,
				Component: "OSS",
				Source:    "Trivy",

				OriginPath: result.Target,
				OriginRef:  vuln.PrimaryURL,

				Postfix: postfix,
				Branch:  opts.Branch,
				Commit:  opts.Commit,

				RemediationVersion: vuln.FixedVersion,
				AffectsVersion:     vuln.InstalledVersion,

				Labels: []string{
					fmt.Sprintf("pkg:%s", vuln.PkgName),
					fmt.Sprintf("type:%s", result.Type),
				},
				CVEs: cves,
				CWEs: cwes,

				RawData: rawDataMap,
			}

			vulnerabilities = append(vulnerabilities, vulnerability)

			// Update summary counts
			summary.TotalFindings++
			switch severity {
			case "CRITICAL":
				summary.CriticalCount++
			case "HIGH":
				summary.HighCount++
			case "MEDIUM":
				summary.MediumCount++
			case "LOW":
				summary.LowCount++
			}
		}
	}

	slog.Info("Converted Trivy results to vulnerabilities",
		"totalVulnerabilities", len(vulnerabilities),
		"critical", summary.CriticalCount,
		"high", summary.HighCount,
		"medium", summary.MediumCount,
		"low", summary.LowCount,
	)

	return vulnerabilities, summary
}

// generatePrimaryKey creates a unique identifier for a vulnerability
func generatePrimaryKey(vulnID, pkgName, pkgVersion, postfix, branch string) string {
	// Use a hash-based approach for consistency
	data := fmt.Sprintf("%s:%s:%s:%s:%s", vulnID, pkgName, pkgVersion, postfix, branch)
	hash := sha256.Sum256([]byte(data))
	hashStr := fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes of hash

	// Create a readable key with hash suffix
	return fmt.Sprintf("%s:%s:%s:%s", vulnID, pkgName, pkgVersion, hashStr)
}

// normalizeSeverity converts Trivy severity to standard format
func normalizeSeverity(severity string) string {
	severity = strings.ToUpper(strings.TrimSpace(severity))
	switch severity {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "UNKNOWN", "":
		return "LOW" // Default to LOW for unknown severities
	default:
		return severity
	}
}

// extractCVEs extracts CVE identifiers from vulnerability ID and references
func extractCVEs(vulnID string, references []string) []string {
	cves := []string{}

	// Check if vulnerability ID itself is a CVE
	if strings.HasPrefix(strings.ToUpper(vulnID), "CVE-") {
		cves = append(cves, strings.ToUpper(vulnID))
	}

	// Extract CVEs from references
	for _, ref := range references {
		refUpper := strings.ToUpper(ref)
		if strings.Contains(refUpper, "CVE-") {
			// Find CVE patterns in the reference string
			// CVE format: CVE-YYYY-NNNNN (where YYYY is year and NNNNN is number)
			idx := 0
			for idx < len(refUpper) {
				cveIdx := strings.Index(refUpper[idx:], "CVE-")
				if cveIdx == -1 {
					break
				}

				startIdx := idx + cveIdx
				// Find the end of the CVE identifier
				endIdx := startIdx + 4 // Start after "CVE-"

				// Skip to end of year (4 digits)
				for endIdx < len(ref) && ref[endIdx] >= '0' && ref[endIdx] <= '9' {
					endIdx++
				}

				// Skip the hyphen after year
				if endIdx < len(ref) && ref[endIdx] == '-' {
					endIdx++
				}

				// Skip the CVE number (at least 4 digits)
				for endIdx < len(ref) && ref[endIdx] >= '0' && ref[endIdx] <= '9' {
					endIdx++
				}

				cve := strings.ToUpper(ref[startIdx:endIdx])
				if !contains(cves, cve) {
					cves = append(cves, cve)
				}

				idx = endIdx
			}
		}
	}

	return cves
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

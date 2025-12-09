package opengrep

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/splunk/securelens/pkg/scanner"
	"github.com/splunk/securelens/pkg/srs"
)

// OpengrepScanner implements the Scanner interface for Opengrep SAST scanning
type OpengrepScanner struct {
	config     map[string]interface{}
	binaryPath string
	rulesPath  string
}

// OpengrepResults represents the raw JSON output from opengrep
type OpengrepResults struct {
	Results struct {
		Errors                 []interface{} `json:"errors"`
		InterfileLanguagesUsed []interface{} `json:"interfile_languages_used"`
		Paths                  struct {
			Scanned []string `json:"scanned"`
		} `json:"paths"`
		Results      []OpengrepFinding `json:"results"`
		SkippedRules []interface{}     `json:"skipped_rules"`
		Version      string            `json:"version"`
	} `json:"results"`
}

// OpengrepFinding represents a single finding from opengrep
type OpengrepFinding struct {
	CheckID string `json:"check_id"`
	End     struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		EngineKind  string `json:"engine_kind"`
		Fingerprint string `json:"fingerprint"`
		IsIgnored   bool   `json:"is_ignored"`
		Lines       string `json:"lines"`
		Message     string `json:"message"`
		Metadata    struct {
			CWE        interface{} `json:"cwe"`
			OWASP      interface{} `json:"owasp"`
			References []string    `json:"references"`
		} `json:"metadata"`
		Severity        string `json:"severity"`
		ValidationState string `json:"validation_state"`
	} `json:"extra"`
	Path  string `json:"path"`
	Start struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"start"`
}

// NewOpengrepScanner creates a new Opengrep scanner instance
func NewOpengrepScanner(config map[string]interface{}) *OpengrepScanner {
	return &OpengrepScanner{
		config: config,
	}
}

// Name returns the scanner name
func (o *OpengrepScanner) Name() string {
	return "opengrep"
}

// Type returns the scanner type
func (o *OpengrepScanner) Type() scanner.ScannerType {
	return scanner.SAST
}

// IsAvailable checks if the opengrep binary and rules exist
func (o *OpengrepScanner) IsAvailable() (bool, string) {
	// Check if opengrep binary exists
	binaryPath, err := exec.LookPath("opengrep")
	if err != nil {
		return false, fmt.Sprintf("opengrep binary not found in PATH: %v", err)
	}
	o.binaryPath = binaryPath

	// Get working directory
	wd, err := os.Getwd()
	if err != nil {
		return false, fmt.Sprintf("failed to get working directory: %v", err)
	}

	// Check if rules exist at assets/opengrep-rules
	rulesPath := filepath.Join(wd, "assets", "opengrep-rules")
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		return false, fmt.Sprintf("opengrep rules not found at %s", rulesPath)
	}
	o.rulesPath = rulesPath

	return true, ""
}

// Scan executes an Opengrep scan on the given repository
func (o *OpengrepScanner) Scan(ctx context.Context, repoPath string, opts scanner.ScanOptions) (*scanner.ScanResult, error) {
	startTime := time.Now()

	slog.Info("Starting opengrep scan",
		"repoPath", repoPath,
		"branch", opts.Branch,
		"commit", opts.Commit,
	)

	// Check if scanner is available
	available, errMsg := o.IsAvailable()
	if !available {
		slog.Error("opengrep scanner not available", "error", errMsg)
		return &scanner.ScanResult{
			ScannerName: o.Name(),
			ScannerType: o.Type(),
			StartTime:   startTime,
			EndTime:     time.Now(),
			Status:      "FAILED",
			Error:       fmt.Errorf("scanner not available: %s", errMsg),
		}, fmt.Errorf("scanner not available: %s", errMsg)
	}

	// Create temporary file for JSON output
	outputFile, err := os.CreateTemp("", "opengrep-results-*.json")
	if err != nil {
		slog.Error("failed to create temporary output file", "error", err)
		return nil, fmt.Errorf("failed to create temporary output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	// Build the opengrep command
	// opengrep scan -f <rulesPath> <repoPath> --json --json-output <outputFile>
	cmd := exec.CommandContext(ctx, "opengrep", "scan", "-f", o.rulesPath, repoPath, "--json", "--json-output", outputFile.Name())

	slog.Info("executing opengrep command",
		"command", cmd.String(),
		"rulesPath", o.rulesPath,
		"outputFile", outputFile.Name(),
	)

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Opengrep may return non-zero exit code even on successful scans with findings
		slog.Warn("opengrep command returned non-zero exit code",
			"error", err,
			"output", string(output),
		)
	}

	// Read the JSON output file
	jsonData, err := os.ReadFile(outputFile.Name())
	if err != nil {
		slog.Error("failed to read opengrep output file", "error", err)
		return nil, fmt.Errorf("failed to read opengrep output file: %w", err)
	}

	// Parse the JSON results
	var results OpengrepResults
	if err := json.Unmarshal(jsonData, &results); err != nil {
		slog.Error("failed to parse opengrep JSON output", "error", err)
		return nil, fmt.Errorf("failed to parse opengrep JSON output: %w", err)
	}

	// Convert opengrep findings to scanner vulnerabilities
	vulnerabilities := make([]scanner.Vulnerability, 0, len(results.Results.Results))
	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, finding := range results.Results.Results {
		if finding.Extra.IsIgnored {
			continue
		}

		// Map severity to standard format
		severity := normalizeSeverity(finding.Extra.Severity)
		severityCounts[severity]++

		// Extract CWE and CVE information
		cwes := extractCWEs(finding.Extra.Metadata.CWE)

		// Build vulnerability
		vuln := scanner.Vulnerability{
			PrimaryKey:  fmt.Sprintf("%s:%s:%s", finding.CheckID, opts.RepoOwner, opts.Branch),
			TicketName:  finding.CheckID,
			Description: finding.Extra.Message,
			Severity:    severity,
			Component:   "SAST",
			Source:      "opengrep",
			OriginPath:  finding.Path,
			OriginRef:   fmt.Sprintf("line %d", finding.Start.Line),
			Postfix:     opts.RepoOwner,
			Branch:      opts.Branch,
			Commit:      opts.Commit,
			CWEs:        cwes,
			Labels:      []string{"opengrep", finding.CheckID},
			RawData: map[string]interface{}{
				"check_id":    finding.CheckID,
				"path":        finding.Path,
				"start_line":  finding.Start.Line,
				"end_line":    finding.End.Line,
				"start_col":   finding.Start.Col,
				"end_col":     finding.End.Col,
				"code_lines":  finding.Extra.Lines,
				"fingerprint": finding.Extra.Fingerprint,
				"metadata":    finding.Extra.Metadata,
			},
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds()

	scanResult := &scanner.ScanResult{
		ScannerName:     o.Name(),
		ScannerType:     o.Type(),
		StartTime:       startTime,
		EndTime:         endTime,
		Status:          "SUCCESS",
		Vulnerabilities: vulnerabilities,
		Summary: scanner.ScanSummary{
			TotalFindings:    len(vulnerabilities),
			CriticalCount:    severityCounts["CRITICAL"],
			HighCount:        severityCounts["HIGH"],
			MediumCount:      severityCounts["MEDIUM"],
			LowCount:         severityCounts["LOW"],
			DurationSeconds:  duration,
			ScannedFileCount: len(results.Results.Paths.Scanned),
		},
	}

	slog.Info("opengrep scan completed",
		"repoPath", repoPath,
		"findings", len(vulnerabilities),
		"duration", duration,
		"filesScanned", len(results.Results.Paths.Scanned),
	)

	return scanResult, nil
}

// ConvertToSemgrepResults converts opengrep results to SRS-compatible SemgrepResults format
func ConvertToSemgrepResults(ogResults *OpengrepResults) *srs.SemgrepResults {
	semgrepResults := &srs.SemgrepResults{}

	semgrepResults.Results.Errors = ogResults.Results.Errors
	semgrepResults.Results.InterfileLanguagesUsed = ogResults.Results.InterfileLanguagesUsed
	semgrepResults.Results.SkippedRules = ogResults.Results.SkippedRules
	semgrepResults.Results.Version = ogResults.Results.Version

	// Copy paths
	semgrepResults.Results.Paths.Scanned = ogResults.Results.Paths.Scanned

	// Convert findings
	semgrepResults.Results.Results = make([]srs.SemgrepFinding, len(ogResults.Results.Results))
	for i, finding := range ogResults.Results.Results {
		semgrepResults.Results.Results[i] = srs.SemgrepFinding{
			CheckID: finding.CheckID,
			Path:    finding.Path,
		}

		// Copy position data
		semgrepResults.Results.Results[i].Start.Col = finding.Start.Col
		semgrepResults.Results.Results[i].Start.Line = finding.Start.Line
		semgrepResults.Results.Results[i].Start.Offset = finding.Start.Offset

		semgrepResults.Results.Results[i].End.Col = finding.End.Col
		semgrepResults.Results.Results[i].End.Line = finding.End.Line
		semgrepResults.Results.Results[i].End.Offset = finding.End.Offset

		// Copy extra data
		semgrepResults.Results.Results[i].Extra.EngineKind = finding.Extra.EngineKind
		semgrepResults.Results.Results[i].Extra.Fingerprint = finding.Extra.Fingerprint
		semgrepResults.Results.Results[i].Extra.IsIgnored = finding.Extra.IsIgnored
		semgrepResults.Results.Results[i].Extra.Lines = finding.Extra.Lines
		semgrepResults.Results.Results[i].Extra.Message = finding.Extra.Message
		semgrepResults.Results.Results[i].Extra.Severity = finding.Extra.Severity
		semgrepResults.Results.Results[i].Extra.ValidationState = finding.Extra.ValidationState

		// Copy metadata
		semgrepResults.Results.Results[i].Extra.Metadata.CWE = finding.Extra.Metadata.CWE
		semgrepResults.Results.Results[i].Extra.Metadata.OWASP = finding.Extra.Metadata.OWASP
		semgrepResults.Results.Results[i].Extra.Metadata.References = finding.Extra.Metadata.References
	}

	return semgrepResults
}

// normalizeSeverity converts opengrep severity to standard format
func normalizeSeverity(severity string) string {
	switch severity {
	case "ERROR", "error":
		return "HIGH"
	case "WARNING", "warning":
		return "MEDIUM"
	case "INFO", "info":
		return "LOW"
	default:
		// If severity is already in standard format, use it
		upper := string([]rune{rune(severity[0] - 32)}) + severity[1:]
		if upper == "CRITICAL" || upper == "HIGH" || upper == "MEDIUM" || upper == "LOW" {
			return upper
		}
		return "MEDIUM"
	}
}

// extractCWEs extracts CWE identifiers from metadata
func extractCWEs(cweData interface{}) []string {
	if cweData == nil {
		return []string{}
	}

	switch v := cweData.(type) {
	case string:
		return []string{v}
	case []interface{}:
		cwes := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				cwes = append(cwes, str)
			}
		}
		return cwes
	case []string:
		return v
	default:
		return []string{}
	}
}

package standalone

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/splunk/securelens/pkg/srs"
)

// ScannerType represents the type of standalone scanner
type ScannerType string

const (
	ScannerOpengrep   ScannerType = "opengrep"
	ScannerTrivy      ScannerType = "trivy"
	ScannerTrufflehog ScannerType = "trufflehog"
)

// ToolStatus represents the installation status of a tool
type ToolStatus struct {
	Name        string
	Available   bool
	Path        string
	Version     string
	RulesPath   string // For opengrep
	Error       string
	InstallHint string
}

// CheckTools checks all standalone tools and returns their status
func CheckTools(assetsDir string) []ToolStatus {
	statuses := []ToolStatus{}

	// Check opengrep
	ogStatus := checkOpengrep(assetsDir)
	statuses = append(statuses, ogStatus)

	// Check trivy
	trivyStatus := checkTrivy()
	statuses = append(statuses, trivyStatus)

	// Check trufflehog
	thStatus := checkTrufflehog()
	statuses = append(statuses, thStatus)

	return statuses
}

func checkOpengrep(assetsDir string) ToolStatus {
	status := ToolStatus{
		Name: "opengrep",
		InstallHint: `Install opengrep:
  make install_opengrep
  make install_opengrep_rules

Or manually:
  # Linux
  curl -L "https://github.com/opengrep/opengrep/releases/download/v1.6.0/opengrep_musllinux_x86_64" -o /usr/local/bin/opengrep
  chmod +x /usr/local/bin/opengrep

  # macOS
  curl -L "https://github.com/opengrep/opengrep/releases/download/v1.6.0/opengrep_osx_x86_64" -o /usr/local/bin/opengrep
  chmod +x /usr/local/bin/opengrep

  # Download rules
  mkdir -p assets && cd assets
  git clone --depth 1 https://github.com/opengrep/opengrep-rules ./opengrep-rules
  rm -rf opengrep-rules/.git opengrep-rules/.github`,
	}

	path, err := exec.LookPath("opengrep")
	if err != nil {
		status.Error = "opengrep binary not found in PATH"
		return status
	}
	status.Path = path

	// Check version
	cmd := exec.Command("opengrep", "--version")
	output, err := cmd.Output()
	if err == nil {
		status.Version = strings.TrimSpace(strings.Split(string(output), "\n")[0])
	}

	// Check rules directory
	rulesPath := filepath.Join(assetsDir, "opengrep-rules")
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		status.Error = fmt.Sprintf("opengrep rules not found at %s", rulesPath)
		return status
	}
	status.RulesPath = rulesPath
	status.Available = true

	return status
}

func checkTrivy() ToolStatus {
	status := ToolStatus{
		Name: "trivy",
		InstallHint: `Install trivy:
  make install_trivy

Or manually:
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`,
	}

	path, err := exec.LookPath("trivy")
	if err != nil {
		status.Error = "trivy binary not found in PATH"
		return status
	}
	status.Path = path
	status.Available = true

	// Check version
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err == nil {
		status.Version = strings.TrimSpace(strings.Split(string(output), "\n")[0])
	}

	return status
}

func checkTrufflehog() ToolStatus {
	status := ToolStatus{
		Name: "trufflehog",
		InstallHint: `Install trufflehog:
  make install_trufflehog

Or manually:
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin`,
	}

	path, err := exec.LookPath("trufflehog")
	if err != nil {
		status.Error = "trufflehog binary not found in PATH"
		return status
	}
	status.Path = path
	status.Available = true

	// Check version
	cmd := exec.Command("trufflehog", "--version")
	output, err := cmd.Output()
	if err == nil {
		status.Version = strings.TrimSpace(strings.Split(string(output), "\n")[0])
	}

	return status
}

// PrintToolStatus prints the status of all tools
func PrintToolStatus(statuses []ToolStatus) {
	fmt.Print("\n=== Standalone Scanner Tools Status ===\n\n")

	allAvailable := true
	for _, s := range statuses {
		if s.Available {
			fmt.Printf("  ✓ %s: installed (%s)\n", s.Name, s.Version)
			if s.RulesPath != "" {
				fmt.Printf("      Rules: %s\n", s.RulesPath)
			}
		} else {
			allAvailable = false
			fmt.Printf("  ✗ %s: NOT INSTALLED\n", s.Name)
			fmt.Printf("      Error: %s\n", s.Error)
		}
	}

	if !allAvailable {
		fmt.Println("\n=== Installation Instructions ===")
		fmt.Println("\nRun the following to install all tools:")
		fmt.Println("  make install_scan_tools_standalone")
		fmt.Println("\nOr install individually:")
		for _, s := range statuses {
			if !s.Available {
				fmt.Printf("\n--- %s ---\n%s\n", s.Name, s.InstallHint)
			}
		}
	}
	fmt.Println()
}

// StandaloneScanResult represents results from standalone scanning
type StandaloneScanResult struct {
	Scanner   string                 `json:"scanner"`
	Status    string                 `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  string                 `json:"duration"`
	Results   map[string]interface{} `json:"results"`
	Error     string                 `json:"error,omitempty"`
}

// ScannerResult is used for channel communication
type ScannerResult struct {
	Scanner string
	Result  *StandaloneScanResult
}

// RunStandaloneScans runs the requested scanners on the repository
// When parallel is true, scanners run concurrently using goroutines
func RunStandaloneScans(ctx context.Context, repoPath string, scanners []ScannerType, assetsDir string) (map[string]*StandaloneScanResult, error) {
	return RunStandaloneScansParallel(ctx, repoPath, scanners, assetsDir, true)
}

// RunStandaloneScansParallel runs scanners with optional parallelism
func RunStandaloneScansParallel(ctx context.Context, repoPath string, scanners []ScannerType, assetsDir string, parallel bool) (map[string]*StandaloneScanResult, error) {
	if !parallel {
		return runScannersSequential(ctx, repoPath, scanners, assetsDir)
	}

	results := make(map[string]*StandaloneScanResult)
	resultChan := make(chan ScannerResult, len(scanners))

	// Create a context with timeout for the entire scan operation
	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	// Launch goroutines for each scanner
	for _, scanner := range scanners {
		go func(s ScannerType) {
			result := runSingleScanner(scanCtx, s, repoPath, assetsDir)
			select {
			case resultChan <- ScannerResult{Scanner: string(s), Result: result}:
			case <-scanCtx.Done():
				slog.Warn("Scanner result dropped due to context cancellation", "scanner", s)
			}
		}(scanner)
	}

	// Collect results with timeout
	for i := 0; i < len(scanners); i++ {
		select {
		case res := <-resultChan:
			results[res.Scanner] = res.Result
		case <-scanCtx.Done():
			slog.Warn("Timeout waiting for scanner results", "collected", len(results), "expected", len(scanners))
			return results, nil
		}
	}

	return results, nil
}

func runScannersSequential(ctx context.Context, repoPath string, scanners []ScannerType, assetsDir string) (map[string]*StandaloneScanResult, error) {
	results := make(map[string]*StandaloneScanResult)
	for _, scanner := range scanners {
		results[string(scanner)] = runSingleScanner(ctx, scanner, repoPath, assetsDir)
	}
	return results, nil
}

func runSingleScanner(ctx context.Context, scanner ScannerType, repoPath, assetsDir string) *StandaloneScanResult {
	slog.Info("Running standalone scanner", "scanner", scanner, "repo_path", repoPath)

	result := &StandaloneScanResult{
		Scanner:   string(scanner),
		StartTime: time.Now(),
	}

	var err error
	switch scanner {
	case ScannerOpengrep:
		result.Results, err = runOpengrep(ctx, repoPath, assetsDir)
	case ScannerTrivy:
		result.Results, err = runTrivy(ctx, repoPath)
	case ScannerTrufflehog:
		result.Results, err = runTrufflehog(ctx, repoPath)
	default:
		err = fmt.Errorf("unknown scanner: %s", scanner)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()

	if err != nil {
		result.Status = "FAILED"
		result.Error = err.Error()
		slog.Error("Scanner failed", "scanner", scanner, "error", err)
	} else {
		result.Status = "COMPLETE"
		slog.Info("Scanner completed", "scanner", scanner, "duration", result.Duration)
	}

	return result
}

// OpenGrepResults represents the direct output from opengrep (different from SRS semgrep format)
type OpenGrepResults struct {
	Errors                 []interface{}     `json:"errors"`
	InterfileLanguagesUsed []interface{}     `json:"interfile_languages_used"`
	Paths                  OpenGrepPaths     `json:"paths"`
	Results                []OpenGrepFinding `json:"results"`
	SkippedRules           []interface{}     `json:"skipped_rules"`
	Version                string            `json:"version"`
}

type OpenGrepPaths struct {
	Scanned []string `json:"scanned"`
}

type OpenGrepFinding struct {
	CheckID string `json:"check_id"`
	End     struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		EngineKind      string                 `json:"engine_kind"`
		Fingerprint     string                 `json:"fingerprint"`
		IsIgnored       bool                   `json:"is_ignored"`
		Lines           string                 `json:"lines"`
		Message         string                 `json:"message"`
		Metadata        map[string]interface{} `json:"metadata"`
		Severity        string                 `json:"severity"`
		ValidationState string                 `json:"validation_state"`
	} `json:"extra"`
	Path  string `json:"path"`
	Start struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"start"`
}

func runOpengrep(ctx context.Context, repoPath, assetsDir string) (map[string]interface{}, error) {
	rulesPath := filepath.Join(assetsDir, "opengrep-rules")

	// Create temp output file
	tmpFile, err := os.CreateTemp("", "opengrep-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	slog.Info("Running opengrep scan",
		"rules_path", rulesPath,
		"repo_path", repoPath,
		"output_file", tmpFile.Name(),
	)

	cmd := exec.CommandContext(ctx, "opengrep", "scan",
		"-f", rulesPath,
		repoPath,
		"--json",
		"--json-output", tmpFile.Name(),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// opengrep may return non-zero even on success with findings
		slog.Debug("opengrep command output", "output", string(output))
	}

	// Read and parse results
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read opengrep output: %w", err)
	}

	// OpenGrep outputs directly as the results object, not wrapped
	var results OpenGrepResults
	if err := json.Unmarshal(data, &results); err != nil {
		// Log the first 500 chars of data for debugging
		preview := string(data)
		if len(preview) > 500 {
			preview = preview[:500]
		}
		slog.Debug("Failed to parse opengrep output", "preview", preview, "error", err)
		return nil, fmt.Errorf("failed to parse opengrep output: %w", err)
	}

	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, finding := range results.Results {
		severityCounts[finding.Extra.Severity]++
	}

	return map[string]interface{}{
		"status":         "COMPLETE",
		"findings_count": len(results.Results),
		"files_scanned":  len(results.Paths.Scanned),
		"findings":       results.Results,
		"by_severity":    severityCounts,
		"errors":         results.Errors,
		"version":        results.Version,
	}, nil
}

func countBySeverity(findings []srs.SemgrepFinding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Extra.Severity]++
	}
	return counts
}

func runTrivy(ctx context.Context, repoPath string) (map[string]interface{}, error) {
	slog.Info("Running trivy scan", "repo_path", repoPath)

	cmd := exec.CommandContext(ctx, "trivy", "fs",
		repoPath,
		"--format", "json",
		"--scanners", "vuln,secret,misconfig",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	var results srs.TrivyRawData
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)
	totalVulns := 0
	for _, result := range results.Results {
		for _, vuln := range result.Vulnerabilities {
			severityCounts[vuln.Severity]++
			totalVulns++
		}
	}

	return map[string]interface{}{
		"status":                "COMPLETE",
		"vulnerabilities_count": totalVulns,
		"by_severity":           severityCounts,
		"artifact_name":         results.ArtifactName,
		"artifact_type":         results.ArtifactType,
		"results":               results.Results,
	}, nil
}

func runTrufflehog(ctx context.Context, repoPath string) (map[string]interface{}, error) {
	slog.Info("Running trufflehog scan", "repo_path", repoPath)

	cmd := exec.CommandContext(ctx, "trufflehog", "filesystem",
		repoPath,
		"--json",
		"--no-update",
	)

	output, err := cmd.Output()
	if err != nil {
		// trufflehog may return non-zero on findings
		if exitErr, ok := err.(*exec.ExitError); ok {
			slog.Debug("trufflehog exited with code", "code", exitErr.ExitCode())
		}
	}

	// Parse NDJSON output
	var findings []srs.TrufflehogSecret
	var scanDuration string
	var trufflehogVersion string
	verifiedCount := 0
	unverifiedCount := 0

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as finding
		var finding srs.TrufflehogSecret
		if err := json.Unmarshal([]byte(line), &finding); err == nil {
			if finding.DetectorName != "" {
				findings = append(findings, finding)
				if finding.Verified {
					verifiedCount++
				} else {
					unverifiedCount++
				}
				continue
			}
		}

		// Try to parse as metadata
		var meta map[string]interface{}
		if err := json.Unmarshal([]byte(line), &meta); err == nil {
			if dur, ok := meta["scan_duration"].(string); ok {
				scanDuration = dur
			}
			if ver, ok := meta["trufflehog_version"].(string); ok {
				trufflehogVersion = ver
			}
		}
	}

	return map[string]interface{}{
		"status":             "COMPLETE",
		"findings_count":     len(findings),
		"verified_secrets":   verifiedCount,
		"unverified_secrets": unverifiedCount,
		"scan_duration":      scanDuration,
		"version":            trufflehogVersion,
		"findings":           findings,
	}, nil
}

// GetDefaultScanners returns the default list of scanners for standalone mode
// Note: FOSSA is not supported in standalone mode
func GetDefaultScanners() []ScannerType {
	return []ScannerType{ScannerOpengrep, ScannerTrivy, ScannerTrufflehog}
}

// ParseScannerNames converts string scanner names to ScannerType
func ParseScannerNames(names []string) []ScannerType {
	scannerMap := map[string]ScannerType{
		"opengrep":   ScannerOpengrep,
		"semgrep":    ScannerOpengrep, // semgrep maps to opengrep in standalone
		"trivy":      ScannerTrivy,
		"trufflehog": ScannerTrufflehog,
	}

	var result []ScannerType
	for _, name := range names {
		if scanner, ok := scannerMap[strings.ToLower(name)]; ok {
			result = append(result, scanner)
		}
	}

	if len(result) == 0 {
		return GetDefaultScanners()
	}
	return result
}

package standalone

import (
	"context"
	"testing"

	"github.com/splunk/securelens/pkg/srs"
)

func TestParseScannerNames(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []ScannerType
	}{
		{
			name:     "empty input returns defaults",
			input:    []string{},
			expected: GetDefaultScanners(),
		},
		{
			name:     "single scanner opengrep",
			input:    []string{"opengrep"},
			expected: []ScannerType{ScannerOpengrep},
		},
		{
			name:     "semgrep maps to opengrep",
			input:    []string{"semgrep"},
			expected: []ScannerType{ScannerOpengrep},
		},
		{
			name:     "multiple scanners",
			input:    []string{"opengrep", "trivy", "trufflehog"},
			expected: []ScannerType{ScannerOpengrep, ScannerTrivy, ScannerTrufflehog},
		},
		{
			name:     "case insensitive",
			input:    []string{"OPENGREP", "Trivy", "TruffleHog"},
			expected: []ScannerType{ScannerOpengrep, ScannerTrivy, ScannerTrufflehog},
		},
		{
			name:     "unknown scanners ignored",
			input:    []string{"opengrep", "fossa", "unknown"},
			expected: []ScannerType{ScannerOpengrep},
		},
		{
			name:     "all unknown returns defaults",
			input:    []string{"fossa", "unknown"},
			expected: GetDefaultScanners(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseScannerNames(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("ParseScannerNames(%v) = %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i, scanner := range result {
				if scanner != tt.expected[i] {
					t.Errorf("ParseScannerNames(%v)[%d] = %v, want %v", tt.input, i, scanner, tt.expected[i])
				}
			}
		})
	}
}

func TestGetDefaultScanners(t *testing.T) {
	defaults := GetDefaultScanners()
	if len(defaults) != 3 {
		t.Errorf("GetDefaultScanners() returned %d scanners, want 3", len(defaults))
	}

	expected := map[ScannerType]bool{
		ScannerOpengrep:   true,
		ScannerTrivy:      true,
		ScannerTrufflehog: true,
	}

	for _, scanner := range defaults {
		if !expected[scanner] {
			t.Errorf("GetDefaultScanners() contains unexpected scanner: %s", scanner)
		}
	}
}

func TestCheckTools(t *testing.T) {
	// This test checks that CheckTools returns proper status structures
	// even if tools are not installed (common in CI environments)
	statuses := CheckTools("assets")

	if len(statuses) != 3 {
		t.Errorf("CheckTools() returned %d statuses, want 3", len(statuses))
	}

	expectedNames := map[string]bool{
		"opengrep":   true,
		"trivy":      true,
		"trufflehog": true,
	}

	for _, status := range statuses {
		if !expectedNames[status.Name] {
			t.Errorf("CheckTools() returned unexpected tool: %s", status.Name)
		}
		// Every status should have an install hint
		if status.InstallHint == "" {
			t.Errorf("CheckTools() tool %s has empty InstallHint", status.Name)
		}
		// If not available, should have error message
		if !status.Available && status.Error == "" {
			t.Errorf("CheckTools() tool %s is not available but has no Error", status.Name)
		}
	}
}

func TestToolStatusFields(t *testing.T) {
	status := ToolStatus{
		Name:        "test-tool",
		Available:   true,
		Path:        "/usr/bin/test-tool",
		Version:     "1.0.0",
		RulesPath:   "/path/to/rules",
		InstallHint: "Install with: make install_test",
	}

	if status.Name != "test-tool" {
		t.Errorf("ToolStatus.Name = %s, want test-tool", status.Name)
	}
	if !status.Available {
		t.Errorf("ToolStatus.Available = false, want true")
	}
	if status.Path != "/usr/bin/test-tool" {
		t.Errorf("ToolStatus.Path = %s, want /usr/bin/test-tool", status.Path)
	}
}

func TestScannerTypeConstants(t *testing.T) {
	if ScannerOpengrep != "opengrep" {
		t.Errorf("ScannerOpengrep = %s, want opengrep", ScannerOpengrep)
	}
	if ScannerTrivy != "trivy" {
		t.Errorf("ScannerTrivy = %s, want trivy", ScannerTrivy)
	}
	if ScannerTrufflehog != "trufflehog" {
		t.Errorf("ScannerTrufflehog = %s, want trufflehog", ScannerTrufflehog)
	}
}

func TestStandaloneScanResultFields(t *testing.T) {
	result := StandaloneScanResult{
		Scanner:  "opengrep",
		Status:   "COMPLETE",
		Duration: "1m30s",
		Results: map[string]interface{}{
			"findings_count": 10,
		},
	}

	if result.Scanner != "opengrep" {
		t.Errorf("StandaloneScanResult.Scanner = %s, want opengrep", result.Scanner)
	}
	if result.Status != "COMPLETE" {
		t.Errorf("StandaloneScanResult.Status = %s, want COMPLETE", result.Status)
	}
	if count, ok := result.Results["findings_count"].(int); !ok || count != 10 {
		t.Errorf("StandaloneScanResult.Results[findings_count] = %v, want 10", result.Results["findings_count"])
	}
}

func TestRunStandaloneScans_NoScanners(t *testing.T) {
	ctx := context.Background()
	results, err := RunStandaloneScans(ctx, "/nonexistent/path", []ScannerType{}, "assets")

	if err != nil {
		t.Errorf("RunStandaloneScans() with empty scanners returned error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("RunStandaloneScans() with empty scanners returned %d results, want 0", len(results))
	}
}

func TestCountBySeverity(t *testing.T) {
	// Create findings with various severities
	findings := make([]srs.SemgrepFinding, 4)
	findings[0].Extra.Severity = "ERROR"
	findings[1].Extra.Severity = "ERROR"
	findings[2].Extra.Severity = "WARNING"
	findings[3].Extra.Severity = "INFO"

	counts := countBySeverity(findings)

	if counts["ERROR"] != 2 {
		t.Errorf("countBySeverity() ERROR = %d, want 2", counts["ERROR"])
	}
	if counts["WARNING"] != 1 {
		t.Errorf("countBySeverity() WARNING = %d, want 1", counts["WARNING"])
	}
	if counts["INFO"] != 1 {
		t.Errorf("countBySeverity() INFO = %d, want 1", counts["INFO"])
	}
}

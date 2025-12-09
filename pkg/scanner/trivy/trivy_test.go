package trivy

import (
	"context"
	"testing"
	"time"

	"github.com/splunk/securelens/pkg/scanner"
	"github.com/stretchr/testify/assert"
)

func TestNewTrivyScanner(t *testing.T) {
	config := map[string]interface{}{
		"timeout": 300,
	}

	ts := NewTrivyScanner(config)
	assert.NotNil(t, ts)
	assert.Equal(t, "Trivy", ts.Name())
	assert.Equal(t, scanner.OSS, ts.Type())
}

func TestIsAvailable(t *testing.T) {
	ts := NewTrivyScanner(nil)
	available, message := ts.IsAvailable()

	// Test will pass whether trivy is installed or not
	// Just verify the function returns proper values
	assert.NotEmpty(t, message)
	t.Logf("Trivy availability: %v, message: %s", available, message)
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "CRITICAL"},
		{"critical", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"high", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"medium", "MEDIUM"},
		{"LOW", "LOW"},
		{"low", "LOW"},
		{"UNKNOWN", "LOW"},
		{"", "LOW"},
		{"  high  ", "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name       string
		vulnID     string
		references []string
		expected   []string
	}{
		{
			name:       "CVE in vulnerability ID",
			vulnID:     "CVE-2024-1234",
			references: []string{},
			expected:   []string{"CVE-2024-1234"},
		},
		{
			name:   "CVE in references",
			vulnID: "GHSA-xxxx-yyyy-zzzz",
			references: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
				"https://example.com/advisory",
			},
			expected: []string{"CVE-2024-5678"},
		},
		{
			name:   "Multiple CVEs",
			vulnID: "CVE-2024-1111",
			references: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2024-2222",
				"See also CVE-2024-3333",
			},
			expected: []string{"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"},
		},
		{
			name:       "No CVEs",
			vulnID:     "GHSA-xxxx-yyyy-zzzz",
			references: []string{"https://example.com/advisory"},
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCVEs(tt.vulnID, tt.references)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestGeneratePrimaryKey(t *testing.T) {
	key1 := generatePrimaryKey("CVE-2024-1234", "lodash", "4.17.19", "splunk/app", "main")
	key2 := generatePrimaryKey("CVE-2024-1234", "lodash", "4.17.19", "splunk/app", "main")
	key3 := generatePrimaryKey("CVE-2024-5678", "lodash", "4.17.19", "splunk/app", "main")

	// Same inputs should generate same key
	assert.Equal(t, key1, key2)

	// Different inputs should generate different keys
	assert.NotEqual(t, key1, key3)

	// Key should contain the vulnerability ID and package name
	assert.Contains(t, key1, "CVE-2024-1234")
	assert.Contains(t, key1, "lodash")
}

func TestContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	assert.True(t, contains(slice, "apple"))
	assert.True(t, contains(slice, "banana"))
	assert.True(t, contains(slice, "cherry"))
	assert.False(t, contains(slice, "date"))
	assert.False(t, contains(slice, ""))
}

func TestMin(t *testing.T) {
	assert.Equal(t, 1, min(1, 2))
	assert.Equal(t, 1, min(2, 1))
	assert.Equal(t, 5, min(5, 5))
	assert.Equal(t, -1, min(-1, 10))
}

func TestScanResult_NoTrivyInstalled(t *testing.T) {
	// This test will only pass if trivy is not installed
	// Skip if trivy is available
	ts := NewTrivyScanner(nil)
	available, _ := ts.IsAvailable()
	if available {
		t.Skip("Skipping test: trivy is installed")
	}

	ctx := context.Background()
	opts := scanner.ScanOptions{
		Branch:    "main",
		Commit:    "abc123",
		Timeout:   30 * time.Second,
		RepoURL:   "https://github.com/splunk/test",
		RepoOwner: "splunk",
	}

	result, err := ts.Scan(ctx, "/tmp/test-repo", opts)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "FAILED", result.Status)
	assert.Equal(t, "Trivy", result.ScannerName)
	assert.Equal(t, scanner.OSS, result.ScannerType)
}

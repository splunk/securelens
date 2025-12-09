# Trivy Scanner Module

This package provides a Trivy scanner implementation for the SecureLens security scanning tool.

## Overview

The Trivy scanner module implements the `Scanner` interface to perform vulnerability, secret, and misconfiguration scanning using [Aqua Security's Trivy](https://github.com/aquasecurity/trivy).

## Features

- **Binary Availability Check**: Verifies that the trivy binary is available on the system
- **Comprehensive Scanning**: Runs trivy with vulnerability, secret, and misconfiguration scanners
- **SRS-Compatible Output**: Parses Trivy JSON output into a format compatible with SRS (Security Report Service)
- **Detailed Vulnerability Mapping**: Converts Trivy findings to standardized vulnerability format
- **Severity Normalization**: Standardizes severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- **CVE Extraction**: Extracts CVE identifiers from vulnerability IDs and references
- **Structured Logging**: Uses log/slog for detailed logging throughout the scanning process

## Usage

```go
import (
    "context"
    "time"
    "github.com/splunk/securelens/pkg/scanner"
    "github.com/splunk/securelens/pkg/scanner/trivy"
)

// Create a new Trivy scanner
config := map[string]interface{}{}
scanner := trivy.NewTrivyScanner(config)

// Check if Trivy is available
available, message := scanner.IsAvailable()
if !available {
    log.Fatal(message)
}

// Configure scan options
opts := scanner.ScanOptions{
    Branch:    "main",
    Commit:    "abc123",
    Timeout:   5 * time.Minute,
    RepoURL:   "https://github.com/org/repo",
    RepoOwner: "org",
}

// Perform the scan
ctx := context.Background()
result, err := scanner.Scan(ctx, "/path/to/repo", opts)
if err != nil {
    log.Fatalf("Scan failed: %v", err)
}

// Process results
fmt.Printf("Total findings: %d\n", result.Summary.TotalFindings)
fmt.Printf("Critical: %d, High: %d, Medium: %d, Low: %d\n",
    result.Summary.CriticalCount,
    result.Summary.HighCount,
    result.Summary.MediumCount,
    result.Summary.LowCount,
)

for _, vuln := range result.Vulnerabilities {
    fmt.Printf("- %s: %s (Severity: %s)\n",
        vuln.TicketName,
        vuln.Description,
        vuln.Severity,
    )
}
```

## Scanner Interface Implementation

The TrivyScanner implements the following methods:

### `Name() string`
Returns the scanner name: "Trivy"

### `Type() ScannerType`
Returns the scanner type: `scanner.OSS` (Open Source Software)

### `IsAvailable() (bool, string)`
Checks if the trivy binary exists in the system PATH using `exec.LookPath`.

Returns:
- `bool`: true if trivy is available, false otherwise
- `string`: status message indicating the location or error

### `Scan(ctx context.Context, repoPath string, opts ScanOptions) (*ScanResult, error)`
Performs a comprehensive security scan on the specified repository.

The scan:
1. Verifies trivy binary availability
2. Executes: `trivy fs <repoPath> --format json --scanners vuln,secret,misconfig`
3. Parses the JSON output into SRS-compatible format
4. Converts findings to standardized vulnerability format
5. Generates vulnerability counts by severity
6. Returns detailed scan results

## Data Structures

### ScanResult
```go
type ScanResult struct {
    ScannerName     string              // "Trivy"
    ScannerType     ScannerType         // OSS
    StartTime       time.Time
    EndTime         time.Time
    Status          string              // "SUCCESS", "FAILED", "PARTIAL"
    Error           error
    Vulnerabilities []Vulnerability
    Summary         ScanSummary
}
```

### Vulnerability
Each vulnerability includes:
- **Identification**: PrimaryKey, TicketName (CVE/GHSA ID), Description
- **Classification**: Severity (CRITICAL/HIGH/MEDIUM/LOW), Component (OSS), Source (Trivy)
- **Location**: OriginPath (target file), OriginRef (reference URL)
- **Repository Context**: Postfix (org/repo), Branch, Commit
- **Version Info**: RemediationVersion (fix version), AffectsVersion (installed version)
- **Metadata**: Labels, CVEs, CWEs
- **Raw Data**: Additional scanner-specific information

### ScanSummary
```go
type ScanSummary struct {
    TotalFindings    int
    CriticalCount    int
    HighCount        int
    MediumCount      int
    LowCount         int
    DurationSeconds  float64
    ScannedFileCount int
}
```

## Primary Key Generation

The scanner generates unique primary keys for each vulnerability using the format:
```
{vulnerability_id}:{package_name}:{package_version}:{hash}
```

Where the hash is derived from:
- Vulnerability ID
- Package name
- Package version
- Repository postfix (org/repo)
- Branch name

This ensures consistent identification of vulnerabilities across scans.

## CVE Extraction

The module automatically extracts CVE identifiers from:
1. Vulnerability IDs (e.g., "CVE-2024-1234")
2. Reference URLs (e.g., "https://nvd.nist.gov/vuln/detail/CVE-2024-5678")
3. Reference text containing CVE mentions

CVEs are normalized to uppercase format.

## Logging

The scanner uses structured logging (log/slog) at various levels:

- **INFO**: Scan start/completion, binary checks, result summaries
- **DEBUG**: Detailed processing information for each result target
- **ERROR**: Failures in binary availability, execution, or parsing

## Prerequisites

- **Trivy Binary**: Must be installed and available in system PATH
  ```bash
  # Install on macOS
  brew install aquasecurity/trivy/trivy

  # Install on Linux
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
  sudo apt-get update
  sudo apt-get install trivy
  ```

## Testing

Run the test suite:
```bash
go test -v ./pkg/scanner/trivy/...
```

The tests cover:
- Scanner initialization
- Binary availability checks
- Severity normalization
- CVE extraction from various formats
- Primary key generation
- Helper functions (contains, min)
- Error handling when trivy is not installed

## Error Handling

The scanner handles various error conditions:

1. **Binary Not Found**: Returns error if trivy is not in PATH
2. **Execution Failure**: Captures and reports trivy command failures
3. **Parse Errors**: Handles JSON parsing failures with detailed error messages
4. **Context Cancellation**: Respects context cancellation for timeout handling

All errors are logged with context and returned to the caller.

## Integration with SRS

The scanner produces output compatible with the SRS (Security Report Service) TrivyResults format:

- `TrivyRawData`: Raw scan output from Trivy
- `TrivyResultDetail`: Individual scan targets (lock files, manifests, etc.)
- `TrivyVulnDetail`: Detailed vulnerability information
- `TrivyPackageDetail`: Package information

This allows seamless integration with existing SRS workflows and data pipelines.

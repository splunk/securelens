# SecureLens

A CLI-based vulnerability scanning tool that aggregates results from multiple security scanners (SAST, secrets, and dependency scanning) into unified reports.

## Features

- **Multi-Scanner Support**: Run OpenGrep (SAST), Trivy (dependencies/vulnerabilities), and Trufflehog (secrets) in parallel
- **Standalone Mode**: Run scans locally without external API dependencies
- **Parallel Execution**: Scanners run concurrently using goroutines for faster results
- **Organized Reports**: Results saved in `reports/{owner}/{repo}/{branch}/{commit}/` structure
- **Multiple Output Formats**: Table, JSON, and YAML output support
- **Severity Breakdown**: Findings categorized by severity (Critical, High, Medium, Low, Info)

## Quick Start

### 1. Build SecureLens

```bash
git clone https://github.com/splunk/securelens.git
cd securelens
go build -o securelens .
```

### 2. Install Scanner Binaries

SecureLens requires local scanner binaries for standalone mode:

```bash
# Install all scanners to ~/.local/bin
make install_scanners INSTALL_DIR=~/.local/bin

# Or install individually
make install_opengrep INSTALL_DIR=~/.local/bin
make install_trivy INSTALL_DIR=~/.local/bin
make install_trufflehog INSTALL_DIR=~/.local/bin
```

Ensure `~/.local/bin` is in your PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 3. Verify Installation

```bash
opengrep --version
trivy --version
trufflehog --version
```

## Running Scans

### Basic Standalone Scan

Scan a repository using local scanner binaries:

```bash
./securelens scan repo https://github.com/org/repo --mode standalone
```

### Scan with Debug Output

Save detailed reports to the `reports/` directory:

```bash
./securelens scan repo https://github.com/org/repo --mode standalone --debug
```

### Scan Specific Branch or Commit

```bash
# Scan a specific branch
./securelens scan repo https://github.com/org/repo --branch develop --mode standalone

# Scan a specific commit
./securelens scan repo https://github.com/org/repo --commit abc123 --mode standalone
```

### Select Specific Scanners

```bash
# Run only OpenGrep (SAST)
./securelens scan repo https://github.com/org/repo --mode standalone --scanners opengrep

# Run OpenGrep and Trivy (skip secrets scanning)
./securelens scan repo https://github.com/org/repo --mode standalone --scanners opengrep,trivy
```

### Disable Parallel Execution

```bash
./securelens scan repo https://github.com/org/repo --mode standalone --parallel=false
```

## Interpreting Scan Results

### Summary Table

After a scan completes, you'll see a summary table:

```
=== SecureLens Scan Report ===

Repository: https://github.com/org/repo
Branch:     main
Commit:     abc123def456...
Timestamp:  2025-12-09T00:58:43Z
Status:     completed

┌────────────┬──────────┬───────────────────┬────────────────┐
│  SCANNER   │  STATUS  │     FINDINGS      │  BY SEVERITY   │
├────────────┼──────────┼───────────────────┼────────────────┤
│ opengrep   │ COMPLETE │ 183 findings      │ E:40 W:96 I:47 │
│ trivy      │ COMPLETE │ 0 vulnerabilities │ -              │
│ trufflehog │ COMPLETE │ 3 findings        │ -              │
└────────────┴──────────┴───────────────────┴────────────────┘
```

**Column Descriptions:**
- **SCANNER**: The security scanner that ran
- **STATUS**: `COMPLETE` (success), `ERROR` (failed), or `SKIPPED`
- **FINDINGS**: Total count of issues found
- **BY SEVERITY**: Breakdown using abbreviations:
  - `C` = Critical
  - `H` = High
  - `E` = Error
  - `M` = Medium
  - `W` = Warning
  - `L` = Low
  - `I` = Info

### Scanner Types

| Scanner | Type | Detects |
|---------|------|---------|
| **OpenGrep** | SAST | Code vulnerabilities, security anti-patterns, bugs |
| **Trivy** | SCA | Vulnerable dependencies, CVEs in packages |
| **Trufflehog** | Secrets | Hardcoded credentials, API keys, tokens |

## Viewing Saved Reports

When using `--debug`, reports are saved to `reports/{owner}/{repo}/{branch}/{commit}/`.

### List All Reports

```bash
./securelens scan results --list
```

Output:
```
=== Available Scan Reports ===

Reports directory: reports

Found 4 report(s):

  splunk/securelens [main @ 4b18c9f1]
    Path: reports/splunk/securelens/main/4b18c9f1/latest.json

  splunk/other-repo [develop @ 9725cf87]
    Path: reports/splunk/other-repo/develop/9725cf87/latest.json
```

### View a Report

```bash
# Table format (default)
./securelens scan results reports/splunk/repo/main/abc123/latest.json

# JSON format
./securelens scan results reports/splunk/repo/main/abc123/latest.json --format json

# YAML format
./securelens scan results reports/splunk/repo/main/abc123/latest.json --format yaml
```

### View Detailed Findings

```bash
# Show all findings with details
./securelens scan results reports/splunk/repo/main/abc123/latest.json --details

# Filter by specific scanner
./securelens scan results reports/splunk/repo/main/abc123/latest.json --details --scanner opengrep
```

Detailed output shows individual findings:

```
=== OPENGREP Findings ===

┌───┬──────────┬──────────────────────┬──────────────────┬──────┬─────────────────────────┐
│ # │ SEVERITY │         RULE         │       FILE       │ LINE │         MESSAGE         │
├───┼──────────┼──────────────────────┼──────────────────┼──────┼─────────────────────────┤
│ 1 │ ERROR    │ go.lang.security...  │ pkg/auth/jwt.go  │ 45   │ JWT token not validated │
│ 2 │ WARNING  │ go.lang.best-pra...  │ pkg/db/query.go  │ 123  │ SQL query concatenation │
└───┴──────────┴──────────────────────┴──────────────────┴──────┴─────────────────────────┘
```

## Report Directory Structure

```
reports/
└── {owner}/
    └── {repo}/
        └── {branch}/
            └── {commit-short}/
                ├── latest.json              # Most recent combined report
                ├── report-YYYYMMDD-HHMMSS.json
                ├── opengrep-latest.json     # Raw OpenGrep output
                ├── trivy-latest.json        # Raw Trivy output
                └── trufflehog-latest.json   # Raw Trufflehog output
```

## Configuration

SecureLens looks for `config.yaml` in the current directory or `~/.securelens/config.yaml`.

```yaml
# config.yaml
srs:
  base_url: "https://srs.example.com"  # Optional SRS API

scanners:
  opengrep:
    rules_path: "assets/opengrep-rules"
  trivy:
    severity: "CRITICAL,HIGH,MEDIUM"
  trufflehog:
    only_verified: false
```

## Command Reference

```bash
# Scan commands
securelens scan repo <url> [flags]     # Scan a repository
securelens scan results [path] [flags] # View saved reports

# Scan flags
--mode standalone    # Use local scanner binaries
--branch <name>      # Target branch
--commit <sha>       # Target commit
--scanners <list>    # Comma-separated scanner list
--parallel           # Run scanners in parallel (default: true)
--debug              # Save detailed reports to reports/
--format <type>      # Output format: table, json, yaml

# Results flags
--list               # List all saved reports
--details            # Show detailed findings
--scanner <name>     # Filter by scanner name
--format <type>      # Output format: table, json, yaml
```

## License

Apache 2.0 (ASL2)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

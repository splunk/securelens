# SecureLens: scan repo Command

The `scan repo` command scans a single repository for vulnerabilities using multiple security scanners.

## Usage

```bash
securelens scan repo [url] [flags]
```

## URL Formats

You can specify the repository in several ways:

| Format | Description |
|--------|-------------|
| `url` | Scan the default branch |
| `url:branch` | Scan a specific branch |
| `url:branch:commit` | Scan a specific commit |

**Examples:**
```bash
# Default branch
securelens scan repo https://github.com/myorg/myrepo

# Specific branch
securelens scan repo https://github.com/myorg/myrepo:develop

# Specific commit
securelens scan repo https://github.com/myorg/myrepo:main:abc123def
```

Alternatively, use explicit flags:
```bash
securelens scan repo --url https://github.com/myorg/myrepo --branch develop --commit abc123
```

## Scan Modes

SecureLens supports three scan modes:

### Local Mode (Default)
```bash
securelens scan repo https://github.com/myorg/myrepo --mode local
```
Clones the repository locally and runs built-in scanners. Uses scanner configurations from your config file.

### Remote Mode (SRS API)
```bash
securelens scan repo https://github.com/myorg/myrepo --mode remote --srs-url https://srs.example.com/api/v1/orchestrator/job_submit
```
Submits the repository to an SRS (Scan Report Service) API for scanning. Supports async mode and job polling.

### Standalone Mode
```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone
```
Uses locally installed scanner binaries (opengrep, trivy, trufflehog). Useful when you don't have access to an SRS API.

## Supported Scanners

### Remote/Local Mode
| Scanner | Type | Description |
|---------|------|-------------|
| `fossa` | OSS/SCA | Open source dependency vulnerabilities |
| `semgrep` | SAST | Static application security testing |
| `trufflehog` | Secrets | Secret/credential detection |

### Standalone Mode
| Scanner | Type | Description |
|---------|------|-------------|
| `opengrep` | SAST | Static application security testing (semgrep alternative) |
| `trivy` | OSS/SCA | Open source dependency vulnerabilities |
| `trufflehog` | Secrets | Secret/credential detection |

**Note:** FOSSA is not supported in standalone mode.

## Flags

### URL/Branch/Commit
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | | | Repository URL (alternative to positional argument) |
| `--branch` | `-b` | | Branch to scan (overrides URL-embedded branch) |
| `--commit` | | | Specific commit to scan (overrides URL-embedded commit) |

### Scanner Selection
| Flag | Default | Description |
|------|---------|-------------|
| `--scanners` | all | Scanners to run (fossa, semgrep, trufflehog for remote; opengrep, trivy, trufflehog for standalone) |

### Output
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | | Output file for raw results (e.g., results.json) |
| `--output-format` | `-f` | `table` | Output format: table, json, yaml |
| `--output-dir` | | `reports` | Directory for parsed report files |
| `--debug` | | `false` | Enable debug mode with raw report output to debug/ directory |

### Mode
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `local` | Scan mode: local, remote, or standalone |
| `--assets-dir` | `assets` | Directory containing scanner assets (e.g., opengrep rules) |

### SRS Flags (Remote Mode)
| Flag | Default | Description |
|------|---------|-------------|
| `--srs-url` | | SRS API endpoint URL |
| `--async` | `false` | Return immediately with job URL without waiting for results |
| `--wait-for` | | Job status URL(s) to wait on (skips scanning) |
| `--poll-interval` | `10` | Seconds between status polls when waiting |
| `--max-wait` | `30` | Maximum minutes to wait for results |

### Config
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | | Path to configuration file |
| `--dry-run` | | `false` | Show what would be done without executing |
| `--verbose` | `-v` | `false` | Enable verbose output |

## Examples

### Basic Scanning
```bash
# Scan with all default scanners
securelens scan repo https://github.com/myorg/myrepo

# Scan specific branch
securelens scan repo https://github.com/myorg/myrepo:develop

# Run only specific scanners
securelens scan repo https://github.com/myorg/myrepo --scanners semgrep --scanners trufflehog
```

### Standalone Mode
```bash
# Use local scanner binaries
securelens scan repo https://github.com/myorg/myrepo --mode standalone

# Specify scanners in standalone mode
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners opengrep --scanners trivy

# Enable debug output for troubleshooting
securelens scan repo https://github.com/myorg/myrepo --mode standalone --debug
```

### Remote Mode (SRS)
```bash
# Submit to SRS API
securelens scan repo https://github.com/myorg/myrepo --mode remote --srs-url https://srs.example.com/api/v1/orchestrator/job_submit

# Async mode - return immediately with job URL
securelens scan repo https://github.com/myorg/myrepo --mode remote --srs-url https://srs.example.com/api/v1/orchestrator/job_submit --async

# Wait for existing job
securelens scan repo --wait-for https://srs.example.com/api/v1/job_status/abc123
```

### Output Options
```bash
# JSON output to stdout
securelens scan repo https://github.com/myorg/myrepo --output-format json

# Save results to file
securelens scan repo https://github.com/myorg/myrepo --output results.json

# YAML output
securelens scan repo https://github.com/myorg/myrepo --output-format yaml --output results.yaml
```

## Installing Standalone Tools

If you're using standalone mode, you need to install the scanner binaries:

```bash
# Install all standalone tools
make install_scan_tools_standalone

# Or install individually
make install_opengrep
make install_opengrep_rules
make install_trivy
make install_trufflehog

# Check tool status
make check_tools
```

When you run standalone mode without the tools installed, SecureLens will display installation instructions.

## Debug Mode

Enable debug mode to get raw scanner outputs for troubleshooting:

```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone --debug
```

This writes detailed outputs to the `reports/debug/` directory:
- `report-{timestamp}.json` - Full scan report
- `{scanner}-raw-{timestamp}.json` - Raw output from each scanner

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Scanner not installed (standalone mode) |

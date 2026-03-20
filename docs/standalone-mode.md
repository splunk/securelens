# SecureLens: Standalone Mode

Standalone mode allows you to run security scans using locally installed scanner binaries, without requiring access to an SRS (Scan Report Service) API.

## Overview

In standalone mode, SecureLens orchestrates three open-source security scanners:

| Scanner | Type | Purpose |
|---------|------|---------|
| **opengrep** | SAST | Static Application Security Testing - finds code vulnerabilities |
| **trivy** | OSS/SCA | Dependency vulnerability scanning |
| **trufflehog** | Secrets | Credential and secret detection |

## Requirements

Before using standalone mode, you must install the scanner binaries.

### Quick Install (All Tools)

```bash
make install_scan_tools_standalone
```

### Individual Installation

```bash
# Install opengrep (SAST scanner)
make install_opengrep

# Download opengrep rules (required for scanning)
make install_opengrep_rules

# Install trufflehog (secrets scanner)
make install_trufflehog
```

### Check Installation Status

```bash
make check_tools
```

Example output:
```
Checking standalone tools...

  opengrep:    ✓ installed (opengrep 1.6.0)
  trufflehog:  ✓ installed (trufflehog 3.63.0)

  opengrep-rules: ✓ installed (assets/opengrep-rules)
```

## Usage

### Basic Usage

```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone
```

### Specify Scanners

```bash
# Run only SAST scan
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners opengrep

# Run SAST and secrets scanning
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners opengrep --scanners trufflehog

# Run only dependency scanning
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners trivy
```

### Scanner Name Mapping

For convenience, `semgrep` is automatically mapped to `opengrep` in standalone mode:

```bash
# These are equivalent in standalone mode
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners semgrep
securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners opengrep
```

### Debug Mode

For troubleshooting, enable debug mode to capture raw scanner outputs:

```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone --debug
```

Debug files are written to `reports/debug/`:
- `report-{timestamp}.json` - Full scan report
- `opengrep-raw-{timestamp}.json` - Raw opengrep output
- `trivy-raw-{timestamp}.json` - Raw trivy output
- `trufflehog-raw-{timestamp}.json` - Raw trufflehog output

### Custom Assets Directory

By default, opengrep rules are expected in `./assets/opengrep-rules/`. You can specify a custom location:

```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone --assets-dir /path/to/assets
```

## Output Format

Standalone mode outputs results in the same format as remote (SRS) mode for consistency:

```json
{
  "repository": "https://github.com/myorg/myrepo",
  "branch": "main",
  "commit": "abc123def",
  "timestamp": "2024-01-15T10:30:00Z",
  "status": "completed",
  "scanners": ["opengrep", "trivy", "trufflehog"],
  "results": {
    "opengrep": {
      "status": "COMPLETE",
      "findings_count": 5,
      "files_scanned": 150,
      "by_severity": {
        "ERROR": 2,
        "WARNING": 3
      }
    },
    "trivy": {
      "status": "COMPLETE",
      "vulnerabilities_count": 12,
      "by_severity": {
        "CRITICAL": 1,
        "HIGH": 3,
        "MEDIUM": 5,
        "LOW": 3
      }
    },
    "trufflehog": {
      "status": "COMPLETE",
      "findings_count": 2,
      "verified_secrets": 0,
      "unverified_secrets": 2
    }
  }
}
```

## Scanner Details

### opengrep (SAST)

opengrep is an open-source fork of Semgrep used for static analysis security testing.

**What it finds:**
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Insecure cryptography
- Security misconfigurations
- And many more code-level vulnerabilities

**Rules location:** `assets/opengrep-rules/`

### trivy (OSS/SCA)

Trivy is a comprehensive vulnerability scanner for dependencies and configurations.

**What it finds:**
- Known vulnerabilities (CVEs) in dependencies
- License compliance issues
- Misconfigurations
- Secrets (optionally)

### trufflehog (Secrets)

TruffleHog detects secrets and credentials in code.

**What it finds:**
- API keys
- OAuth tokens
- Private keys
- Database credentials
- Cloud provider credentials
- And many other credential types

**Verification:** TruffleHog can verify if discovered secrets are still active.

## Differences from Remote Mode

| Feature | Standalone Mode | Remote Mode |
|---------|-----------------|-------------|
| Scanner binaries | Required locally | Not required |
| Network access | Only for git clone | Required for SRS API |
| FOSSA support | Not available | Available |
| Processing | Local CPU | Remote server |
| Async operation | Not applicable | Supported |

## Troubleshooting

### Tools Not Found

If SecureLens reports tools are not found:

1. Check if tools are in your PATH:
   ```bash
   which opengrep trivy trufflehog
   ```

2. Run the installation:
   ```bash
   make install_scan_tools_standalone
   ```

3. If using a custom INSTALL_DIR:
   ```bash
   INSTALL_DIR=/custom/path make install_scan_tools_standalone
   export PATH=/custom/path:$PATH
   ```

### opengrep Rules Not Found

If opengrep rules are missing:

```bash
make install_opengrep_rules

# Or with custom assets directory
ASSETS_DIR=/custom/path make install_opengrep_rules
```

### Scanner Fails with Error

Enable debug mode to see raw scanner output:

```bash
securelens scan repo https://github.com/myorg/myrepo --mode standalone --debug
```

Check the files in `reports/debug/` for detailed error messages.

### Different Results Than Expected

Scanner outputs may differ from SRS results due to:
- Different scanner versions
- Different rule versions
- Different configuration options

Use `--debug` to capture raw outputs and compare with expected results.

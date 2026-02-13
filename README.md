# SecureLens

A CLI-based vulnerability scanning tool that aggregates results from multiple security scanners (SAST, secrets, and dependency scanning) into unified reports.

## Features

- **SRS Integration**: Offload scanning to SRS (Scan Request Service) API for managed scanning infrastructure
- **Standalone Mode**: Run scans locally without external API dependencies
- **Multi-Scanner Support**: Semgrep/OpenGrep (SAST), FOSSA/Trivy (dependencies), and Trufflehog (secrets)
- **Parallel Execution**: Scanners run concurrently for faster results
- **Organized Reports**: Results saved in `reports/{owner}/{repo}/{branch}/{commit}/` structure
- **Multiple Output Formats**: Table, JSON, and YAML output support

## Quick Start

### 1. Build SecureLens

```bash
git clone https://github.com/splunk/securelens.git
cd securelens
make config
```

The Makefile target will build the `securelens` binary and initialize the configuration file.

### 2. Run a Scan

#### Option A: Remote Mode (Recommended) - Using SRS API

The recommended approach is to use SRS (Scan Request Service) which handles scanning infrastructure:

```bash
# Set your SRS API endpoint
export SRS_ORCHESTRATOR_API_ENDPOINT="https://your-srs-instance.example.com"

# Run scan via SRS
./securelens scan repo https://github.com/org/repo --mode remote --srs-url ${SRS_ORCHESTRATOR_API_ENDPOINT}
```

SRS will:
1. Receive the repository zip
2. Run Semgrep (SAST), FOSSA (dependencies), and Trufflehog (secrets)
3. Return aggregated results

#### Option B: Standalone Mode - Local Scanner Binaries

For local scanning without SRS, install scanner binaries:

```bash
# Install all scanners to ~/.local/bin
make install_scan_tools_standalone INSTALL_DIR=~/.local/bin

# Ensure ~/.local/bin is in your PATH
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
opengrep --version && trivy --version && trufflehog --version

# Run standalone scan
./securelens scan repo https://github.com/org/repo --mode standalone
```

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Remote** | `--mode remote` | Send repo to SRS API (Semgrep, FOSSA, Trufflehog) |
| **Standalone** | `--mode standalone` | Run local binaries (OpenGrep, Trivy, Trufflehog) |
| **Local** | `--mode local` | Run configured local scanners (requires config) |

## Running Scans

### Remote Scan (via SRS)

```bash
./securelens scan repo https://github.com/org/repo --mode remote --srs-url ${SRS_ORCHESTRATOR_API_ENDPOINT}
```

### Standalone Scan (local binaries)

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

## Splunk Integration

SecureLens can send scan results to Splunk via HEC (HTTP Event Collector). Each finding/vulnerability/secret is sent as a separate event.

### Run Splunk Locally (Docker)

Pull the Splunk image:

```bash
docker pull splunk/splunk:latest
```

On macOS (Apple Silicon), use the Linux AMD64 image:

```bash
docker pull --platform linux/amd64 splunk/splunk:latest
```

Start Splunk Enterprise:

```bash
docker run -d --name splunk \
  -p 8000:8000 -p 8088:8088 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
  -e SPLUNK_PASSWORD='your_secure_password' \
  splunk/splunk:latest start
```

On macOS (Apple Silicon):

```bash
docker run -d --name splunk --platform linux/amd64 \
  -p 8000:8000 -p 8088:8088 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
  -e SPLUNK_PASSWORD='your_secure_password' \
  splunk/splunk:latest start
```

Open the UI at http://localhost:8000 and sign in as `admin` with the password you set.

Optional: switch to the free license (after the trial ends, this happens automatically). Go to Settings -> Licensing -> Change License Group -> Free License.

### Enable HEC and Create a Token

1. Settings -> Data Inputs -> HTTP Event Collector -> Global Settings -> Enable -> Save.
2. Click New Token, choose a name, then set the sourcetype to `_json` and select the index you want (for example, `main`).
3. Copy the generated token.

### Configure SecureLens

Add this to your config file (for local Splunk):

```yaml
splunk:
  enabled: true
  hec_endpoint: "http://localhost:8088/services/collector"
  hec_token: "your-hec-token"
```

Run a standalone scan to send events:

```bash
./securelens scan repo https://github.com/org/repo --mode standalone
```

### Splunk Searches (Table Views)

Use these searches to build tables for each scanner. Replace `index` with your value.

OpenGrep (one event per finding):

```spl
index=main sourcetype=_json scanner=opengrep
| spath
| spath path=results.findings{} output=finding
| spath input=finding path=check_id output=rule_id
| spath input=finding path=path output=file
| spath input=finding path=start.line output=line
| spath input=finding path=extra.severity output=severity
| spath input=finding path=extra.message output=message
| table _time repository scanner severity rule_id file line message
| appendpipe [
  stats count
  | where count=0
  | eval _time=now(), repository="-", scanner="opengrep", severity="-", rule_id="No findings", file="-", line="-", message="-"
  | table _time repository scanner severity rule_id file line message
]
```

Trivy (one event per vulnerability):

```spl
index=main sourcetype=_json scanner=trivy
| spath
| spath path=results.results{} output=entry
| spath input=entry path=Target output=target
| spath input=entry path=Vulnerabilities{} output=vuln
| spath input=vuln path=VulnerabilityID output=cve
| spath input=vuln path=PkgName output=package
| spath input=vuln path=InstalledVersion output=installed
| spath input=vuln path=FixedVersion output=fixed
| spath input=vuln path=Severity output=severity
| spath input=vuln path=Title output=title
| table _time repository scanner severity cve package installed fixed target title
| appendpipe [
  stats count
  | where count=0
  | eval _time=now(), repository="-", scanner="trivy", severity="-", cve="No findings", package="-", installed="-", fixed="-", target="-", title="-"
  | table _time repository scanner severity cve package installed fixed target title
]
```

Trufflehog (one event per secret):

```spl
index=main sourcetype=_json scanner=trufflehog
| spath
| spath path=results.findings{} output=finding
| spath input=finding path=DetectorName output=detector
| spath input=finding path=Verified output=verified
| spath input=finding path=Redacted output=redacted
| spath input=finding path=SourceMetadata.Data.Git.file output=file_git
| spath input=finding path=SourceMetadata.Data.Git.line output=line_git
| spath input=finding path=SourceMetadata.Data.Filesystem.file output=file_fs
| spath input=finding path=SourceMetadata.Data.Filesystem.line output=line_fs
| eval file=coalesce(file_git, file_fs), line=coalesce(line_git, line_fs)
| where detector!=""
| table _time repository scanner verified detector file line redacted
| appendpipe [
  stats count
  | where count=0
  | eval _time=now(), repository="-", scanner="trufflehog", verified="-", detector="No findings", file="-", line="-", redacted="-"
  | table _time repository scanner verified detector file line redacted
]
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

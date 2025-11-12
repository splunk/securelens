# Scanning Modes

SecureLens supports three scanning modes: single repository, bulk, and discovery.

## Single Repository Scan

Scan a single repository with optional branch and commit specification.

### Basic Usage

```bash
# Scan default branch
securelens scan repo https://github.com/myorg/myrepo

# Scan specific branch
securelens scan repo https://github.com/myorg/myrepo:develop

# Scan specific commit
securelens scan repo https://github.com/myorg/myrepo:main:abc123def
```

### URL Formats

- `url` - Scan default branch (usually `main`)
- `url:branch` - Scan specific branch
- `url:branch:commit` - Scan specific commit

### Supported Providers

- GitHub
- GitLab
- Bitbucket
- Splunk GitLab (cd.splunkdev.com)

## Bulk Scanning

Scan multiple repositories from a YAML or JSON file.

### Input File Format (YAML)

```yaml
repositories:
  - url: https://github.com/org/repo1
    branches: [main, develop]
  - url: https://github.com/org/repo2:feature-branch
  - url: https://gitlab.com/org/repo3:main:abc123def
```

### Usage

```bash
# Scan with default parallelism (5 workers)
securelens scan bulk repos.yaml

# Scan with custom parallelism
securelens scan bulk repos.yaml --parallel 10
```

## Discovery Scanning

Discover and scan repositories based on API scope or specific criteria.

### Scope Discovery

Scan all repositories accessible with provided credentials:

```bash
securelens scan discover scope
```

This will:
1. Use configured Git provider credentials
2. Enumerate all accessible repositories
3. Apply configured filters
4. Scan discovered repositories

### Configuration

Control discovery behavior in `~/.securelens/config.yaml`:

```yaml
discovery:
  max_repos_per_scan: 100
  filters:
    min_stars: 0
    languages: []
    exclude_archived: true
```

## Scanner Selection

### SRS API Mode

When SRS API is configured and available:

```yaml
srs:
  enabled: true
  api_url: https://srs.example.com
  api_key: ${SRS_API_KEY}
```

SecureLens submits scan requests to SRS and retrieves results.

### Local CLI Mode

When SRS is unavailable, SecureLens falls back to local scanner installations:

- Semgrep CLI
- FOSSA CLI
- Trufflehog CLI

Ensure scanners are installed and available in PATH.

## Output and Results

### Query Scanned Vulnerabilities

```bash
# All vulnerabilities
securelens query vulns

# Filter by severity
securelens query vulns --severity critical,high

# Filter by repository
securelens query vulns --repo myorg/myrepo

# Export to JSON
securelens query vulns --format json > vulnerabilities.json
```

### Output Formats

- `table` - Human-readable table (default)
- `json` - JSON format
- `csv` - CSV format
- `sarif` - SARIF format (for CI/CD integration)

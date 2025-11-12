# Configuration Guide

SecureLens uses a YAML configuration file located at `~/.securelens/config.yaml`.

## Configuration File Structure

```yaml
# Database configuration
database:
  host: localhost
  port: 3306
  name: securelens
  username: ${DB_USER}
  password: ${DB_PASSWORD}
  max_connections: 10

# Git provider credentials
git:
  gitlab:
    token: ${GITLAB_TOKEN}
    api_url: https://gitlab.com
  github:
    token: ${GITHUB_TOKEN}
    api_url: https://api.github.com
  bitbucket:
    username: ${BITBUCKET_USERNAME}
    app_password: ${BITBUCKET_APP_PASSWORD}
    api_url: https://api.bitbucket.org

# SRS API configuration (optional)
srs:
  enabled: false
  api_url: https://srs.example.com
  api_key: ${SRS_API_KEY}
  timeout: 600

# Local scanner configuration
scanners:
  semgrep:
    enabled: true
    config: auto
    timeout: 300
    custom_rules: []
  fossa:
    enabled: true
    api_key: ${FOSSA_API_KEY}
    timeout: 600
  trufflehog:
    enabled: true
    timeout: 300
    verify: true

# Scanning behavior
scanning:
  parallel_workers: 5
  clone_depth: 1
  cleanup_on_error: true
  max_repo_size_mb: 1000

# Output preferences
output:
  format: table  # table, json, yaml
  verbosity: info  # debug, info, warn, error
  save_reports: true
  reports_dir: ~/.securelens/reports

# Discovery settings
discovery:
  max_repos_per_scan: 100
  filters:
    min_stars: 0
    languages: []
    exclude_archived: true
```

## Environment Variables

Configuration values can reference environment variables using `${VAR_NAME}` syntax.

Required variables:
```bash
export DB_USER="securelens"
export DB_PASSWORD="your_password"
```

Git provider tokens (at least one required):
```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxx"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
export BITBUCKET_USERNAME="username"
export BITBUCKET_APP_PASSWORD="xxxxxxxxxxxx"
```

Optional:
```bash
export SRS_API_KEY="srs_xxxxxxxxxxxx"
export SEMGREP_APP_TOKEN="xxxxx"
export FOSSA_API_KEY="xxxxx"
```

## Configuration Priority

1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## Managing Configuration

Initialize configuration:
```bash
securelens config init
```

Validate configuration:
```bash
securelens config validate
```

Set individual values:
```bash
securelens config set database.host localhost
securelens config set scanning.parallel_workers 10
```

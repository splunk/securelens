# SecureLens: scan discover Command

The `scan discover` command discovers repositories across configured git providers (GitHub, GitLab, Bitbucket).

## Usage

```bash
securelens scan discover scope [flags]
```

## Description

The discover command scans all repositories accessible with your configured credentials. This is useful for:
- Auditing your organization's repository inventory
- Identifying repositories for security scanning
- Generating repository lists for bulk scanning

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | | Path to configuration file |
| `--format` | `-f` | `table` | Output format: table, json, yaml |
| `--output` | `-o` | | Output file (default: stdout) |
| `--count-only` | | `false` | Only display the count of discovered repositories |
| `--repo` | | | Check if a specific repository is accessible (format: owner/repo) |
| `--provider` | | | Provider for the repo (github, gitlab, bitbucket) when using --repo |
| `--limit` | | `0` | Limit the number of repositories to scan (0 for no limit) |
| `--include-branches` | | `false` | Include all accessible branches for each repository |

## Configuration

The discover command requires credentials configured in your config file (`~/.securelens/config.yaml` or specified with `--config`).

### Example Configuration

```yaml
git:
  gitlab:
    - name: gitlab-main
      api_url: https://gitlab.com/api/v4
      token: glpat-xxxxxxxxxxxx

  github:
    - name: github-org
      api_url: https://api.github.com
      token: ghp_xxxxxxxxxxxx
      organizations:
        - myorg
        - anotherorg

  bitbucket:
    - name: bitbucket-workspace
      api_url: https://api.bitbucket.org/2.0
      workspace: myworkspace
      username: myuser
      app_password: xxxxxxxxxxxx
```

## Examples

### Discover All Repositories

```bash
# Discover repositories from all configured providers
securelens scan discover scope --config ~/.securelens/config.yaml

# Get count only
securelens scan discover scope --count-only
```

### Output Formats

```bash
# Table format (default)
securelens scan discover scope

# JSON format
securelens scan discover scope --format json

# YAML format
securelens scan discover scope --format yaml

# Save to file
securelens scan discover scope --format json --output repos.json
```

### Limit Results

```bash
# Discover first 100 repositories
securelens scan discover scope --limit 100
```

### Include Branch Information

```bash
# Include branches for each repository
securelens scan discover scope --include-branches
```

### Check Specific Repository Access

```bash
# Check if a specific repo is accessible
securelens scan discover scope --repo myorg/myrepo --provider github
securelens scan discover scope --repo group/project --provider gitlab
securelens scan discover scope --repo workspace/repo --provider bitbucket
```

## Output

### Table Format

```
+----------+--------+------------------+--------------------------------+---------+----------+--------+
| PROVIDER | NAME   | FULL NAME        | URL                            | PRIVATE | LANGUAGE | SOURCE |
+----------+--------+------------------+--------------------------------+---------+----------+--------+
| github   | myrepo | myorg/myrepo     | https://github.com/myorg/myrepo| Yes     | Go       | github |
| gitlab   | proj   | group/proj       | https://gitlab.com/group/proj  | Yes     |          | gitlab |
+----------+--------+------------------+--------------------------------+---------+----------+--------+
```

### JSON Format

```json
[
  {
    "provider": "github",
    "name": "myrepo",
    "full_name": "myorg/myrepo",
    "url": "https://github.com/myorg/myrepo.git",
    "is_private": true,
    "language": "Go",
    "source": "github-org",
    "branches": ["main", "develop"]
  }
]
```

## Provider-Specific Notes

### GitHub

- Uses GitHub's REST API
- Can scan organizations specified in config
- Respects API rate limits

### GitLab

- Uses GitLab API v4
- Discovers projects accessible with the token
- Works with self-hosted GitLab instances

### Bitbucket

- Uses Bitbucket Cloud API v2
- Requires workspace configuration
- Uses app password for authentication

## Integration with scan repo

The output from `scan discover` can be used to create bulk scan lists:

```bash
# Discover repos and save as JSON
securelens scan discover scope --format json --output repos.json

# Use the output for bulk scanning
securelens scan bulk repos.json
```

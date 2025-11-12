# Quick Start Guide

This guide will help you get started with SecureLens Open Source.

## Prerequisites

- Go 1.21 or later
- MySQL 8.0 or later
- Git
- (Optional) Semgrep, FOSSA, and Trufflehog CLI tools

## Installation

### From Source

```bash
git clone https://github.com/splunk/securelens.git
cd securelens-open-source
go build -o securelens main.go
```

## Initial Setup

### 1. Initialize Configuration

```bash
./securelens config init
```

This creates `~/.securelens/config.yaml` with default values.

### 2. Configure Database

Edit `~/.securelens/config.yaml`:

```yaml
database:
  host: localhost
  port: 3306
  name: securelens
  username: ${DB_USER}
  password: ${DB_PASSWORD}
```

Set environment variables:

```bash
export DB_USER="securelens"
export DB_PASSWORD="your_password"
```

### 3. Configure Git Providers

Add credentials for at least one Git provider:

```bash
# GitLab
export GITLAB_TOKEN="glpat-xxxxxxxxxxxx"

# GitHub
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# Bitbucket
export BITBUCKET_USERNAME="username"
export BITBUCKET_APP_PASSWORD="xxxxxxxxxxxx"
```

### 4. Validate Configuration

```bash
./securelens config validate
```

## First Scan

### Scan a Single Repository

```bash
./securelens scan repo https://github.com/myorg/myrepo
```

### Query Results

```bash
./securelens query vulns
```

## Next Steps

- [Configuration Guide](configuration.md) - Detailed configuration options
- [Scanning Modes](scanning-modes.md) - Learn about bulk and discovery scanning

# SecureLens Open Source

A CLI-based vulnerability management framework designed to democratize enterprise-grade security scanning for the open source community.

## Overview

SecureLens Open Source provides a streamlined, organization-agnostic tool for aggregating, deduplicating, and tracking security vulnerabilities across multiple repositories and scanning tools.

## Features

- **Multi-Scanner Support**: Integrates with Semgrep (SAST), FOSSA (OSS), and Trufflehog (Secrets)
- **Intelligent Deduplication**: Advanced primary key generation prevents duplicate vulnerability reports
- **Flexible Scanning**: Single repository, bulk, or discovery-based scanning modes
- **Ownership Attribution**: Built-in support for mapping repositories to teams and individuals
- **SRS Integration**: Optional integration with SRS Open Source API
- **Local CLI Fallback**: Works with local scanner installations when SRS is unavailable

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/splunk/securelens.git
cd securelens-open-source

# Build the binary
go build -o securelens main.go

# Install (optional)
go install
```

### Configuration

```bash
# Initialize configuration
./securelens config init

# Edit configuration file
vim ~/.securelens/config.yaml

# Validate configuration
./securelens config validate
```

### Basic Usage

```bash
# Scan a single repository
./securelens scan repo https://github.com/myorg/myrepo

# Scan specific branch
./securelens scan repo https://github.com/myorg/myrepo:develop

# Query vulnerabilities
./securelens query vulns --severity critical,high

# Bulk scan from file
./securelens scan bulk repos.yaml --parallel 5
```

## Project Structure

```
securelens-open-source/
├── cmd/            # CLI entry point
├── cli/            # Command implementations
├── pkg/            # Core packages
├── internal/       # Internal utilities
├── lib/            # Git provider clients
├── mysql/          # Database migrations
└── docs/           # Documentation
```

## Documentation

- [Configuration Guide](docs/configuration.md)
- [Scanning Modes](docs/scanning-modes.md)
- [Quick Start](docs/quickstart.md)

## License

Apache 2.0 (ASL2)

## Contributing

This is a Splunk-authored open source project. Contributions are welcome!

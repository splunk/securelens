# SecureLens Makefile
# Standalone scanner installation and management

.PHONY: all build install clean test
.PHONY: install_scan_tools_standalone install_opengrep install_trivy install_trufflehog install_opengrep_rules
.PHONY: check_tools help

# Build settings
BINARY_NAME=securelens
GO=go
GOFLAGS=-v

# Installation paths
INSTALL_DIR ?= /usr/local/bin
ASSETS_DIR ?= $(shell pwd)/assets

# Tool versions
OPENGREP_VERSION ?= v1.6.0
TRIVY_VERSION ?= latest

# Detect architecture
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_M),x86_64)
    OPENGREP_ARCH := x86
    TRIVY_ARCH := 64bit
else ifeq ($(UNAME_M),aarch64)
    OPENGREP_ARCH := aarch64
    TRIVY_ARCH := ARM64
else ifeq ($(UNAME_M),arm64)
    OPENGREP_ARCH := arm64
    TRIVY_ARCH := ARM64
else
    OPENGREP_ARCH := $(UNAME_M)
    TRIVY_ARCH := 64bit
endif

ifeq ($(UNAME_S),Darwin)
    TRIVY_OS := macOS
    OPENGREP_OS := osx
else
    TRIVY_OS := Linux
    # For Linux, opengrep uses musllinux or manylinux
    OPENGREP_OS := musllinux
endif

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

all: build

build:
	@echo "$(GREEN)Building SecureLens...$(NC)"
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

install: build
	@echo "$(GREEN)Installing SecureLens to $(INSTALL_DIR)...$(NC)"
	cp $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -f $(BINARY_NAME)
	rm -rf assets/opengrep-rules

test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(GO) test -v ./...

# ============================================================================
# Standalone Scanner Tools Installation
# ============================================================================

help:
	@echo "SecureLens Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  make build                        - Build SecureLens binary"
	@echo "  make install                      - Install SecureLens to $(INSTALL_DIR)"
	@echo "  make test                         - Run tests"
	@echo "  make clean                        - Clean build artifacts"
	@echo ""
	@echo "Standalone scanner installation:"
	@echo "  make install_scan_tools_standalone - Install all standalone scanning tools"
	@echo "  make install_opengrep             - Install opengrep (SAST)"
	@echo "  make install_opengrep_rules       - Download opengrep rules"
	@echo "  make install_trivy                - Install trivy (OSS/SCA)"
	@echo "  make install_trufflehog           - Install trufflehog (secrets)"
	@echo "  make check_tools                  - Check if all tools are installed"
	@echo ""
	@echo "Environment variables:"
	@echo "  INSTALL_DIR                       - Installation directory (default: /usr/local/bin)"
	@echo "  ASSETS_DIR                        - Assets directory (default: ./assets)"
	@echo "  OPENGREP_VERSION                  - Opengrep version (default: v1.6.0)"

# Install all standalone tools
install_scan_tools_standalone: install_opengrep install_opengrep_rules install_trivy install_trufflehog
	@echo "$(GREEN)All standalone scanning tools installed successfully!$(NC)"
	@echo ""
	@make check_tools

# Install opengrep (SAST scanner - semgrep alternative)
install_opengrep:
	@echo "$(GREEN)Installing opengrep $(OPENGREP_VERSION) for $(OPENGREP_OS)/$(OPENGREP_ARCH)...$(NC)"
	@curl -fL "https://github.com/opengrep/opengrep/releases/download/$(OPENGREP_VERSION)/opengrep_$(OPENGREP_OS)_$(OPENGREP_ARCH)" -o $(INSTALL_DIR)/opengrep
	@chmod +x $(INSTALL_DIR)/opengrep
	@echo "$(GREEN)opengrep installed to $(INSTALL_DIR)/opengrep$(NC)"

# Download opengrep rules
install_opengrep_rules:
	@echo "$(GREEN)Downloading opengrep rules to $(ASSETS_DIR)/opengrep-rules...$(NC)"
	@mkdir -p $(ASSETS_DIR)
	@if [ -d "$(ASSETS_DIR)/opengrep-rules" ]; then \
		echo "$(YELLOW)Rules directory already exists, removing...$(NC)"; \
		rm -rf "$(ASSETS_DIR)/opengrep-rules"; \
	fi
	@cd $(ASSETS_DIR) && \
		git clone --depth 1 https://github.com/opengrep/opengrep-rules ./opengrep-rules && \
		rm -rf opengrep-rules/.git opengrep-rules/.github opengrep-rules/.pre-commit-config.yaml && \
		rm -rf opengrep-rules/elixir opengrep-rules/apex opengrep-rules/stats 2>/dev/null || true
	@echo "$(GREEN)opengrep rules installed to $(ASSETS_DIR)/opengrep-rules$(NC)"

# Install trivy (OSS/SCA vulnerability scanner)
install_trivy:
	@echo "$(GREEN)Installing trivy for $(TRIVY_OS)/$(TRIVY_ARCH)...$(NC)"
	@curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $(INSTALL_DIR)
	@echo "$(GREEN)trivy installed to $(INSTALL_DIR)/trivy$(NC)"

# Install trufflehog (secrets scanner)
install_trufflehog:
	@echo "$(GREEN)Installing trufflehog...$(NC)"
	@curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b $(INSTALL_DIR)
	@echo "$(GREEN)trufflehog installed to $(INSTALL_DIR)/trufflehog$(NC)"

# Check if all tools are installed
check_tools:
	@echo "$(GREEN)Checking standalone tools...$(NC)"
	@echo ""
	@printf "  opengrep:    "
	@if command -v opengrep >/dev/null 2>&1; then \
		echo "$(GREEN)✓ installed$(NC) ($$(opengrep --version 2>/dev/null | head -1 || echo 'version unknown'))"; \
	else \
		echo "$(RED)✗ not found$(NC) (run: make install_opengrep)"; \
	fi
	@printf "  trivy:       "
	@if command -v trivy >/dev/null 2>&1; then \
		echo "$(GREEN)✓ installed$(NC) ($$(trivy --version 2>/dev/null | head -1 || echo 'version unknown'))"; \
	else \
		echo "$(RED)✗ not found$(NC) (run: make install_trivy)"; \
	fi
	@printf "  trufflehog:  "
	@if command -v trufflehog >/dev/null 2>&1; then \
		echo "$(GREEN)✓ installed$(NC) ($$(trufflehog --version 2>/dev/null | head -1 || echo 'version unknown'))"; \
	else \
		echo "$(RED)✗ not found$(NC) (run: make install_trufflehog)"; \
	fi
	@echo ""
	@printf "  opengrep-rules: "
	@if [ -d "$(ASSETS_DIR)/opengrep-rules" ]; then \
		echo "$(GREEN)✓ installed$(NC) ($(ASSETS_DIR)/opengrep-rules)"; \
	else \
		echo "$(RED)✗ not found$(NC) (run: make install_opengrep_rules)"; \
	fi
	@echo ""

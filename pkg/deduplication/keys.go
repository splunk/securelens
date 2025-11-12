package deduplication

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/splunk/securelens/pkg/scanner"
)

// GeneratePrimaryKey generates a unique primary key for a vulnerability
// based on its scanner type and attributes
func GeneratePrimaryKey(vuln scanner.Vulnerability) string {
	var key string

	switch vuln.Component {
	case "SAST":
		// SAST Key Format: {check_id}:{repo_postfix}:{branch}
		key = generateSASTKey(vuln)
	case "OSS":
		// OSS Key Format: {package_name}:{package_version}:{repo_postfix}:{branch}
		key = generateOSSKey(vuln)
	case "Secrets":
		// Secrets Key Format: {gitlab_id}::{branch}::{credential_hash}::{location_hash}
		key = generateSecretsKey(vuln)
	default:
		slog.Warn("Unknown component type, using fallback key generation", "component", vuln.Component)
		key = generateFallbackKey(vuln)
	}

	slog.Debug("Generated primary key", "component", vuln.Component, "key", key)

	return key
}

// generateSASTKey generates a primary key for SAST (Semgrep) findings
// Format: {check_id}:{repo_postfix}:{branch}
func generateSASTKey(vuln scanner.Vulnerability) string {
	// TODO: Extract check_id from vuln.RawData or vuln.TicketName
	// For now, using TicketName as placeholder
	checkID := vuln.TicketName

	return fmt.Sprintf("%s:%s:%s", checkID, vuln.Postfix, vuln.Branch)
}

// generateOSSKey generates a primary key for OSS (FOSSA) findings
// Format: {package_name}:{package_version}:{repo_postfix}:{branch}
func generateOSSKey(vuln scanner.Vulnerability) string {
	// TODO: Extract package_name and package_version from vuln.RawData
	// For now, using placeholder values
	packageName := vuln.TicketName
	packageVersion := vuln.AffectsVersion

	return fmt.Sprintf("%s:%s:%s:%s", packageName, packageVersion, vuln.Postfix, vuln.Branch)
}

// generateSecretsKey generates a primary key for Secrets (Trufflehog) findings
// Format: {gitlab_id}::{branch}::{credential_hash}::{location_hash}
func generateSecretsKey(vuln scanner.Vulnerability) string {
	// TODO: Extract gitlab_id from repository metadata
	// For non-GitLab repos, use "0"
	gitlabID := "0"

	// Hash the credential (if available in RawData)
	credentialHash := hashString("credential_placeholder")

	// Hash the file path
	locationHash := hashString(vuln.OriginPath)

	return fmt.Sprintf("%s::%s::%s::%s", gitlabID, vuln.Branch, credentialHash, locationHash)
}

// generateFallbackKey generates a fallback key when component type is unknown
func generateFallbackKey(vuln scanner.Vulnerability) string {
	// Use a combination of available fields
	combined := fmt.Sprintf("%s:%s:%s:%s", vuln.TicketName, vuln.Postfix, vuln.Branch, vuln.OriginPath)
	return hashString(combined)
}

// hashString returns SHA256 hash of a string (truncated to first 16 chars for readability)
func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	if len(hash) > 16 {
		return hash[:16]
	}
	return hash
}

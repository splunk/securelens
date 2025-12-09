package trufflehog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/splunk/securelens/pkg/srs"
)

// Scanner implements a standalone Trufflehog scanner
type Scanner struct {
	binaryPath string
}

// Secret represents a single secret finding
type Secret struct {
	DetectorName string
	File         string
	Line         int64
	Verified     bool
	Redacted     string
	Raw          string
	Commit       string
	Timestamp    string
	Email        string
	Repository   string
}

// ScanResult contains the results of a Trufflehog scan
type ScanResult struct {
	Findings           []Secret
	VerifiedSecrets    int
	UnverifiedSecrets  int
	ScanDuration       string
	TrufflehogVersion  string
	Bytes              int64
	Chunks             int64
	Error              string
}

// NewScanner creates a new Trufflehog scanner instance
func NewScanner() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return "trufflehog"
}

// IsAvailable checks if the trufflehog binary is available on the system
func (s *Scanner) IsAvailable() (bool, string) {
	path, err := exec.LookPath("trufflehog")
	if err != nil {
		return false, fmt.Sprintf("trufflehog binary not found: %v", err)
	}
	s.binaryPath = path
	return true, fmt.Sprintf("trufflehog found at %s", path)
}

// Scan performs a Trufflehog scan on the given repository path
func (s *Scanner) Scan(ctx context.Context, repoPath string) (*ScanResult, error) {
	startTime := time.Now()

	slog.Info("Starting Trufflehog scan",
		"repoPath", repoPath,
		"scanner", s.Name(),
	)

	// Check if binary is available
	if s.binaryPath == "" {
		available, message := s.IsAvailable()
		if !available {
			return &ScanResult{
				Error: message,
			}, fmt.Errorf("%s", message)
		}
	}

	// Execute trufflehog
	cmd := exec.CommandContext(ctx, "trufflehog", "filesystem", repoPath, "--json", "--no-update")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	slog.Debug("Executing trufflehog command",
		"command", cmd.String(),
		"args", cmd.Args,
	)

	err := cmd.Run()
	if err != nil {
		// Check if it's a context cancellation
		if ctx.Err() != nil {
			errMsg := fmt.Sprintf("trufflehog scan cancelled: %v", ctx.Err())
			slog.Warn(errMsg, "repoPath", repoPath)
			return &ScanResult{
				Error:        errMsg,
				ScanDuration: time.Since(startTime).String(),
			}, fmt.Errorf("%s", errMsg)
		}

		// Log stderr for debugging
		if stderr.Len() > 0 {
			slog.Warn("Trufflehog stderr output", "stderr", stderr.String())
		}

		// Trufflehog may exit with non-zero even on successful scans with findings
		// So we continue processing if we got output
		if stdout.Len() == 0 {
			errMsg := fmt.Sprintf("trufflehog execution failed: %v", err)
			slog.Error(errMsg, "repoPath", repoPath, "stderr", stderr.String())
			return &ScanResult{
				Error:        errMsg,
				ScanDuration: time.Since(startTime).String(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Parse the NDJSON output
	result, parseErr := s.parseOutput(&stdout)
	if parseErr != nil {
		slog.Error("Failed to parse trufflehog output",
			"error", parseErr,
			"repoPath", repoPath,
		)
		result.Error = parseErr.Error()
		result.ScanDuration = time.Since(startTime).String()
		return result, parseErr
	}

	result.ScanDuration = time.Since(startTime).String()

	slog.Info("Trufflehog scan completed",
		"repoPath", repoPath,
		"findings", len(result.Findings),
		"verified", result.VerifiedSecrets,
		"unverified", result.UnverifiedSecrets,
		"duration", result.ScanDuration,
	)

	return result, nil
}

// parseOutput parses the NDJSON output from Trufflehog
func (s *Scanner) parseOutput(output *bytes.Buffer) (*ScanResult, error) {
	result := &ScanResult{
		Findings: make([]Secret, 0),
	}

	scanner := bufio.NewScanner(output)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Try to parse as a TrufflehogSecret first (finding)
		var finding srs.TrufflehogSecret
		if err := json.Unmarshal(line, &finding); err != nil {
			// If it's not a secret, try to parse as summary/metadata
			var metadata map[string]interface{}
			if metaErr := json.Unmarshal(line, &metadata); metaErr != nil {
				slog.Debug("Failed to parse line as JSON",
					"lineNum", lineNum,
					"error", err,
					"line", string(line),
				)
				continue
			}

			// Extract summary information if available
			if msg, ok := metadata["msg"].(string); ok && msg == "finished scanning" {
				if duration, ok := metadata["scan_duration"].(string); ok {
					result.ScanDuration = duration
				}
				if version, ok := metadata["trufflehog_version"].(string); ok {
					result.TrufflehogVersion = version
				}
				if bytes, ok := metadata["bytes"].(float64); ok {
					result.Bytes = int64(bytes)
				}
				if chunks, ok := metadata["chunks"].(float64); ok {
					result.Chunks = int64(chunks)
				}
			}
			continue
		}

		// Check if this is a valid finding with DetectorName
		if finding.DetectorName == "" {
			continue
		}

		// Convert to our Secret format
		secret := Secret{
			DetectorName: finding.DetectorName,
			File:         finding.SourceMetadata.Data.Git.File,
			Line:         finding.SourceMetadata.Data.Git.Line,
			Verified:     finding.Verified,
			Redacted:     finding.Redacted,
			Raw:          finding.Raw,
			Commit:       finding.SourceMetadata.Data.Git.Commit,
			Timestamp:    finding.SourceMetadata.Data.Git.Timestamp,
			Email:        finding.SourceMetadata.Data.Git.Email,
			Repository:   finding.SourceMetadata.Data.Git.Repository,
		}

		result.Findings = append(result.Findings, secret)

		// Update counters
		if finding.Verified {
			result.VerifiedSecrets++
		} else {
			result.UnverifiedSecrets++
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("error reading trufflehog output: %w", err)
	}

	return result, nil
}

// ConvertToTrufflehogResults converts ScanResult to SRS TrufflehogResults format
func (s *Scanner) ConvertToTrufflehogResults(scanResult *ScanResult) *srs.TrufflehogResults {
	findings := make([]srs.TrufflehogSecret, len(scanResult.Findings))

	for i, secret := range scanResult.Findings {
		findings[i] = srs.TrufflehogSecret{
			DetectorName: secret.DetectorName,
			Verified:     secret.Verified,
			Raw:          secret.Raw,
			Redacted:     secret.Redacted,
		}
		findings[i].SourceMetadata.Data.Git.File = secret.File
		findings[i].SourceMetadata.Data.Git.Line = secret.Line
		findings[i].SourceMetadata.Data.Git.Commit = secret.Commit
		findings[i].SourceMetadata.Data.Git.Timestamp = secret.Timestamp
		findings[i].SourceMetadata.Data.Git.Email = secret.Email
		findings[i].SourceMetadata.Data.Git.Repository = secret.Repository
	}

	return &srs.TrufflehogResults{
		Findings:          findings,
		VerifiedSecrets:   int64(scanResult.VerifiedSecrets),
		UnverifiedSecrets: int64(scanResult.UnverifiedSecrets),
		ScanDuration:      scanResult.ScanDuration,
		TrufflehogVersion: scanResult.TrufflehogVersion,
		Bytes:             scanResult.Bytes,
		Chunks:            scanResult.Chunks,
	}
}

// GeneratePrimaryKey generates a unique primary key for a secret finding
// Format: {repo_postfix}::{branch}::{credential_hash}::{location_hash}
func GeneratePrimaryKey(repoPostfix, branch, file string, line int64, redacted string) string {
	// Hash the credential (using redacted version for consistency)
	credentialHash := fmt.Sprintf("%x", sha256.Sum256([]byte(redacted)))[:16]

	// Hash the location
	location := fmt.Sprintf("%s:%d", file, line)
	locationHash := fmt.Sprintf("%x", sha256.Sum256([]byte(location)))[:16]

	return fmt.Sprintf("%s::%s::%s::%s", repoPostfix, branch, credentialHash, locationHash)
}

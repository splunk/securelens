package utils

import (
	"fmt"
	"strings"
)

// ExtractRepoPostfix extracts the org/repo format from a repository URL
// Example: https://github.com/myorg/myrepo -> myorg/myrepo
func ExtractRepoPostfix(url string) string {
	// TODO: Implement robust postfix extraction
	// Handle various URL formats:
	// - https://github.com/org/repo
	// - git@github.com:org/repo.git
	// - https://cd.splunkdev.com/org/repo

	// Simple placeholder implementation
	parts := strings.Split(url, "/")
	if len(parts) >= 2 {
		org := parts[len(parts)-2]
		repo := strings.TrimSuffix(parts[len(parts)-1], ".git")
		return fmt.Sprintf("%s/%s", org, repo)
	}

	return url
}

// Contains checks if a string slice contains a specific string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// SeverityToInt converts severity string to integer for sorting
func SeverityToInt(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// IntToSeverity converts severity integer back to string
func IntToSeverity(level int) string {
	switch level {
	case 4:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

package repository

import (
	"log/slog"
	"strings"
)

// GitProvider represents a Git hosting provider
type GitProvider string

const (
	GitLab     GitProvider = "gitlab"
	GitHub     GitProvider = "github"
	Bitbucket  GitProvider = "bitbucket"
	Unknown    GitProvider = "unknown"
)

// DetectProvider detects the Git provider from a repository URL
func DetectProvider(url string) GitProvider {
	slog.Debug("Detecting Git provider", "url", url)

	// TODO: Implement robust provider detection
	// Should handle various URL formats:
	// - https://gitlab.com/org/repo
	// - git@gitlab.com:org/repo.git
	// - https://cd.splunkdev.com/org/repo (GitLab)
	// - etc.

	lower := strings.ToLower(url)

	if strings.Contains(lower, "gitlab") || strings.Contains(lower, "cd.splunkdev.com") {
		return GitLab
	} else if strings.Contains(lower, "github") {
		return GitHub
	} else if strings.Contains(lower, "bitbucket") {
		return Bitbucket
	}

	return Unknown
}

// ParseRepoURL parses a repository URL into its components
type RepoURLInfo struct {
	Provider GitProvider
	URL      string
	Branch   string
	Commit   string
	Owner    string
	Repo     string
	Postfix  string // owner/repo format
}

// ParseRepoURL parses a repository URL with optional branch and commit
// Formats: url, url:branch, url:branch:commit
func ParseRepoURL(input string) (*RepoURLInfo, error) {
	slog.Debug("Parsing repository URL", "input", input)

	// TODO: Implement robust URL parsing
	// 1. Split by colons to get url:branch:commit
	// 2. Detect provider
	// 3. Extract owner and repo name
	// 4. Build postfix (owner/repo)
	// 5. Return RepoURLInfo

	parts := strings.Split(input, ":")
	url := parts[0]

	info := &RepoURLInfo{
		Provider: DetectProvider(url),
		URL:      url,
		Branch:   "main", // default
		Commit:   "HEAD", // default
	}

	if len(parts) > 1 {
		info.Branch = parts[1]
	}
	if len(parts) > 2 {
		info.Commit = parts[2]
	}

	slog.Debug("Parsed repository URL", "provider", info.Provider, "branch", info.Branch)

	return info, nil
}

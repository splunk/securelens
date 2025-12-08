package repository

import (
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// GitProvider represents a Git hosting provider
type GitProvider string

const (
	GitLab    GitProvider = "gitlab"
	GitHub    GitProvider = "github"
	Bitbucket GitProvider = "bitbucket"
	Unknown   GitProvider = "unknown"
)

// DetectProvider detects the Git provider from a repository URL
func DetectProvider(repoURL string) GitProvider {
	slog.Debug("Detecting Git provider", "url", repoURL)

	lower := strings.ToLower(repoURL)

	// Check for known GitLab instances
	if strings.Contains(lower, "gitlab") || strings.Contains(lower, "cd.splunkdev.com") {
		return GitLab
	}
	// Check for GitHub
	if strings.Contains(lower, "github") {
		return GitHub
	}
	// Check for Bitbucket
	if strings.Contains(lower, "bitbucket") {
		return Bitbucket
	}

	return Unknown
}

// RepoURLInfo holds parsed repository URL information
type RepoURLInfo struct {
	Provider   GitProvider
	URL        string // Full clone URL (e.g., https://github.com/owner/repo.git)
	Branch     string // Branch name (empty means default branch)
	Commit     string // Commit hash (empty means HEAD)
	Owner      string // Owner/organization name
	Repo       string // Repository name
	Postfix    string // owner/repo format
	CloneURL   string // URL suitable for cloning
	ProjectKey string // Bitbucket project key (if applicable)
}

// ParseRepoURL parses a repository URL with optional branch and commit
// Supported formats:
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo:branch
//   - https://github.com/owner/repo:branch:commit
//   - git@github.com:owner/repo.git
//   - git@github.com:owner/repo.git:branch
//   - owner/repo (postfix format - requires provider hint)
//
// Also supports explicit flags via ParseRepoURLWithFlags
func ParseRepoURL(input string) (*RepoURLInfo, error) {
	slog.Debug("Parsing repository URL", "input", input)

	// Handle empty input
	if input == "" {
		return nil, fmt.Errorf("empty repository URL")
	}

	// Determine if this is a URL or postfix format
	isHTTPURL := strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
	isSSHURL := strings.HasPrefix(input, "git@") || strings.HasPrefix(input, "ssh://")

	if isHTTPURL {
		return parseHTTPURL(input)
	}
	if isSSHURL {
		return parseSSHURL(input)
	}

	// Assume postfix format (owner/repo or owner/repo:branch or owner/repo:branch:commit)
	return parsePostfixFormat(input)
}

// ParseRepoURLWithFlags parses URL with explicit branch and commit flags
func ParseRepoURLWithFlags(repoURL, branch, commit string) (*RepoURLInfo, error) {
	info, err := ParseRepoURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Override with explicit flags if provided
	if branch != "" {
		info.Branch = branch
	}
	if commit != "" {
		info.Commit = commit
	}

	return info, nil
}

// parseHTTPURL parses HTTP/HTTPS URLs
// Format: https://github.com/owner/repo:branch:commit
func parseHTTPURL(input string) (*RepoURLInfo, error) {
	info := &RepoURLInfo{}

	// Find the last colon that's not part of the protocol
	// We need to handle: https://github.com/owner/repo:branch:commit
	protocolEnd := strings.Index(input, "://")
	if protocolEnd == -1 {
		return nil, fmt.Errorf("invalid HTTP URL format: %s", input)
	}

	// Get the part after the protocol
	afterProtocol := input[protocolEnd+3:]

	// Split by colon to extract branch and commit
	parts := strings.Split(afterProtocol, ":")
	hostAndPath := parts[0]

	// Reconstruct the base URL
	baseURL := input[:protocolEnd+3] + hostAndPath

	// Parse the URL to extract components
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Extract path and clean it
	path := strings.TrimPrefix(parsedURL.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimSuffix(path, "/")

	// Handle special Bitbucket formats
	if strings.Contains(parsedURL.Host, "bitbucket") {
		return parseBitbucketHTTPURL(input, parsedURL, parts)
	}

	// Standard path format: owner/repo
	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		return nil, fmt.Errorf("invalid repository path: %s", path)
	}

	info.Owner = pathParts[0]
	info.Repo = pathParts[1]
	info.Postfix = fmt.Sprintf("%s/%s", info.Owner, info.Repo)
	info.Provider = DetectProvider(parsedURL.Host)
	info.URL = baseURL
	info.CloneURL = baseURL
	if !strings.HasSuffix(info.CloneURL, ".git") {
		info.CloneURL += ".git"
	}

	// Extract branch and commit from remaining parts
	if len(parts) > 1 && parts[1] != "" {
		info.Branch = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		info.Commit = parts[2]
	}

	slog.Debug("Parsed HTTP URL",
		"provider", info.Provider,
		"owner", info.Owner,
		"repo", info.Repo,
		"branch", info.Branch,
		"commit", info.Commit,
	)

	return info, nil
}

// parseBitbucketHTTPURL handles Bitbucket-specific URL formats
func parseBitbucketHTTPURL(input string, parsedURL *url.URL, parts []string) (*RepoURLInfo, error) {
	info := &RepoURLInfo{
		Provider: Bitbucket,
	}

	path := parsedURL.Path

	// Handle /scm/PROJECT/repo format
	if strings.Contains(path, "/scm/") {
		scmParts := strings.Split(path, "/scm/")
		if len(scmParts) == 2 {
			repoParts := strings.Split(strings.Trim(scmParts[1], "/"), "/")
			if len(repoParts) >= 2 {
				info.ProjectKey = repoParts[0]
				info.Repo = strings.TrimSuffix(repoParts[1], ".git")
				info.Owner = info.ProjectKey
				info.Postfix = fmt.Sprintf("%s/%s", info.ProjectKey, info.Repo)
			}
		}
	} else if strings.Contains(path, "/projects/") && strings.Contains(path, "/repos/") {
		// Handle /projects/PROJECT/repos/repo format
		re := regexp.MustCompile(`/projects/([^/]+)/repos/([^/]+)`)
		matches := re.FindStringSubmatch(path)
		if len(matches) == 3 {
			info.ProjectKey = matches[1]
			info.Repo = matches[2]
			info.Owner = info.ProjectKey
			info.Postfix = fmt.Sprintf("%s/%s", info.ProjectKey, info.Repo)
		}
	}

	if info.Repo == "" {
		return nil, fmt.Errorf("failed to parse Bitbucket URL: %s", input)
	}

	// Build clone URL using SCM format
	info.CloneURL = fmt.Sprintf("%s://%s/scm/%s/%s.git",
		parsedURL.Scheme, parsedURL.Host, info.ProjectKey, info.Repo)
	info.URL = info.CloneURL

	// Extract branch and commit
	if len(parts) > 1 && parts[1] != "" {
		info.Branch = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		info.Commit = parts[2]
	}

	return info, nil
}

// parseSSHURL parses SSH URLs
// Formats:
//   - git@github.com:owner/repo.git
//   - git@github.com:owner/repo.git:branch
//   - ssh://git@github.com/owner/repo.git
func parseSSHURL(input string) (*RepoURLInfo, error) {
	info := &RepoURLInfo{}

	// Handle ssh:// format
	if strings.HasPrefix(input, "ssh://") {
		// ssh://git@github.com/owner/repo.git:branch:commit
		withoutProtocol := strings.TrimPrefix(input, "ssh://")
		// Find first / after the host
		slashIdx := strings.Index(withoutProtocol, "/")
		if slashIdx == -1 {
			return nil, fmt.Errorf("invalid SSH URL format: %s", input)
		}

		host := withoutProtocol[:slashIdx]
		pathAndRest := withoutProtocol[slashIdx+1:]

		// Split by colon for branch/commit
		parts := strings.Split(pathAndRest, ":")
		path := strings.TrimSuffix(parts[0], ".git")

		pathParts := strings.Split(path, "/")
		if len(pathParts) < 2 {
			return nil, fmt.Errorf("invalid repository path in SSH URL: %s", input)
		}

		// Handle Bitbucket port in host
		hostWithoutPort := strings.Split(host, ":")[0]
		if strings.Contains(host, "@") {
			hostWithoutPort = strings.Split(hostWithoutPort, "@")[1]
		}

		info.Provider = DetectProvider(hostWithoutPort)
		info.Owner = pathParts[0]
		info.Repo = pathParts[1]
		info.Postfix = fmt.Sprintf("%s/%s", info.Owner, info.Repo)
		info.URL = input
		info.CloneURL = input

		if len(parts) > 1 {
			info.Branch = parts[1]
		}
		if len(parts) > 2 {
			info.Commit = parts[2]
		}

		return info, nil
	}

	// Handle git@ format: git@github.com:owner/repo.git:branch:commit
	// The challenge: colons separate host:path and also path:branch:commit
	re := regexp.MustCompile(`^git@([^:]+):(.+)$`)
	matches := re.FindStringSubmatch(input)
	if len(matches) != 3 {
		return nil, fmt.Errorf("invalid SSH URL format: %s", input)
	}

	host := matches[1]
	pathAndRest := matches[2]

	// Split the path part by colon
	parts := strings.Split(pathAndRest, ":")
	path := strings.TrimSuffix(parts[0], ".git")

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		return nil, fmt.Errorf("invalid repository path in SSH URL: %s", input)
	}

	info.Provider = DetectProvider(host)
	info.Owner = pathParts[0]
	info.Repo = pathParts[1]
	info.Postfix = fmt.Sprintf("%s/%s", info.Owner, info.Repo)
	info.URL = input
	info.CloneURL = fmt.Sprintf("git@%s:%s/%s.git", host, info.Owner, info.Repo)

	if len(parts) > 1 {
		info.Branch = parts[1]
	}
	if len(parts) > 2 {
		info.Commit = parts[2]
	}

	slog.Debug("Parsed SSH URL",
		"provider", info.Provider,
		"owner", info.Owner,
		"repo", info.Repo,
		"branch", info.Branch,
	)

	return info, nil
}

// parsePostfixFormat parses owner/repo format with optional branch and commit
// Format: owner/repo or owner/repo:branch or owner/repo:branch:commit
func parsePostfixFormat(input string) (*RepoURLInfo, error) {
	info := &RepoURLInfo{}

	// Split by colon for branch/commit
	parts := strings.Split(input, ":")
	postfix := parts[0]

	// Validate postfix format
	pathParts := strings.Split(postfix, "/")
	if len(pathParts) != 2 {
		return nil, fmt.Errorf("invalid postfix format (expected owner/repo): %s", input)
	}

	info.Owner = pathParts[0]
	info.Repo = pathParts[1]
	info.Postfix = postfix
	info.Provider = Unknown // Provider must be determined by caller or config

	if len(parts) > 1 && parts[1] != "" {
		info.Branch = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		info.Commit = parts[2]
	}

	slog.Debug("Parsed postfix format",
		"owner", info.Owner,
		"repo", info.Repo,
		"branch", info.Branch,
		"commit", info.Commit,
	)

	return info, nil
}

// BuildCloneURL constructs a clone URL for a given provider
func (info *RepoURLInfo) BuildCloneURL(provider GitProvider, baseURL string) string {
	if info.CloneURL != "" {
		return info.CloneURL
	}

	switch provider {
	case GitHub:
		if baseURL == "" {
			baseURL = "https://github.com"
		}
		return fmt.Sprintf("%s/%s/%s.git", strings.TrimSuffix(baseURL, "/"), info.Owner, info.Repo)
	case GitLab:
		if baseURL == "" {
			baseURL = "https://gitlab.com"
		}
		return fmt.Sprintf("%s/%s/%s.git", strings.TrimSuffix(baseURL, "/"), info.Owner, info.Repo)
	case Bitbucket:
		if baseURL == "" {
			baseURL = "https://bitbucket.org"
		}
		return fmt.Sprintf("%s/%s/%s.git", strings.TrimSuffix(baseURL, "/"), info.Owner, info.Repo)
	default:
		return ""
	}
}

// PrimaryKey returns the primary unique key in the format used by SRS
func (info *RepoURLInfo) PrimaryKey() string {
	branch := info.Branch
	if branch == "" {
		branch = "main"
	}
	return fmt.Sprintf("%s:%s", info.URL, branch)
}

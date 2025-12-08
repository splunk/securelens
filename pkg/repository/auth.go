package repository

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/splunk/securelens/internal/config"
)

// AuthProvider handles authentication for different Git providers
type AuthProvider struct {
	gitlabToken    string
	githubToken    string
	bitbucketUser  string
	bitbucketToken string

	// Per-instance configuration
	gitlabInstances    map[string]string // baseURL -> token
	githubInstances    map[string]string // baseURL -> token
	bitbucketInstances map[string]BitbucketCreds
}

// BitbucketCreds holds Bitbucket credentials
type BitbucketCreds struct {
	Username string
	Token    string
}

// NewAuthProvider creates a new authentication provider
func NewAuthProvider() *AuthProvider {
	return &AuthProvider{
		gitlabInstances:    make(map[string]string),
		githubInstances:    make(map[string]string),
		bitbucketInstances: make(map[string]BitbucketCreds),
	}
}

// NewAuthProviderFromConfig creates an AuthProvider from configuration
func NewAuthProviderFromConfig(cfg *config.Config) *AuthProvider {
	auth := NewAuthProvider()

	// Load GitLab instances
	for _, gl := range cfg.Git.GitLab {
		if gl.Token != "" {
			baseURL := gl.APIURL
			if baseURL == "" {
				baseURL = "https://gitlab.com"
			}
			auth.gitlabInstances[normalizeBaseURL(baseURL)] = gl.Token
			// Set default token from first configured instance
			if auth.gitlabToken == "" {
				auth.gitlabToken = gl.Token
			}
		}
	}

	// Load GitHub instances
	for _, gh := range cfg.Git.GitHub {
		if gh.Token != "" {
			baseURL := gh.APIURL
			if baseURL == "" {
				baseURL = "https://api.github.com"
			}
			// Convert API URL to clone URL base
			cloneBase := strings.Replace(baseURL, "api.", "", 1)
			cloneBase = strings.Replace(cloneBase, "/api/v3", "", 1)
			auth.githubInstances[normalizeBaseURL(cloneBase)] = gh.Token
			if auth.githubToken == "" {
				auth.githubToken = gh.Token
			}
		}
	}

	// Load Bitbucket instances
	for _, bb := range cfg.Git.Bitbucket {
		if bb.AppPassword != "" {
			baseURL := bb.APIURL
			if baseURL == "" {
				baseURL = "https://bitbucket.org"
			}
			// Convert API URL to clone URL base
			cloneBase := strings.Replace(baseURL, "api.", "", 1)
			cloneBase = strings.Replace(cloneBase, "/2.0", "", 1)
			auth.bitbucketInstances[normalizeBaseURL(cloneBase)] = BitbucketCreds{
				Username: bb.Username,
				Token:    bb.AppPassword,
			}
			if auth.bitbucketToken == "" {
				auth.bitbucketUser = bb.Username
				auth.bitbucketToken = bb.AppPassword
			}
		}
	}

	return auth
}

// normalizeBaseURL ensures consistent URL formatting
func normalizeBaseURL(baseURL string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}
	return strings.ToLower(baseURL)
}

// SetGitLabToken sets the GitLab authentication token
func (a *AuthProvider) SetGitLabToken(token string) {
	a.gitlabToken = token
	slog.Debug("GitLab token configured")
}

// SetGitHubToken sets the GitHub authentication token
func (a *AuthProvider) SetGitHubToken(token string) {
	a.githubToken = token
	slog.Debug("GitHub token configured")
}

// SetBitbucketCredentials sets Bitbucket authentication credentials
func (a *AuthProvider) SetBitbucketCredentials(username, appPassword string) {
	a.bitbucketUser = username
	a.bitbucketToken = appPassword
	slog.Debug("Bitbucket credentials configured")
}

// GetToken returns the token for a given provider
func (a *AuthProvider) GetToken(provider GitProvider) string {
	switch provider {
	case GitHub:
		return a.githubToken
	case GitLab:
		return a.gitlabToken
	case Bitbucket:
		return a.bitbucketToken
	default:
		return ""
	}
}

// GetTokenForURL returns the appropriate token for a given URL
func (a *AuthProvider) GetTokenForURL(repoURL string) (string, GitProvider) {
	provider := DetectProvider(repoURL)

	// Parse URL to get base
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return a.GetToken(provider), provider
	}

	baseURL := normalizeBaseURL(fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host))

	switch provider {
	case GitHub:
		if token, ok := a.githubInstances[baseURL]; ok {
			return token, GitHub
		}
		return a.githubToken, GitHub
	case GitLab:
		if token, ok := a.gitlabInstances[baseURL]; ok {
			return token, GitLab
		}
		return a.gitlabToken, GitLab
	case Bitbucket:
		if creds, ok := a.bitbucketInstances[baseURL]; ok {
			return creds.Token, Bitbucket
		}
		return a.bitbucketToken, Bitbucket
	}

	return "", Unknown
}

// GetAuthURL returns an authenticated URL for cloning
func (a *AuthProvider) GetAuthURL(repoURL string) (string, error) {
	slog.Debug("Getting authenticated URL", "url", repoURL)

	provider := DetectProvider(repoURL)
	token, _ := a.GetTokenForURL(repoURL)

	if token == "" {
		slog.Debug("No token available, returning original URL")
		return repoURL, nil
	}

	// Parse the URL
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// Only modify HTTPS URLs
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return repoURL, nil
	}

	switch provider {
	case GitHub:
		// GitHub: https://x-access-token:<token>@github.com/...
		parsed.User = url.UserPassword("x-access-token", token)
	case GitLab:
		// GitLab: https://oauth2:<token>@gitlab.com/...
		parsed.User = url.UserPassword("oauth2", token)
	case Bitbucket:
		// Get username for Bitbucket
		username := a.bitbucketUser
		if username == "" {
			username = "x-token-auth"
		}
		// Bitbucket: https://<username>:<app_password>@bitbucket.org/...
		parsed.User = url.UserPassword(username, token)
	default:
		return repoURL, nil
	}

	return parsed.String(), nil
}

// HasCredentials returns true if credentials are configured for any provider
func (a *AuthProvider) HasCredentials() bool {
	return a.gitlabToken != "" || a.githubToken != "" || a.bitbucketToken != ""
}

// HasCredentialsForProvider returns true if credentials are configured for a specific provider
func (a *AuthProvider) HasCredentialsForProvider(provider GitProvider) bool {
	switch provider {
	case GitHub:
		return a.githubToken != "" || len(a.githubInstances) > 0
	case GitLab:
		return a.gitlabToken != "" || len(a.gitlabInstances) > 0
	case Bitbucket:
		return a.bitbucketToken != "" || len(a.bitbucketInstances) > 0
	default:
		return false
	}
}

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testGitLabURL    = "https://gitlab.com"
	testGitHubURL    = "https://api.github.com"
	testBitbucketURL = "https://api.bitbucket.org/2.0"
)

func TestLoadWithConfigFile(t *testing.T) {
	// Set up environment variables for substitution
	_ = os.Setenv("TEST_GITLAB_TOKEN", "glpat-test123")
	_ = os.Setenv("TEST_GITHUB_TOKEN", "ghp-test456")
	defer func() { _ = os.Unsetenv("TEST_GITLAB_TOKEN") }()
	defer func() { _ = os.Unsetenv("TEST_GITHUB_TOKEN") }()

	// Load config from example file
	cfg, err := Load("../../cli/config/config.example.yaml")
	require.NoError(t, err, "Failed to load config")
	require.NotNil(t, cfg, "Config should not be nil")

	// Test that defaults were applied
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 3306, cfg.Database.Port)
	assert.Equal(t, "table", cfg.Output.Format)
	assert.Equal(t, 100, cfg.Discovery.MaxReposPerScan)
}

func TestLoadWithoutConfigFile(t *testing.T) {
	// Test loading with no config file (should use defaults)
	// Don't specify a path, let it search default locations
	cfg, err := Load("")
	require.NoError(t, err, "Should not fail when config file doesn't exist")
	require.NotNil(t, cfg, "Config should not be nil")

	// Verify defaults are set
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 3306, cfg.Database.Port)
	assert.Equal(t, "table", cfg.Output.Format)
	assert.Equal(t, 5, cfg.Scanning.ParallelWorkers)
}

func TestValidateNoGitProviders(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitLab:    []GitLabConfig{},
			GitHub:    []GitHubConfig{},
			Bitbucket: []BitbucketConfig{},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err, "Should fail when no Git providers configured")
	assert.Contains(t, err.Error(), "at least one Git provider")
}

func TestValidateGitLabMissingToken(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitLab: []GitLabConfig{
				{Name: "test", Token: "", APIURL: testGitLabURL},
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err, "Should fail when GitLab token is missing")
	assert.Contains(t, err.Error(), "missing token")
}

func TestValidateGitHubMissingToken(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitHub: []GitHubConfig{
				{Name: "test", Token: "", APIURL: testGitHubURL},
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err, "Should fail when GitHub token is missing")
	assert.Contains(t, err.Error(), "missing token")
}

func TestValidateBitbucketMissingCredentials(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			Bitbucket: []BitbucketConfig{
				{Name: "test", Username: "", AppPassword: "password"},
			},
		},
	}

	err := cfg.Validate()
	assert.Error(t, err, "Should fail when Bitbucket username is missing")
	assert.Contains(t, err.Error(), "missing username")

	cfg.Git.Bitbucket[0].Username = "user"
	cfg.Git.Bitbucket[0].AppPassword = ""
	err = cfg.Validate()
	assert.Error(t, err, "Should fail when Bitbucket password is missing")
	assert.Contains(t, err.Error(), "missing app_password")
}

func TestValidateInvalidOutputFormat(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitLab: []GitLabConfig{
				{Name: "test", Token: "token", APIURL: testGitLabURL},
			},
		},
		Output: OutputConfig{
			Format: "invalid",
		},
	}

	err := cfg.Validate()
	assert.Error(t, err, "Should fail with invalid output format")
	assert.Contains(t, err.Error(), "invalid output format")
}

func TestValidateValidConfig(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitLab: []GitLabConfig{
				{Name: "gitlab-com", Token: "glpat-test123", APIURL: testGitLabURL},
			},
			GitHub: []GitHubConfig{
				{Name: "github-com", Token: "ghp-test456", APIURL: testGitHubURL},
			},
		},
		Output: OutputConfig{
			Format: "json",
		},
		Discovery: DiscoveryConfig{
			OutputFormat: "yaml",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err, "Should pass validation with valid config")
}

func TestSetDefaultURLs(t *testing.T) {
	cfg := &Config{
		Git: GitConfig{
			GitLab: []GitLabConfig{
				{Name: "test", Token: "token", APIURL: ""},
			},
			GitHub: []GitHubConfig{
				{Name: "test", Token: "token", APIURL: ""},
			},
			Bitbucket: []BitbucketConfig{
				{Name: "test", Username: "user", AppPassword: "pass", APIURL: ""},
			},
		},
	}

	setDefaultURLs(cfg)

	assert.Equal(t, testGitLabURL, cfg.Git.GitLab[0].APIURL)
	assert.Equal(t, testGitHubURL, cfg.Git.GitHub[0].APIURL)
	assert.Equal(t, testBitbucketURL, cfg.Git.Bitbucket[0].APIURL)
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}

	applyDefaults(cfg)

	// Database defaults
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 3306, cfg.Database.Port)
	assert.Equal(t, "securelens", cfg.Database.Name)
	assert.Equal(t, 10, cfg.Database.MaxConnections)

	// Scanning defaults
	assert.Equal(t, 5, cfg.Scanning.ParallelWorkers)
	assert.Equal(t, 1, cfg.Scanning.CloneDepth)
	assert.Equal(t, 1000, cfg.Scanning.MaxRepoSizeMB)

	// Output defaults
	assert.Equal(t, "table", cfg.Output.Format)
	assert.Equal(t, "info", cfg.Output.Verbosity)

	// Discovery defaults
	assert.Equal(t, 100, cfg.Discovery.MaxReposPerScan)
	assert.Equal(t, "table", cfg.Discovery.OutputFormat)
}

func TestValidateSplunkConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       SplunkConfig
		wantError bool
		contains  string
	}{
		{
			name: "disabled with empty fields",
			cfg: SplunkConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled missing endpoint",
			cfg: SplunkConfig{
				Enabled:  true,
				HECToken: "token",
			},
			wantError: true,
			contains:  "HEC endpoint",
		},
		{
			name: "enabled missing token",
			cfg: SplunkConfig{
				Enabled:     true,
				HECEndpoint: "https://splunk.example.com:8088/services/collector",
			},
			wantError: true,
			contains:  "HEC token",
		},
		{
			name: "enabled invalid URL",
			cfg: SplunkConfig{
				Enabled:     true,
				HECEndpoint: "://bad-url",
				HECToken:    "token",
			},
			wantError: true,
			contains:  "valid URL",
		},
		{
			name: "enabled non-http scheme",
			cfg: SplunkConfig{
				Enabled:     true,
				HECEndpoint: "ftp://splunk.example.com:8088/services/collector",
				HECToken:    "token",
			},
			wantError: true,
			contains:  "http or https",
		},
		{
			name: "enabled valid config",
			cfg: SplunkConfig{
				Enabled:     true,
				HECEndpoint: "https://splunk.example.com:8088/services/collector",
				HECToken:    "token",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSplunkConfig(tt.cfg)
			if tt.wantError {
				require.Error(t, err)
				if tt.contains != "" {
					assert.Contains(t, err.Error(), tt.contains)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestValidateSlackConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       SlackConfig
		wantError bool
		contains  string
	}{
		{
			name: "disabled with empty fields",
			cfg: SlackConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled missing bot token",
			cfg: SlackConfig{
				Enabled: true,
			},
			wantError: true,
			contains:  "bot token",
		},
		{
			name: "enabled missing channel",
			cfg: SlackConfig{
				Enabled:  true,
				BotToken: "xoxb-test",
			},
			wantError: true,
			contains:  "channel",
		},
		{
			name: "enabled valid config",
			cfg: SlackConfig{
				Enabled:  true,
				BotToken: "xoxb-test",
				Channel:  "C1234567890",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSlackConfig(tt.cfg)
			if tt.wantError {
				require.Error(t, err)
				if tt.contains != "" {
					assert.Contains(t, err.Error(), tt.contains)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

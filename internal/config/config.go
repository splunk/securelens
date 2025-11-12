package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Database  DatabaseConfig  `yaml:"database"`
	Git       GitConfig       `yaml:"git"`
	SRS       SRSConfig       `yaml:"srs"`
	Scanners  ScannersConfig  `yaml:"scanners"`
	Scanning  ScanningConfig  `yaml:"scanning"`
	Output    OutputConfig    `yaml:"output"`
	Discovery DiscoveryConfig `yaml:"discovery"`
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Name           string `yaml:"name"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	MaxConnections int    `yaml:"max_connections"`
}

// GitConfig holds Git provider credentials
type GitConfig struct {
	GitLab    []GitLabConfig    `yaml:"gitlab"`
	GitHub    []GitHubConfig    `yaml:"github"`
	Bitbucket []BitbucketConfig `yaml:"bitbucket"`
}

type GitLabConfig struct {
	Name   string `mapstructure:"name"`
	Token  string `mapstructure:"token"`
	APIURL string `mapstructure:"api_url"`
}

type GitHubConfig struct {
	Name          string   `mapstructure:"name"`
	Token         string   `mapstructure:"token"`
	APIURL        string   `mapstructure:"api_url"`
	Organizations []string `mapstructure:"organizations"`
}

type BitbucketConfig struct {
	Name        string `mapstructure:"name"`
	Username    string `mapstructure:"username"`
	AppPassword string `mapstructure:"app_password"`
	APIURL      string `mapstructure:"api_url"`
	Workspace   string `mapstructure:"workspace"`
}

// SRSConfig holds SRS API configuration
type SRSConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIURL  string `yaml:"api_url"`
	APIKey  string `yaml:"api_key"`
	Timeout int    `yaml:"timeout"`
}

// ScannersConfig holds scanner-specific configuration
type ScannersConfig struct {
	Semgrep    SemgrepConfig    `yaml:"semgrep"`
	FOSSA      FOSSAConfig      `yaml:"fossa"`
	Trufflehog TrufflehogConfig `yaml:"trufflehog"`
}

type SemgrepConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Config      string   `yaml:"config"`
	Timeout     int      `yaml:"timeout"`
	CustomRules []string `yaml:"custom_rules"`
}

type FOSSAConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
	Timeout int    `yaml:"timeout"`
}

type TrufflehogConfig struct {
	Enabled bool `yaml:"enabled"`
	Timeout int  `yaml:"timeout"`
	Verify  bool `yaml:"verify"`
}

// ScanningConfig holds scanning behavior settings
type ScanningConfig struct {
	ParallelWorkers int  `yaml:"parallel_workers"`
	CloneDepth      int  `yaml:"clone_depth"`
	CleanupOnError  bool `yaml:"cleanup_on_error"`
	MaxRepoSizeMB   int  `yaml:"max_repo_size_mb"`
}

// OutputConfig holds output preferences
type OutputConfig struct {
	Format      string `yaml:"format"`
	Verbosity   string `yaml:"verbosity"`
	SaveReports bool   `yaml:"save_reports"`
	ReportsDir  string `yaml:"reports_dir"`
}

// DiscoveryConfig holds discovery settings
type DiscoveryConfig struct {
	MaxReposPerScan int      `yaml:"max_repos_per_scan"`
	MinStars        int      `yaml:"min_stars"`
	Languages       []string `yaml:"languages"`
	ExcludeArchived bool     `yaml:"exclude_archived"`
	OutputFormat    string   `yaml:"output_format"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	slog.Info("Loading configuration", "path", configPath)

	var cfg Config

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("$HOME/.securelens")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/securelens")
	}

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Info("Config file not found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		slog.Info("Config file loaded", "path", viper.ConfigFileUsed())
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	applyDefaults(&cfg)
	setDefaultURLs(&cfg)

	slog.Info("Configuration loaded successfully")

	return &cfg, nil
}

// Validate validates the configuration for required fields
func (c *Config) Validate() error {
	hasGitProvider := len(c.Git.GitLab) > 0 || len(c.Git.GitHub) > 0 || len(c.Git.Bitbucket) > 0

	if !hasGitProvider {
		return fmt.Errorf("at least one Git provider (GitLab, GitHub, or Bitbucket) must be configured")
	}

	if err := validateGitLabConfigs(c.Git.GitLab); err != nil {
		return err
	}
	if err := validateGitHubConfigs(c.Git.GitHub); err != nil {
		return err
	}
	if err := validateBitbucketConfigs(c.Git.Bitbucket); err != nil {
		return err
	}

	if err := validateOutputFormats(c.Output.Format, c.Discovery.OutputFormat); err != nil {
		return err
	}

	return nil
}

// validateGitLabConfigs validates GitLab configurations
func validateGitLabConfigs(configs []GitLabConfig) error {
	for i, gl := range configs {
		if gl.Token == "" {
			return fmt.Errorf("GitLab config at index %d is missing token", i)
		}
	}
	return nil
}

// validateGitHubConfigs validates GitHub configurations
func validateGitHubConfigs(configs []GitHubConfig) error {
	for i, gh := range configs {
		if gh.Token == "" {
			return fmt.Errorf("GitHub config at index %d is missing token", i)
		}
	}
	return nil
}

// validateBitbucketConfigs validates Bitbucket configurations
func validateBitbucketConfigs(configs []BitbucketConfig) error {
	for i, bb := range configs {
		if bb.Username == "" {
			return fmt.Errorf("Bitbucket config at index %d is missing username", i)
		}
		if bb.AppPassword == "" {
			return fmt.Errorf("Bitbucket config at index %d is missing app_password", i)
		}
	}
	return nil
}

// validateOutputFormats validates output format settings
func validateOutputFormats(outputFormat, discoveryFormat string) error {
	validFormats := map[string]bool{"table": true, "json": true, "yaml": true}

	if outputFormat != "" && !validFormats[outputFormat] {
		return fmt.Errorf("invalid output format '%s', must be one of: table, json, yaml", outputFormat)
	}
	if discoveryFormat != "" && !validFormats[discoveryFormat] {
		return fmt.Errorf("invalid discovery output format '%s', must be one of: table, json, yaml", discoveryFormat)
	}

	return nil
}

// Save saves the configuration to file
func (c *Config) Save(path string) error {
	slog.Info("Saving configuration", "path", path)

	// TODO: Implement configuration saving
	// 1. Marshal Config to YAML
	// 2. Write to file at path
	// 3. Set appropriate file permissions

	slog.Info("Configuration saved successfully")

	return nil
}

// applyDefaults sets default values for fields that are zero-valued
func applyDefaults(cfg *Config) {
	// This function might not be necessary after newInitCmd() is implemented
	// in cli/config/config.go.

	// Database defaults
	if cfg.Database.Host == "" {
		cfg.Database.Host = "localhost"
	}
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 3306
	}
	if cfg.Database.Name == "" {
		cfg.Database.Name = "securelens"
	}
	if cfg.Database.Username == "" {
		cfg.Database.Username = "root"
	}
	if cfg.Database.MaxConnections == 0 {
		cfg.Database.MaxConnections = 10
	}

	// Scanning defaults
	if cfg.Scanning.ParallelWorkers == 0 {
		cfg.Scanning.ParallelWorkers = 5
	}
	if cfg.Scanning.CloneDepth == 0 {
		cfg.Scanning.CloneDepth = 1
	}
	if cfg.Scanning.MaxRepoSizeMB == 0 {
		cfg.Scanning.MaxRepoSizeMB = 1000
	}

	// Output defaults
	if cfg.Output.Format == "" {
		cfg.Output.Format = "table"
	}
	if cfg.Output.Verbosity == "" {
		cfg.Output.Verbosity = "info"
	}

	// Discovery defaults
	if cfg.Discovery.MaxReposPerScan == 0 {
		cfg.Discovery.MaxReposPerScan = 100
	}
	if cfg.Discovery.OutputFormat == "" {
		cfg.Discovery.OutputFormat = "table"
	}
}

// setDefaultURLs sets default API URLs for providers if not specified
func setDefaultURLs(cfg *Config) {
	for i := range cfg.Git.GitLab {
		if cfg.Git.GitLab[i].APIURL == "" {
			cfg.Git.GitLab[i].APIURL = "https://gitlab.com"
		}
	}

	for i := range cfg.Git.GitHub {
		if cfg.Git.GitHub[i].APIURL == "" {
			cfg.Git.GitHub[i].APIURL = "https://api.github.com"
		}
	}

	for i := range cfg.Git.Bitbucket {
		if cfg.Git.Bitbucket[i].APIURL == "" {
			cfg.Git.Bitbucket[i].APIURL = "https://api.bitbucket.org/2.0"
		}
	}
}

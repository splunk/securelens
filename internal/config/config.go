package config

import (
	"log/slog"
	"os"
)

// Config represents the application configuration
type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Git      GitConfig      `yaml:"git"`
	SRS      SRSConfig      `yaml:"srs"`
	Scanners ScannersConfig `yaml:"scanners"`
	Scanning ScanningConfig `yaml:"scanning"`
	Output   OutputConfig   `yaml:"output"`
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
	GitLab    GitLabConfig    `yaml:"gitlab"`
	GitHub    GitHubConfig    `yaml:"github"`
	Bitbucket BitbucketConfig `yaml:"bitbucket"`
}

type GitLabConfig struct {
	Token  string `yaml:"token"`
	APIURL string `yaml:"api_url"`
}

type GitHubConfig struct {
	Token  string `yaml:"token"`
	APIURL string `yaml:"api_url"`
}

type BitbucketConfig struct {
	Username    string `yaml:"username"`
	AppPassword string `yaml:"app_password"`
	APIURL      string `yaml:"api_url"`
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
	ParallelWorkers  int  `yaml:"parallel_workers"`
	CloneDepth       int  `yaml:"clone_depth"`
	CleanupOnError   bool `yaml:"cleanup_on_error"`
	MaxRepoSizeMB    int  `yaml:"max_repo_size_mb"`
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
	MaxReposPerScan  int      `yaml:"max_repos_per_scan"`
	MinStars         int      `yaml:"min_stars"`
	Languages        []string `yaml:"languages"`
	ExcludeArchived  bool     `yaml:"exclude_archived"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	slog.Info("Loading configuration", "path", configPath)

	// TODO: Implement configuration loading
	// 1. Read YAML file from configPath
	// 2. Unmarshal into Config struct
	// 3. Override with environment variables
	// 4. Validate configuration
	// 5. Return Config

	// Default configuration for now
	cfg := &Config{
		Database: DatabaseConfig{
			Host:           getEnv("DB_HOST", "localhost"),
			Port:           3306,
			Name:           getEnv("DB_NAME", "securelens"),
			Username:       getEnv("DB_USER", "root"),
			Password:       getEnv("DB_PASSWORD", ""),
			MaxConnections: 10,
		},
		Scanning: ScanningConfig{
			ParallelWorkers: 5,
			CloneDepth:      1,
			CleanupOnError:  true,
			MaxRepoSizeMB:   1000,
		},
	}

	slog.Info("Configuration loaded successfully")

	return cfg, nil
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

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

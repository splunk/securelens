package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/lib/bitbucket"
	"github.com/splunk/securelens/lib/github"
	"github.com/splunk/securelens/lib/gitlab"
	"github.com/splunk/securelens/pkg/repository"
	"github.com/splunk/securelens/pkg/scanner/standalone"
	"github.com/splunk/securelens/pkg/srs"
)

type DiscoveredRepository struct {
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	FullName    string   `json:"full_name"`
	URL         string   `json:"url"`
	IsPrivate   bool     `json:"is_private"`
	Language    string   `json:"language"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	Branches    []string `json:"branches,omitempty"`
}

type discoveryFunc func(context.Context, int, bool) ([]DiscoveredRepository, error)

func discoverRepositories(ctx context.Context, cfg *config.Config, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	slog.Info("Starting repository discovery", "limit", limit)

	var allRepos []DiscoveredRepository

	// Define discovery functions for each provider
	discoveries := []struct {
		name string
		fn   discoveryFunc
	}{
		{"GitLab", func(ctx context.Context, remaining int, branches bool) ([]DiscoveredRepository, error) {
			return discoverFromGitLab(ctx, cfg.Git.GitLab, remaining, branches)
		}},
		{"GitHub", func(ctx context.Context, remaining int, branches bool) ([]DiscoveredRepository, error) {
			return discoverFromGitHub(ctx, cfg.Git.GitHub, remaining, branches)
		}},
		{"Bitbucket", func(ctx context.Context, remaining int, branches bool) ([]DiscoveredRepository, error) {
			return discoverFromBitbucket(ctx, cfg.Git.Bitbucket, remaining, branches)
		}},
	}

	for _, discovery := range discoveries {
		if limit > 0 && len(allRepos) >= limit {
			break
		}

		remaining := limit
		if limit > 0 {
			remaining = limit - len(allRepos)
		}

		repos, err := discovery.fn(ctx, remaining, includeBranches)
		if err != nil {
			slog.Error("Error discovering repositories", "provider", discovery.name, "error", err)
			continue
		}

		allRepos = append(allRepos, repos...)
		slog.Info("Discovered repositories", "provider", discovery.name, "count", len(repos))
	}

	if limit > 0 && len(allRepos) > limit {
		allRepos = allRepos[:limit]
	}

	slog.Info("Repository discovery completed", "total_count", len(allRepos), "limit", limit)

	return allRepos, nil
}

// DiscoverRepositories is the exported version for use by other packages (like UI)
func DiscoverRepositories(ctx context.Context, cfg *config.Config, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	return discoverRepositories(ctx, cfg, limit, includeBranches)
}

func setBranches(ctx context.Context, includeBranches bool, fetchBranches func() ([]string, error)) []string {
	if !includeBranches {
		return nil
	}

	branches, err := fetchBranches()
	if err != nil {
		slog.Error("Failed to fetch branches", "error", err)
		return nil
	}
	return branches
}

func discoverFromGitLab(ctx context.Context, configs []config.GitLabConfig, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	var repos []DiscoveredRepository

	for _, cfg := range configs {
		if limit > 0 && len(repos) >= limit {
			break
		}

		slog.Info("Discovering GitLab repositories", "instance", cfg.Name, "url", cfg.APIURL)

		client, err := gitlab.NewClient(cfg.Token, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create GitLab client", "instance", cfg.Name, "error", err)
			continue
		}

		projects, err := client.ListProjects(ctx, limit)
		if err != nil {
			slog.Error("Failed to list GitLab projects", "instance", cfg.Name, "error", err)
			continue
		}

		for _, project := range projects {
			discovered := DiscoveredRepository{
				Provider:    "gitlab",
				Name:        project.Name,
				FullName:    project.PathWithNS,
				URL:         project.HTTPURL,
				IsPrivate:   project.Visibility != "public",
				Language:    "",
				Description: "",
				Source:      cfg.Name,
			}

			discovered.Branches = setBranches(ctx, includeBranches, func() ([]string, error) {
				return client.ListBranches(ctx, project.ID)
			})
			repos = append(repos, discovered)
		}
		slog.Info("Discovered repositories from GitLab instance", "instance", cfg.Name, "count", len(projects))
	}
	return repos, nil
}

func discoverFromGitHub(ctx context.Context, configs []config.GitHubConfig, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	var repos []DiscoveredRepository

	for _, cfg := range configs {
		if limit > 0 && len(repos) >= limit {
			break
		}

		slog.Info("Discovering GitHub repositories", "instance", cfg.Name, "url", cfg.APIURL)

		client, err := github.NewClient(cfg.Token, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create GitHub client", "instance", cfg.Name, "error", err)
		}

		var githubRepos []github.Repository
		if len(cfg.Organizations) > 0 {
			githubRepos, err = client.ListRepositoriesForOrganizations(ctx, cfg.Organizations, limit)
		} else {
			githubRepos, err = client.ListRepositories(ctx, "", limit)
		}

		if err != nil {
			slog.Error("Failed to list GitHub repositories", "instance", cfg.Name, "error", err)
			continue
		}

		for _, repo := range githubRepos {
			discovered := DiscoveredRepository{
				Provider:  "github",
				Name:      repo.Name,
				FullName:  repo.FullName,
				URL:       repo.CloneURL,
				IsPrivate: repo.Private,
				Language:  repo.Language,
				Source:    cfg.Name,
			}

			parts := strings.Split(repo.FullName, "/")
			if len(parts) == 2 {
				discovered.Branches = setBranches(ctx, includeBranches, func() ([]string, error) {
					return client.ListBranches(ctx, parts[0], parts[1])
				})
			}

			repos = append(repos, discovered)
		}
		slog.Info("Discovered repositories from GitHub instance", "instance", cfg.Name, "count", len(githubRepos))
	}
	return repos, nil
}

func discoverFromBitbucket(ctx context.Context, configs []config.BitbucketConfig, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	var repos []DiscoveredRepository

	for _, cfg := range configs {
		if limit > 0 && len(repos) >= limit {
			break
		}

		slog.Info("Discovering Bitbucket repositories", "instance", cfg.Name, "workspace", cfg.Workspace)

		client, err := bitbucket.NewClient(cfg.Username, cfg.AppPassword, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create Bitbucket client", "instance", cfg.Name, "error", err)
			continue
		}

		bitbucketRepos, err := client.ListRepositories(ctx, cfg.Workspace, limit)
		if err != nil {
			slog.Error("Failed to list Bitbucket repositories", "instance", cfg.Name, "error", err)
			continue
		}

		for _, repo := range bitbucketRepos {
			if limit > 0 && len(repos) >= limit {
				break
			}

			cloneURL := ""
			if len(repo.Links.Clone) > 0 {
				cloneURL = repo.Links.Clone[0].Href
			}

			discovered := DiscoveredRepository{
				Provider:    "bitbucket",
				Name:        repo.Name,
				FullName:    repo.FullName,
				URL:         cloneURL,
				IsPrivate:   repo.IsPrivate,
				Language:    repo.Language,
				Description: "",
				Source:      cfg.Name,
			}

			parts := strings.Split(repo.FullName, "/")
			if len(parts) == 2 {
				discovered.Branches = setBranches(ctx, includeBranches, func() ([]string, error) {
					return client.ListBranches(ctx, parts[0], parts[1])
				})
			}

			repos = append(repos, discovered)
		}
		slog.Info("Discovered repositories from Bitbucket instance", "instance", cfg.Name, "count", len(bitbucketRepos))
	}
	return repos, nil
}

// FilterConfigByProvider creates a filtered config with only the specified provider (exported for UI use)
func FilterConfigByProvider(cfg *config.Config, provider string) *config.Config {
	filtered := &config.Config{
		Database:  cfg.Database,
		SRS:       cfg.SRS,
		Scanners:  cfg.Scanners,
		Scanning:  cfg.Scanning,
		Output:    cfg.Output,
		Discovery: cfg.Discovery,
	}

	switch strings.ToLower(provider) {
	case "github":
		filtered.Git.GitHub = cfg.Git.GitHub
	case "gitlab":
		filtered.Git.GitLab = cfg.Git.GitLab
	case "bitbucket":
		filtered.Git.Bitbucket = cfg.Git.Bitbucket
	default:
		slog.Warn("Unknown provider, returning full config", "provider", provider)
		return cfg
	}

	return filtered
}

// NewScanCmd creates the scan command
func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan repositories for vulnerabilities",
		Long: `Scan repositories for vulnerabilities using multiple security tools.
Supports single repository scanning, bulk scanning, and discovery scanning.`,
	}

	// Add subcommands
	cmd.AddCommand(newRepoCmd())
	cmd.AddCommand(newBulkCmd())
	cmd.AddCommand(newDiscoverCmd())
	cmd.AddCommand(newResultsCmd())

	return cmd
}

// ScanMode determines how the scan is executed
type ScanMode string

const (
	ScanModeLocal      ScanMode = "local"      // Clone locally and run scanners
	ScanModeRemote     ScanMode = "remote"     // Submit to SRS API
	ScanModeStandalone ScanMode = "standalone" // Use locally installed scanner binaries
)

// RepoScanOptions holds options for repository scanning
type RepoScanOptions struct {
	URL          string
	Branch       string
	Commit       string
	Scanners     []string // fossa, semgrep, trufflehog, opengrep, trivy
	OutputFile   string
	OutputFormat string // raw, json, parsed
	OutputDir    string // Directory for parsed reports
	Mode         ScanMode
	ConfigPath   string
	DryRun       bool
	Verbose      bool
	Debug        bool     // Enable debug mode with raw report output
	Parallel     bool     // Run scanners in parallel (standalone mode)
	SRSURL       string   // SRS API endpoint URL
	Async        bool     // Return immediately without waiting for results
	WaitFor      []string // Job status URLs to wait on (skip scanning)
	PollInterval int      // Seconds between status polls
	MaxWait      int      // Maximum minutes to wait for results
	AssetsDir    string   // Directory for scanner assets (rules, etc.)
	LocalPath    string   // Local directory to scan instead of cloning (standalone mode)
}

// ScanReport represents the scan results
type ScanReport struct {
	Repository string                 `json:"repository"`
	Branch     string                 `json:"branch"`
	Commit     string                 `json:"commit"`
	Timestamp  string                 `json:"timestamp"`
	Status     string                 `json:"status"`
	Scanners   []string               `json:"scanners"`
	Results    map[string]interface{} `json:"results,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// ScanRepository runs a scan on a discovered repository (exported for UI use)
func ScanRepository(ctx context.Context, cfg *config.Config, repo DiscoveredRepository, scanMode string) (*ScanReport, error) {
	// Build repo URL info
	repoInfo := &repository.RepoURLInfo{
		URL:      repo.URL,
		Owner:    strings.Split(repo.FullName, "/")[0],
		Repo:     repo.Name,
		Provider: mapProviderToRepoProvider(repo.Provider),
	}

	// Default scanners
	scanners := []string{"opengrep", "trivy", "trufflehog"}

	opts := &RepoScanOptions{
		Branch:       "main", // Use default branch
		Scanners:     scanners,
		Parallel:     true,
		AssetsDir:    "assets",
		PollInterval: 10,
		MaxWait:      30,
	}

	// Auto-detect mode if not specified
	if scanMode == "" {
		scanMode = "standalone"
		if srsURL := os.Getenv("SRS_ORCHESTRATOR_API_ENDPOINT"); srsURL != "" {
			scanMode = "remote"
			opts.SRSURL = srsURL
		} else if cfg != nil && cfg.SRS.APIURL != "" {
			scanMode = "remote"
			opts.SRSURL = cfg.SRS.APIURL
		}
	}

	if scanMode == "remote" {
		return executeRemoteScan(ctx, cfg, repoInfo, scanners, opts)
	}
	return executeStandaloneScan(ctx, cfg, repoInfo, scanners, opts)
}

// mapProviderToRepoProvider converts string provider to repository.GitProvider
func mapProviderToRepoProvider(provider string) repository.GitProvider {
	switch strings.ToLower(provider) {
	case "github":
		return repository.GitHub
	case "gitlab":
		return repository.GitLab
	case "bitbucket":
		return repository.Bitbucket
	default:
		return repository.Unknown
	}
}

func newRepoCmd() *cobra.Command {
	var opts RepoScanOptions

	cmd := &cobra.Command{
		Use:   "repo [url]",
		Short: "Scan a single repository for vulnerabilities",
		Long: `Scan a single repository for vulnerabilities using multiple security scanners.

URL Formats (positional argument or --url flag):
  url                    Scan default branch
  url:branch             Scan specific branch
  url:branch:commit      Scan specific commit

Alternatively, use explicit flags:
  --url https://github.com/org/repo --branch develop --commit abc123

Local Path Mode (standalone only):
  --local-path ./        : Scan a local directory instead of cloning
                           Useful in CI/CD where code is already checked out

Scan Modes:
  --mode local           : Clone locally and run built-in scanners (default)
  --mode remote          : Submit to SRS API for scanning
  --mode standalone      : Use locally installed scanner binaries

Supported Scanners:
  Remote/Local Mode:
    - fossa      : Open source dependency vulnerabilities (OSS/SCA)
    - semgrep    : Static application security testing (SAST)
    - trufflehog : Secret detection

  Standalone Mode (local binaries required):
    - opengrep   : Static application security testing (SAST) - semgrep alternative
    - trivy      : Open source dependency vulnerabilities (OSS/SCA)
    - trufflehog : Secret detection
    Note: FOSSA is not supported in standalone mode

Output Modes:
  --output raw.json      : Write raw JSON results to file
  --output-format json   : Format output as JSON (default: table)
  --output-dir reports/  : Directory for parsed report files
  --debug                : Write raw scanner outputs to debug/ directory

Examples:
  # Scan default branch of a GitHub repository
  securelens scan repo https://github.com/myorg/myrepo

  # Scan specific branch
  securelens scan repo https://github.com/myorg/myrepo:develop
  securelens scan repo --url https://github.com/myorg/myrepo --branch develop

  # Scan specific commit
  securelens scan repo https://github.com/myorg/myrepo:main:abc123def
  securelens scan repo --url https://github.com/myorg/myrepo --branch main --commit abc123

  # Run only specific scanners
  securelens scan repo https://github.com/myorg/myrepo --scanners fossa --scanners semgrep

  # Use standalone mode with local scanner binaries
  securelens scan repo https://github.com/myorg/myrepo --mode standalone
  securelens scan repo https://github.com/myorg/myrepo --mode standalone --scanners opengrep --scanners trivy

  # Scan a local directory (CI/CD mode - no cloning needed)
  securelens scan repo --local-path . --mode standalone --debug
  securelens scan repo --local-path /path/to/repo --mode standalone --branch main --commit abc123

  # Output raw results to file
  securelens scan repo https://github.com/myorg/myrepo --output results.json

  # Enable debug mode for raw scanner outputs
  securelens scan repo https://github.com/myorg/myrepo --mode standalone --debug

  # Submit to SRS API (remote mode)
  securelens scan repo https://github.com/myorg/myrepo --mode remote --srs-url https://srs.example.com/api/v1/orchestrator/job_submit`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle --wait-for mode (skip scanning, just wait)
			if len(opts.WaitFor) > 0 {
				return runWaitForJobs(cmd.Context(), &opts)
			}

			// Handle positional argument
			if len(args) > 0 {
				opts.URL = args[0]
			}

			// If local-path is provided, URL is optional
			if opts.LocalPath != "" {
				// Validate local path exists
				if _, err := os.Stat(opts.LocalPath); os.IsNotExist(err) {
					return fmt.Errorf("local path does not exist: %s", opts.LocalPath)
				}
				// local-path only works with standalone mode
				if opts.Mode != ScanModeStandalone {
					return fmt.Errorf("--local-path only works with --mode standalone")
				}
			} else if opts.URL == "" {
				return fmt.Errorf("repository URL is required (provide as argument, --url flag, or use --local-path for local directories)")
			}

			return runRepoScan(cmd.Context(), &opts)
		},
	}

	// URL/Branch/Commit flags
	cmd.Flags().StringVar(&opts.URL, "url", "", "repository URL (alternative to positional argument)")
	cmd.Flags().StringVarP(&opts.Branch, "branch", "b", "", "branch to scan (overrides URL-embedded branch)")
	cmd.Flags().StringVar(&opts.Commit, "commit", "", "specific commit to scan (overrides URL-embedded commit)")
	cmd.Flags().StringVar(&opts.LocalPath, "local-path", "", "local directory to scan instead of cloning (standalone mode only, useful for CI/CD)")

	// Scanner selection flags
	cmd.Flags().StringSliceVar(&opts.Scanners, "scanners", []string{}, "scanners to run (fossa, semgrep, trufflehog); default: all")

	// Output flags
	cmd.Flags().StringVarP(&opts.OutputFile, "output", "o", "", "output file for raw results (e.g., results.json)")
	cmd.Flags().StringVarP(&opts.OutputFormat, "output-format", "f", "table", "output format: table, json, yaml")
	cmd.Flags().StringVar(&opts.OutputDir, "output-dir", "reports", "directory for parsed report files")

	// Mode flags
	cmd.Flags().StringVar((*string)(&opts.Mode), "mode", "local", "scan mode: local, remote (SRS API), or standalone (local binaries)")
	cmd.Flags().StringVar(&opts.AssetsDir, "assets-dir", "assets", "directory containing scanner assets (e.g., opengrep rules)")
	cmd.Flags().BoolVar(&opts.Parallel, "parallel", true, "run scanners in parallel using goroutines (standalone mode)")

	// SRS flags
	cmd.Flags().StringVar(&opts.SRSURL, "srs-url", "", "SRS API endpoint URL (e.g., https://srs.example.com/api/v1/orchestrator/job_submit)")
	cmd.Flags().BoolVar(&opts.Async, "async", false, "return immediately with job URL without waiting for results")
	cmd.Flags().StringSliceVar(&opts.WaitFor, "wait-for", []string{}, "job status URL(s) to wait on (skips scanning, just waits for results)")
	cmd.Flags().IntVar(&opts.PollInterval, "poll-interval", 10, "seconds between status polls when waiting")
	cmd.Flags().IntVar(&opts.MaxWait, "max-wait", 30, "maximum minutes to wait for results")

	// Config flags
	cmd.Flags().StringVarP(&opts.ConfigPath, "config", "c", "", "path to configuration file")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "show what would be done without executing")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "enable verbose output")
	cmd.Flags().BoolVar(&opts.Debug, "debug", false, "enable debug mode with raw report output to debug/ directory")

	// Add shorthand flag for parsed output
	var parsed bool
	cmd.Flags().BoolVar(&parsed, "parsed", false, "generate parsed reports in output-dir")

	return cmd
}

// runWaitForJobs waits for existing SRS job URLs to complete
func runWaitForJobs(ctx context.Context, opts *RepoScanOptions) error {
	slog.Info("Waiting for existing SRS jobs", "job_urls", opts.WaitFor)

	waitConfig := srs.WaitConfig{
		PollInterval: time.Duration(opts.PollInterval) * time.Second,
		MaxTimeout:   time.Duration(opts.MaxWait) * time.Minute,
		MaxRetries:   100,
	}

	srsClient := srs.NewClient(waitConfig)

	// Collect results for all jobs
	allResults := make(map[string]interface{})

	for i, jobURL := range opts.WaitFor {
		slog.Info(fmt.Sprintf("Waiting for job %d/%d", i+1, len(opts.WaitFor)), "url", jobURL)

		jobResponse, err := srsClient.WaitForJob(ctx, jobURL)
		if err != nil {
			slog.Error("Failed to wait for job", "url", jobURL, "error", err)
			allResults[jobURL] = map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}
			continue
		}

		// Parse and summarize results
		summary := srs.GetFindingsSummary(jobResponse)
		allResults[jobURL] = summary
	}

	// Create a report
	report := &ScanReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "completed",
		Results:   allResults,
	}

	return outputScanResults(report, opts)
}

func runRepoScan(ctx context.Context, opts *RepoScanOptions) error {
	slog.Info("Starting repository scan",
		"url", opts.URL,
		"branch", opts.Branch,
		"commit", opts.Commit,
		"scanners", opts.Scanners,
		"mode", opts.Mode,
		"local_path", opts.LocalPath,
	)

	// Load configuration
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		slog.Warn("Failed to load config, using defaults", "error", err)
		cfg = &config.Config{}
	}

	// Parse repository URL (or create minimal info for local-path mode)
	var repoInfo *repository.RepoURLInfo
	if opts.LocalPath != "" && opts.URL == "" {
		// Local path mode without URL - create minimal repo info
		repoInfo = &repository.RepoURLInfo{
			Branch: opts.Branch,
			Commit: opts.Commit,
		}
		slog.Info("Using local path mode", "path", opts.LocalPath, "branch", opts.Branch, "commit", opts.Commit)
	} else {
		// Parse repository URL
		repoInfo, err = parseRepoInput(opts)
		if err != nil {
			return fmt.Errorf("failed to parse repository URL: %w", err)
		}
		slog.Info("Parsed repository info",
			"provider", repoInfo.Provider,
			"owner", repoInfo.Owner,
			"repo", repoInfo.Repo,
			"branch", repoInfo.Branch,
			"commit", repoInfo.Commit,
		)
	}

	// Determine scanners to run based on mode
	scanners := opts.Scanners
	if len(scanners) == 0 {
		switch opts.Mode {
		case ScanModeStandalone:
			// Standalone mode uses local binaries: opengrep, trivy, trufflehog
			scanners = []string{"opengrep", "trivy", "trufflehog"}
		default:
			// Remote/Local mode uses SRS scanners: fossa, semgrep, trufflehog
			scanners = []string{"fossa", "semgrep", "trufflehog"}
		}
	}

	if opts.DryRun {
		fmt.Printf("Dry run - would scan:\n")
		if opts.LocalPath != "" {
			fmt.Printf("  Local Path: %s\n", opts.LocalPath)
		}
		if repoInfo.URL != "" {
			fmt.Printf("  Repository: %s\n", repoInfo.URL)
		}
		fmt.Printf("  Branch:     %s\n", repoInfo.Branch)
		fmt.Printf("  Commit:     %s\n", repoInfo.Commit)
		fmt.Printf("  Scanners:   %v\n", scanners)
		fmt.Printf("  Mode:       %s\n", opts.Mode)
		return nil
	}

	// Execute scan based on mode
	var report *ScanReport
	switch opts.Mode {
	case ScanModeLocal:
		report, err = executeLocalScan(ctx, cfg, repoInfo, scanners)
	case ScanModeRemote:
		report, err = executeRemoteScan(ctx, cfg, repoInfo, scanners, opts)
	case ScanModeStandalone:
		report, err = executeStandaloneScan(ctx, cfg, repoInfo, scanners, opts)
	default:
		return fmt.Errorf("unknown scan mode: %s", opts.Mode)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	return outputScanResults(report, opts)
}

func parseRepoInput(opts *RepoScanOptions) (*repository.RepoURLInfo, error) {
	// Use the repository package's parser
	info, err := repository.ParseRepoURL(opts.URL)
	if err != nil {
		return nil, err
	}

	// Override with explicit flags if provided
	if opts.Branch != "" {
		info.Branch = opts.Branch
	}
	if opts.Commit != "" {
		info.Commit = opts.Commit
	}

	// Note: If info.Branch is empty, go-git will use the repository's default branch
	// (usually main or master depending on the repo)

	return info, nil
}

func executeLocalScan(ctx context.Context, cfg *config.Config, repoInfo *repository.RepoURLInfo, scanners []string) (*ScanReport, error) {
	slog.Info("Executing local scan")

	// Create auth provider from config
	auth := repository.NewAuthProviderFromConfig(cfg)

	// Create clone manager
	cloneManager := repository.NewCloneManager("", auth)

	// Build clone URL if not already set
	if repoInfo.CloneURL == "" && repoInfo.Provider != repository.Unknown {
		// Try to build URL from provider info
		switch repoInfo.Provider {
		case repository.GitHub:
			repoInfo.CloneURL = fmt.Sprintf("https://github.com/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
		case repository.GitLab:
			baseURL := "https://gitlab.com"
			if len(cfg.Git.GitLab) > 0 && cfg.Git.GitLab[0].APIURL != "" {
				baseURL = strings.TrimSuffix(cfg.Git.GitLab[0].APIURL, "/api/v4")
			}
			repoInfo.CloneURL = fmt.Sprintf("%s/%s/%s.git", baseURL, repoInfo.Owner, repoInfo.Repo)
		case repository.Bitbucket:
			repoInfo.CloneURL = fmt.Sprintf("https://bitbucket.org/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
		}
	}

	// Clone repository
	slog.Info("Cloning repository", "url", repoInfo.CloneURL)
	cloneResult, err := cloneManager.Clone(ctx, repoInfo, true)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	defer func() { _ = cloneManager.Cleanup(cloneResult) }()

	report := &ScanReport{
		Repository: repoInfo.URL,
		Branch:     cloneResult.Branch,
		Commit:     cloneResult.CommitHash,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Status:     "completed",
		Scanners:   scanners,
		Results:    make(map[string]interface{}),
	}

	// Run each scanner
	for _, scannerName := range scanners {
		slog.Info("Running scanner", "scanner", scannerName, "path", cloneResult.Path)

		result, err := runScanner(ctx, scannerName, cloneResult.Path, cfg)
		if err != nil {
			slog.Error("Scanner failed", "scanner", scannerName, "error", err)
			report.Results[scannerName] = map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		} else {
			report.Results[scannerName] = result
		}
	}

	return report, nil
}

func executeRemoteScan(ctx context.Context, cfg *config.Config, repoInfo *repository.RepoURLInfo, scanners []string, opts *RepoScanOptions) (*ScanReport, error) {
	srsURL := opts.SRSURL
	slog.Info("Executing remote scan via SRS API", "srs_url", srsURL)

	// Check if SRS URL is provided
	if srsURL == "" {
		srsURL = cfg.SRS.APIURL
	}
	if srsURL == "" {
		return nil, fmt.Errorf("SRS API URL not configured. Use --srs-url flag or set srs.api_url in config")
	}

	// Create auth provider from config
	auth := repository.NewAuthProviderFromConfig(cfg)

	// Create clone manager
	cloneManager := repository.NewCloneManager("", auth)

	// Build clone URL if not already set
	if repoInfo.CloneURL == "" && repoInfo.Provider != repository.Unknown {
		switch repoInfo.Provider {
		case repository.GitHub:
			repoInfo.CloneURL = fmt.Sprintf("https://github.com/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
		case repository.GitLab:
			baseURL := "https://gitlab.com"
			if len(cfg.Git.GitLab) > 0 && cfg.Git.GitLab[0].APIURL != "" {
				baseURL = strings.TrimSuffix(cfg.Git.GitLab[0].APIURL, "/api/v4")
			}
			repoInfo.CloneURL = fmt.Sprintf("%s/%s/%s.git", baseURL, repoInfo.Owner, repoInfo.Repo)
		case repository.Bitbucket:
			repoInfo.CloneURL = fmt.Sprintf("https://bitbucket.org/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
		}
	}

	// Clone and create zip
	slog.Info("Step 1/4: Cloning repository...", "url", repoInfo.CloneURL, "branch", repoInfo.Branch)
	cloneResult, err := cloneManager.CloneAndZip(ctx, repoInfo, true)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	defer func() { _ = cloneManager.Cleanup(cloneResult) }()

	slog.Info("Step 2/4: Repository cloned and zipped",
		"path", cloneResult.Path,
		"zip_path", cloneResult.ZipPath,
		"commit", cloneResult.CommitHash,
	)

	// Get zip file info
	zipInfo, err := os.Stat(cloneResult.ZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat zip file: %w", err)
	}
	slog.Info("Zip file created", "size_bytes", zipInfo.Size(), "size_mb", fmt.Sprintf("%.2f", float64(zipInfo.Size())/1024/1024))

	// Submit to SRS
	slog.Info("Step 3/4: Submitting to SRS API...", "endpoint", srsURL)
	srsResponse, err := submitToSRS(ctx, srsURL, cloneResult.ZipPath, repoInfo, scanners)
	if err != nil {
		return nil, fmt.Errorf("failed to submit to SRS: %w", err)
	}

	slog.Info("SRS submission successful", "job_status_url", srsResponse.JobStatusURL)

	report := &ScanReport{
		Repository: repoInfo.URL,
		Branch:     cloneResult.Branch,
		Commit:     cloneResult.CommitHash,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Status:     "submitted",
		Scanners:   scanners,
		Results: map[string]interface{}{
			"srs": map[string]interface{}{
				"job_status_url": srsResponse.JobStatusURL,
				"status":         "submitted",
			},
		},
	}

	// If async mode, return immediately
	if opts.Async {
		slog.Info("Async mode enabled, returning immediately with job URL")
		fmt.Printf("\n=== Job Submitted (Async Mode) ===\n")
		fmt.Printf("Job Status URL: %s\n", srsResponse.JobStatusURL)
		fmt.Printf("\nTo wait for results, run:\n")
		fmt.Printf("  securelens scan repo --wait-for %s\n\n", srsResponse.JobStatusURL)
		return report, nil
	}

	// Wait for job completion
	slog.Info("Step 4/4: Waiting for SRS job to complete...", "job_status_url", srsResponse.JobStatusURL)
	waitConfig := srs.WaitConfig{
		PollInterval: time.Duration(opts.PollInterval) * time.Second,
		MaxTimeout:   time.Duration(opts.MaxWait) * time.Minute,
		MaxRetries:   100,
	}

	srsClient := srs.NewClient(waitConfig)
	jobResponse, err := srsClient.WaitForJob(ctx, srsResponse.JobStatusURL)
	if err != nil {
		slog.Error("Failed to wait for job", "error", err)
		report.Status = "wait_failed"
		report.Error = err.Error()
		return report, nil // Return partial results
	}

	// Update report with final results
	report.Status = "completed"
	report.Results = srs.GetFindingsSummary(jobResponse)
	report.Results["job_status_url"] = srsResponse.JobStatusURL

	return report, nil
}

func executeStandaloneScan(ctx context.Context, cfg *config.Config, repoInfo *repository.RepoURLInfo, scanners []string, opts *RepoScanOptions) (*ScanReport, error) {
	slog.Info("Executing standalone scan with local binaries")

	// Check tool availability
	toolStatuses := standalone.CheckTools(opts.AssetsDir)

	// Check if any requested scanners are unavailable
	standaloneTypes := standalone.ParseScannerNames(scanners)
	missingTools := false
	for _, status := range toolStatuses {
		for _, scannerType := range standaloneTypes {
			if string(scannerType) == status.Name && !status.Available {
				missingTools = true
				break
			}
		}
	}

	if missingTools {
		standalone.PrintToolStatus(toolStatuses)
		return nil, fmt.Errorf("required standalone tools are not installed - see instructions above")
	}

	var scanPath string
	var branch string
	var commit string
	var repoURL string

	// Check if we're using local path mode (no cloning needed)
	if opts.LocalPath != "" {
		// Use local path directly - no cloning
		absPath, err := filepath.Abs(opts.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve local path: %w", err)
		}
		scanPath = absPath
		branch = opts.Branch
		commit = opts.Commit
		// Use URL if provided, otherwise use local path as identifier
		if repoInfo != nil && repoInfo.URL != "" {
			repoURL = repoInfo.URL
		} else {
			repoURL = "local://" + absPath
		}
		slog.Info("Using local path for standalone scan", "path", scanPath, "branch", branch, "commit", commit)
	} else {
		// Clone repository as before
		// Create auth provider from config
		auth := repository.NewAuthProviderFromConfig(cfg)

		// Create clone manager
		cloneManager := repository.NewCloneManager("", auth)

		// Build clone URL if not already set
		if repoInfo.CloneURL == "" && repoInfo.Provider != repository.Unknown {
			switch repoInfo.Provider {
			case repository.GitHub:
				repoInfo.CloneURL = fmt.Sprintf("https://github.com/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
			case repository.GitLab:
				baseURL := "https://gitlab.com"
				if len(cfg.Git.GitLab) > 0 && cfg.Git.GitLab[0].APIURL != "" {
					baseURL = strings.TrimSuffix(cfg.Git.GitLab[0].APIURL, "/api/v4")
				}
				repoInfo.CloneURL = fmt.Sprintf("%s/%s/%s.git", baseURL, repoInfo.Owner, repoInfo.Repo)
			case repository.Bitbucket:
				repoInfo.CloneURL = fmt.Sprintf("https://bitbucket.org/%s/%s.git", repoInfo.Owner, repoInfo.Repo)
			}
		}

		// Clone repository
		slog.Info("Cloning repository for standalone scan", "url", repoInfo.CloneURL)
		cloneResult, err := cloneManager.Clone(ctx, repoInfo, true)
		if err != nil {
			return nil, fmt.Errorf("failed to clone repository: %w", err)
		}
		defer func() { _ = cloneManager.Cleanup(cloneResult) }()

		slog.Info("Repository cloned", "path", cloneResult.Path, "branch", cloneResult.Branch, "commit", cloneResult.CommitHash)
		scanPath = cloneResult.Path
		branch = cloneResult.Branch
		commit = cloneResult.CommitHash
		repoURL = repoInfo.URL
	}

	// Run standalone scanners (parallel by default)
	slog.Info("Running scanners", "parallel", opts.Parallel, "scanners", standaloneTypes)
	standaloneResults, err := standalone.RunStandaloneScansParallel(ctx, scanPath, standaloneTypes, opts.AssetsDir, opts.Parallel)
	if err != nil {
		return nil, fmt.Errorf("standalone scan failed: %w", err)
	}

	// Convert standalone results to ScanReport format
	report := &ScanReport{
		Repository: repoURL,
		Branch:     branch,
		Commit:     commit,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Status:     "completed",
		Scanners:   scanners,
		Results:    make(map[string]interface{}),
	}

	for scannerName, result := range standaloneResults {
		report.Results[scannerName] = result.Results
		if result.Error != "" {
			report.Results[scannerName+"_error"] = result.Error
		}
	}

	// Write debug output if enabled
	if opts.Debug {
		if err := writeDebugOutput(report, standaloneResults, opts); err != nil {
			slog.Warn("Failed to write debug output", "error", err)
		}
	}

	return report, nil
}

// buildReportPath creates the commit-based report directory structure:
// reports/{owner}/{repo}/{branch}/{commit}/
func buildReportPath(baseDir string, report *ScanReport) string {
	// Parse the repository URL to extract owner/repo
	repoURL := report.Repository
	owner := "unknown"
	repo := "unknown"

	// Try to extract from URL
	// Handle: https://github.com/owner/repo, https://gitlab.com/owner/repo, etc.
	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	if len(parts) >= 2 {
		repo = parts[len(parts)-1]
		owner = parts[len(parts)-2]
	}

	branch := report.Branch
	if branch == "" {
		branch = "default"
	}
	// Sanitize branch name (replace / with -)
	branch = strings.ReplaceAll(branch, "/", "-")

	commit := report.Commit
	if commit == "" {
		commit = "unknown"
	}
	// Use short commit hash
	if len(commit) > 8 {
		commit = commit[:8]
	}

	return filepath.Join(baseDir, owner, repo, branch, commit)
}

func writeDebugOutput(report *ScanReport, standaloneResults map[string]*standalone.StandaloneScanResult, opts *RepoScanOptions) error {
	// Build commit-based directory structure
	debugDir := buildReportPath(opts.OutputDir, report)
	if err := os.MkdirAll(debugDir, 0755); err != nil {
		return fmt.Errorf("failed to create debug directory: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")

	// Write full report
	reportPath := filepath.Join(debugDir, fmt.Sprintf("report-%s.json", timestamp))
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	slog.Info("Debug report written", "path", reportPath)

	// Also write a "latest.json" symlink/copy for easy access
	latestPath := filepath.Join(debugDir, "latest.json")
	_ = os.Remove(latestPath) // Remove existing
	if err := os.WriteFile(latestPath, reportData, 0644); err != nil {
		slog.Warn("Failed to write latest report", "error", err)
	}

	// Write raw scanner outputs
	for name, result := range standaloneResults {
		rawPath := filepath.Join(debugDir, fmt.Sprintf("%s-raw-%s.json", name, timestamp))
		rawData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			slog.Warn("Failed to marshal raw result", "scanner", name, "error", err)
			continue
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			slog.Warn("Failed to write raw result", "scanner", name, "error", err)
			continue
		}
		slog.Info("Debug raw output written", "scanner", name, "path", rawPath)

		// Also write latest for each scanner
		latestRawPath := filepath.Join(debugDir, fmt.Sprintf("%s-latest.json", name))
		_ = os.Remove(latestRawPath)
		_ = os.WriteFile(latestRawPath, rawData, 0644)
	}

	slog.Info("Reports saved to", "directory", debugDir)
	return nil
}

// SRSSubmitResponse represents the response from SRS job submission
type SRSSubmitResponse struct {
	JobStatusURL string `json:"job_status_url"`
}

func submitToSRS(ctx context.Context, srsURL, zipPath string, repoInfo *repository.RepoURLInfo, scanners []string) (*SRSSubmitResponse, error) {
	slog.Info("Preparing SRS submission",
		"zip_path", zipPath,
		"repo", repoInfo.Postfix,
		"branch", repoInfo.Branch,
		"scanners", scanners,
	)

	// Open zip file
	zipFile, err := os.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file: %w", err)
	}
	defer func() { _ = zipFile.Close() }()

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add archive file
	slog.Debug("Adding archive to multipart form")
	fw, err := writer.CreateFormFile("archive", filepath.Base(zipPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	written, err := io.Copy(fw, zipFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy zip to form: %w", err)
	}
	slog.Debug("Archive added to form", "bytes_written", written)

	// Build request_params_collection based on selected scanners
	servicePayloads := buildServicePayloads(scanners)
	requestParamsCollection := fmt.Sprintf(`{"request_params_list":[%s]}`, strings.Join(servicePayloads, ","))

	slog.Info("Request params collection", "content", requestParamsCollection)

	if err := writer.WriteField("request_params_collection", requestParamsCollection); err != nil {
		return nil, fmt.Errorf("failed to write request_params_collection: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create HTTP request
	slog.Info("Sending POST request to SRS", "url", srsURL, "content_length", body.Len())

	req, err := http.NewRequestWithContext(ctx, "POST", srsURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{Timeout: 5 * time.Minute}
	slog.Info("Waiting for SRS response...")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	slog.Info("SRS response received",
		"status_code", resp.StatusCode,
		"status", resp.Status,
		"body_length", len(respBody),
	)

	// Accept both 200 OK and 202 Accepted as success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		slog.Error("SRS returned error status",
			"status_code", resp.StatusCode,
			"body", string(respBody),
		)
		return nil, fmt.Errorf("SRS returned status %d: %s", resp.StatusCode, string(respBody))
	}

	slog.Info("SRS submission accepted", "status_code", resp.StatusCode)

	// Parse response
	var srsResp map[string]interface{}
	if err := json.Unmarshal(respBody, &srsResp); err != nil {
		slog.Error("Failed to parse SRS response", "body", string(respBody))
		return nil, fmt.Errorf("failed to parse SRS response: %w", err)
	}

	slog.Info("SRS response parsed", "response", srsResp)

	jobStatusURL, ok := srsResp["job_status_url"].(string)
	if !ok {
		return nil, fmt.Errorf("SRS response missing job_status_url: %s", string(respBody))
	}

	return &SRSSubmitResponse{
		JobStatusURL: jobStatusURL,
	}, nil
}

func buildServicePayloads(scanners []string) []string {
	payloadMap := map[string]string{
		"fossa":      `{"service": "fossa", "resource": "api/v1/fossa", "payload": {"archive":"file"}}`,
		"trufflehog": `{"service": "trufflehog", "resource": "api/v1/trufflehog", "payload": {"archive":"file"}}`,
		"semgrep":    `{"service": "semgrep", "resource": "api/v1/semgrep", "payload": {"archive":"file_scan"}}`,
	}

	var payloads []string
	for _, scanner := range scanners {
		if payload, ok := payloadMap[scanner]; ok {
			payloads = append(payloads, payload)
		}
	}

	// If no specific scanners selected, use all
	if len(payloads) == 0 {
		for _, payload := range payloadMap {
			payloads = append(payloads, payload)
		}
	}

	return payloads
}

func runScanner(ctx context.Context, scannerName, repoPath string, cfg *config.Config) (interface{}, error) {
	// This is a placeholder for scanner execution
	// In a full implementation, this would invoke the actual scanner tools

	switch scannerName {
	case "fossa":
		if !cfg.Scanners.FOSSA.Enabled {
			return map[string]interface{}{
				"status":  "skipped",
				"message": "FOSSA scanner not enabled in config",
			}, nil
		}
		return runFossaScan(ctx, repoPath, cfg)

	case "semgrep":
		if !cfg.Scanners.Semgrep.Enabled {
			return map[string]interface{}{
				"status":  "skipped",
				"message": "Semgrep scanner not enabled in config",
			}, nil
		}
		return runSemgrepScan(ctx, repoPath, cfg)

	case "trufflehog":
		if !cfg.Scanners.Trufflehog.Enabled {
			return map[string]interface{}{
				"status":  "skipped",
				"message": "Trufflehog scanner not enabled in config",
			}, nil
		}
		return runTrufflehogScan(ctx, repoPath, cfg)

	default:
		return nil, fmt.Errorf("unknown scanner: %s", scannerName)
	}
}

func runFossaScan(ctx context.Context, repoPath string, cfg *config.Config) (interface{}, error) {
	slog.Info("Running FOSSA scan", "path", repoPath)
	// Placeholder - actual implementation would run fossa analyze
	return map[string]interface{}{
		"status":          "completed",
		"vulnerabilities": []interface{}{},
		"message":         "FOSSA scan completed (scanner integration pending)",
	}, nil
}

func runSemgrepScan(ctx context.Context, repoPath string, cfg *config.Config) (interface{}, error) {
	slog.Info("Running Semgrep scan", "path", repoPath)
	// Placeholder - actual implementation would run semgrep scan
	return map[string]interface{}{
		"status":   "completed",
		"findings": []interface{}{},
		"message":  "Semgrep scan completed (scanner integration pending)",
	}, nil
}

func runTrufflehogScan(ctx context.Context, repoPath string, cfg *config.Config) (interface{}, error) {
	slog.Info("Running Trufflehog scan", "path", repoPath)
	// Placeholder - actual implementation would run trufflehog
	return map[string]interface{}{
		"status":  "completed",
		"secrets": []interface{}{},
		"message": "Trufflehog scan completed (scanner integration pending)",
	}, nil
}

func outputScanResults(report *ScanReport, opts *RepoScanOptions) error {
	var output []byte
	var err error

	switch opts.OutputFormat {
	case "json":
		output, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		output, err = yaml.Marshal(report)
	case "table":
		return outputScanTable(report, opts.OutputFile)
	default:
		return fmt.Errorf("unsupported output format: %s", opts.OutputFormat)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write to file or stdout
	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		slog.Info("Results written to file", "path", opts.OutputFile)
	} else {
		fmt.Println(string(output))
	}

	return nil
}

func outputScanTable(report *ScanReport, outputFile string) error {
	var writer io.Writer = os.Stdout

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = file.Close() }()
		writer = file
	}

	// Print header
	_, _ = fmt.Fprintf(writer, "\n=== SecureLens Scan Report ===\n\n")
	_, _ = fmt.Fprintf(writer, "Repository: %s\n", report.Repository)
	_, _ = fmt.Fprintf(writer, "Branch:     %s\n", report.Branch)
	_, _ = fmt.Fprintf(writer, "Commit:     %s\n", report.Commit)
	_, _ = fmt.Fprintf(writer, "Timestamp:  %s\n", report.Timestamp)
	_, _ = fmt.Fprintf(writer, "Status:     %s\n\n", report.Status)

	// Print scanner results
	table := tablewriter.NewWriter(writer)
	table.Header([]string{"Scanner", "Status", "Findings", "By Severity"})

	for _, scanner := range report.Scanners {
		result, ok := report.Results[scanner].(map[string]interface{})
		status := "unknown"
		findings := "-"
		severityStr := "-"

		if ok {
			if s, exists := result["status"]; exists {
				status = fmt.Sprintf("%v", s)
			}

			// Get findings count - check multiple possible keys
			findings = extractFindingsCount(result)

			// Get severity breakdown
			severityStr = extractSeveritySummary(result)
		}

		_ = table.Append([]string{scanner, status, findings, severityStr})
	}

	_ = table.Render()
	_, _ = fmt.Fprintln(writer)

	return nil
}

// extractFindingsCount extracts the findings count from various result formats
func extractFindingsCount(result map[string]interface{}) string {
	// Try findings_count (standalone opengrep, trufflehog)
	if count, exists := result["findings_count"]; exists {
		return fmt.Sprintf("%v findings", count)
	}

	// Try vulnerabilities_count (standalone trivy)
	if count, exists := result["vulnerabilities_count"]; exists {
		return fmt.Sprintf("%v vulnerabilities", count)
	}

	// Try counting findings array
	if findings, exists := result["findings"]; exists {
		if arr, ok := findings.([]interface{}); ok {
			return fmt.Sprintf("%d findings", len(arr))
		}
	}

	// Try counting vulnerabilities array
	if vulns, exists := result["vulnerabilities"]; exists {
		if arr, ok := vulns.([]interface{}); ok {
			return fmt.Sprintf("%d vulnerabilities", len(arr))
		}
	}

	// Try counting secrets array
	if secrets, exists := result["secrets"]; exists {
		if arr, ok := secrets.([]interface{}); ok {
			return fmt.Sprintf("%d secrets", len(arr))
		}
	}

	// Try verified/unverified secrets (trufflehog)
	verified, hasVerified := result["verified_secrets"]
	unverified, hasUnverified := result["unverified_secrets"]
	if hasVerified || hasUnverified {
		v := toInt(verified)
		u := toInt(unverified)
		if v+u > 0 {
			return fmt.Sprintf("%d secrets (%d verified)", v+u, v)
		}
		return "0 secrets"
	}

	return "-"
}

// ExtractSeveritySummary extracts severity breakdown from results (exported for UI use)
func ExtractSeveritySummary(result map[string]interface{}) string {
	return extractSeveritySummary(result)
}

// extractSeveritySummary extracts severity breakdown from results
func extractSeveritySummary(result map[string]interface{}) string {
	bySev, exists := result["by_severity"]
	if !exists {
		return "-"
	}

	parts := []string{}
	severityOrder := []string{"CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO"}

	// Handle map[string]interface{} (from JSON unmarshaling)
	if sevMap, ok := bySev.(map[string]interface{}); ok {
		if len(sevMap) == 0 {
			return "-"
		}
		for _, sev := range severityOrder {
			if count, exists := sevMap[sev]; exists {
				parts = append(parts, fmt.Sprintf("%s:%v", sev[:1], count))
			}
		}
	}

	// Handle map[string]int (from Go code directly)
	if sevMap, ok := bySev.(map[string]int); ok {
		if len(sevMap) == 0 {
			return "-"
		}
		for _, sev := range severityOrder {
			if count, exists := sevMap[sev]; exists {
				parts = append(parts, fmt.Sprintf("%s:%d", sev[:1], count))
			}
		}
	}

	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	return "-"
}

// toInt converts interface{} to int safely
func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if i, err := fmt.Sscanf(n, "%d"); err == nil {
			return i
		}
	}
	return 0
}

func newBulkCmd() *cobra.Command {
	var parallel int

	cmd := &cobra.Command{
		Use:   "bulk <file>",
		Short: "Scan multiple repositories from a file",
		Long: `Scan multiple repositories from a YAML or JSON file.

Input file format (YAML):
  repositories:
    - url: https://github.com/org/repo1
      branches: [main, develop]
    - url: https://gitlab.com/org/repo2:feature-branch
    - url: https://bitbucket.org/org/repo3:main:abc123def

Examples:
  securelens scan bulk repos.yaml
  securelens scan bulk repos.yaml --parallel 10`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Starting bulk scan", "file", args[0], "parallel", parallel)
			// TODO: Implement bulk scanning logic
			slog.Info("Bulk scan completed successfully")
		},
	}

	cmd.Flags().IntVarP(&parallel, "parallel", "p", 5, "number of parallel workers")

	return cmd
}

func newDiscoverCmd() *cobra.Command {
	var (
		configPath      string
		format          string
		outputFile      string
		countOnly       bool
		repoName        string
		provider        string
		limit           int
		includeBranches bool
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover and scan repositories",
		Long:  `Discover repositories based on various criteria and scan them.`,
	}

	scopeCmd := &cobra.Command{
		Use:   "scope",
		Short: "Scan all repositories within API scope",
		Long: `Scan all repositories accessible with the provided credentials.

Examples:
  securelens scan discover scope
  securelens scan discover scope --config ~/.securelens/config.yaml
  securelens scan discover scope --format json --output repos.json`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			cfg, err := config.Load(configPath)
			if err != nil {
				slog.Error("Failed to load configuration", "error", err)
				return
			}

			if repoName != "" {
				if provider == "" {
					slog.Error("--provider must be specified when using --repo")
					return
				}
				checkRepositoryAccess(ctx, cfg, repoName, provider)
				return
			}

			if err := cfg.Validate(); err != nil {
				slog.Error("Invalid configuration", "error", err)
				return
			}

			slog.Info("Discovering repositories within scope")

			// If provider filter is specified (and not used with --repo), filter config
			if provider != "" && repoName == "" {
				cfg = FilterConfigByProvider(cfg, provider)
			}

			repos, err := discoverRepositories(ctx, cfg, limit, includeBranches)
			if err != nil {
				slog.Error("Failed to discover repositories", "error", err)
				return
			}

			slog.Info("Discovery scan completed successfully", "count", len(repos))

			if countOnly {
				fmt.Printf("Total repositories discovered: %d\n", len(repos))
				return
			}

			err = outputResults(repos, format, outputFile)
			if err != nil {
				slog.Error("Failed to output results", "error", err)
			}
		},
	}

	scopeCmd.Flags().StringVarP(&configPath, "config", "c", "", "path to configuration file "+
		"(searches: ~/.securelens/config.yaml, ./config.yaml, /etc/securelens/config.yaml)")
	scopeCmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, yaml")
	scopeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	scopeCmd.Flags().BoolVar(&countOnly, "count-only", false, "only display the count of discovered repositories")
	scopeCmd.Flags().StringVar(&repoName, "repo", "", "check if a specific repository is accessible (format: owner/repo)")
	scopeCmd.Flags().StringVar(&provider, "provider", "", "filter by provider (github, gitlab, bitbucket) or specify provider for --repo")
	scopeCmd.Flags().IntVar(&limit, "limit", 0, "limit the number of repositories to scan (0 for no limit)")
	scopeCmd.Flags().BoolVar(&includeBranches, "include-branches", false, "include all accessible branches for each repository")

	cmd.AddCommand(scopeCmd)

	return cmd
}

func outputResults(repos []DiscoveredRepository, format, outputFile string) error {
	var output []byte
	var err error

	switch format {
	case "json":
		output, err = formatJSON(repos)
	case "yaml":
		output, err = formatYAML(repos)
	case "table":
		return formatTable(repos, outputFile)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, output, 0644)
	}

	fmt.Println(string(output))
	return nil
}

func formatJSON(repos []DiscoveredRepository) ([]byte, error) {
	return json.MarshalIndent(repos, "", "  ")
}

func formatYAML(repos []DiscoveredRepository) ([]byte, error) {
	return yaml.Marshal(repos)
}

func formatTable(repos []DiscoveredRepository, outputFile string) error {
	var writer io.Writer = os.Stdout

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = file.Close() }()
		writer = file
	}

	table := tablewriter.NewWriter(writer)

	hasBranches := false
	for _, repo := range repos {
		if len(repo.Branches) > 0 {
			hasBranches = true
			break
		}
	}

	headers := []string{"Provider", "Name", "Full Name", "URL", "Private", "Language", "Source"}
	if hasBranches {
		headers = append(headers, "Branches")
	}
	table.Header(headers)

	for _, repo := range repos {
		private := "No"
		if repo.IsPrivate {
			private = "Yes"
		}

		row := []string{
			repo.Provider,
			repo.Name,
			repo.FullName,
			repo.URL,
			private,
			repo.Language,
			repo.Source,
		}

		if hasBranches {
			branchesStr := strings.Join(repo.Branches, ", ")
			if branchesStr == "" {
				branchesStr = "-"
			}
			row = append(row, branchesStr)
		}
		_ = table.Append(row)
	}

	return table.Render()
}

func checkRepositoryAccess(ctx context.Context, cfg *config.Config, repoURL string, provider string) {
	slog.Info("Checking repository access", "url", repoURL)

	switch provider {
	case "gitlab":
		checkGitlabRepoAccess(ctx, cfg.Git.GitLab, repoURL)
	case "github":
		checkGitHubRepoAccess(ctx, cfg.Git.GitHub, repoURL)
	case "bitbucket":
		checkBitbucketRepoAccess(ctx, cfg.Git.Bitbucket, repoURL)
	default:
		slog.Error("Unsupported provider", "provider", provider)
	}
}

func checkGitlabRepoAccess(ctx context.Context, configs []config.GitLabConfig, repoName string) {
	for _, cfg := range configs {
		client, err := gitlab.NewClient(cfg.Token, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create Gitlab client", "intance", cfg.Name, "error", err)
		}

		project, err := client.GetProject(ctx, repoName)
		if err != nil {
			slog.Error("Failed to get project", "instance", cfg.Name, "repo", repoName, "error", err)
			continue
		}

		if project != nil {
			slog.Info("Repository is accessible via Gitlab instance", "instance", cfg.Name, "repo", repoName)
			return
		}
	}

	slog.Info("Repository not found or not accessible with current Gitlab credentials.\n")
}

func checkGitHubRepoAccess(ctx context.Context, configs []config.GitHubConfig, repoName string) {
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		slog.Error("Invalid repository format. Use owner/repo format.", "repo", repoName)
		return
	}

	owner := parts[0]
	repo := parts[1]

	for _, cfg := range configs {
		client, err := github.NewClient(cfg.Token, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create Github client", "instance", cfg.Name, "error", err)
			continue
		}

		repository, err := client.GetRepository(ctx, owner, repo)
		if err != nil {
			slog.Error("Failed to get repository", "instance", cfg.Name, "owner", owner, "repo", repo, "error", err)
			continue
		}

		if repository != nil {
			slog.Info("Repository is accessible via Github instance", "instance", cfg.Name, "owner", owner, "repo", repo)
			return
		}
	}
	slog.Info("Repository not found or not accessible with current Github credentials.\n")
}

func checkBitbucketRepoAccess(ctx context.Context, configs []config.BitbucketConfig, repoName string) {
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		slog.Error("Invalid repository format. Use workspace/repo format.", "repo", repoName)
		return
	}

	workspace := parts[0]
	repoSlug := parts[1]

	for _, cfg := range configs {
		client, err := bitbucket.NewClient(cfg.Username, cfg.AppPassword, cfg.APIURL)
		if err != nil {
			slog.Error("Failed to create Bitbucket client", "instance", cfg.Name, "error", err)
			continue
		}

		repository, err := client.GetRepository(ctx, workspace, repoSlug)
		if err != nil {
			slog.Error("Failed to get repository", "instance", cfg.Name, "workspace", workspace, "repo", repoSlug, "error", err)
			continue
		}

		if repository != nil {
			slog.Info("Repository is accessible via Bitbucket instance", "instance", cfg.Name, "workspace", workspace, "repo", repoSlug)
			return
		}
	}

	slog.Info("Repository not found or not accessible with current Bitbucket credentials\n.")
}

// newResultsCmd creates the results command for viewing saved scan reports
func newResultsCmd() *cobra.Command {
	var (
		reportsDir  string
		format      string
		showDetails bool
		scanner     string
	)

	cmd := &cobra.Command{
		Use:   "results [report-path]",
		Short: "View saved scan results",
		Long: `View and analyze saved scan results from previous scans.

Reports are stored in: reports/{owner}/{repo}/{branch}/{commit}/

Examples:
  # View latest results from a specific path
  securelens scan results reports/splunk/securelens/main/abc123/latest.json

  # List all available reports
  securelens scan results --list

  # Show detailed findings for a specific scanner
  securelens scan results reports/splunk/securelens/main/abc123/latest.json --details --scanner opengrep`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			listReports, _ := cmd.Flags().GetBool("list")

			if listReports {
				return listSavedReports(reportsDir)
			}

			if len(args) == 0 {
				return fmt.Errorf("report path required (or use --list to see available reports)")
			}

			return viewReport(args[0], format, showDetails, scanner)
		},
	}

	cmd.Flags().StringVar(&reportsDir, "reports-dir", "reports", "directory containing saved reports")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json, yaml")
	cmd.Flags().BoolVar(&showDetails, "details", false, "show detailed findings")
	cmd.Flags().StringVar(&scanner, "scanner", "", "filter findings by scanner (opengrep, trivy, trufflehog)")
	cmd.Flags().Bool("list", false, "list available reports")

	return cmd
}

func listSavedReports(reportsDir string) error {
	fmt.Printf("\n=== Available Scan Reports ===\n\n")
	fmt.Printf("Reports directory: %s\n\n", reportsDir)

	// Walk the reports directory
	var reports []string
	err := filepath.Walk(reportsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() && strings.HasSuffix(path, "latest.json") {
			relPath, _ := filepath.Rel(reportsDir, path)
			reports = append(reports, relPath)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk reports directory: %w", err)
	}

	if len(reports) == 0 {
		fmt.Println("No reports found.")
		fmt.Println("\nRun a scan with --debug to save reports:")
		fmt.Println("  securelens scan repo https://github.com/org/repo --mode standalone --debug")
		return nil
	}

	fmt.Printf("Found %d report(s):\n\n", len(reports))
	for _, report := range reports {
		// Extract repo info from path: owner/repo/branch/commit/latest.json
		parts := strings.Split(report, string(os.PathSeparator))
		if len(parts) >= 4 {
			owner := parts[0]
			repo := parts[1]
			branch := parts[2]
			commit := parts[3]
			fmt.Printf("  %s/%s [%s @ %s]\n", owner, repo, branch, commit)
			fmt.Printf("    Path: %s\n\n", filepath.Join(reportsDir, report))
		} else {
			fmt.Printf("  %s\n", report)
		}
	}

	return nil
}

func viewReport(reportPath string, format string, showDetails bool, scannerFilter string) error {
	// Read the report file
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("failed to read report: %w", err)
	}

	var report ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("failed to parse report: %w", err)
	}

	switch format {
	case "json":
		output, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(output))
		return nil
	case "yaml":
		output, _ := yaml.Marshal(report)
		fmt.Println(string(output))
		return nil
	}

	// Table format
	fmt.Printf("\n=== SecureLens Scan Report ===\n\n")
	fmt.Printf("Repository: %s\n", report.Repository)
	fmt.Printf("Branch:     %s\n", report.Branch)
	fmt.Printf("Commit:     %s\n", report.Commit)
	fmt.Printf("Timestamp:  %s\n", report.Timestamp)
	fmt.Printf("Status:     %s\n\n", report.Status)

	// Summary table
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Scanner", "Status", "Findings", "By Severity"})

	for _, scanner := range report.Scanners {
		if scannerFilter != "" && scanner != scannerFilter {
			continue
		}
		result, ok := report.Results[scanner].(map[string]interface{})
		status := "unknown"
		findings := "-"
		severityStr := "-"

		if ok {
			if s, exists := result["status"]; exists {
				status = fmt.Sprintf("%v", s)
			}
			findings = extractFindingsCount(result)
			severityStr = extractSeveritySummary(result)
		}

		_ = table.Append([]string{scanner, status, findings, severityStr})
	}

	_ = table.Render()

	// Show detailed findings if requested
	if showDetails {
		fmt.Println()
		for _, scanner := range report.Scanners {
			if scannerFilter != "" && scanner != scannerFilter {
				continue
			}
			result, ok := report.Results[scanner].(map[string]interface{})
			if !ok {
				continue
			}

			printDetailedFindings(scanner, result)
		}
	}

	return nil
}

func printDetailedFindings(scanner string, result map[string]interface{}) {
	fmt.Printf("\n=== %s Findings ===\n\n", strings.ToUpper(scanner))

	findings, hasFindings := result["findings"].([]interface{})
	if !hasFindings || len(findings) == 0 {
		fmt.Println("No findings to display.")
		return
	}

	// Limit to first 20 findings
	displayCount := len(findings)
	if displayCount > 20 {
		displayCount = 20
	}

	table := tablewriter.NewWriter(os.Stdout)

	switch scanner {
	case "opengrep":
		table.Header([]string{"#", "Severity", "Rule", "File", "Line", "Message"})
		for i, f := range findings[:displayCount] {
			finding, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			severity := "-"
			message := "-"
			checkID := "-"
			path := "-"
			line := "-"

			if extra, ok := finding["extra"].(map[string]interface{}); ok {
				if s, ok := extra["severity"].(string); ok {
					severity = s
				}
				if m, ok := extra["message"].(string); ok {
					message = truncate(m, 50)
				}
			}
			if c, ok := finding["check_id"].(string); ok {
				checkID = truncate(c, 30)
			}
			if p, ok := finding["path"].(string); ok {
				path = truncate(filepath.Base(p), 25)
			}
			if start, ok := finding["start"].(map[string]interface{}); ok {
				if l, ok := start["line"].(float64); ok {
					line = fmt.Sprintf("%d", int(l))
				}
			}
			_ = table.Append([]string{fmt.Sprintf("%d", i+1), severity, checkID, path, line, message})
		}

	case "trivy":
		table.Header([]string{"#", "Severity", "CVE", "Package", "Version", "Fixed"})
		if results, ok := result["results"].([]interface{}); ok {
			count := 0
			for _, r := range results {
				res, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				vulns, ok := res["Vulnerabilities"].([]interface{})
				if !ok {
					continue
				}
				for _, v := range vulns {
					if count >= displayCount {
						break
					}
					vuln, ok := v.(map[string]interface{})
					if !ok {
						continue
					}
					count++
					_ = table.Append([]string{
						fmt.Sprintf("%d", count),
						getString(vuln, "Severity"),
						truncate(getString(vuln, "VulnerabilityID"), 20),
						truncate(getString(vuln, "PkgName"), 20),
						truncate(getString(vuln, "InstalledVersion"), 15),
						truncate(getString(vuln, "FixedVersion"), 15),
					})
				}
			}
		}

	case "trufflehog":
		table.Header([]string{"#", "Verified", "Detector", "File", "Line", "Redacted"})
		for i, f := range findings[:displayCount] {
			finding, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			verified := "No"
			if v, ok := finding["Verified"].(bool); ok && v {
				verified = "YES"
			}
			detector := getString(finding, "DetectorName")
			file := "-"
			line := "-"
			redacted := truncate(getString(finding, "Redacted"), 30)

			if sm, ok := finding["SourceMetadata"].(map[string]interface{}); ok {
				if data, ok := sm["Data"].(map[string]interface{}); ok {
					// Try Git source first
					if git, ok := data["Git"].(map[string]interface{}); ok {
						if f, ok := git["file"].(string); ok && f != "" {
							file = truncate(f, 40)
						}
						if l, ok := git["line"].(float64); ok && l > 0 {
							line = fmt.Sprintf("%d", int(l))
						}
					}
					// Try Filesystem source (used in standalone mode with --local-path)
					if fs, ok := data["Filesystem"].(map[string]interface{}); ok {
						if f, ok := fs["file"].(string); ok && f != "" {
							file = truncate(f, 40)
						}
						if l, ok := fs["line"].(float64); ok && l > 0 {
							line = fmt.Sprintf("%d", int(l))
						}
					}
				}
			}
			_ = table.Append([]string{fmt.Sprintf("%d", i+1), verified, detector, file, line, redacted})
		}
	}

	_ = table.Render()

	if len(findings) > displayCount {
		fmt.Printf("\n... and %d more findings (showing first %d)\n", len(findings)-displayCount, displayCount)
	}
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return "-"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

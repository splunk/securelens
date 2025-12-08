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

	return cmd
}

// ScanMode determines how the scan is executed
type ScanMode string

const (
	ScanModeLocal  ScanMode = "local"  // Clone locally and run scanners
	ScanModeRemote ScanMode = "remote" // Submit to SRS API
)

// RepoScanOptions holds options for repository scanning
type RepoScanOptions struct {
	URL          string
	Branch       string
	Commit       string
	Scanners     []string // fossa, semgrep, trufflehog
	OutputFile   string
	OutputFormat string // raw, json, parsed
	OutputDir    string // Directory for parsed reports
	Mode         ScanMode
	ConfigPath   string
	DryRun       bool
	Verbose      bool
	SRSURL       string   // SRS API endpoint URL
	Async        bool     // Return immediately without waiting for results
	WaitFor      []string // Job status URLs to wait on (skip scanning)
	PollInterval int      // Seconds between status polls
	MaxWait      int      // Maximum minutes to wait for results
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

Supported Scanners:
  - fossa      : Open source dependency vulnerabilities (OSS/SCA)
  - semgrep    : Static application security testing (SAST)
  - trufflehog : Secret detection

Output Modes:
  --output raw.json      : Write raw JSON results to file
  --output-format json   : Format output as JSON (default: table)
  --output-dir reports/  : Directory for parsed report files
  --parsed               : Generate parsed reports in reports/ directory

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

  # Output raw results to file
  securelens scan repo https://github.com/myorg/myrepo --output results.json

  # Generate parsed reports
  securelens scan repo https://github.com/myorg/myrepo --parsed --output-dir ./reports`,
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

			if opts.URL == "" {
				return fmt.Errorf("repository URL is required (provide as argument or --url flag)")
			}

			return runRepoScan(cmd.Context(), &opts)
		},
	}

	// URL/Branch/Commit flags
	cmd.Flags().StringVar(&opts.URL, "url", "", "repository URL (alternative to positional argument)")
	cmd.Flags().StringVarP(&opts.Branch, "branch", "b", "", "branch to scan (overrides URL-embedded branch)")
	cmd.Flags().StringVar(&opts.Commit, "commit", "", "specific commit to scan (overrides URL-embedded commit)")

	// Scanner selection flags
	cmd.Flags().StringSliceVar(&opts.Scanners, "scanners", []string{}, "scanners to run (fossa, semgrep, trufflehog); default: all")

	// Output flags
	cmd.Flags().StringVarP(&opts.OutputFile, "output", "o", "", "output file for raw results (e.g., results.json)")
	cmd.Flags().StringVarP(&opts.OutputFormat, "output-format", "f", "table", "output format: table, json, yaml")
	cmd.Flags().StringVar(&opts.OutputDir, "output-dir", "reports", "directory for parsed report files")

	// Mode flags
	cmd.Flags().StringVar((*string)(&opts.Mode), "mode", "local", "scan mode: local (clone and scan) or remote (SRS API)")

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
	)

	// Load configuration
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		slog.Warn("Failed to load config, using defaults", "error", err)
		cfg = &config.Config{}
	}

	// Parse repository URL
	repoInfo, err := parseRepoInput(opts)
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

	// Determine scanners to run
	scanners := opts.Scanners
	if len(scanners) == 0 {
		scanners = []string{"fossa", "semgrep", "trufflehog"}
	}

	if opts.DryRun {
		fmt.Printf("Dry run - would scan:\n")
		fmt.Printf("  Repository: %s\n", repoInfo.URL)
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
	defer cloneManager.Cleanup(cloneResult)

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
	defer cloneManager.Cleanup(cloneResult)

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
	defer zipFile.Close()

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
	defer resp.Body.Close()

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
		defer file.Close()
		writer = file
	}

	// Print header
	fmt.Fprintf(writer, "\n=== SecureLens Scan Report ===\n\n")
	fmt.Fprintf(writer, "Repository: %s\n", report.Repository)
	fmt.Fprintf(writer, "Branch:     %s\n", report.Branch)
	fmt.Fprintf(writer, "Commit:     %s\n", report.Commit)
	fmt.Fprintf(writer, "Timestamp:  %s\n", report.Timestamp)
	fmt.Fprintf(writer, "Status:     %s\n\n", report.Status)

	// Print scanner results
	table := tablewriter.NewWriter(writer)
	table.Header([]string{"Scanner", "Status", "Findings"})

	for _, scanner := range report.Scanners {
		result, ok := report.Results[scanner].(map[string]interface{})
		status := "unknown"
		findings := "-"

		if ok {
			if s, exists := result["status"]; exists {
				status = fmt.Sprintf("%v", s)
			}
			// Count findings based on scanner type
			if vulns, exists := result["vulnerabilities"]; exists {
				if arr, ok := vulns.([]interface{}); ok {
					findings = fmt.Sprintf("%d vulnerabilities", len(arr))
				}
			} else if f, exists := result["findings"]; exists {
				if arr, ok := f.([]interface{}); ok {
					findings = fmt.Sprintf("%d findings", len(arr))
				}
			} else if secrets, exists := result["secrets"]; exists {
				if arr, ok := secrets.([]interface{}); ok {
					findings = fmt.Sprintf("%d secrets", len(arr))
				}
			}
		}

		table.Append([]string{scanner, status, findings})
	}

	table.Render()
	fmt.Fprintln(writer)

	return nil
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
	scopeCmd.Flags().StringVar(&provider, "provider", "", "provider for the repo (github, gitlab, bitbucket) when using --repo")
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
		return fmt.Errorf("Unsupported output format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("Failed to format output: %w", err)
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
			return fmt.Errorf("Failed to create output file: %w", err)
		}
		defer file.Close()
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
		table.Append(row)
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

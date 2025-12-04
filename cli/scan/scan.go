package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/lib/bitbucket"
	"github.com/splunk/securelens/lib/github"
	"github.com/splunk/securelens/lib/gitlab"
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

func discoverRepositories(ctx context.Context, cfg *config.Config, limit int, includeBranches bool) ([]DiscoveredRepository, error) {
	slog.Info("Starting repository discovery", "limit", limit)

	var allRepos []DiscoveredRepository
	remaining := limit

	limitReached := func() bool {
		return limit > 0 && len(allRepos) >= limit
	}

	// Gitlab
	if !limitReached() {
		gitlabRepos, err := discoverFromGitLab(ctx, cfg.Git.GitLab, remaining, includeBranches)
		if err != nil {
			slog.Error("Error discovering GitLab repositories", "error", err)
		} else {
			allRepos = append(allRepos, gitlabRepos...)
			if limit > 0 {
				remaining = limit - len(allRepos)
			}
			slog.Info("Discovered GitLab repositories", "count", len(gitlabRepos))
		}
	}

	// Github
	if !limitReached() {
		githubRepos, err := discoverFromGitHub(ctx, cfg.Git.GitHub, remaining, includeBranches)
		if err != nil {
			slog.Error("Error discovering GitHub repositories", "error", err)
		} else {
			allRepos = append(allRepos, githubRepos...)
			if limit > 0 {
				remaining = limit - len(allRepos)
			}
			slog.Info("Discovered GitHub repositories", "count", len(githubRepos))
		}
	}

	// Bitbucket
	if !limitReached() {
		bitbucketRepos, err := discoverFromBitbucket(ctx, cfg.Git.Bitbucket, remaining, includeBranches)
		if err != nil {
			slog.Error("Error discovering Bitbucket repositories", "error", err)
		} else {
			allRepos = append(allRepos, bitbucketRepos...)
			slog.Info("Discovered Bitbucket repositories", "count", len(bitbucketRepos))
		}
	}

	if limit > 0 && len(allRepos) > limit {
		allRepos = allRepos[:limit]
	}

	slog.Info("Repository discovery completed", "total_count", len(allRepos), "limit", limit)

	return allRepos, nil
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

			if includeBranches {
				branches, err := client.ListBranches(ctx, project.ID)
				if err != nil {
					slog.Warn("Failed to list Gitlab branches", "project", project.PathWithNS, "error", err)
				} else {
					discovered.Branches = branches
				}
			}
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

			if includeBranches {
				parts := strings.Split(repo.FullName, "/")
				if len(parts) == 2 {
					branches, err := client.ListBranches(ctx, parts[0], parts[1])
					if err != nil {
						slog.Warn("Failed to list GitHub branches", "repo", repo.FullName, "error", err)
					} else {
						discovered.Branches = branches
					}
				}
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

			if includeBranches {
				parts := strings.Split(repo.FullName, "/")
				if len(parts) == 2 {
					branches, err := client.ListBranches(ctx, parts[0], parts[1])
					if err != nil {
						slog.Warn("Failed to list Bitbucket branches", "repo", repo.FullName, "error", err)
					} else {
						discovered.Branches = branches
					}
				}
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

func newRepoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repo <url>",
		Short: "Scan a single repository",
		Long: `Scan a single repository for vulnerabilities.

Supported formats:
  - url: Scan default branch
  - url:branch: Scan specific branch
  - url:branch:commit: Scan specific commit

Examples:
  securelens scan repo https://github.com/myorg/myrepo
  securelens scan repo https://github.com/myorg/myrepo:develop
  securelens scan repo https://github.com/myorg/myrepo:main:abc123def`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Scanning repository", "url", args[0])
			// TODO: Implement repository scanning logic
			slog.Info("Repository scan completed successfully")
		},
	}
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

package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"
	"github.com/splunk/securelens/cli/scan"
	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/pkg/database"
)

var (
	providerName string
	allProviders bool
)

// NewIngestCmd creates the ingest command group
func NewIngestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Ingest data from providers into local database",
		Long: `Ingest data from configured providers (GitHub, GitLab, Bitbucket)
into the local SQLite database for offline browsing and analysis.

This allows the UI to work offline by caching repository metadata locally.`,
	}

	// Add subcommands
	cmd.AddCommand(newProviderCmd())

	return cmd
}

// newProviderCmd creates the "ingest provider" subcommand
func newProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "Ingest repository metadata from providers",
		Long: `Fetch repository metadata from configured Git providers and store in SQLite.

Examples:
  # Ingest from a specific provider by name (from config.yaml)
  securelens ingest provider --provider-name github-enterprise

  # Ingest from all configured providers
  securelens ingest provider --all

Provider names match the 'name' field in your config.yaml for each provider instance.`,
		RunE: runProviderIngest,
	}

	cmd.Flags().StringVar(&providerName, "provider-name", "", "Name of the provider to ingest from (matches 'name' in config.yaml)")
	cmd.Flags().BoolVar(&allProviders, "all", false, "Ingest from all configured providers")

	return cmd
}

func runProviderIngest(cmd *cobra.Command, args []string) error {
	if providerName == "" && !allProviders {
		return fmt.Errorf("either --provider-name or --all must be specified")
	}

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize database
	db, err := database.New(database.Config{
		Driver: "sqlite",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	if allProviders {
		return ingestAllProviders(ctx, cfg, db)
	}

	return ingestProvider(ctx, cfg, db, providerName)
}

// ingestAllProviders ingests from all configured providers
func ingestAllProviders(ctx context.Context, cfg *config.Config, db database.DB) error {
	var totalCount int
	var errors []error

	// Ingest GitHub providers
	for _, gh := range cfg.Git.GitHub {
		name := gh.Name
		if name == "" {
			name = "github-" + gh.APIURL
		}
		count, err := ingestGitHub(ctx, cfg, db, gh)
		if err != nil {
			slog.Error("Failed to ingest GitHub provider", "name", name, "error", err)
			errors = append(errors, fmt.Errorf("github %s: %w", name, err))
		} else {
			totalCount += count
		}
	}

	// Ingest GitLab providers
	for _, gl := range cfg.Git.GitLab {
		name := gl.Name
		if name == "" {
			name = "gitlab-" + gl.APIURL
		}
		count, err := ingestGitLab(ctx, cfg, db, gl)
		if err != nil {
			slog.Error("Failed to ingest GitLab provider", "name", name, "error", err)
			errors = append(errors, fmt.Errorf("gitlab %s: %w", name, err))
		} else {
			totalCount += count
		}
	}

	// Ingest Bitbucket providers
	for _, bb := range cfg.Git.Bitbucket {
		name := bb.Name
		if name == "" {
			name = "bitbucket-" + bb.Workspace
		}
		count, err := ingestBitbucket(ctx, cfg, db, bb)
		if err != nil {
			slog.Error("Failed to ingest Bitbucket provider", "name", name, "error", err)
			errors = append(errors, fmt.Errorf("bitbucket %s: %w", name, err))
		} else {
			totalCount += count
		}
	}

	fmt.Printf("\nIngest complete: %d repositories synced\n", totalCount)
	if len(errors) > 0 {
		fmt.Printf("Errors encountered: %d\n", len(errors))
		for _, e := range errors {
			fmt.Printf("  - %v\n", e)
		}
	}

	return nil
}

// ingestProvider ingests from a specific provider by name
func ingestProvider(ctx context.Context, cfg *config.Config, db database.DB, name string) error {
	// Search for provider by name
	for _, gh := range cfg.Git.GitHub {
		if gh.Name == name {
			count, err := ingestGitHub(ctx, cfg, db, gh)
			if err != nil {
				return err
			}
			fmt.Printf("Ingested %d repositories from GitHub provider '%s'\n", count, name)
			return nil
		}
	}

	for _, gl := range cfg.Git.GitLab {
		if gl.Name == name {
			count, err := ingestGitLab(ctx, cfg, db, gl)
			if err != nil {
				return err
			}
			fmt.Printf("Ingested %d repositories from GitLab provider '%s'\n", count, name)
			return nil
		}
	}

	for _, bb := range cfg.Git.Bitbucket {
		if bb.Name == name {
			count, err := ingestBitbucket(ctx, cfg, db, bb)
			if err != nil {
				return err
			}
			fmt.Printf("Ingested %d repositories from Bitbucket provider '%s'\n", count, name)
			return nil
		}
	}

	// List available providers
	var availableProviders []string
	for _, gh := range cfg.Git.GitHub {
		if gh.Name != "" {
			availableProviders = append(availableProviders, gh.Name+" (github)")
		}
	}
	for _, gl := range cfg.Git.GitLab {
		if gl.Name != "" {
			availableProviders = append(availableProviders, gl.Name+" (gitlab)")
		}
	}
	for _, bb := range cfg.Git.Bitbucket {
		if bb.Name != "" {
			availableProviders = append(availableProviders, bb.Name+" (bitbucket)")
		}
	}

	return fmt.Errorf("provider '%s' not found in config. Available providers: %v", name, availableProviders)
}

// ingestGitHub ingests repositories from a GitHub provider
func ingestGitHub(ctx context.Context, cfg *config.Config, db database.DB, gh config.GitHubConfig) (int, error) {
	name := gh.Name
	if name == "" {
		name = "github"
	}
	slog.Info("Ingesting GitHub repositories", "provider", name, "orgs", gh.Organizations)

	// Create a filtered config with only this provider
	filteredCfg := &config.Config{
		Git: config.GitConfig{
			GitHub: []config.GitHubConfig{gh},
		},
	}

	// Discover repositories
	repos, err := scan.DiscoverRepositories(ctx, filteredCfg, 0, false) // 0 = no limit
	if err != nil {
		return 0, fmt.Errorf("failed to discover repositories: %w", err)
	}

	// Upsert each repository to database
	count := 0
	for _, repo := range repos {
		dbRepo := discoveredToDBRepository(repo, name)
		if err := db.UpsertRepository(ctx, dbRepo); err != nil {
			slog.Error("Failed to upsert repository", "repo", repo.FullName, "error", err)
			continue
		}
		count++
	}

	slog.Info("GitHub ingest complete", "provider", name, "count", count)
	return count, nil
}

// ingestGitLab ingests repositories from a GitLab provider
func ingestGitLab(ctx context.Context, cfg *config.Config, db database.DB, gl config.GitLabConfig) (int, error) {
	name := gl.Name
	if name == "" {
		name = "gitlab"
	}
	slog.Info("Ingesting GitLab repositories", "provider", name, "groups", gl.Groups)

	// Create a filtered config with only this provider
	filteredCfg := &config.Config{
		Git: config.GitConfig{
			GitLab: []config.GitLabConfig{gl},
		},
	}

	// Discover repositories
	repos, err := scan.DiscoverRepositories(ctx, filteredCfg, 0, false)
	if err != nil {
		return 0, fmt.Errorf("failed to discover repositories: %w", err)
	}

	// Upsert each repository to database
	count := 0
	for _, repo := range repos {
		dbRepo := discoveredToDBRepository(repo, name)
		if err := db.UpsertRepository(ctx, dbRepo); err != nil {
			slog.Error("Failed to upsert repository", "repo", repo.FullName, "error", err)
			continue
		}
		count++
	}

	slog.Info("GitLab ingest complete", "provider", name, "count", count)
	return count, nil
}

// ingestBitbucket ingests repositories from a Bitbucket provider
func ingestBitbucket(ctx context.Context, cfg *config.Config, db database.DB, bb config.BitbucketConfig) (int, error) {
	name := bb.Name
	if name == "" {
		name = "bitbucket"
	}
	slog.Info("Ingesting Bitbucket repositories", "provider", name, "workspace", bb.Workspace)

	// Create a filtered config with only this provider
	filteredCfg := &config.Config{
		Git: config.GitConfig{
			Bitbucket: []config.BitbucketConfig{bb},
		},
	}

	// Discover repositories
	repos, err := scan.DiscoverRepositories(ctx, filteredCfg, 0, false)
	if err != nil {
		return 0, fmt.Errorf("failed to discover repositories: %w", err)
	}

	// Upsert each repository to database
	count := 0
	for _, repo := range repos {
		dbRepo := discoveredToDBRepository(repo, name)
		if err := db.UpsertRepository(ctx, dbRepo); err != nil {
			slog.Error("Failed to upsert repository", "repo", repo.FullName, "error", err)
			continue
		}
		count++
	}

	slog.Info("Bitbucket ingest complete", "provider", name, "count", count)
	return count, nil
}

// discoveredToDBRepository converts a DiscoveredRepository to database.Repository
func discoveredToDBRepository(repo scan.DiscoveredRepository, sourceName string) *database.Repository {
	return &database.Repository{
		Provider:    repo.Provider,
		Name:        repo.Name,
		FullName:    repo.FullName,
		URL:         repo.URL,
		CloneURL:    repo.URL, // Use URL as clone URL
		IsPrivate:   repo.IsPrivate,
		Language:    repo.Language,
		Description: repo.Description,
		Source:      sourceName,
		UpdatedAt:   time.Now(),
	}
}

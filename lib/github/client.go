package github

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/go-github/v66/github"
	"golang.org/x/time/rate"
)

// Client represents a GitHub API client
type Client struct {
	client  *github.Client
	limiter *rate.Limiter
	apiURL  string
}

// NewClient creates a new GitHub API client
func NewClient(token, apiURL string) (*Client, error) {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	githubClient := github.NewClient(nil).WithAuthToken(token)

	if apiURL != "https://api.github.com" {
		var err error
		githubClient, err = githubClient.WithEnterpriseURLs(apiURL, apiURL)
		if err != nil {
			return nil, err
		}
	}

	limiter := rate.NewLimiter(rate.Every(60*time.Millisecond), 1)

	return &Client{
		client:  githubClient,
		limiter: limiter,
		apiURL:  apiURL,
	}, nil
}

// Repository represents a GitHub repository
type Repository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	SSHURL   string `json:"ssh_url"`
	HTMLURL  string `json:"html_url"`
	Private  bool   `json:"private"`
	Archived bool   `json:"archived"`
	Language string `json:"language"`
	Stars    int    `json:"stargazers_count"`
}

// ListRepositories lists all accessible repositories for a given owner (user or organization)
// If owner is empty string, lists repositories for the authenticated user
func (c *Client) ListRepositories(ctx context.Context, owner string, limit int) ([]Repository, error) {
	slog.Info("Listing GitHub repositories", "apiURL", c.apiURL, "owner", owner, "limit", limit)

	var allRepos []Repository

	// Use different pagination options based on whether we're listing by user/org or authenticated user
	if owner == "" {
		// List authenticated user's repositories
		return c.listAuthenticatedUserRepos(ctx, limit)
	}

	// List by specific user or organization
	options := &github.RepositoryListByUserOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}

	for limit <= 0 || len(allRepos) < limit {
		if err := c.limiter.Wait(ctx); err != nil {
			return []Repository{}, err
		}

		var repos []*github.Repository
		var resp *github.Response
		var err error

		repos, resp, err = c.client.Repositories.ListByUser(ctx, owner, options)

		if err != nil {
			slog.Error("Failed to fetch GitHub repositories", "error", err, "owner", owner, "page", options.Page)
			return []Repository{}, err
		}

		for _, r := range repos {
			allRepos = append(allRepos, Repository{
				ID:       r.GetID(),
				Name:     r.GetName(),
				FullName: r.GetFullName(),
				CloneURL: r.GetCloneURL(),
				SSHURL:   r.GetSSHURL(),
				HTMLURL:  r.GetHTMLURL(),
				Private:  r.GetPrivate(),
				Archived: r.GetArchived(),
				Language: r.GetLanguage(),
				Stars:    r.GetStargazersCount(),
			})
		}

		slog.Debug("Fetched GitHub repositories page", "page", options.Page, "count", len(repos), "total", len(allRepos))

		if limit > 0 && len(allRepos) >= limit {
			break
		}
		if resp.NextPage == 0 {
			break
		}

		options.Page = resp.NextPage
	}

	slog.Info("Repositories listed successfully", "total", len(allRepos))
	return allRepos, nil
}

// ListRepositoriesForOrganizations lists all repositories for multiple organizations
// This is useful when the config specifies multiple organizations to scan
func (c *Client) ListRepositoriesForOrganizations(ctx context.Context, organizations []string, limit int) ([]Repository, error) {
	slog.Info("Listing GitHub repositories for multiple organizations", "orgCount", len(organizations), "limit", limit)

	allRepos := []Repository{}

	if len(organizations) == 0 {
		slog.Info("No organizations specified, listing repositories for authenticated user")
		return c.ListRepositories(ctx, "", limit)
	}

	for _, org := range organizations {
		if limit > 0 && len(allRepos) >= limit {
			break
		}

		slog.Debug("Fetching repositories for organization", "org", org)

		remaining := limit
		if limit > 0 {
			remaining = limit - len(allRepos)
		}

		repos, err := c.ListRepositories(ctx, org, remaining)
		if err != nil {
			slog.Error("Failed to list repositories for organization", "org", org, "error", err)
			continue
		}

		slog.Debug("Fetched repositories for organization", "org", org, "count", len(repos))
		allRepos = append(allRepos, repos...)
	}

	slog.Info("All repositories listed successfully", "total", len(allRepos), "organizations", len(organizations))
	return allRepos, nil
}

// GetRepository retrieves a specific repository
func (c *Client) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	slog.Info("Getting GitHub repository", "owner", owner, "repo", repo)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	retrievedRepo, _, err := c.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	repository := &Repository{
		ID:       retrievedRepo.GetID(),
		Name:     retrievedRepo.GetName(),
		FullName: retrievedRepo.GetFullName(),
		CloneURL: retrievedRepo.GetCloneURL(),
		SSHURL:   retrievedRepo.GetSSHURL(),
		HTMLURL:  retrievedRepo.GetHTMLURL(),
		Private:  retrievedRepo.GetPrivate(),
	}

	slog.Info("Repository retrieved successfully", "fullName", repository.FullName)

	return repository, nil
}

// listAuthenticatedUserRepos lists repositories for the authenticated user
func (c *Client) listAuthenticatedUserRepos(ctx context.Context, limit int) ([]Repository, error) {
	slog.Info("Listing repositories for authenticated GitHub user", "limit", limit)

	var allRepos []Repository
	options := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
		Affiliation: "owner,collaborator,organization_member",
	}

	for limit <= 0 || len(allRepos) < limit {
		if err := c.limiter.Wait(ctx); err != nil {
			return []Repository{}, err
		}

		repos, resp, err := c.client.Repositories.ListByAuthenticatedUser(ctx, options)
		if err != nil {
			slog.Error("Failed to fetch authenticated user repositories", "error", err, "page", options.Page)
			return []Repository{}, err
		}

		for _, r := range repos {
			allRepos = append(allRepos, Repository{
				ID:       r.GetID(),
				Name:     r.GetName(),
				FullName: r.GetFullName(),
				CloneURL: r.GetCloneURL(),
				SSHURL:   r.GetSSHURL(),
				HTMLURL:  r.GetHTMLURL(),
				Private:  r.GetPrivate(),
				Archived: r.GetArchived(),
				Language: r.GetLanguage(),
				Stars:    r.GetStargazersCount(),
			})
		}

		slog.Debug("Fetched authenticated user repositories page", "page", options.Page, "count", len(repos), "total", len(allRepos))

		if limit > 0 && len(allRepos) >= limit {
			break
		}
		if resp.NextPage == 0 {
			break
		}
		options.Page = resp.NextPage
	}

	slog.Info("Authenticated user repositories listed successfully", "total", len(allRepos))
	return allRepos, nil
}

func (c *Client) ListBranches(ctx context.Context, owner, repo string) ([]string, error) {
	slog.Info("Listing branches for GitHub repository", "owner", owner, "repo", repo)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var allBranches []string
	opts := &github.BranchListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		branches, resp, err := c.client.Repositories.ListBranches(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}

		for _, branch := range branches {
			allBranches = append(allBranches, branch.GetName())
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allBranches, nil
}

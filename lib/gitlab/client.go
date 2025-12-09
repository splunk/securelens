package gitlab

import (
	"context"
	"log/slog"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/time/rate"
)

// Client represents a GitLab API client
type Client struct {
	client  *gitlab.Client
	limiter *rate.Limiter
	apiURL  string
}

// NewClient creates a new GitLab API client
func NewClient(token, apiURL string) (*Client, error) {
	if apiURL == "" {
		apiURL = "https://gitlab.com"
	}

	// Create GitLab client with authentication
	gitlabClient, err := gitlab.NewClient(token, gitlab.WithBaseURL(apiURL))
	if err != nil {
		return nil, err
	}

	// Create rate limiter: 1 request per 60ms (same as reference project)
	limiter := rate.NewLimiter(rate.Every(60*time.Millisecond), 1)

	return &Client{
		client:  gitlabClient,
		limiter: limiter,
		apiURL:  apiURL,
	}, nil
}

// Project represents a GitLab project
type Project struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	PathWithNS string `json:"path_with_namespace"`
	HTTPURL    string `json:"http_url_to_repo"`
	SSHURL     string `json:"ssh_url_to_repo"`
	WebURL     string `json:"web_url"`
	Visibility string `json:"visibility"`
	Archived   bool   `json:"archived"`
}

// ListProjects lists all accessible projects where the authenticated user is a member
func (c *Client) ListProjects(ctx context.Context, limit int) ([]Project, error) {
	slog.Info("Listing GitLab projects", "apiURL", c.apiURL, "limit", limit)

	var allProjects []Project
	membership := true
	options := &gitlab.ListProjectsOptions{
		Membership: &membership, // Only projects where user is a member
		ListOptions: gitlab.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}

	for limit <= 0 || len(allProjects) < limit {
		if err := c.limiter.Wait(ctx); err != nil {
			return []Project{}, err
		}

		projects, resp, err := c.client.Projects.ListProjects(options)
		if err != nil {
			slog.Error("Failed to fetch GitLab projects", "error", err, "page", options.Page)
			return []Project{}, err
		}

		for _, p := range projects {
			if limit > 0 && len(allProjects) >= limit {
				break
			}

			allProjects = append(allProjects, Project{
				ID:         p.ID,
				Name:       p.Name,
				Path:       p.Path,
				PathWithNS: p.PathWithNamespace,
				HTTPURL:    p.HTTPURLToRepo,
				SSHURL:     p.SSHURLToRepo,
				WebURL:     p.WebURL,
				Visibility: string(p.Visibility),
				Archived:   p.Archived,
			})
		}

		slog.Debug("Fetched GitLab projects page", "page", options.Page, "count", len(projects), "total", len(allProjects), "totalPages", resp.TotalPages, "totalItems", resp.TotalItems)

		if limit > 0 && len(allProjects) >= limit {
			break
		}
		if resp.NextPage == 0 {
			break
		}

		options.Page = resp.NextPage
	}

	slog.Info("Projects listed successfully", "total", len(allProjects))
	return allProjects, nil
}

// GetProject retrieves a specific project by its path (e.g., "group/project" or "group/subgroup/project")
func (c *Client) GetProject(ctx context.Context, projectPath string) (*Project, error) {
	slog.Info("Getting Gitlab project", "path", projectPath)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	gitlabProject, _, err := c.client.Projects.GetProject(projectPath, nil)
	if err != nil {
		slog.Error("Failed to get GitLab project", "error", err, "path", projectPath)
		return nil, err
	}

	project := &Project{
		ID:         gitlabProject.ID,
		Name:       gitlabProject.Name,
		Path:       gitlabProject.Path,
		PathWithNS: gitlabProject.PathWithNamespace,
		HTTPURL:    gitlabProject.HTTPURLToRepo,
		SSHURL:     gitlabProject.SSHURLToRepo,
		WebURL:     gitlabProject.WebURL,
		Visibility: string(gitlabProject.Visibility),
		Archived:   gitlabProject.Archived,
	}

	slog.Info("Project retrieved successfully", "path", project.PathWithNS)

	return project, nil
}

func (c *Client) ListBranches(ctx context.Context, projectID int) ([]string, error) {
	slog.Info("Listing branches for GitLab project", "projectID", projectID)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var allBranches []string
	opts := &gitlab.ListBranchesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}

	for {
		branches, resp, err := c.client.Branches.ListBranches(projectID, opts)
		if err != nil {
			slog.Error("Failed to list branches", "projectID", projectID, "error", err)
			return nil, err
		}

		for _, branch := range branches {
			allBranches = append(allBranches, branch.Name)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

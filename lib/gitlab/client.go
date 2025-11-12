package gitlab

import (
	"context"
	"log/slog"
)

// Client represents a GitLab API client
type Client struct {
	token  string
	apiURL string
}

// NewClient creates a new GitLab API client
func NewClient(token, apiURL string) *Client {
	if apiURL == "" {
		apiURL = "https://gitlab.com"
	}

	return &Client{
		token:  token,
		apiURL: apiURL,
	}
}

// Project represents a GitLab project
type Project struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	PathWithNS  string `json:"path_with_namespace"`
	HTTPURL     string `json:"http_url_to_repo"`
	SSHURL      string `json:"ssh_url_to_repo"`
	WebURL      string `json:"web_url"`
	Visibility  string `json:"visibility"`
	Archived    bool   `json:"archived"`
}

// ListProjects lists all accessible projects
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	slog.Info("Listing GitLab projects")

	// TODO: Implement GitLab API integration
	// 1. Make GET request to /api/v4/projects
	// 2. Handle pagination
	// 3. Parse response into Project structs
	// 4. Return projects

	slog.Info("Projects listed successfully")

	return []Project{}, nil
}

// GetProject retrieves a specific project by ID or path
func (c *Client) GetProject(ctx context.Context, projectID string) (*Project, error) {
	slog.Info("Getting GitLab project", "projectID", projectID)

	// TODO: Implement project retrieval
	// GET /api/v4/projects/:id

	return nil, nil
}

package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// Client represents a Bitbucket API client
type Client struct {
	httpClient  *http.Client
	limiter     *rate.Limiter
	username    string
	appPassword string
	apiURL      string
}

// NewClient creates a new Bitbucket API client
func NewClient(username, appPassword, apiURL string) (*Client, error) {
	if apiURL == "" {
		apiURL = "https://api.bitbucket.org/2.0"
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	limiter := rate.NewLimiter(rate.Every(60*time.Millisecond), 1)

	return &Client{
		httpClient:  httpClient,
		limiter:     limiter,
		username:    username,
		appPassword: appPassword,
		apiURL:      apiURL,
	}, nil
}

// Repository represents a Bitbucket repository
type Repository struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	FullName  string `json:"full_name"`
	IsPrivate bool   `json:"is_private"`
	Language  string `json:"language"`
	Links     struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

// ListRepositories lists all accessible repositories for a workspace (Bitbucket Cloud)
// or all repositories the user has access to if workspace is empty
func (c *Client) ListRepositories(ctx context.Context, workspace string) ([]Repository, error) {
	slog.Info("Listing Bitbucket repositories", "apiURL", c.apiURL, "workspace", workspace)

	allRepos := []Repository{}
	apiURL := c.buildRepositoriesURL(workspace)
	page := 1

	for {
		repos, hasMore, err := c.fetchRepositoriesPage(ctx, apiURL, page)
		if err != nil {
			return []Repository{}, err
		}

		allRepos = append(allRepos, repos...)

		if !hasMore {
			break
		}
		page++
	}

	slog.Info("Repositories listed successfully", "count", len(allRepos))
	return allRepos, nil
}

// buildRepositoriesURL constructs the API URL based on workspace parameter
func (c *Client) buildRepositoriesURL(workspace string) string {
	if workspace != "" {
		return fmt.Sprintf("%s/repositories/%s", c.apiURL, workspace)
	}
	return fmt.Sprintf("%s/repositories", c.apiURL)
}

// fetchRepositoriesPage fetches a single page of repositories
func (c *Client) fetchRepositoriesPage(ctx context.Context, apiURL string, page int) ([]Repository, bool, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return []Repository{}, false, err
	}

	pageURL := fmt.Sprintf("%s?page=%d&pagelen=100", apiURL, page)

	body, err := c.makeAuthenticatedRequest(ctx, pageURL)
	if err != nil {
		return []Repository{}, false, err
	}

	var response struct {
		Values []Repository `json:"values"`
		Next   string       `json:"next"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		slog.Error("Failed to parse Bitbucket response", "error", err)
		return []Repository{}, false, err
	}

	slog.Debug("Fetched Bitbucket repositories page", "page", page, "count", len(response.Values))

	hasMore := response.Next != ""
	return response.Values, hasMore, nil
}

// makeAuthenticatedRequest makes an authenticated HTTP request to Bitbucket API
func (c *Client) makeAuthenticatedRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		slog.Error("Failed to create Bitbucket request", "error", err)
		return nil, err
	}

	req.SetBasicAuth(c.username, c.appPassword)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Error("Failed to fetch from Bitbucket", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read Bitbucket response body", "error", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("Bitbucket API returned error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("bitbucket API error: %d - %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *Client) ListRepositoriesForWorkspaces(ctx context.Context, workspaces []string) ([]Repository, error) {
	slog.Info("Listing Bitbucket repositories for multiple workspaces", "workspaceCount", len(workspaces))

	allRepos := []Repository{}

	if len(workspaces) == 0 {
		slog.Info("No workspaces specified, listing repositories for authenticated user")
		return c.ListRepositories(ctx, "")
	}

	for _, workspace := range workspaces {
		slog.Info("Fetching repositories for workspace", "workspace", workspace)

		repos, err := c.ListRepositories(ctx, workspace)
		if err != nil {
			slog.Error("Failed to list repositories for workspace", "workspace", workspace, "error", err)
			continue
		}

		slog.Info("Fetched repositories for workspace", "workspace", workspace, "count", len(repos))
		allRepos = append(allRepos, repos...)
	}

	slog.Info("Sucessfully listed repositories", "total", len(allRepos))
	return allRepos, nil
}

// GetRepository retrieves a specific repository
func (c *Client) GetRepository(ctx context.Context, workspace, repoSlug string) (*Repository, error) {
	slog.Info("Getting Bitbucket repository", "workspace", workspace, "repo", repoSlug)

	// TODO: Implement repository retrieval
	// GET /repositories/:workspace/:repo_slug

	return nil, nil
}

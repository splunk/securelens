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

const (
	serverAPIPath = "/rest/api"
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

// ServerRepository represents a Bitbucket Server repository response
type ServerRepository struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Project struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"project"`
	Public bool `json:"public"`
	Links  struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
		Self []struct {
			Href string `json:"href"`
		} `json:"self"`
	} `json:"links"`
}

// ServerResponse represents a Bitbucket Server paginated response
type ServerResponse struct {
	Values        []ServerRepository `json:"values"`
	Size          int                `json:"size"`
	Limit         int                `json:"limit"`
	IsLastPage    bool               `json:"isLastPage"`
	Start         int                `json:"start"`
	NextPageStart int                `json:"nextPageStart"`
}

func (c *Client) isServerAPI() bool {
	for i := 0; i <= len(c.apiURL)-len(serverAPIPath); i++ {
		if c.apiURL[i:i+len(serverAPIPath)] == serverAPIPath {
			return true
		}
	}
	return false
}

// ListRepositories lists all accessible repositories for a workspace (Bitbucket Cloud)
// or all repositories the user has access to if workspace is empty
func (c *Client) ListRepositories(ctx context.Context, workspace string, limit int) ([]Repository, error) {
	slog.Info("Listing Bitbucket repositories", "apiURL", c.apiURL, "workspace", workspace, "limit", limit)

	allRepos := []Repository{}
	apiURL := c.buildRepositoriesURL(workspace)
	page := 1

	for limit <= 0 || len(allRepos) < limit {
		remaining := limit - len(allRepos)
		repos, hasMore, err := c.fetchRepositoriesPage(ctx, apiURL, page, remaining)
		if err != nil {
			return []Repository{}, err
		}

		allRepos = append(allRepos, repos...)

		if limit > 0 && len(allRepos) >= limit {
			break
		}
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
	// Bitbucket Server API
	if c.isServerAPI() {
		return fmt.Sprintf("%s/repos", c.apiURL)
	}

	// Bitbucket Cloud API
	if workspace != "" {
		return fmt.Sprintf("%s/repositories/%s", c.apiURL, workspace)
	}
	return fmt.Sprintf("%s/repositories", c.apiURL)
}

// fetchRepositoriesPage fetches a single page of repositories
func (c *Client) fetchRepositoriesPage(ctx context.Context, apiURL string, page int, remaining int) ([]Repository, bool, error) {
	// Rate limiting
	if err := c.limiter.Wait(ctx); err != nil {
		return []Repository{}, false, err
	}

	var pageURL string
	if c.isServerAPI() {
		start := (page - 1) * 100
		pageURL = fmt.Sprintf("%s?start=%d&limit=100", apiURL, start)
	} else {
		// Build paginated URL
		pageURL = fmt.Sprintf("%s?page=%d&pagelen=100", apiURL, page)
	}

	// Make HTTP request
	body, err := c.makeAuthenticatedRequest(ctx, pageURL)
	if err != nil {
		return []Repository{}, false, err
	}

	if c.isServerAPI() {
		return c.parseServerResponse(body, page, remaining)
	}
	return c.parseCloudResponse(body, page, remaining)
}

// parseCloudResponse parses Bitbucket Cloud API response
func (c *Client) parseCloudResponse(body []byte, page int, remaining int) ([]Repository, bool, error) {
	var response struct {
		Values []Repository `json:"values"`
		Next   string       `json:"next"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		slog.Error("Failed to parse Bitbucket Cloud response", "error", err)
		return []Repository{}, false, err
	}

	repos := response.Values
	if remaining > 0 && len(repos) > remaining {
		repos = repos[:remaining]
		return repos, response.Next != "", nil
	}

	slog.Info("Fetched Bitbucket Cloud repositories page", "page", page, "count", len(response.Values))
	hasMore := response.Next != ""
	return response.Values, hasMore, nil
}

func (c *Client) parseServerResponse(body []byte, page int, remaining int) ([]Repository, bool, error) {
	var response ServerResponse
	if err := json.Unmarshal(body, &response); err != nil {
		slog.Error("Failed to parse Bitbucket Server response", "error", err)
		return []Repository{}, false, err
	}

	repos := make([]Repository, len(response.Values))
	for i, serverRepo := range response.Values {
		if remaining > 0 && i >= remaining {
			break
		}

		repo := Repository{
			UUID:      serverRepo.Slug,
			Name:      serverRepo.Name,
			FullName:  fmt.Sprintf("%s/%s", serverRepo.Project.Key, serverRepo.Slug),
			IsPrivate: !serverRepo.Public,
			Language:  "",
		}
		repo.Links.Clone = serverRepo.Links.Clone

		if len(serverRepo.Links.Self) > 0 {
			repo.Links.HTML.Href = serverRepo.Links.Self[0].Href
		}
		repos[i] = repo
	}

	slog.Debug("Fetched Bitbucket Server repositories page", "page", page, "count", len(repos))
	hasMore := !response.IsLastPage
	return repos, hasMore, nil
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
	defer func() { _ = resp.Body.Close() }()

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

// GetRepository retrieves a specific repository
func (c *Client) GetRepository(ctx context.Context, workspace, repoSlug string) (*Repository, error) {
	slog.Info("Getting Bitbucket repository", "workspace", workspace, "repo", repoSlug)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var url string
	if c.isServerAPI() {
		url = fmt.Sprintf("%s/projects/%s/repos/%s", c.apiURL, workspace, repoSlug)
	} else {
		url = fmt.Sprintf("%s/repositories/%s/%s", c.apiURL, workspace, repoSlug)
	}

	body, err := c.makeAuthenticatedRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	if c.isServerAPI() {
		var serverRepo ServerRepository
		if err := json.Unmarshal(body, &serverRepo); err != nil {
			slog.Error("Failed to parse Bitbucket Server repository response", "error", err)
			return nil, err
		}

		repo := &Repository{
			UUID:      serverRepo.Slug,
			Name:      serverRepo.Name,
			FullName:  fmt.Sprintf("%s/%s", serverRepo.Project.Key, serverRepo.Slug),
			IsPrivate: !serverRepo.Public,
			Language:  "",
		}
		repo.Links.Clone = serverRepo.Links.Clone

		if len(serverRepo.Links.Self) > 0 {
			repo.Links.HTML.Href = serverRepo.Links.Self[0].Href
		}

		slog.Info("Repository retrieved successfully", "workspace", workspace, "repo", repoSlug)
		return repo, nil
	}

	// Bitbucket Cloud
	var repo Repository
	if err := json.Unmarshal(body, &repo); err != nil {
		slog.Error("Failed to parse Bitbucket Cloud response", "error", err)
		return nil, err
	}

	slog.Info("Repository retrieved successfully", "fullName", repo.FullName)
	return &repo, nil
}

func (c *Client) ListBranches(ctx context.Context, workspace, repoSlug string) ([]string, error) {
	slog.Info("Listing branches for Bitbucket repository", "workspace", workspace, "repo", repoSlug)

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var url string
	if c.isServerAPI() {
		url = fmt.Sprintf("%s/projects/%s/repos/%s/branches", c.apiURL, workspace, repoSlug)
	} else {
		url = fmt.Sprintf("%s/repositories/%s/%s/refs/branches", c.apiURL, workspace, repoSlug)
	}

	body, err := c.makeAuthenticatedRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	var response struct {
		Values []struct {
			Name      string `json:"name"`
			ID        string `json:"id"`
			DisplayID string `json:"displayId"`
		} `json:"values"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		slog.Error("Failed to parse Bitbucket branches response", "error", err)
		return nil, err
	}

	branchNames := make([]string, len(response.Values))
	for i, branch := range response.Values {
		if branch.DisplayID != "" {
			branchNames[i] = branch.DisplayID
		} else if branch.Name != "" {
			branchNames[i] = branch.Name
		} else {
			branchNames[i] = branch.ID
		}
	}

	return branchNames, nil
}

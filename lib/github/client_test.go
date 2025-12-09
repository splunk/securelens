package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultGitHubURL = "https://api.github.com"
	testToken        = "test-token"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		apiURL     string
		wantAPIURL string
	}{
		{
			name:       "Valid token and URL",
			token:      "ghp_test123",
			apiURL:     "https://github.example.com/api/v3",
			wantAPIURL: "https://github.example.com/api/v3",
		},
		{
			name:       "Valid token with default URL",
			token:      "ghp_test456",
			apiURL:     "",
			wantAPIURL: defaultGitHubURL,
		},
		{
			name:       "Empty token still creates client",
			token:      "",
			apiURL:     defaultGitHubURL,
			wantAPIURL: defaultGitHubURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.token, tt.apiURL)

			// go-github doesn't validate token at creation time
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.NotNil(t, client.client)
			assert.NotNil(t, client.limiter)
			assert.Equal(t, tt.wantAPIURL, client.apiURL)
		})
	}
}

func TestListRepositories(t *testing.T) {
	t.Run("Function signature with empty owner", func(t *testing.T) {
		client, err := NewClient(testToken, defaultGitHubURL)
		require.NoError(t, err)

		ctx := context.Background()
		repos, err := client.ListRepositories(ctx, "", 0)

		// We expect an error since we don't have a valid token
		// But repos should be non-nil (empty slice)
		assert.NotNil(t, repos)
		assert.Error(t, err, "Expected error with invalid token")
		t.Logf("ListRepositories returned %d repos with error: %v", len(repos), err)
	})

	t.Run("Function signature with owner", func(t *testing.T) {
		client, err := NewClient(testToken, defaultGitHubURL)
		require.NoError(t, err)

		ctx := context.Background()
		repos, err := client.ListRepositories(ctx, "octocat", 0)

		// We expect an error since we don't have a valid token
		assert.NotNil(t, repos)
		assert.Error(t, err, "Expected error with invalid token")
		t.Logf("ListRepositories for 'octocat' returned %d repos with error: %v", len(repos), err)
	})
}

func TestListRepositoriesContextCancellation(t *testing.T) {
	client, err := NewClient(testToken, defaultGitHubURL)
	require.NoError(t, err)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.ListRepositories(ctx, "", 0)
	assert.Error(t, err, "Should return error when context is cancelled")
}

func TestListRepositoriesForOrganizations(t *testing.T) {
	t.Run("Empty organizations list", func(t *testing.T) {
		client, err := NewClient(testToken, defaultGitHubURL)
		require.NoError(t, err)

		ctx := context.Background()
		repos, _ := client.ListRepositoriesForOrganizations(ctx, []string{}, 0)

		// Should fall back to authenticated user's repos
		assert.NotNil(t, repos)
		// Will get error due to invalid token, but that's okay for this test
		t.Logf("ListRepositoriesForOrganizations with empty list returned %d repos", len(repos))
	})

	t.Run("Multiple organizations", func(t *testing.T) {
		client, err := NewClient(testToken, defaultGitHubURL)
		require.NoError(t, err)

		ctx := context.Background()
		orgs := []string{"org1", "org2"}
		repos, err := client.ListRepositoriesForOrganizations(ctx, orgs, 0)

		// Should attempt to fetch from both orgs (will fail with invalid token)
		assert.NotNil(t, repos)
		// No error returned - method continues on individual org failures
		assert.NoError(t, err, "Should not return error even when individual orgs fail")
		t.Logf("ListRepositoriesForOrganizations returned %d repos for %d orgs", len(repos), len(orgs))
	})
}

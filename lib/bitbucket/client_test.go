package bitbucket

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultBitbucketURL = "https://api.bitbucket.org/2.0"
	testUsername        = "test-user"
	testAppPassword     = "test-password"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		appPassword string
		apiURL      string
		wantAPIURL  string
	}{
		{
			name:        "Valid credentials and URL",
			username:    testUsername,
			appPassword: testAppPassword,
			apiURL:      "https://bitbucket.example.com/api/2.0",
			wantAPIURL:  "https://bitbucket.example.com/api/2.0",
		},
		{
			name:        "Valid credentials with default URL",
			username:    testUsername,
			appPassword: testAppPassword,
			apiURL:      "",
			wantAPIURL:  defaultBitbucketURL,
		},
		{
			name:        "Empty credentials still creates client",
			username:    "",
			appPassword: "",
			apiURL:      defaultBitbucketURL,
			wantAPIURL:  defaultBitbucketURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.username, tt.appPassword, tt.apiURL)

			// Client creation doesn't validate credentials
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.NotNil(t, client.httpClient)
			assert.NotNil(t, client.limiter)
			assert.Equal(t, tt.wantAPIURL, client.apiURL)
			assert.Equal(t, tt.username, client.username)
			assert.Equal(t, tt.appPassword, client.appPassword)
		})
	}
}

func TestListRepositories(t *testing.T) {
	t.Run("Function signature with empty workspace", func(t *testing.T) {
		client, err := NewClient(testUsername, testAppPassword, defaultBitbucketURL)
		require.NoError(t, err)

		ctx := context.Background()
		repos, err := client.ListRepositories(ctx, "", 0)

		// We expect an error since we don't have valid credentials
		// But repos should be non-nil (empty slice)
		assert.NotNil(t, repos)
		assert.Error(t, err, "Expected error with invalid credentials")
		t.Logf("ListRepositories returned %d repos with error: %v", len(repos), err)
	})

	t.Run("Function signature with workspace", func(t *testing.T) {
		client, err := NewClient(testUsername, testAppPassword, defaultBitbucketURL)
		require.NoError(t, err)

		ctx := context.Background()
		repos, err := client.ListRepositories(ctx, "my-workspace", 0)

		// We expect an error since we don't have valid credentials
		assert.NotNil(t, repos)
		assert.Error(t, err, "Expected error with invalid credentials")
		t.Logf("ListRepositories for 'my-workspace' returned %d repos with error: %v", len(repos), err)
	})
}

func TestListRepositoriesContextCancellation(t *testing.T) {
	client, err := NewClient(testUsername, testAppPassword, defaultBitbucketURL)
	require.NoError(t, err)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.ListRepositories(ctx, "", 0)
	assert.Error(t, err, "Should return error when context is cancelled")
}

func TestBuildRepositoriesURL(t *testing.T) {
	client, _ := NewClient(testUsername, testAppPassword, defaultBitbucketURL)

	tests := []struct {
		name      string
		workspace string
		wantURL   string
	}{
		{
			name:      "With workspace",
			workspace: "my-workspace",
			wantURL:   "https://api.bitbucket.org/2.0/repositories/my-workspace",
		},
		{
			name:      "Empty workspace",
			workspace: "",
			wantURL:   "https://api.bitbucket.org/2.0/repositories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := client.buildRepositoriesURL(tt.workspace)
			assert.Equal(t, tt.wantURL, url)
		})
	}
}

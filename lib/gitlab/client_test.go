package gitlab

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultGitLabURL = "https://gitlab.com"
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
			token:      "glpat-test123",
			apiURL:     "https://gitlab.example.com",
			wantAPIURL: "https://gitlab.example.com",
		},
		{
			name:       "Valid token with default URL",
			token:      "glpat-test456",
			apiURL:     "",
			wantAPIURL: defaultGitLabURL,
		},
		{
			name:       "Empty token still creates client",
			token:      "",
			apiURL:     defaultGitLabURL,
			wantAPIURL: defaultGitLabURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.token, tt.apiURL)

			// gitlab.com/gitlab-org/api/client-go doesn't validate token at creation time
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.NotNil(t, client.client)
			assert.NotNil(t, client.limiter)
			assert.Equal(t, tt.wantAPIURL, client.apiURL)
		})
	}
}

func TestListProjects(t *testing.T) {
	// Note: This is an integration test that would require a real GitLab instance
	// For now, we'll test that the function exists and has correct signature
	t.Run("Function signature", func(t *testing.T) {
		// Create a client
		client, err := NewClient("test-token", defaultGitLabURL)
		require.NoError(t, err)

		ctx := context.Background()
		projects, err := client.ListProjects(ctx, 0)

		// We expect an error since we don't have a valid token
		// But projects should be non-nil (empty slice)
		assert.NotNil(t, projects)
		assert.Error(t, err, "Expected error with invalid token")
		t.Logf("ListProjects returned %d projects with error: %v", len(projects), err)
	})
}

func TestListProjectsContextCancellation(t *testing.T) {
	client, err := NewClient("test-token", defaultGitLabURL)
	if err != nil {
		t.Skip("Skipping test - requires valid client creation")
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.ListProjects(ctx, 0)
	assert.Error(t, err, "Should return error when context is cancelled")
}

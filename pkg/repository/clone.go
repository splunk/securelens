package repository

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// CloneManager handles Git repository cloning operations
type CloneManager struct {
	tempDir      string
	authProvider *AuthProvider
}

// CloneResult contains information about a cloned repository
type CloneResult struct {
	Path       string // Local path to the cloned repository
	CommitHash string // HEAD commit hash
	Branch     string // Branch that was checked out
	ZipPath    string // Path to zip file (if created)
}

// NewCloneManager creates a new clone manager instance
func NewCloneManager(tempDir string, auth *AuthProvider) *CloneManager {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &CloneManager{
		tempDir:      tempDir,
		authProvider: auth,
	}
}

// Clone clones a repository to a temporary directory
func (c *CloneManager) Clone(ctx context.Context, repoInfo *RepoURLInfo, shallow bool) (*CloneResult, error) {
	slog.Info("Cloning repository",
		"url", repoInfo.CloneURL,
		"branch", repoInfo.Branch,
		"commit", repoInfo.Commit,
		"shallow", shallow,
	)

	// Create unique temp directory for this clone
	repoName := strings.ReplaceAll(repoInfo.Repo, " ", "_")
	cloneDir, err := os.MkdirTemp(c.tempDir, fmt.Sprintf("securelens-%s-", repoName))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Get authentication for the provider
	auth := c.getAuth(repoInfo.Provider)

	// Build clone options
	depth := 0 // Full clone by default
	if shallow && repoInfo.Commit == "" {
		depth = 1
	}

	cloneOpts := &gogit.CloneOptions{
		URL:             repoInfo.CloneURL,
		Auth:            auth,
		Depth:           depth,
		Tags:            gogit.NoTags,
		InsecureSkipTLS: true, // Allow self-signed certs for internal instances
	}

	// Set branch reference if specified, otherwise use default remote branch
	if repoInfo.Branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(repoInfo.Branch)
		cloneOpts.SingleBranch = true
	} else {
		// No branch specified - clone the default branch (main/master/etc)
		cloneOpts.SingleBranch = true
	}

	// Attempt clone
	slog.Debug("Starting git clone", "dir", cloneDir, "opts", cloneOpts)
	repo, err := gogit.PlainCloneContext(ctx, cloneDir, false, cloneOpts)
	if err != nil {
		// Try without submodules if it fails
		cloneOpts.RecurseSubmodules = gogit.NoRecurseSubmodules
		repo, err = gogit.PlainCloneContext(ctx, cloneDir, false, cloneOpts)
		if err != nil {
			_ = os.RemoveAll(cloneDir)
			return nil, fmt.Errorf("failed to clone repository: %w", err)
		}
	}

	result := &CloneResult{
		Path:   cloneDir,
		Branch: repoInfo.Branch,
	}

	// Get HEAD reference to determine actual branch and commit
	ref, err := repo.Head()
	if err == nil {
		result.CommitHash = ref.Hash().String()
		// If branch was not specified, extract it from HEAD
		if result.Branch == "" && ref.Name().IsBranch() {
			result.Branch = ref.Name().Short()
		}
	}

	// If specific commit is requested, checkout that commit
	if repoInfo.Commit != "" && repoInfo.Commit != "HEAD" {
		worktree, err := repo.Worktree()
		if err != nil {
			_ = os.RemoveAll(cloneDir)
			return nil, fmt.Errorf("failed to get worktree: %w", err)
		}

		hash := plumbing.NewHash(repoInfo.Commit)
		err = worktree.Checkout(&gogit.CheckoutOptions{
			Hash:  hash,
			Force: true,
		})
		if err != nil {
			_ = os.RemoveAll(cloneDir)
			return nil, fmt.Errorf("failed to checkout commit %s: %w", repoInfo.Commit, err)
		}
		result.CommitHash = repoInfo.Commit
	}

	slog.Info("Repository cloned successfully",
		"path", cloneDir,
		"commit", result.CommitHash,
		"branch", result.Branch,
	)

	return result, nil
}

// CloneAndZip clones a repository and creates a zip archive
func (c *CloneManager) CloneAndZip(ctx context.Context, repoInfo *RepoURLInfo, shallow bool) (*CloneResult, error) {
	result, err := c.Clone(ctx, repoInfo, shallow)
	if err != nil {
		return nil, err
	}

	// Create zip file
	zipPath := result.Path + ".zip"
	if err := c.createZip(result.Path, zipPath); err != nil {
		_ = os.RemoveAll(result.Path)
		return nil, fmt.Errorf("failed to create zip: %w", err)
	}

	result.ZipPath = zipPath
	return result, nil
}

// getAuth returns appropriate authentication for the provider
func (c *CloneManager) getAuth(provider GitProvider) transport.AuthMethod {
	if c.authProvider == nil {
		return nil
	}

	switch provider {
	case GitHub:
		if c.authProvider.githubToken != "" {
			return &http.BasicAuth{
				Username: "x-access-token",
				Password: c.authProvider.githubToken,
			}
		}
	case GitLab:
		if c.authProvider.gitlabToken != "" {
			return &http.BasicAuth{
				Username: "oauth2",
				Password: c.authProvider.gitlabToken,
			}
		}
	case Bitbucket:
		if c.authProvider.bitbucketToken != "" {
			// Bitbucket uses BasicAuth with token as password
			return &http.BasicAuth{
				Username: c.authProvider.bitbucketUser,
				Password: c.authProvider.bitbucketToken,
			}
		}
	}

	return nil
}

// createZip creates a zip archive of the repository
func (c *CloneManager) createZip(source, target string) error {
	slog.Debug("Creating zip archive", "source", source, "target", target)

	zipFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip symbolic links
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		// Skip .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		// Create header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Method = zip.Deflate

		// Set relative path
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if info.IsDir() {
			header.Name += "/"
		}

		headerWriter, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			// Skip files that can't be opened
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		defer file.Close()

		_, err = io.Copy(headerWriter, file)
		return err
	})
}

// Cleanup removes the cloned repository and associated files
func (c *CloneManager) Cleanup(result *CloneResult) error {
	if result == nil {
		return nil
	}

	slog.Info("Cleaning up repository", "path", result.Path)

	var errs []string

	if result.Path != "" {
		if err := os.RemoveAll(result.Path); err != nil {
			errs = append(errs, fmt.Sprintf("path: %v", err))
		}
	}

	if result.ZipPath != "" {
		if err := os.Remove(result.ZipPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("zip: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}

	slog.Info("Repository cleaned up successfully")
	return nil
}

// GetZipBuffer returns the zip file contents as a buffer
func (c *CloneManager) GetZipBuffer(zipPath string) (*bytes.Buffer, error) {
	data, err := os.ReadFile(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read zip file: %w", err)
	}
	return bytes.NewBuffer(data), nil
}

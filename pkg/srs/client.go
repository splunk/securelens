package srs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// WaitConfig configures the waiting behavior
type WaitConfig struct {
	PollInterval time.Duration // How often to poll for status
	MaxTimeout   time.Duration // Maximum time to wait
	MaxRetries   int           // Maximum number of retries for errors
}

// DefaultWaitConfig returns the default waiting configuration
func DefaultWaitConfig() WaitConfig {
	return WaitConfig{
		PollInterval: 10 * time.Second,
		MaxTimeout:   30 * time.Minute,
		MaxRetries:   100,
	}
}

// Client handles SRS API interactions
type Client struct {
	httpClient *http.Client
	config     WaitConfig
}

// NewClient creates a new SRS client
func NewClient(config WaitConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: config,
	}
}

// WaitForJob polls the SRS job URL until all jobs are complete
func (c *Client) WaitForJob(ctx context.Context, jobURL string) (*SRSJobResponse, error) {
	slog.Info("Starting to wait for SRS job", "job_url", jobURL)

	// Normalize URL
	jobURL = c.normalizeURL(jobURL)

	startTime := time.Now()
	retries := c.config.MaxRetries
	var lastResponse *SRSJobResponse

	for {
		select {
		case <-ctx.Done():
			slog.Warn("Context cancelled while waiting for SRS job", "job_url", jobURL)
			return lastResponse, ctx.Err()
		default:
		}

		// Check timeout
		elapsed := time.Since(startTime)
		if elapsed > c.config.MaxTimeout {
			slog.Warn("Maximum timeout reached waiting for SRS job",
				"job_url", jobURL,
				"elapsed", elapsed.String(),
				"max_timeout", c.config.MaxTimeout.String(),
			)
			if lastResponse != nil && len(lastResponse.ServiceResponse.Jobs) > 0 {
				slog.Info("Returning partial results due to timeout")
				return lastResponse, nil
			}
			return nil, fmt.Errorf("maximum timeout reached waiting for job completion")
		}

		// Make request
		response, err := c.pollJobStatus(ctx, jobURL)
		if err != nil {
			slog.Error("Error polling job status", "error", err, "retries_remaining", retries)
			retries--
			if retries <= 0 {
				if lastResponse != nil && len(lastResponse.ServiceResponse.Jobs) > 0 {
					slog.Info("Returning partial results due to persistent errors")
					return lastResponse, nil
				}
				return nil, fmt.Errorf("maximum retries exceeded: %w", err)
			}
			time.Sleep(c.config.PollInterval)
			continue
		}

		lastResponse = response

		// Check if all jobs are complete
		if len(response.ServiceResponse.Jobs) == 0 {
			slog.Warn("Empty jobs array in response, retrying...", "retries_remaining", retries)
			retries--
			if retries <= 0 {
				return nil, fmt.Errorf("maximum retries exceeded with empty jobs array")
			}
			time.Sleep(c.config.PollInterval)
			continue
		}

		// Track job statuses
		statuses := c.getJobStatuses(response)
		allComplete := c.allJobsTerminal(response)

		slog.Info("SRS job status update",
			"elapsed", elapsed.Round(time.Second).String(),
			"statuses", statuses,
			"all_complete", allComplete,
		)

		if allComplete {
			slog.Info("All SRS jobs completed",
				"elapsed", elapsed.Round(time.Second).String(),
				"job_count", len(response.ServiceResponse.Jobs),
			)
			return response, nil
		}

		// Wait before next poll
		time.Sleep(c.config.PollInterval)
	}
}

// WaitForJobs waits for multiple job URLs concurrently
func (c *Client) WaitForJobs(ctx context.Context, jobURLs []string) (map[string]*SRSJobResponse, error) {
	results := make(map[string]*SRSJobResponse)

	for _, url := range jobURLs {
		slog.Info("Waiting for job", "url", url)
		response, err := c.WaitForJob(ctx, url)
		if err != nil {
			slog.Error("Failed to wait for job", "url", url, "error", err)
			// Continue with other jobs
		}
		results[url] = response
	}

	return results, nil
}

func (c *Client) pollJobStatus(ctx context.Context, jobURL string) (*SRSJobResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	var response SRSJobResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}

func (c *Client) normalizeURL(jobURL string) string {
	if !strings.HasPrefix(jobURL, "http://") && !strings.HasPrefix(jobURL, "https://") {
		if strings.HasPrefix(jobURL, "/") {
			// Relative URL - this shouldn't happen but handle it
			jobURL = "https://srs.example.com" + jobURL
		} else {
			jobURL = "https://" + jobURL
		}
	}
	return jobURL
}

func (c *Client) getJobStatuses(response *SRSJobResponse) map[string]int {
	statuses := make(map[string]int)
	for _, job := range response.ServiceResponse.Jobs {
		statuses[job.Status]++
	}
	return statuses
}

func (c *Client) allJobsTerminal(response *SRSJobResponse) bool {
	for _, job := range response.ServiceResponse.Jobs {
		if !job.IsTerminal() {
			return false
		}
	}
	return true
}

// ParseJobResults parses the results string for each job into typed results
func ParseJobResults(job *Job) (interface{}, error) {
	if job.Results == "" {
		return nil, nil
	}

	switch strings.ToLower(job.Service) {
	case "semgrep":
		var results SemgrepResults
		if err := json.Unmarshal([]byte(job.Results), &results); err != nil {
			return nil, fmt.Errorf("failed to parse semgrep results: %w", err)
		}
		return &results, nil

	case "trufflehog":
		var results TrufflehogResults
		if err := json.Unmarshal([]byte(job.Results), &results); err != nil {
			return nil, fmt.Errorf("failed to parse trufflehog results: %w", err)
		}
		return &results, nil

	case "fossa":
		var results FossaResults
		if err := json.Unmarshal([]byte(job.Results), &results); err != nil {
			return nil, fmt.Errorf("failed to parse fossa results: %w", err)
		}
		return &results, nil

	case "trivy":
		var results TrivyResults
		if err := json.Unmarshal([]byte(job.Results), &results); err != nil {
			return nil, fmt.Errorf("failed to parse trivy results: %w", err)
		}
		return &results, nil

	default:
		// Return raw JSON for unknown services
		var raw interface{}
		if err := json.Unmarshal([]byte(job.Results), &raw); err != nil {
			return job.Results, nil // Return as string if not valid JSON
		}
		return raw, nil
	}
}

// GetFindingsSummary returns a summary of findings from all jobs
func GetFindingsSummary(response *SRSJobResponse) map[string]interface{} {
	summary := make(map[string]interface{})

	for _, job := range response.ServiceResponse.Jobs {
		jobSummary := map[string]interface{}{
			"status":    job.Status,
			"timestamp": job.Timestamp,
		}

		if job.Status == JobStatusComplete && job.Results != "" {
			results, err := ParseJobResults(&job)
			if err != nil {
				jobSummary["parse_error"] = err.Error()
			} else {
				switch r := results.(type) {
				case *SemgrepResults:
					jobSummary["findings_count"] = len(r.Results.Results)
					jobSummary["files_scanned"] = len(r.Results.Paths.Scanned)
					// Count by severity
					severities := make(map[string]int)
					for _, finding := range r.Results.Results {
						severities[finding.Extra.Severity]++
					}
					jobSummary["by_severity"] = severities

				case *TrufflehogResults:
					jobSummary["findings_count"] = len(r.Findings)
					jobSummary["verified_secrets"] = r.VerifiedSecrets
					jobSummary["unverified_secrets"] = r.UnverifiedSecrets
					jobSummary["scan_duration"] = r.ScanDuration

				case *FossaResults:
					jobSummary["findings_count"] = len(r.Issues)
					// Count by severity
					severities := make(map[string]int)
					for _, issue := range r.Issues {
						severities[issue.Severity]++
					}
					jobSummary["by_severity"] = severities

				case *TrivyResults:
					jobSummary["vulnerabilities_count"] = len(r.Vulnerabilities)
					jobSummary["packages_count"] = len(r.Packages)
					// Count by severity from raw data
					severities := make(map[string]int)
					for _, result := range r.RawData.Results {
						for _, vuln := range result.Vulnerabilities {
							severities[vuln.Severity]++
						}
					}
					jobSummary["by_severity"] = severities

				default:
					jobSummary["raw_results"] = results
				}
			}
		} else if job.Status == JobStatusFailed {
			jobSummary["error"] = "Job failed"
		}

		summary[job.Service] = jobSummary
	}

	return summary
}

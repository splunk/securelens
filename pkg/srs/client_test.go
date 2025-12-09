package srs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultWaitConfig(t *testing.T) {
	config := DefaultWaitConfig()

	if config.PollInterval != 10*time.Second {
		t.Errorf("DefaultWaitConfig().PollInterval = %v, want %v", config.PollInterval, 10*time.Second)
	}
	if config.MaxTimeout != 30*time.Minute {
		t.Errorf("DefaultWaitConfig().MaxTimeout = %v, want %v", config.MaxTimeout, 30*time.Minute)
	}
	if config.MaxRetries != 100 {
		t.Errorf("DefaultWaitConfig().MaxRetries = %d, want 100", config.MaxRetries)
	}
}

func TestNewClient(t *testing.T) {
	config := WaitConfig{
		PollInterval: 5 * time.Second,
		MaxTimeout:   10 * time.Minute,
		MaxRetries:   50,
	}

	client := NewClient(config)

	if client.config.PollInterval != 5*time.Second {
		t.Errorf("NewClient().config.PollInterval = %v, want %v", client.config.PollInterval, 5*time.Second)
	}
	if client.httpClient == nil {
		t.Error("NewClient().httpClient is nil")
	}
}

func TestClient_normalizeURL(t *testing.T) {
	client := NewClient(DefaultWaitConfig())

	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/job/123", "https://example.com/job/123"},
		{"http://example.com/job/123", "http://example.com/job/123"},
		{"example.com/job/123", "https://example.com/job/123"},
		{"/api/v1/job/123", "https://srs.example.com/api/v1/job/123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := client.normalizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeURL(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestJob_IsTerminal(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{JobStatusPending, false},
		{JobStatusRunning, false},
		{JobStatusComplete, true},
		{JobStatusFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			job := &Job{Status: tt.status}
			if result := job.IsTerminal(); result != tt.expected {
				t.Errorf("Job{Status: %s}.IsTerminal() = %v, want %v", tt.status, result, tt.expected)
			}
		})
	}
}

func TestClient_getJobStatuses(t *testing.T) {
	client := NewClient(DefaultWaitConfig())
	response := &SRSJobResponse{
		ServiceResponse: ServiceResponse{
			Jobs: []Job{
				{Status: JobStatusComplete},
				{Status: JobStatusComplete},
				{Status: JobStatusFailed},
				{Status: JobStatusRunning},
			},
		},
	}

	statuses := client.getJobStatuses(response)

	if statuses[JobStatusComplete] != 2 {
		t.Errorf("getJobStatuses() COMPLETE = %d, want 2", statuses[JobStatusComplete])
	}
	if statuses[JobStatusFailed] != 1 {
		t.Errorf("getJobStatuses() FAILED = %d, want 1", statuses[JobStatusFailed])
	}
	if statuses[JobStatusRunning] != 1 {
		t.Errorf("getJobStatuses() RUNNING = %d, want 1", statuses[JobStatusRunning])
	}
}

func TestClient_allJobsTerminal(t *testing.T) {
	client := NewClient(DefaultWaitConfig())

	tests := []struct {
		name     string
		jobs     []Job
		expected bool
	}{
		{
			name:     "all complete",
			jobs:     []Job{{Status: JobStatusComplete}, {Status: JobStatusComplete}},
			expected: true,
		},
		{
			name:     "all failed",
			jobs:     []Job{{Status: JobStatusFailed}, {Status: JobStatusFailed}},
			expected: true,
		},
		{
			name:     "mixed terminal",
			jobs:     []Job{{Status: JobStatusComplete}, {Status: JobStatusFailed}},
			expected: true,
		},
		{
			name:     "one running",
			jobs:     []Job{{Status: JobStatusComplete}, {Status: JobStatusRunning}},
			expected: false,
		},
		{
			name:     "one pending",
			jobs:     []Job{{Status: JobStatusComplete}, {Status: JobStatusPending}},
			expected: false,
		},
		{
			name:     "empty jobs",
			jobs:     []Job{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := &SRSJobResponse{
				ServiceResponse: ServiceResponse{Jobs: tt.jobs},
			}
			result := client.allJobsTerminal(response)
			if result != tt.expected {
				t.Errorf("allJobsTerminal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClient_WaitForJob_ImmediateComplete(t *testing.T) {
	// Create a test server that returns completed jobs immediately
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := SRSJobResponse{
			ServiceResponse: ServiceResponse{
				Jobs: []Job{
					{
						JobID:     "test-job-1",
						Service:   "semgrep",
						Status:    JobStatusComplete,
						Timestamp: time.Now().Format(time.RFC3339),
						Results:   `{"results":{"results":[]}}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(WaitConfig{
		PollInterval: 100 * time.Millisecond,
		MaxTimeout:   5 * time.Second,
		MaxRetries:   3,
	})

	ctx := context.Background()
	result, err := client.WaitForJob(ctx, server.URL)

	if err != nil {
		t.Fatalf("WaitForJob() returned error: %v", err)
	}
	if result == nil {
		t.Fatal("WaitForJob() returned nil result")
	}
	if len(result.ServiceResponse.Jobs) != 1 {
		t.Errorf("WaitForJob() returned %d jobs, want 1", len(result.ServiceResponse.Jobs))
	}
	if result.ServiceResponse.Jobs[0].Status != JobStatusComplete {
		t.Errorf("WaitForJob() job status = %s, want COMPLETE", result.ServiceResponse.Jobs[0].Status)
	}
}

func TestClient_WaitForJob_ContextCancellation(t *testing.T) {
	// Create a test server that never completes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := SRSJobResponse{
			ServiceResponse: ServiceResponse{
				Jobs: []Job{
					{
						JobID:   "test-job-1",
						Service: "semgrep",
						Status:  JobStatusRunning,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(WaitConfig{
		PollInterval: 50 * time.Millisecond,
		MaxTimeout:   10 * time.Second,
		MaxRetries:   100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := client.WaitForJob(ctx, server.URL)

	if err == nil {
		t.Error("WaitForJob() should return error on context cancellation")
	}
}

func TestParseJobResults_Semgrep(t *testing.T) {
	job := &Job{
		Service: "semgrep",
		Results: `{"results":{"results":[{"check_id":"test-rule","path":"test.go"}],"paths":{"scanned":["test.go"]}}}`,
	}

	result, err := ParseJobResults(job)
	if err != nil {
		t.Fatalf("ParseJobResults() returned error: %v", err)
	}

	semgrepResults, ok := result.(*SemgrepResults)
	if !ok {
		t.Fatalf("ParseJobResults() returned %T, want *SemgrepResults", result)
	}

	if len(semgrepResults.Results.Results) != 1 {
		t.Errorf("ParseJobResults() returned %d findings, want 1", len(semgrepResults.Results.Results))
	}
}

func TestParseJobResults_EmptyResults(t *testing.T) {
	job := &Job{
		Service: "semgrep",
		Results: "",
	}

	result, err := ParseJobResults(job)
	if err != nil {
		t.Fatalf("ParseJobResults() returned error: %v", err)
	}
	if result != nil {
		t.Errorf("ParseJobResults() with empty results returned %v, want nil", result)
	}
}

func TestGetFindingsSummary(t *testing.T) {
	response := &SRSJobResponse{
		ServiceResponse: ServiceResponse{
			Jobs: []Job{
				{
					Service:   "semgrep",
					Status:    JobStatusComplete,
					Timestamp: "2024-01-01T00:00:00Z",
					Results:   `{"results":{"results":[{"check_id":"test","extra":{"severity":"ERROR"}}],"paths":{"scanned":["file.go"]}}}`,
				},
				{
					Service:   "trufflehog",
					Status:    JobStatusFailed,
					Timestamp: "2024-01-01T00:00:00Z",
				},
			},
		},
	}

	summary := GetFindingsSummary(response)

	if _, ok := summary["semgrep"]; !ok {
		t.Error("GetFindingsSummary() missing semgrep key")
	}
	if _, ok := summary["trufflehog"]; !ok {
		t.Error("GetFindingsSummary() missing trufflehog key")
	}

	semgrepSummary, ok := summary["semgrep"].(map[string]interface{})
	if !ok {
		t.Fatalf("GetFindingsSummary() semgrep is not a map")
	}
	if semgrepSummary["status"] != JobStatusComplete {
		t.Errorf("GetFindingsSummary() semgrep status = %v, want COMPLETE", semgrepSummary["status"])
	}

	trufflehogSummary, ok := summary["trufflehog"].(map[string]interface{})
	if !ok {
		t.Fatalf("GetFindingsSummary() trufflehog is not a map")
	}
	if trufflehogSummary["status"] != JobStatusFailed {
		t.Errorf("GetFindingsSummary() trufflehog status = %v, want FAILED", trufflehogSummary["status"])
	}
}

func TestJobStatusConstants(t *testing.T) {
	if JobStatusPending != "PENDING" {
		t.Errorf("JobStatusPending = %s, want PENDING", JobStatusPending)
	}
	if JobStatusRunning != "RUNNING" {
		t.Errorf("JobStatusRunning = %s, want RUNNING", JobStatusRunning)
	}
	if JobStatusComplete != "COMPLETE" {
		t.Errorf("JobStatusComplete = %s, want COMPLETE", JobStatusComplete)
	}
	if JobStatusFailed != "FAILED" {
		t.Errorf("JobStatusFailed = %s, want FAILED", JobStatusFailed)
	}
}

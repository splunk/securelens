package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/pkg/scanner/standalone"
)

func TestShouldSendToSlack(t *testing.T) {
	cfg := &config.Config{Slack: config.SlackConfig{Enabled: true}}
	results := map[string]*standalone.StandaloneScanResult{"scanner": {}}
	if !shouldSendToSlack(cfg, results) {
		t.Errorf("Expected shouldSendToSlack to return true")
	}

	cfg.Slack.Enabled = false
	if shouldSendToSlack(cfg, results) {
		t.Errorf("Expected shouldSendToSlack to return false when Slack disabled")
	}

	cfg.Slack.Enabled = true
	if shouldSendToSlack(nil, results) {
		t.Errorf("Expected shouldSendToSlack to return false when cfg is nil")
	}

	if shouldSendToSlack(cfg, map[string]*standalone.StandaloneScanResult{}) {
		t.Errorf("Expected shouldSendToSlack to return false when results empty")
	}
}

func TestBuildSlackSummaryMessage(t *testing.T) {
	repoCtx := slackRepoContext{Repository: "repo", Branch: "main", Commit: "abc123"}
	results := map[string]*standalone.StandaloneScanResult{
		"scanner": {
			Status:  "success",
			Results: map[string]interface{}{"findings": 2, "severity": "high"},
		},
	}
	msg := buildSlackSummaryMessage(results, repoCtx)
	if msg == "" {
		t.Errorf("Expected summary message to be non-empty")
	}
	if !strings.Contains(msg, "repo") || !strings.Contains(msg, "main") || !strings.Contains(msg, "abc123") {
		t.Errorf("Expected repo context in summary message")
	}
}

func TestBuildSlackThreadHeader(t *testing.T) {
	repoCtx := slackRepoContext{Repository: "repo", Branch: "main", Commit: "abc123"}
	head := buildSlackThreadHeader(repoCtx, "scanner")
	if !strings.Contains(head, "repo") || !strings.Contains(head, "main") || !strings.Contains(head, "abc123") {
		t.Errorf("Expected repo context in thread header")
	}
}

func TestBuildSlackThreadEntryNilEvent(t *testing.T) {
	entry := buildSlackThreadEntry(nil)
	if entry != "" {
		t.Errorf("Expected empty string for nil event")
	}
}

func TestGetStringValue(t *testing.T) {
	m := map[string]interface{}{"key": "value"}
	if getStringValue(m, "key") != "value" {
		t.Errorf("Expected getStringValue to return 'value'")
	}
	if getStringValue(m, "missing") != "" {
		t.Errorf("Expected getStringValue to return empty string for missing key")
	}
}

func TestGetBoolValue(t *testing.T) {
	m := map[string]interface{}{"flag": true}
	if !getBoolValue(m, "flag") {
		t.Errorf("Expected getBoolValue to return true")
	}
	if getBoolValue(m, "missing") {
		t.Errorf("Expected getBoolValue to return false for missing key")
	}
}

func TestGetNestedString(t *testing.T) {
	m := map[string]interface{}{"a": map[string]interface{}{"b": "c"}}
	if getNestedString(m, "a", "b") != "c" {
		t.Errorf("Expected getNestedString to return 'c'")
	}
	if getNestedString(m, "a", "missing") != "" {
		t.Errorf("Expected getNestedString to return empty string for missing key")
	}
}

func TestGetNestedInt(t *testing.T) {
	m := map[string]interface{}{"a": map[string]interface{}{"b": 42}}
	if getNestedInt(m, "a", "b") != 42 {
		t.Errorf("Expected getNestedInt to return 42")
	}
	if getNestedInt(m, "a", "missing") != 0 {
		t.Errorf("Expected getNestedInt to return 0 for missing key")
	}
}

func TestSanitizeSingleLine(t *testing.T) {
	input := "  hello\nworld\rtest  "
	output := sanitizeSingleLine(input)
	if output != "hello world test" {
		t.Errorf("Expected sanitized single line")
	}
}

func TestTruncateText(t *testing.T) {
	input := "abcdefghijklmnopqrstuvwxyz"
	output := truncateText(input, 10)
	if output != "abcdefg..." {
		t.Errorf("Expected truncated text with ellipsis")
	}
	output = truncateText(input, 30)
	if output != input {
		t.Errorf("Expected no truncation if under maxLen")
	}
}

func TestRedactSlackError(t *testing.T) {
	err := fmt.Errorf("token:12345")
	redacted := redactSlackError(err, "12345")
	if !strings.Contains(redacted, "[redacted]") {
		t.Errorf("Expected token to be redacted")
	}
	if redactSlackError(nil, "token") != "" {
		t.Errorf("Expected empty string for nil error")
	}
}

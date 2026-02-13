package scan

import (
	"log/slog"
	"strings"

	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/pkg/scanner/standalone"
	"github.com/splunk/securelens/pkg/splunk"
)

type splunkRepoContext struct {
	Repository string
	Branch     string
	Commit     string
}

func sendStandaloneResultsToSplunk(cfg *config.Config, standaloneResults map[string]*standalone.StandaloneScanResult, repoCtx splunkRepoContext) {
	if !shouldSendToSplunk(cfg, standaloneResults) {
		return
	}

	splunkClient, err := newSplunkClient(cfg)
	if err != nil {
		slog.Warn("Splunk client not initialized - check configuration", "error", redactSplunkError(err, cfg.Splunk.HECToken))
		return
	}

	scannerNames := collectScannerNames(standaloneResults)
	slog.Info("Sending standalone results to Splunk", "count", len(scannerNames), "scanners", strings.Join(scannerNames, ","))

	for scannerName, result := range standaloneResults {
		sendScannerEventsToSplunk(splunkClient, scannerName, result, repoCtx)
	}
}

func shouldSendToSplunk(cfg *config.Config, standaloneResults map[string]*standalone.StandaloneScanResult) bool {
	if cfg == nil || !cfg.Splunk.Enabled {
		return false
	}
	if len(standaloneResults) == 0 {
		slog.Warn("No standalone results to send to Splunk")
		return false
	}
	return true
}

func newSplunkClient(cfg *config.Config) (*splunk.Client, error) {
	splunkCfg := splunk.Config{
		HECEndpoint: cfg.Splunk.HECEndpoint,
		Token:       cfg.Splunk.HECToken,
	}
	if err := splunk.ValidateConfig(splunkCfg); err != nil {
		return nil, err
	}
	return splunk.NewClient(splunkCfg), nil
}

func collectScannerNames(standaloneResults map[string]*standalone.StandaloneScanResult) []string {
	scannerNames := make([]string, 0, len(standaloneResults))
	for scannerName := range standaloneResults {
		scannerNames = append(scannerNames, scannerName)
	}
	return scannerNames
}

func sendScannerEventsToSplunk(splunkClient *splunk.Client, scannerName string, result *standalone.StandaloneScanResult, repoCtx splunkRepoContext) {
	if result == nil {
		slog.Warn("Skipping nil standalone result", "scanner", scannerName)
		return
	}

	events := buildStandaloneResultEvents(scannerName, result)
	slog.Info("Prepared standalone events for Splunk", "scanner", scannerName, "count", len(events))

	sentCount := 0
	failedCount := 0
	for _, event := range events {
		if err := sendStandaloneEvent(splunkClient, scannerName, event, repoCtx); err != nil {
			failedCount++
			continue
		}
		sentCount++
	}

	slog.Info("Sent standalone events to Splunk", "scanner", scannerName, "sent", sentCount, "failed", failedCount, "total", len(events))
}

func sendStandaloneEvent(splunkClient *splunk.Client, scannerName string, event *standalone.StandaloneScanResult, repoCtx splunkRepoContext) error {
	if err := splunkClient.SendEvent(buildSplunkEventPayload(event, repoCtx)); err != nil {
		slog.Error("Failed to send scan results to Splunk", "scanner", scannerName, "error", err)
		return err
	}
	return nil
}

func buildSplunkEventPayload(event *standalone.StandaloneScanResult, repoCtx splunkRepoContext) map[string]interface{} {
	payload := map[string]interface{}{
		"scanner":    event.Scanner,
		"status":     event.Status,
		"start_time": event.StartTime,
		"end_time":   event.EndTime,
		"duration":   event.Duration,
		"results":    event.Results,
		"repository": repoCtx.Repository,
		"branch":     repoCtx.Branch,
		"commit":     repoCtx.Commit,
	}
	if event.Error != "" {
		payload["error"] = event.Error
	}
	return payload
}

func buildStandaloneResultEvents(scannerName string, result *standalone.StandaloneScanResult) []*standalone.StandaloneScanResult {
	switch scannerName {
	case string(standalone.ScannerOpengrep):
		return splitFindingsResult(result, string(standalone.ScannerOpengrep))
	case string(standalone.ScannerTrivy):
		return splitTrivyResult(result)
	case string(standalone.ScannerTrufflehog):
		return splitFindingsResult(result, string(standalone.ScannerTrufflehog))
	default:
		return []*standalone.StandaloneScanResult{result}
	}
}

func splitFindingsResult(result *standalone.StandaloneScanResult, scannerName string) []*standalone.StandaloneScanResult {
	findings, ok := result.Results["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		return []*standalone.StandaloneScanResult{result}
	}

	events := make([]*standalone.StandaloneScanResult, 0, len(findings))
	for _, finding := range findings {
		event := cloneStandaloneResult(result)
		results := cloneMap(event.Results)
		results["findings"] = []interface{}{finding}
		results["findings_count"] = 1

		switch scannerName {
		case "opengrep":
			severity := extractFindingSeverity(finding)
			if severity != "" {
				results["by_severity"] = map[string]int{severity: 1}
			}
		case "trufflehog":
			verified := extractTrufflehogVerified(finding)
			if verified {
				results["verified_secrets"] = 1
				results["unverified_secrets"] = 0
			} else {
				results["verified_secrets"] = 0
				results["unverified_secrets"] = 1
			}
		}

		event.Results = results
		events = append(events, event)
	}

	return events
}

func splitTrivyResult(result *standalone.StandaloneScanResult) []*standalone.StandaloneScanResult {
	resultsList, ok := result.Results["results"].([]interface{})
	if !ok || len(resultsList) == 0 {
		return []*standalone.StandaloneScanResult{result}
	}

	var events []*standalone.StandaloneScanResult
	for _, entry := range resultsList {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		vulns, ok := entryMap["Vulnerabilities"].([]interface{})
		if !ok || len(vulns) == 0 {
			continue
		}
		for _, vuln := range vulns {
			event := cloneStandaloneResult(result)
			results := cloneMap(event.Results)

			// Shallow copy is sufficient since we replace Vulnerabilities entirely.
			entryCopy := cloneMap(entryMap)
			entryCopy["Vulnerabilities"] = []interface{}{vuln}
			results["results"] = []interface{}{entryCopy}
			results["vulnerabilities_count"] = 1

			severity := extractTrivySeverity(vuln)
			if severity != "" {
				results["by_severity"] = map[string]int{severity: 1}
			}

			event.Results = results
			events = append(events, event)
		}
	}

	if len(events) == 0 {
		return []*standalone.StandaloneScanResult{result}
	}

	return events
}

func cloneStandaloneResult(result *standalone.StandaloneScanResult) *standalone.StandaloneScanResult {
	return &standalone.StandaloneScanResult{
		Scanner:   result.Scanner,
		Status:    result.Status,
		StartTime: result.StartTime,
		EndTime:   result.EndTime,
		Duration:  result.Duration,
		Results:   cloneMap(result.Results),
		Error:     result.Error,
	}
}

func cloneMap(src map[string]interface{}) map[string]interface{} {
	// Shallow copy only; nested maps/slices share references with the original.
	if src == nil {
		return map[string]interface{}{}
	}
	dup := make(map[string]interface{}, len(src))
	for k, v := range src {
		dup[k] = v
	}
	return dup
}

func extractFindingSeverity(finding interface{}) string {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return ""
	}
	extra, ok := findingMap["extra"].(map[string]interface{})
	if !ok {
		return ""
	}
	severity, ok := extra["severity"].(string)
	if !ok {
		return ""
	}
	return severity
}

func extractTrufflehogVerified(finding interface{}) bool {
	findingMap, ok := finding.(map[string]interface{})
	if !ok {
		return false
	}
	verified, ok := findingMap["Verified"].(bool)
	if !ok {
		return false
	}
	return verified
}

func extractTrivySeverity(vuln interface{}) string {
	vulnMap, ok := vuln.(map[string]interface{})
	if !ok {
		return ""
	}
	severity, ok := vulnMap["Severity"].(string)
	if !ok {
		return ""
	}
	return severity
}

func redactSplunkError(err error, token string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if token == "" {
		return message
	}
	return strings.ReplaceAll(message, token, "[redacted]")
}

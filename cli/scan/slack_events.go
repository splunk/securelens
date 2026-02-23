package scan

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/splunk/securelens/internal/config"
	"github.com/splunk/securelens/pkg/scanner/standalone"
	"github.com/splunk/securelens/pkg/slack"
)

type slackRepoContext struct {
	Repository string
	Branch     string
	Commit     string
}

const slackMessageMaxChars = 40000
const dividerLine = "-----------------------------------------------------------------------"

func sendStandaloneResultsToSlack(cfg *config.Config, standaloneResults map[string]*standalone.StandaloneScanResult, repoCtx slackRepoContext) {
	if !shouldSendToSlack(cfg, standaloneResults) {
		return
	}

	slackClient, err := newSlackClient(cfg)
	if err != nil {
		slog.Warn("Slack client not initialized - check configuration", "error", redactSlackError(err, cfg.Slack.BotToken))
		return
	}

	scannerNames := collectScannerNames(standaloneResults)
	slog.Info("Sending standalone results to Slack", "count", len(scannerNames), "scanners", strings.Join(scannerNames, ","))

	message := buildSlackSummaryMessage(standaloneResults, repoCtx)
	threadTS, err := slackClient.SendMessage(message)
	if err != nil {
		slog.Error("Failed to send scan summary to Slack", "error", err)
		return
	}

	sendSlackThreadResults(slackClient, standaloneResults, repoCtx, threadTS)
}

func shouldSendToSlack(cfg *config.Config, standaloneResults map[string]*standalone.StandaloneScanResult) bool {
	if cfg == nil || !cfg.Slack.Enabled {
		return false
	}
	if len(standaloneResults) == 0 {
		slog.Warn("No standalone results to send to Slack")
		return false
	}
	return true
}

func newSlackClient(cfg *config.Config) (*slack.Client, error) {
	slackCfg := slack.Config{
		Token:     cfg.Slack.BotToken,
		Channel:   cfg.Slack.Channel,
		Username:  cfg.Slack.Username,
		IconEmoji: cfg.Slack.IconEmoji,
	}
	if err := slack.ValidateConfig(slackCfg); err != nil {
		return nil, err
	}
	return slack.NewClient(slackCfg), nil
}

func sendSlackThreadResults(slackClient *slack.Client, standaloneResults map[string]*standalone.StandaloneScanResult, repoCtx slackRepoContext, threadTS string) {
	if threadTS == "" {
		slog.Warn("Skipping Slack thread replies - missing thread timestamp")
		return
	}

	for scannerName, result := range standaloneResults {
		if result == nil {
			slog.Warn("Skipping nil standalone result", "scanner", scannerName)
			continue
		}

		events := buildStandaloneResultEvents(scannerName, result)
		slog.Info("Prepared standalone thread messages for Slack", "scanner", scannerName, "count", len(events))

		chunks := buildSlackThreadChunks(events, repoCtx, scannerName)
		for _, message := range chunks {
			if _, err := slackClient.SendThreadMessage(threadTS, message); err != nil {
				slog.Error("Failed to send Slack thread message", "scanner", scannerName, "error", err)
			}
		}
	}
}

func buildSlackSummaryMessage(standaloneResults map[string]*standalone.StandaloneScanResult, repoCtx slackRepoContext) string {
	var builder strings.Builder
	builder.WriteString("SecureLens scan summary\n")
	builder.WriteString(fmt.Sprintf("Repository: %s\n", repoCtx.Repository))
	if repoCtx.Branch != "" {
		builder.WriteString(fmt.Sprintf("Branch: %s\n", repoCtx.Branch))
	}
	if repoCtx.Commit != "" {
		builder.WriteString(fmt.Sprintf("Commit: %s\n", repoCtx.Commit))
	}
	builder.WriteString("Please see the detailed findings in the thread below.\n")

	builder.WriteString("\n")
	builder.WriteString("```")
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("%-14s  %-10s  %-20s  %s\n", "Scanner", "Status", "Findings", "Severity"))
	builder.WriteString(fmt.Sprintf("%-14s  %-10s  %-20s  %s\n", "------", "------", "--------", "--------"))

	scannerNames := collectScannerNames(standaloneResults)
	for _, scannerName := range scannerNames {
		result := standaloneResults[scannerName]
		if result == nil {
			builder.WriteString(fmt.Sprintf("%-14s  %-10s  %-20s  %s\n", scannerName, "-", "-", "-"))
			continue
		}

		status := result.Status
		if status == "" {
			status = "-"
		}
		findings := "-"
		severity := "-"
		if result.Results != nil {
			findings = extractFindingsCount(result.Results)
			severity = extractSeveritySummary(result.Results)
		}

		builder.WriteString(fmt.Sprintf("%-14s  %-10s  %-20s  %s\n", scannerName, status, findings, severity))
	}

	builder.WriteString("```")

	return strings.TrimRight(builder.String(), "\n")
}

func buildSlackThreadChunks(events []*standalone.StandaloneScanResult, repoCtx slackRepoContext, scannerName string) []string {
	header := buildSlackThreadHeader(repoCtx, scannerName)
	if len(events) == 0 {
		return nil
	}

	chunks := []string{}
	var builder strings.Builder
	builder.WriteString(header)
	currentLen := builder.Len()
	baseLen := currentLen

	for _, event := range events {
		entry := buildSlackThreadEntry(event)
		if entry == "" {
			continue
		}

		separator := "\n\n"
		if currentLen == baseLen {
			separator = "\n"
		}

		entryLen := len(separator) + len(entry)
		if currentLen+entryLen > slackMessageMaxChars && currentLen > baseLen {
			chunks = append(chunks, strings.TrimRight(builder.String(), "\n"))
			builder.Reset()
			builder.WriteString(header)
			currentLen = builder.Len()
			baseLen = currentLen
			separator = "\n"
			entryLen = len(separator) + len(entry)
		}

		if currentLen+entryLen > slackMessageMaxChars && currentLen == baseLen {
			chunks = append(chunks, strings.TrimRight(builder.String(), "\n"))
			// Truncate the entry and log a warning if it exceeds the Slack limit
			truncatedEntry := entry
			if len(entry) > slackMessageMaxChars {
				slog.Warn("Slack thread entry exceeds max message size and will be truncated", "scanner", scannerName, "length", len(entry))
				truncatedEntry = entry[:slackMessageMaxChars-3] + "..."
			}
			chunks = append(chunks, truncatedEntry)
			builder.Reset()
			builder.WriteString(header)
			currentLen = builder.Len()
			baseLen = currentLen
			continue
		}

		builder.WriteString(separator)
		builder.WriteString(entry)
		currentLen += entryLen
	}

	if strings.TrimSpace(builder.String()) != "" {
		chunks = append(chunks, strings.TrimRight(builder.String(), "\n"))
	}

	return chunks
}

func buildSlackThreadHeader(repoCtx slackRepoContext, scannerName string) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s\n*SECURELENS SCAN FINDINGS (%s)*\n", dividerLine, scannerName))
	if repoCtx.Repository != "" {
		builder.WriteString(fmt.Sprintf("*Repository*: %s\n", repoCtx.Repository))
	}
	if repoCtx.Branch != "" {
		builder.WriteString(fmt.Sprintf("*Branch*: %s\n", repoCtx.Branch))
	}
	if repoCtx.Commit != "" {
		builder.WriteString(fmt.Sprintf("*Commit*: %s\n", repoCtx.Commit))
	}
	return strings.TrimRight(builder.String(), "\n")
}

func buildSlackThreadEntry(event *standalone.StandaloneScanResult) string {
	if event == nil {
		return ""
	}

	var builder strings.Builder
	if event.Results != nil {
		detail := buildSlackFindingDetail(strings.ToLower(event.Scanner), event.Results)
		if detail != "" {
			builder.WriteString(detail)
			builder.WriteString("\n")
		}
	}

	if event.Error != "" {
		builder.WriteString(fmt.Sprintf("*Error*: %s\n", event.Error))
	}

	return strings.TrimRight(builder.String(), "\n")
}

func buildSlackFindingDetail(scanner string, results map[string]interface{}) string {
	switch scanner {
	case "opengrep", "semgrep":
		return buildOpengrepFindingDetail(results)
	case "trivy":
		return buildTrivyFindingDetail(results)
	case "trufflehog":
		return buildTrufflehogFindingDetail(results)
	default:
		return buildGenericFindingDetail(results)
	}
}

func buildOpengrepFindingDetail(results map[string]interface{}) string {
	findings, ok := results["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		return buildGenericFindingDetail(results)
	}

	finding, ok := findings[0].(map[string]interface{})
	if !ok {
		return buildGenericFindingDetail(results)
	}

	checkID := getStringValue(finding, "check_id")
	path := getStringValue(finding, "path")
	// Normalize checkID and path for Slack output
	checkID = cleanCheckID(checkID)
	path = cleanPath(path)
	startLine := getNestedInt(finding, "start", "line")
	message := getNestedString(finding, "extra", "message")
	severity := strings.ToUpper(getNestedString(finding, "extra", "severity"))
	code := sanitizeSingleLine(getNestedString(finding, "extra", "lines"))
	code = truncateText(code, 200)

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s\n*Scanner*: Opengrep\n", dividerLine))
	if checkID != "" {
		builder.WriteString(fmt.Sprintf("*Rule*: %s\n", checkID))
	}
	if severity != "" {
		builder.WriteString(fmt.Sprintf("*Severity*: %s\n", severity))
	}
	if message != "" {
		builder.WriteString(fmt.Sprintf("*Message*: %s\n", truncateText(sanitizeSingleLine(message), 240)))
	}
	if path != "" {
		if startLine > 0 {
			builder.WriteString(fmt.Sprintf("*File*: %s:%d\n", path, startLine))
		} else {
			builder.WriteString(fmt.Sprintf("*File*: %s\n", path))
		}
	}
	if code != "" {
		builder.WriteString(fmt.Sprintf("*Code*: %s\n", code))
	}

	return strings.TrimRight(builder.String(), "\n")
}

func buildTrivyFindingDetail(results map[string]interface{}) string {
	resultsList, ok := results["results"].([]interface{})
	if !ok || len(resultsList) == 0 {
		return buildGenericFindingDetail(results)
	}

	entryMap, ok := resultsList[0].(map[string]interface{})
	if !ok {
		return buildGenericFindingDetail(results)
	}

	vulns, ok := entryMap["Vulnerabilities"].([]interface{})
	if !ok || len(vulns) == 0 {
		return buildGenericFindingDetail(results)
	}

	vuln, ok := vulns[0].(map[string]interface{})
	if !ok {
		return buildGenericFindingDetail(results)
	}

	id := getStringValue(vuln, "VulnerabilityID")
	severity := strings.ToUpper(getStringValue(vuln, "Severity"))
	pkg := getStringValue(vuln, "PkgName")
	installed := getStringValue(vuln, "InstalledVersion")
	fixed := getStringValue(vuln, "FixedVersion")
	title := getStringValue(vuln, "Title")
	primaryURL := getStringValue(vuln, "PrimaryURL")
	target := getStringValue(entryMap, "Target")

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s\n*Scanner*: Trivy\n", dividerLine))
	if id != "" {
		if severity != "" {
			builder.WriteString(fmt.Sprintf("*Vuln*: %s (%s)\n", id, severity))
		} else {
			builder.WriteString(fmt.Sprintf("*Vuln*: %s\n", id))
		}
	}
	if pkg != "" {
		if installed != "" {
			builder.WriteString(fmt.Sprintf("*Package*: %s@%s\n", pkg, installed))
		} else {
			builder.WriteString(fmt.Sprintf("*Package*: %s\n", pkg))
		}
	}
	if fixed != "" {
		builder.WriteString(fmt.Sprintf("*Fixed*: %s\n", fixed))
	}
	if target != "" {
		builder.WriteString(fmt.Sprintf("*Target*: %s\n", target))
	}
	if title != "" {
		builder.WriteString(fmt.Sprintf("*Title*: %s\n", truncateText(sanitizeSingleLine(title), 240)))
	}
	if primaryURL != "" {
		builder.WriteString(fmt.Sprintf("*URL*: %s\n", primaryURL))
	}

	return strings.TrimRight(builder.String(), "\n")
}

func buildTrufflehogFindingDetail(results map[string]interface{}) string {
	findings, ok := results["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		return buildGenericFindingDetail(results)
	}

	finding, ok := findings[0].(map[string]interface{})
	if !ok {
		return buildGenericFindingDetail(results)
	}

	detector := getStringValue(finding, "DetectorName")
	verified := getBoolValue(finding, "Verified")
	redacted := getStringValue(finding, "Redacted")
	file := getNestedString(finding, "SourceMetadata", "Data", "Git", "File")
	line := getNestedInt(finding, "SourceMetadata", "Data", "Git", "Line")
	commit := getNestedString(finding, "SourceMetadata", "Data", "Git", "Commit")
	link := getNestedString(finding, "SourceMetadata", "Data", "Git", "Link")

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s\n*Scanner*: Trufflehog\n", dividerLine))
	if detector != "" {
		builder.WriteString(fmt.Sprintf("*Detector*: %s\n", detector))
	}
	builder.WriteString(fmt.Sprintf("*Verified*: %t\n", verified))
	if redacted != "" {
		builder.WriteString(fmt.Sprintf("*Secret*: %s\n", truncateText(sanitizeSingleLine(redacted), 200)))
	}
	if file != "" {
		if line > 0 {
			builder.WriteString(fmt.Sprintf("*File*: %s:%d\n", file, line))
		} else {
			builder.WriteString(fmt.Sprintf("*File*: %s\n", file))
		}
	}
	if commit != "" {
		builder.WriteString(fmt.Sprintf("*Commit*: %s\n", commit))
	}
	if link != "" {
		builder.WriteString(fmt.Sprintf("*Link*: %s\n", link))
	}

	return strings.TrimRight(builder.String(), "\n")
}

func buildGenericFindingDetail(results map[string]interface{}) string {
	findings := extractFindingsCount(results)
	severity := extractSeveritySummary(results)
	var builder strings.Builder
	if findings != "-" {
		builder.WriteString(fmt.Sprintf("*Findings*: %s\n", findings))
	}
	if severity != "-" {
		builder.WriteString(fmt.Sprintf("*Severity*: %s\n", severity))
	}
	return strings.TrimRight(builder.String(), "\n")
}

func getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if value, ok := data[key]; ok {
		if flag, ok := value.(bool); ok {
			return flag
		}
	}
	return false
}

func getNestedString(data map[string]interface{}, keys ...string) string {
	current := interface{}(data)
	for _, key := range keys {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = obj[key]
		if !ok {
			return ""
		}
	}
	if str, ok := current.(string); ok {
		return str
	}
	return ""
}

func getNestedInt(data map[string]interface{}, keys ...string) int {
	current := interface{}(data)
	for _, key := range keys {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return 0
		}
		current, ok = obj[key]
		if !ok {
			return 0
		}
	}
	switch value := current.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func sanitizeSingleLine(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.ReplaceAll(trimmed, "\n", " ")
	trimmed = strings.ReplaceAll(trimmed, "\r", " ")
	return strings.Join(strings.Fields(trimmed), " ")
}

func truncateText(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return value[:maxLen]
	}
	return value[:maxLen-3] + "..."
}

func redactSlackError(err error, token string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if token == "" {
		return message
	}
	return strings.ReplaceAll(message, token, "[redacted]")
}

package scan

import (
	"reflect"
	"testing"

	"github.com/splunk/securelens/pkg/scanner/standalone"
)

func TestSplitFindingsResultEmpty(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: string(standalone.ScannerOpengrep),
		Results: map[string]interface{}{},
	}

	events := splitFindingsResult(result, string(standalone.ScannerOpengrep))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0] != result {
		t.Fatal("expected original result to be returned")
	}
}

func TestSplitFindingsResultOpengrepSeverity(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: string(standalone.ScannerOpengrep),
		Results: map[string]interface{}{
			"findings": []interface{}{
				map[string]interface{}{
					"extra": map[string]interface{}{"severity": "high"},
				},
				map[string]interface{}{
					"extra": map[string]interface{}{"severity": "low"},
				},
			},
		},
	}

	events := splitFindingsResult(result, string(standalone.ScannerOpengrep))
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	for _, event := range events {
		findings, ok := event.Results["findings"].([]interface{})
		if !ok || len(findings) != 1 {
			t.Fatal("expected findings to contain one item")
		}
		if event.Results["findings_count"] != 1 {
			t.Fatal("expected findings_count to be 1")
		}
		bySeverity, ok := event.Results["by_severity"].(map[string]int)
		if !ok || len(bySeverity) != 1 {
			t.Fatal("expected by_severity to contain one entry")
		}
	}
}

func TestSplitFindingsResultTrufflehogVerified(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: string(standalone.ScannerTrufflehog),
		Results: map[string]interface{}{
			"findings": []interface{}{
				map[string]interface{}{"Verified": true},
				map[string]interface{}{"Verified": false},
			},
		},
	}

	events := splitFindingsResult(result, string(standalone.ScannerTrufflehog))
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	verifiedCounts := make(map[int]int)
	for _, event := range events {
		verified := event.Results["verified_secrets"].(int)
		unverified := event.Results["unverified_secrets"].(int)
		verifiedCounts[verified] = verifiedCounts[verified] + 1
		if verified == 1 && unverified != 0 {
			t.Fatal("expected unverified_secrets to be 0 when verified is 1")
		}
		if verified == 0 && unverified != 1 {
			t.Fatal("expected unverified_secrets to be 1 when verified is 0")
		}
	}

	if verifiedCounts[1] != 1 || verifiedCounts[0] != 1 {
		t.Fatal("expected one verified and one unverified event")
	}
}

func TestSplitTrivyResultEmpty(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: string(standalone.ScannerTrivy),
		Results: map[string]interface{}{},
	}

	events := splitTrivyResult(result)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0] != result {
		t.Fatal("expected original result to be returned")
	}
}

func TestSplitTrivyResultWithVulnerabilities(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: string(standalone.ScannerTrivy),
		Results: map[string]interface{}{
			"results": []interface{}{
				map[string]interface{}{
					"Target": "app",
					"Vulnerabilities": []interface{}{
						map[string]interface{}{"Severity": "CRITICAL"},
						map[string]interface{}{"Severity": "MEDIUM"},
					},
				},
			},
		},
	}

	events := splitTrivyResult(result)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	for _, event := range events {
		resultsList, ok := event.Results["results"].([]interface{})
		if !ok || len(resultsList) != 1 {
			t.Fatal("expected results to contain one entry")
		}
		entry, ok := resultsList[0].(map[string]interface{})
		if !ok {
			t.Fatal("expected results entry to be a map")
		}
		vulns, ok := entry["Vulnerabilities"].([]interface{})
		if !ok || len(vulns) != 1 {
			t.Fatal("expected Vulnerabilities to contain one item")
		}
		if event.Results["vulnerabilities_count"] != 1 {
			t.Fatal("expected vulnerabilities_count to be 1")
		}
		bySeverity, ok := event.Results["by_severity"].(map[string]int)
		if !ok || len(bySeverity) != 1 {
			t.Fatal("expected by_severity to contain one entry")
		}
	}
}

func TestCloneStandaloneResultCopiesResultsMap(t *testing.T) {
	original := &standalone.StandaloneScanResult{
		Scanner: "opengrep",
		Results: map[string]interface{}{"key": "value"},
	}

	clone := cloneStandaloneResult(original)
	clone.Results["new_key"] = "new_value"

	if _, ok := original.Results["new_key"]; ok {
		t.Fatal("expected clone results modification not to affect original")
	}
}

func TestExtractHelpers(t *testing.T) {
	if extractFindingSeverity(nil) != "" {
		t.Fatal("expected empty severity for nil input")
	}
	if extractFindingSeverity(map[string]interface{}{}) != "" {
		t.Fatal("expected empty severity for missing extra")
	}
	if extractTrufflehogVerified(nil) {
		t.Fatal("expected false for nil input")
	}
	if extractTrufflehogVerified(map[string]interface{}{}) {
		t.Fatal("expected false for missing Verified")
	}
	if extractTrivySeverity(nil) != "" {
		t.Fatal("expected empty severity for nil input")
	}
	if extractTrivySeverity(map[string]interface{}{}) != "" {
		t.Fatal("expected empty severity for missing Severity")
	}
}

func TestBuildStandaloneResultEventsDefault(t *testing.T) {
	result := &standalone.StandaloneScanResult{
		Scanner: "unknown",
		Results: map[string]interface{}{"key": "value"},
	}

	events := buildStandaloneResultEvents("unknown", result)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !reflect.DeepEqual(events[0], result) {
		t.Fatal("expected original result to be returned")
	}
}

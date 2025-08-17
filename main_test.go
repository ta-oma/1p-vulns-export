package main

import (
	"strings"
	"testing"
)

func TestGetLatestCVSS(t *testing.T) {
	// Test with CVSS v3.1 data
	metrics := map[string]any{
		"cvssMetricV31": []any{
			map[string]any{
				"cvssData": map[string]any{
					"baseScore": 7.5,
				},
			},
		},
	}

	score := getLatestCVSS(metrics)
	if score != 7.5 {
		t.Errorf("Expected 7.5, got %f", score)
	}
}

func TestGetLatestCVSSFallback(t *testing.T) {
	// Test fallback to CVSS v2 when v3.1 not available
	metrics := map[string]any{
		"cvssMetricV2": []any{
			map[string]any{
				"cvssData": map[string]any{
					"baseScore": 4.3,
				},
			},
		},
	}

	score := getLatestCVSS(metrics)
	if score != 4.3 {
		t.Errorf("Expected 4.3, got %f", score)
	}
}

func TestCPEParsing(t *testing.T) {
	criteria := "cpe:2.3:a:1password:1password:*:*:*:*:*:macos:*:*"
	appName := strings.Split(criteria, ":")[4]

	if appName != "1password" {
		t.Errorf("Expected '1password', got '%s'", appName)
	}
}

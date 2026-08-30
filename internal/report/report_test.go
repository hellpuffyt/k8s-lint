package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hellpuffyt/k8s-lint/internal/lint"
)

func sampleFindings() []lint.Finding {
	return []lint.Finding{
		{
			RuleID: "SEC001", Severity: lint.SeverityCritical, Kind: "Deployment", Name: "web",
			Path:    "spec.template.spec.containers[0].securityContext.privileged",
			Message: "privileged", Fix: "securityContext:\n  privileged: false",
			File: "deploy.yaml", Line: 12,
		},
		{
			RuleID: "REL001", Severity: lint.SeverityHigh, Kind: "Deployment", Name: "web",
			Path:    "spec.template.spec.containers[0].resources",
			Message: "no resources", Fix: "resources: {}",
			File: "deploy.yaml", Line: 12,
		},
	}
}

func TestWriteText_NoIssues(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, nil)
	if !strings.Contains(buf.String(), "No issues found") {
		t.Errorf("expected 'No issues found', got %q", buf.String())
	}
}

func TestWriteText_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, sampleFindings())
	out := buf.String()
	if !strings.Contains(out, "SEC001") || !strings.Contains(out, "REL001") {
		t.Errorf("expected both rule IDs in text output, got: %s", out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected severity label in output, got: %s", out)
	}
	if !strings.Contains(out, "2 issue(s)") {
		t.Errorf("expected summary count, got: %s", out)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleFindings()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var out []lint.Finding
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON produced: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].RuleID != "SEC001" {
		t.Errorf("expected SEC001 first, got %s", out[0].RuleID)
	}
}

func TestWriteJSON_EmptyIsEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("expected '[]' for no findings, got %q", buf.String())
	}
}

func TestWriteSARIF_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleFindings()); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", doc["version"])
	}
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 2 {
		t.Fatalf("expected 2 results, got %v", run["results"])
	}
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	if len(rules) != 2 {
		t.Fatalf("expected 2 distinct rules in the driver, got %d", len(rules))
	}
}

func TestWriteSARIF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON for empty findings: %v", err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	if results, ok := run["results"].([]interface{}); !ok || len(results) != 0 {
		t.Errorf("expected empty results array, got %v", run["results"])
	}
}

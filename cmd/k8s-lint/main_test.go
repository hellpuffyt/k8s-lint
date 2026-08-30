package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func testdata(elems ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, elems...)...)
}

func TestRun_GoodManifestExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{testdata("good", "deployment.yaml")}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 for a clean manifest, got %d; stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "No issues found") {
		t.Errorf("expected 'No issues found', got %q", out.String())
	}
}

func TestRun_BadManifestExitsNonZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{testdata("bad", "deployment.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for a bad manifest, got %d; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "SEC001") {
		t.Errorf("expected SEC001 (privileged) to be reported, got: %s", out.String())
	}
}

func TestRun_JSONFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "json", testdata("bad", "deployment.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", code, errOut.String())
	}
	var findings []map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("invalid JSON: %v; output=%s", err, out.String())
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding in JSON output")
	}
}

func TestRun_SARIFFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "sarif", testdata("bad", "deployment.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", code, errOut.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", doc["version"])
	}
}

func TestRun_OnlyFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "json", "--only", "SEC001", testdata("bad", "deployment.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	var findings []map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, f := range findings {
		if f["ruleId"] != "SEC001" {
			t.Errorf("--only SEC001 leaked rule %v", f["ruleId"])
		}
	}
}

func TestRun_IgnoreFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "json", "--ignore", "SEC001,SEC004,SEC005,REL005,REL008,SEC002,SEC003,SEC006,SEC007,SEC009,SEC010,REL002,REL003", testdata("bad", "deployment.yaml")}, &out, &errOut)
	_ = code
	var findings []map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, f := range findings {
		if f["ruleId"] == "SEC001" {
			t.Error("--ignore SEC001 should have excluded it")
		}
	}
}

func TestRun_SeverityThreshold(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "json", "--severity", "critical", testdata("bad", "deployment.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 (there are critical findings), got %d", code)
	}
	var findings []map[string]interface{}
	json.Unmarshal(out.Bytes(), &findings)
	for _, f := range findings {
		if f["severity"] != "critical" {
			t.Errorf("--severity critical leaked a %v finding", f["severity"])
		}
	}
}

func TestRun_MalformedManifestExitsWithUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{testdata("bad", "malformed.yaml")}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for a malformed manifest, got %d", code)
	}
	if errOut.Len() == 0 {
		t.Error("expected an error message on stderr for malformed YAML")
	}
}

func TestRun_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for missing args, got %d", code)
	}
}

func TestRun_InvalidSeverityFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--severity", "extreme", testdata("good", "deployment.yaml")}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid --severity, got %d", code)
	}
}

func TestRun_InvalidFormatFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "yaml", testdata("good", "deployment.yaml")}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid --format, got %d", code)
	}
}

func TestRun_ListRules(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--list-rules"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "SEC001") || !strings.Contains(out.String(), "REL001") {
		t.Errorf("expected --list-rules to include rule IDs, got %q", out.String())
	}
}

func TestRun_Version(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "k8s-lint") {
		t.Errorf("expected version output to mention k8s-lint, got %q", out.String())
	}
}

func TestRun_DirectoryInput(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{testdata("good")}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0 for a directory of clean manifests, got %d; stderr=%s", code, errOut.String())
	}
}

func TestRun_ListKindManifest(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--format", "json", testdata("bad", "list-kind.yaml")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for a bad List-kind manifest, got %d; stderr=%s", code, errOut.String())
	}
	var findings []map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings from the expanded List items")
	}
}

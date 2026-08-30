package lint

import "testing"

const insecureDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: myregistry/app:latest
`

func TestLint_OnlyFilter(t *testing.T) {
	docs, err := ParseFile("t.yaml", []byte(insecureDeployment))
	if err != nil {
		t.Fatal(err)
	}
	findings := Lint(docs, Options{Only: []string{"REL005"}})
	if len(findings) != 1 || findings[0].RuleID != "REL005" {
		t.Fatalf("expected only REL005, got %+v", findings)
	}
}

func TestLint_IgnoreFilter(t *testing.T) {
	docs, err := ParseFile("t.yaml", []byte(insecureDeployment))
	if err != nil {
		t.Fatal(err)
	}
	findings := Lint(docs, Options{})
	if !hasRule(findings, "REL005") {
		t.Fatal("expected REL005 without ignore")
	}
	findings = Lint(docs, Options{Ignore: []string{"REL005"}})
	if hasRule(findings, "REL005") {
		t.Fatal("expected REL005 to be excluded by --ignore")
	}
}

func TestLint_SeverityThreshold(t *testing.T) {
	docs, err := ParseFile("t.yaml", []byte(insecureDeployment))
	if err != nil {
		t.Fatal(err)
	}
	all := Lint(docs, Options{MinSeverity: SeverityLow})
	criticalOnly := Lint(docs, Options{MinSeverity: SeverityCritical})
	if len(criticalOnly) >= len(all) {
		t.Fatalf("expected fewer findings at critical threshold: all=%d critical=%d", len(all), len(criticalOnly))
	}
	for _, f := range criticalOnly {
		if f.Severity != SeverityCritical {
			t.Errorf("finding %s has severity %s, expected only critical", f.RuleID, f.Severity)
		}
	}
}

func TestLint_CleanManifestProducesNoFindings(t *testing.T) {
	// goodDeployment plus a matching, non-blocking PodDisruptionBudget so the
	// cross-document REL006/REL007 checks are satisfied too.
	src := goodDeployment + `
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: web
`
	docs, err := ParseFile("t.yaml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	findings := Lint(docs, Options{})
	if len(findings) != 0 {
		t.Fatalf("expected a fully-hardened manifest to produce no findings, got %d: %+v", len(findings), findings)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityLow) {
		t.Error("critical should be at least low")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be at least high")
	}
	if !SeverityMedium.AtLeast(SeverityMedium) {
		t.Error("medium should be at least medium")
	}
}

func TestSeverityValid(t *testing.T) {
	if Severity("bogus").Valid() {
		t.Error("bogus severity should not be valid")
	}
	if !SeverityHigh.Valid() {
		t.Error("high should be valid")
	}
}

func TestAllRulesHaveUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range AllRules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		if !r.Severity.Valid() {
			t.Errorf("rule %s has invalid severity %s", r.ID, r.Severity)
		}
	}
}

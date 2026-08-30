package lint

import "testing"

// parseOne parses a single-document YAML string and returns the one
// resulting Doc, failing the test if parsing didn't yield exactly one.
func parseOne(t *testing.T, yamlSrc string) Doc {
	t.Helper()
	docs, err := ParseFile("test.yaml", []byte(yamlSrc))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(docs))
	}
	return docs[0]
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func countRule(findings []Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

// Package lint implements the k8s-lint rule engine: parsing Kubernetes
// manifests and evaluating reliability and security rules against them.
package lint

// Severity levels, ordered from least to most severe.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank returns a numeric rank for ordering/threshold comparisons.
// Unknown severities rank below "low" so they never trip a threshold.
func severityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// AtLeast reports whether severity s meets or exceeds threshold t.
func (s Severity) AtLeast(t Severity) bool {
	return severityRank(s) >= severityRank(t)
}

// Valid reports whether s is one of the known severity levels.
func (s Severity) Valid() bool {
	return severityRank(s) > 0
}

// Finding is a single rule violation reported against a manifest document.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Path      string   `json:"path"`
	Message   string   `json:"message"`
	Fix       string   `json:"fix"`
	File      string   `json:"file"`
	Line      int      `json:"line,omitempty"`
}

// Rule describes a single lint rule.
type Rule struct {
	ID          string
	Severity    Severity
	Description string
}

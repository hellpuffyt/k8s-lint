// Package report renders lint findings as human-readable text, JSON, or
// SARIF (for GitHub code scanning).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/hellpuffyt/k8s-lint/internal/lint"
)

// WriteText renders findings as human-readable text.
func WriteText(w io.Writer, findings []lint.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}
	for _, f := range findings {
		fmt.Fprintf(w, "[%s] %s (%s)\n", severityLabel(f.Severity), f.RuleID, f.Kind)
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "  resource: %s", f.Name)
		if f.Namespace != "" {
			fmt.Fprintf(w, " (namespace: %s)", f.Namespace)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  file:     %s\n", loc)
		fmt.Fprintf(w, "  field:    %s\n", f.Path)
		fmt.Fprintf(w, "  why:      %s\n", f.Message)
		fmt.Fprintf(w, "  fix:\n")
		for _, line := range splitLines(f.Fix) {
			fmt.Fprintf(w, "    %s\n", line)
		}
		fmt.Fprintln(w)
	}

	counts := map[lint.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "%d issue(s): %d critical, %d high, %d medium, %d low\n",
		len(findings), counts[lint.SeverityCritical], counts[lint.SeverityHigh],
		counts[lint.SeverityMedium], counts[lint.SeverityLow])
}

func severityLabel(s lint.Severity) string {
	switch s {
	case lint.SeverityCritical:
		return "CRITICAL"
	case lint.SeverityHigh:
		return "HIGH"
	case lint.SeverityMedium:
		return "MEDIUM"
	case lint.SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func splitLines(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	lines = append(lines, cur)
	return lines
}

// WriteJSON renders findings as a JSON array.
func WriteJSON(w io.Writer, findings []lint.Finding) error {
	if findings == nil {
		findings = []lint.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// sarifLog and friends implement the small subset of the SARIF 2.1.0 schema
// needed for GitHub code scanning ingestion.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifText       `json:"shortDescription"`
	Help             sarifText       `json:"help"`
	Properties       sarifProperties `json:"properties,omitempty"`
}

type sarifProperties struct {
	Severity string `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// ToolVersion is stamped into SARIF output; overridden by main via ldflags
// if desired.
var ToolVersion = "dev"

// WriteSARIF renders findings as a SARIF 2.1.0 log for GitHub code scanning.
func WriteSARIF(w io.Writer, findings []lint.Finding) error {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifText{Text: shortDescriptionFor(f.RuleID)},
				Help:             sarifText{Text: f.Message},
				Properties:       sarifProperties{Severity: sarifSecuritySeverity(f.Severity)},
			}
		}
		line := f.Line
		if line <= 0 {
			line = 1
		}
		results = append(results, sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifText{
				Text: f.Message + " Fix:\n" + f.Fix,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: toSlashPath(f.File)},
					Region:           sarifRegion{StartLine: line},
				},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(ruleSet))
	for _, id := range sortedKeys(ruleSet) {
		rules = append(rules, ruleSet[id])
	}
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "k8s-lint",
				InformationURI: "https://github.com/hellpuffyt/k8s-lint",
				Version:        ToolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func shortDescriptionFor(ruleID string) string {
	for _, r := range lint.AllRules {
		if r.ID == ruleID {
			return r.Description
		}
	}
	return ruleID
}

func sarifLevel(s lint.Severity) string {
	switch s {
	case lint.SeverityCritical, lint.SeverityHigh:
		return "error"
	case lint.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(s lint.Severity) string {
	switch s {
	case lint.SeverityCritical:
		return "9.0"
	case lint.SeverityHigh:
		return "7.0"
	case lint.SeverityMedium:
		return "4.0"
	default:
		return "1.0"
	}
}

func sortedKeys(m map[string]sarifRule) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func toSlashPath(p string) string {
	out := make([]byte, len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' {
			out[i] = '/'
		} else {
			out[i] = p[i]
		}
	}
	return string(out)
}

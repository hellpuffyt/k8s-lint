package lint

import "sort"

// AllRules lists every rule this tool implements, in a stable order. It is
// used for documentation, --only/--ignore validation, and testing that
// every rule has coverage.
var AllRules = []Rule{
	{ID: "REL001", Severity: SeverityHigh, Description: "Missing resource requests/limits"},
	{ID: "REL002", Severity: SeverityHigh, Description: "Missing liveness probe"},
	{ID: "REL003", Severity: SeverityHigh, Description: "Missing readiness probe"},
	{ID: "REL004", Severity: SeverityMedium, Description: "Readiness and liveness probes target the same endpoint"},
	{ID: "REL005", Severity: SeverityMedium, Description: "Deployment/StatefulSet runs a single replica"},
	{ID: "REL006", Severity: SeverityMedium, Description: "No matching PodDisruptionBudget for a multi-replica workload"},
	{ID: "REL007", Severity: SeverityHigh, Description: "PodDisruptionBudget minAvailable blocks all voluntary eviction"},
	{ID: "REL008", Severity: SeverityMedium, Description: "imagePullPolicy Always with a :latest tag"},
	{ID: "REL009", Severity: SeverityLow, Description: "No explicit rolling update strategy"},
	{ID: "REL010", Severity: SeverityHigh, Description: "terminationGracePeriodSeconds set to 0"},
	{ID: "SEC001", Severity: SeverityCritical, Description: "privileged: true"},
	{ID: "SEC002", Severity: SeverityHigh, Description: "Container may run as root"},
	{ID: "SEC003", Severity: SeverityMedium, Description: "Writable root filesystem"},
	{ID: "SEC004", Severity: SeverityCritical, Description: "hostNetwork/hostPID/hostIPC enabled"},
	{ID: "SEC005", Severity: SeverityCritical, Description: "Dangerous Linux capability added"},
	{ID: "SEC006", Severity: SeverityHigh, Description: "allowPrivilegeEscalation not disabled"},
	{ID: "SEC007", Severity: SeverityMedium, Description: "Secret mounted as an environment variable"},
	{ID: "SEC008", Severity: SeverityLow, Description: "automountServiceAccountToken left on by default"},
	{ID: "SEC009", Severity: SeverityMedium, Description: "Image pinned to :latest"},
	{ID: "SEC010", Severity: SeverityLow, Description: "Missing seccomp profile"},
}

type perDocRule func(Doc) []Finding
type crossDocRule func([]Doc) []Finding

var perDocRules = []perDocRule{
	ruleResources,
	ruleProbes,
	ruleProbesSameEndpoint,
	ruleSingleReplica,
	ruleLatestAlwaysPull,
	ruleRolloutStrategy,
	ruleTerminationGrace,
	rulePrivileged,
	ruleRunAsRoot,
	ruleWritableRootFS,
	ruleHostNamespaces,
	ruleDangerousCapabilities,
	ruleAllowPrivilegeEscalation,
	ruleSecretEnvVars,
	ruleAutomountToken,
	ruleLatestTag,
	ruleSeccompProfile,
}

var crossDocRules = []crossDocRule{
	ruleDisruptionBudgets,
}

// Options controls which rules run and at what severity findings are kept.
type Options struct {
	// Only, if non-empty, restricts evaluation to these rule IDs.
	Only []string
	// Ignore excludes these rule IDs from evaluation.
	Ignore []string
	// MinSeverity filters out findings below this severity. Empty/invalid
	// means no filtering.
	MinSeverity Severity
}

func (o Options) enabled(ruleID string) bool {
	if len(o.Only) > 0 && !contains(o.Only, ruleID) {
		return false
	}
	if contains(o.Ignore, ruleID) {
		return false
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Lint runs all enabled rules against the given documents and returns the
// resulting findings, filtered by severity and sorted deterministically.
func Lint(docs []Doc, opts Options) []Finding {
	var findings []Finding
	for _, d := range docs {
		for _, r := range perDocRules {
			for _, f := range r(d) {
				if opts.enabled(f.RuleID) {
					findings = append(findings, f)
				}
			}
		}
	}
	for _, r := range crossDocRules {
		for _, f := range r(docs) {
			if opts.enabled(f.RuleID) {
				findings = append(findings, f)
			}
		}
	}

	if opts.MinSeverity.Valid() {
		filtered := findings[:0]
		for _, f := range findings {
			if f.Severity.AtLeast(opts.MinSeverity) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Name != findings[j].Name {
			return findings[i].Name < findings[j].Name
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}

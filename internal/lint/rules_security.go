package lint

import (
	"fmt"
	"sort"
)

// --- SEC001: privileged: true ----------------------------------------------

func rulePrivileged(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		if b, ok := boolOf(sc["privileged"]); ok && b {
			name, _ := stringOf(c["name"])
			findings = append(findings, Finding{
				RuleID: "SEC001", Severity: SeverityCritical, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
				Path: fmt.Sprintf("%s.containers[%d:%s].securityContext.privileged", prefix, i, name),
				Message: "Container runs privileged, giving it full access to the host's devices and kernel " +
					"capabilities. A compromised container can escape to the host, read every other pod's data, " +
					"and pivot across the cluster.",
				Fix:  "securityContext:\n  privileged: false",
				File: d.File, Line: d.Line,
			})
		}
	}
	return findings
}

// --- SEC002: running as root / no runAsNonRoot -----------------------------

func ruleRunAsRoot(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	podSC := mapOf(podSpec["securityContext"])
	var findings []Finding
	for i, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		nonRoot, nonRootSet := boolOf(sc["runAsNonRoot"])
		if !nonRootSet {
			nonRoot, nonRootSet = boolOf(podSC["runAsNonRoot"])
		}
		uid, uidSet := intOf(sc["runAsUser"])
		if !uidSet {
			uid, uidSet = intOf(podSC["runAsUser"])
		}
		explicitRoot := uidSet && uid == 0
		if (nonRootSet && nonRoot) && !explicitRoot {
			continue
		}
		name, _ := stringOf(c["name"])
		msg := "Container has no runAsNonRoot: true (pod or container level), so it may run as root by default. " +
			"A container-escape or path-traversal bug then hands the attacker root inside the container, " +
			"maximizing the blast radius of any subsequent kernel or mount exploit."
		if explicitRoot {
			msg = "Container explicitly sets runAsUser: 0 (root). A container-escape or path-traversal bug then " +
				"hands the attacker root inside the container, maximizing the blast radius of any subsequent " +
				"kernel or mount exploit."
		}
		findings = append(findings, Finding{
			RuleID: "SEC002", Severity: SeverityHigh, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path:    fmt.Sprintf("%s.containers[%d:%s].securityContext.runAsNonRoot", prefix, i, name),
			Message: msg,
			Fix:     "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
			File:    d.File, Line: d.Line,
		})
	}
	return findings
}

// --- SEC003: writable root filesystem ---------------------------------------

func ruleWritableRootFS(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		if b, ok := boolOf(sc["readOnlyRootFilesystem"]); ok && b {
			continue
		}
		name, _ := stringOf(c["name"])
		findings = append(findings, Finding{
			RuleID: "SEC003", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s].securityContext.readOnlyRootFilesystem", prefix, i, name),
			Message: "Root filesystem is writable. An attacker who gains code execution can drop tools, modify " +
				"binaries, or persist a backdoor directly on disk instead of being confined to explicitly " +
				"mounted volumes.",
			Fix:  "securityContext:\n  readOnlyRootFilesystem: true",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

// --- SEC004: hostNetwork / hostPID / hostIPC --------------------------------

func ruleHostNamespaces(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	checks := []struct {
		field string
		desc  string
	}{
		{"hostNetwork", "shares the host's network namespace, exposing every host network interface and " +
			"letting the container sniff or spoof traffic for other pods on the node"},
		{"hostPID", "shares the host's PID namespace, letting the container see and signal every process on " +
			"the node, including other tenants' workloads"},
		{"hostIPC", "shares the host's IPC namespace, exposing shared memory segments of other processes on " +
			"the node"},
	}
	var findings []Finding
	for _, chk := range checks {
		if b, ok := boolOf(podSpec[chk.field]); ok && b {
			findings = append(findings, Finding{
				RuleID: "SEC004", Severity: SeverityCritical, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
				Path:    fmt.Sprintf("%s.%s", prefix, chk.field),
				Message: "Pod " + chk.desc + ".",
				Fix:     fmt.Sprintf("spec:\n  %s: false", chk.field),
				File:    d.File, Line: d.Line,
			})
		}
	}
	return findings
}

// --- SEC005: dangerous capabilities -----------------------------------------

var dangerousCapabilities = map[string]bool{
	"SYS_ADMIN":    true,
	"NET_RAW":      true,
	"NET_ADMIN":    true,
	"SYS_PTRACE":   true,
	"SYS_MODULE":   true,
	"DAC_OVERRIDE": true,
	"ALL":          true,
}

func ruleDangerousCapabilities(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		caps := mapOf(sc["capabilities"])
		add := sliceOf(caps["add"])
		name, _ := stringOf(c["name"])
		for _, a := range add {
			capName, _ := stringOf(a)
			if dangerousCapabilities[capName] {
				findings = append(findings, Finding{
					RuleID: "SEC005", Severity: SeverityCritical, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
					Path: fmt.Sprintf("%s.containers[%d:%s].securityContext.capabilities.add", prefix, i, name),
					Message: fmt.Sprintf("Container adds the %s capability. This grants near-root-equivalent "+
						"power inside the container (e.g. raw sockets for spoofing, ptrace for reading other "+
						"processes' memory, or module loading into the host kernel), turning a routine app bug "+
						"into a full host compromise.", capName),
					Fix:  "securityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    # add only the specific capability actually required, if any",
					File: d.File, Line: d.Line,
				})
			}
		}
	}
	return findings
}

// --- SEC006: allowPrivilegeEscalation not disabled --------------------------

func ruleAllowPrivilegeEscalation(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		b, ok := boolOf(sc["allowPrivilegeEscalation"])
		if ok && !b {
			continue
		}
		name, _ := stringOf(c["name"])
		findings = append(findings, Finding{
			RuleID: "SEC006", Severity: SeverityHigh, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s].securityContext.allowPrivilegeEscalation", prefix, i, name),
			Message: "allowPrivilegeEscalation is not explicitly disabled, so it defaults to true. A process " +
				"in the container can gain more privileges than its parent (e.g. via a setuid binary), " +
				"undermining any other hardening applied to the container.",
			Fix:  "securityContext:\n  allowPrivilegeEscalation: false",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

// --- SEC007: secrets mounted as environment variables -----------------------

func ruleSecretEnvVars(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		name, _ := stringOf(c["name"])
		var names []string
		for _, e := range sliceOf(c["env"]) {
			em := mapOf(e)
			vf := mapOf(em["valueFrom"])
			if vf["secretKeyRef"] != nil {
				if n, ok := stringOf(em["name"]); ok {
					names = append(names, n)
				}
			}
		}
		for _, ef := range sliceOf(c["envFrom"]) {
			efm := mapOf(ef)
			if efm["secretRef"] != nil {
				names = append(names, "(envFrom secretRef)")
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		findings = append(findings, Finding{
			RuleID: "SEC007", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s].env", prefix, i, name),
			Message: fmt.Sprintf("Secret(s) %v are injected as environment variables. Env vars are inherited by "+
				"child processes, get dumped in crash reports/stack traces, and are readable via /proc/<pid>/environ "+
				"by anything with host/container access — a much wider exposure surface than a mounted file.", names),
			Fix:  "envFrom: []  # remove secretRef/secretKeyRef env usage\nvolumes:\n  - name: secret-vol\n    secret:\n      secretName: my-secret\n# then volumeMount it read-only and read the value from the file",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

// --- SEC008: automountServiceAccountToken left on by default ---------------

func ruleAutomountToken(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	if b, ok := boolOf(podSpec["automountServiceAccountToken"]); ok && !b {
		return nil
	}
	return []Finding{{
		RuleID: "SEC008", Severity: SeverityLow, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
		Path: prefix + ".automountServiceAccountToken",
		Message: "automountServiceAccountToken is not explicitly disabled, so the pod's API token is mounted by " +
			"default. Most workloads never call the Kubernetes API; if the container is compromised, that token " +
			"lets an attacker query or modify cluster resources with whatever RBAC the service account has.",
		Fix:  "spec:\n  automountServiceAccountToken: false",
		File: d.File, Line: d.Line,
	}}
}

// --- SEC009: latest image tag ------------------------------------------------

func ruleLatestTag(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		image, _ := stringOf(c["image"])
		if !isLatestTag(image) {
			continue
		}
		name, _ := stringOf(c["name"])
		findings = append(findings, Finding{
			RuleID: "SEC009", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s].image", prefix, i, name),
			Message: "Image is pinned to :latest (or has no tag, which means the same thing). Two pods of the " +
				"same Deployment can silently run different code if the tag was repushed between scheduling " +
				"events, and there is no way to audit or pin exactly what is deployed.",
			Fix:  "image: myregistry/myapp:1.4.2@sha256:<digest>",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

// --- SEC010: missing seccomp profile ----------------------------------------

func ruleSeccompProfile(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	podSC := mapOf(podSpec["securityContext"])
	if hasSeccomp(podSC) {
		return nil
	}
	for _, c := range containers(podSpec) {
		sc := mapOf(c["securityContext"])
		if hasSeccomp(sc) {
			return nil
		}
	}
	return []Finding{{
		RuleID: "SEC010", Severity: SeverityLow, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
		Path: prefix + ".securityContext.seccompProfile",
		Message: "No seccomp profile is set, so the container gets the container runtime's default (frequently " +
			"'Unconfined' outside of cluster-wide PodSecurity enforcement). Without seccomp filtering, a " +
			"compromised process can make any syscall, including ones only needed to escape the container.",
		Fix:  "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
		File: d.File, Line: d.Line,
	}}
}

func hasSeccomp(sc map[string]interface{}) bool {
	sp := mapOf(sc["seccompProfile"])
	t, ok := stringOf(sp["type"])
	return ok && (t == "RuntimeDefault" || t == "Localhost")
}

package lint

import "fmt"

// --- REL001: missing resource requests/limits -----------------------------

func ruleResources(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		name, _ := stringOf(c["name"])
		res := mapOf(c["resources"])
		requests := mapOf(res["requests"])
		limits := mapOf(res["limits"])
		missing := []string{}
		if requests["cpu"] == nil || requests["memory"] == nil {
			missing = append(missing, "requests")
		}
		if limits["cpu"] == nil || limits["memory"] == nil {
			missing = append(missing, "limits")
		}
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, Finding{
			RuleID:    "REL001",
			Severity:  SeverityHigh,
			Kind:      d.Kind,
			Name:      d.Name,
			Namespace: d.Namespace,
			Path:      fmt.Sprintf("%s.containers[%d:%s].resources", prefix, i, name),
			Message: "Container has no resource " + joinAnd(missing) + " set. Without limits, a runaway container " +
				"can consume all node memory/CPU and get OOM-killed unpredictably or evict its neighbours; " +
				"without requests, the scheduler cannot bin-pack correctly and may co-locate too many pods on one node.",
			Fix:  "resources:\n  requests:\n    cpu: \"100m\"\n    memory: \"128Mi\"\n  limits:\n    cpu: \"500m\"\n    memory: \"256Mi\"",
			File: d.File,
			Line: d.Line,
		})
	}
	return findings
}

// --- REL002/REL003: missing liveness/readiness probes ----------------------

// probeExemptKinds are workloads that legitimately run to completion and do
// not need liveness/readiness probes wired to a load balancer.
func probeExempt(kind string) bool {
	return kind == "Job" || kind == "CronJob"
}

func ruleProbes(d Doc) []Finding {
	if probeExempt(d.Kind) {
		return nil
	}
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		name, _ := stringOf(c["name"])
		if c["livenessProbe"] == nil {
			findings = append(findings, Finding{
				RuleID: "REL002", Severity: SeverityHigh, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
				Path: fmt.Sprintf("%s.containers[%d:%s].livenessProbe", prefix, i, name),
				Message: "No liveness probe defined. If the process wedges (deadlock, stuck event loop) without " +
					"crashing, Kubernetes has no signal to restart it and the pod serves nothing while looking healthy.",
				Fix:  "livenessProbe:\n  httpGet:\n    path: /healthz\n    port: 8080\n  initialDelaySeconds: 10\n  periodSeconds: 10",
				File: d.File, Line: d.Line,
			})
		}
		if c["readinessProbe"] == nil {
			findings = append(findings, Finding{
				RuleID: "REL003", Severity: SeverityHigh, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
				Path: fmt.Sprintf("%s.containers[%d:%s].readinessProbe", prefix, i, name),
				Message: "No readiness probe defined. Kubernetes will route traffic to the pod as soon as the " +
					"container starts, even before it has finished loading dependencies, causing request failures " +
					"during rollout and after restarts.",
				Fix:  "readinessProbe:\n  httpGet:\n    path: /ready\n    port: 8080\n  initialDelaySeconds: 5\n  periodSeconds: 5",
				File: d.File, Line: d.Line,
			})
		}
	}
	return findings
}

// --- REL004: readiness and liveness probes point at the same endpoint ------

func ruleProbesSameEndpoint(d Doc) []Finding {
	if probeExempt(d.Kind) {
		return nil
	}
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	var findings []Finding
	for i, c := range containers(podSpec) {
		lp := mapOf(c["livenessProbe"])
		rp := mapOf(c["readinessProbe"])
		if lp == nil || rp == nil {
			continue
		}
		lSig := probeSignature(lp)
		rSig := probeSignature(rp)
		if lSig == "" || rSig == "" || lSig != rSig {
			continue
		}
		name, _ := stringOf(c["name"])
		findings = append(findings, Finding{
			RuleID: "REL004", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s]", prefix, i, name),
			Message: "Liveness and readiness probes check the exact same endpoint. When a downstream dependency " +
				"slows down, the endpoint fails both probes together: the pod is marked not-ready (correctly pulled " +
				"from load balancing) AND restarted (incorrectly, killing in-flight work), so a slow dependency " +
				"turns into a container restart loop instead of a graceful traffic drain.",
			Fix: "Use a shallow, dependency-free endpoint for livenessProbe (e.g. /healthz) and a deeper, " +
				"dependency-checking endpoint for readinessProbe (e.g. /ready) so they can fail independently.",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

func probeSignature(p map[string]interface{}) string {
	if h := mapOf(p["httpGet"]); h != nil {
		path, _ := stringOf(h["path"])
		port := fmt.Sprint(h["port"])
		return "http:" + path + ":" + port
	}
	if t := mapOf(p["tcpSocket"]); t != nil {
		return "tcp:" + fmt.Sprint(t["port"])
	}
	if e := mapOf(p["exec"]); e != nil {
		return "exec:" + fmt.Sprint(e["command"])
	}
	if g := mapOf(p["grpc"]); g != nil {
		return "grpc:" + fmt.Sprint(g["port"])
	}
	return ""
}

// --- REL005: replicas: 1 for a Deployment/StatefulSet ----------------------

func ruleSingleReplica(d Doc) []Finding {
	if d.Kind != "Deployment" && d.Kind != "StatefulSet" {
		return nil
	}
	spec := mapOf(d.M["spec"])
	replicas, explicit := intOf(spec["replicas"])
	if explicit && replicas != 1 {
		return nil
	}
	// replicas defaults to 1 when unset.
	return []Finding{{
		RuleID: "REL005", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
		Path: "spec.replicas",
		Message: fmt.Sprintf("%s runs a single replica. Any node drain, node failure, or OOM kill takes the "+
			"whole workload down; there is no redundancy to absorb it.", d.Kind),
		Fix:  "spec:\n  replicas: 2",
		File: d.File, Line: d.Line,
	}}
}

// --- REL006/REL007: PodDisruptionBudget checks ------------------------------

func ruleDisruptionBudgets(docs []Doc) []Finding {
	var findings []Finding
	pdbs := []Doc{}
	for _, d := range docs {
		if d.Kind == "PodDisruptionBudget" {
			pdbs = append(pdbs, d)
		}
	}

	for _, d := range docs {
		if d.Kind != "Deployment" && d.Kind != "StatefulSet" {
			continue
		}
		spec := mapOf(d.M["spec"])
		replicas, explicit := intOf(spec["replicas"])
		if !explicit {
			replicas = 1
		}
		if replicas <= 1 {
			continue // single-replica already flagged by REL005; PDB adds nothing.
		}
		labels := podLabels(spec)
		matched, matchedPDB := findMatchingPDB(pdbs, labels)
		if !matched {
			findings = append(findings, Finding{
				RuleID: "REL006", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
				Path: "spec",
				Message: fmt.Sprintf("%s has %d replicas but no matching PodDisruptionBudget. During a node "+
					"drain or cluster upgrade, the eviction API has no guardrail and can evict every replica at once, "+
					"taking the workload fully offline.", d.Kind, replicas),
				Fix: "apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: " + d.Name + "-pdb\nspec:\n  " +
					"minAvailable: 1\n  selector:\n    matchLabels:\n      app: " + d.Name,
				File: d.File, Line: d.Line,
			})
			continue
		}
		if minBlocksEviction(matchedPDB, replicas) {
			findings = append(findings, Finding{
				RuleID: "REL007", Severity: SeverityHigh, Kind: "PodDisruptionBudget", Name: matchedPDB.Name, Namespace: matchedPDB.Namespace,
				Path: "spec.minAvailable",
				Message: fmt.Sprintf("PodDisruptionBudget minAvailable is set so that all %d replicas of %s must "+
					"stay up, which permits zero voluntary evictions. `kubectl drain` and cluster autoscaler/upgrade "+
					"operations will block or time out on this node forever.", replicas, d.Name),
				Fix:  fmt.Sprintf("spec:\n  minAvailable: %d  # less than replica count (%d)", replicas-1, replicas),
				File: matchedPDB.File, Line: matchedPDB.Line,
			})
		}
	}
	return findings
}

func podLabels(workloadSpec map[string]interface{}) map[string]string {
	tmpl := mapOf(workloadSpec["template"])
	meta := mapOf(tmpl["metadata"])
	raw := mapOf(meta["labels"])
	out := map[string]string{}
	for k, v := range raw {
		if s, ok := stringOf(v); ok {
			out[k] = s
		}
	}
	return out
}

func findMatchingPDB(pdbs []Doc, labels map[string]string) (bool, Doc) {
	for _, p := range pdbs {
		spec := mapOf(p.M["spec"])
		sel := mapOf(spec["selector"])
		match := mapOf(sel["matchLabels"])
		if len(match) == 0 {
			continue
		}
		allMatch := true
		for k, v := range match {
			sv, _ := stringOf(v)
			if labels[k] != sv {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true, p
		}
	}
	return false, Doc{}
}

func minBlocksEviction(pdb Doc, replicas int) bool {
	spec := mapOf(pdb.M["spec"])
	switch v := spec["minAvailable"].(type) {
	case string:
		return v == "100%"
	default:
		if n, ok := intOf(v); ok {
			return n >= replicas
		}
	}
	return false
}

// --- REL008: imagePullPolicy Always with :latest ----------------------------

func ruleLatestAlwaysPull(d Doc) []Finding {
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
		policy, hasPolicy := stringOf(c["imagePullPolicy"])
		if hasPolicy && policy != "Always" {
			continue
		}
		name, _ := stringOf(c["name"])
		findings = append(findings, Finding{
			RuleID: "REL008", Severity: SeverityMedium, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
			Path: fmt.Sprintf("%s.containers[%d:%s].image", prefix, i, name),
			Message: "Image uses the :latest tag with imagePullPolicy Always (the default when a tag is 'latest' " +
				"or unset). A rollback by re-applying the old manifest re-pulls whatever 'latest' now points to, " +
				"not the image that was actually running before — the rollback silently does nothing or makes " +
				"things worse.",
			Fix:  "image: myregistry/myapp:1.4.2  # pin to an immutable tag or digest",
			File: d.File, Line: d.Line,
		})
	}
	return findings
}

func isLatestTag(image string) bool {
	if image == "" {
		return false
	}
	// image may be "repo@sha256:..." (digest pin, fine), "repo:tag", or bare "repo" (implicit :latest).
	for i := len(image) - 1; i >= 0; i-- {
		switch image[i] {
		case '@':
			return false
		case ':':
			return image[i+1:] == "latest"
		case '/':
			return true // no ':' before the last '/': bare repo name, implicit latest
		}
	}
	return true
}

// --- REL009: no rolling update strategy -------------------------------------

func ruleRolloutStrategy(d Doc) []Finding {
	if d.Kind != "Deployment" {
		return nil
	}
	spec := mapOf(d.M["spec"])
	if spec["strategy"] != nil {
		return nil
	}
	return []Finding{{
		RuleID: "REL009", Severity: SeverityLow, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
		Path: "spec.strategy",
		Message: "No explicit update strategy. The cluster default (RollingUpdate with 25% max unavailable/surge) " +
			"applies implicitly, which is often too aggressive for a stateful or slow-starting workload and can " +
			"take down more capacity during a rollout than intended.",
		Fix:  "spec:\n  strategy:\n    type: RollingUpdate\n    rollingUpdate:\n      maxUnavailable: 0\n      maxSurge: 1",
		File: d.File, Line: d.Line,
	}}
}

// --- REL010: terminationGracePeriodSeconds: 0 -------------------------------

func ruleTerminationGrace(d Doc) []Finding {
	podSpec, prefix := podTemplateSpec(d)
	if podSpec == nil {
		return nil
	}
	n, ok := intOf(podSpec["terminationGracePeriodSeconds"])
	if !ok || n != 0 {
		return nil
	}
	return []Finding{{
		RuleID: "REL010", Severity: SeverityHigh, Kind: d.Kind, Name: d.Name, Namespace: d.Namespace,
		Path: prefix + ".terminationGracePeriodSeconds",
		Message: "terminationGracePeriodSeconds is set to 0, so the container receives SIGKILL immediately on " +
			"termination instead of SIGTERM plus a grace window. In-flight requests are dropped and connections " +
			"aren't drained, causing client-visible errors on every rollout, scale-down, or node drain.",
		Fix:  "spec:\n  terminationGracePeriodSeconds: 30",
		File: d.File, Line: d.Line,
	}}
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return items[0] + " and " + items[1]
	}
}

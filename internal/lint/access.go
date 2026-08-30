package lint

// Small helpers for navigating the generic map[string]interface{} tree that
// results from decoding arbitrary Kubernetes YAML. Kept deliberately
// permissive: a missing or wrongly-typed field returns the zero value
// rather than panicking, since manifests in the wild are frequently
// incomplete or hand-edited.

func mapOf(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func sliceOf(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func boolOf(v interface{}) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func stringOf(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// intOf coerces common YAML-decoded numeric types to int.
func intOf(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case uint64:
		return int(n), true
	}
	return 0, false
}

func get(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return nil
	}
	return m[key]
}

// podTemplateSpec returns the pod spec map for a workload document, given
// its kind, along with the path prefix to that spec (for reporting).
func podTemplateSpec(d Doc) (spec map[string]interface{}, pathPrefix string) {
	switch d.Kind {
	case "Pod":
		return mapOf(d.M["spec"]), "spec"
	case "CronJob":
		jobTemplate := mapOf(get(mapOf(d.M["spec"]), "jobTemplate"))
		jobSpec := mapOf(get(jobTemplate, "spec"))
		tmpl := mapOf(get(jobSpec, "template"))
		return mapOf(get(tmpl, "spec")), "spec.jobTemplate.spec.template.spec"
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		tmpl := mapOf(get(mapOf(d.M["spec"]), "template"))
		return mapOf(get(tmpl, "spec")), "spec.template.spec"
	default:
		return nil, ""
	}
}

// containers returns the containers list (not initContainers) for a pod
// spec, along with the field name it came from ("containers").
func containers(podSpec map[string]interface{}) []map[string]interface{} {
	raw := sliceOf(get(podSpec, "containers"))
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		if cm := mapOf(c); cm != nil {
			out = append(out, cm)
		}
	}
	return out
}

// isWorkload reports whether the kind is one this tool inspects pod specs
// for.
func isWorkload(kind string) bool {
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
		return true
	}
	return false
}

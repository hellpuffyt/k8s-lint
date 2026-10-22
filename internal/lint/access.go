package lint

import "fmt"

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

// containerRef is a container together with the pod-spec field it came
// from ("containers" or "initContainers") and its index there.
type containerRef struct {
	Field string
	Index int
	M     map[string]interface{}
}

// path renders "<prefix>.<field>[<index>:<name>]" for findings.
func (c containerRef) path(prefix string) string {
	name, _ := stringOf(c.M["name"])
	return fmt.Sprintf("%s.%s[%d:%s]", prefix, c.Field, c.Index, name)
}

// allContainers returns the regular containers followed by the init
// containers. Init containers run with the same privileges on the same
// node, so security rules must inspect them too.
func allContainers(podSpec map[string]interface{}) []containerRef {
	var out []containerRef
	for _, field := range []string{"containers", "initContainers"} {
		for i, c := range sliceOf(get(podSpec, field)) {
			if cm := mapOf(c); cm != nil {
				out = append(out, containerRef{Field: field, Index: i, M: cm})
			}
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

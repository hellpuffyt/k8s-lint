package lint

import "testing"

// Regression tests for defects found in the production-readiness audit.

// hardenedPod is a pod spec body that passes every rule; tests add one
// problem at a time.
const hardenedSpec = `
    automountServiceAccountToken: false
    securityContext:
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
    containers:
      - name: app
        image: example/app:1.0.0
        resources:
          requests: {cpu: 100m, memory: 64Mi}
          limits: {cpu: 200m, memory: 128Mi}
        livenessProbe: {httpGet: {path: /healthz, port: 8080}}
        readinessProbe: {httpGet: {path: /ready, port: 8080}}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
`

// README: "`kind: List` (and `*List`) expansion" — only "List" was expanded,
// so a DeploymentList from `kubectl get deployments -o yaml` was not linted.
func TestTypedListKindsAreExpanded(t *testing.T) {
	docs, err := ParseFile("l.yaml", []byte(`
apiVersion: apps/v1
kind: DeploymentList
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata: {name: a}
    spec: {replicas: 1}
  - apiVersion: apps/v1
    kind: Deployment
    metadata: {name: b}
    spec: {replicas: 1}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].Kind != "Deployment" || docs[1].Name != "b" {
		t.Fatalf("DeploymentList not expanded: %+v", docs)
	}
	// A non-list kind whose name merely ends in "List" and has no items
	// is left alone.
	docs, _ = ParseFile("w.yaml", []byte("apiVersion: example.com/v1\nkind: AllowList\nmetadata: {name: x}\nspec: {}\n"))
	if len(docs) != 1 || docs[0].Kind != "AllowList" {
		t.Fatalf("non-list kind mangled: %+v", docs)
	}
}

// Security rules looked only at spec.containers, so a privileged init
// container (or one adding SYS_ADMIN) produced no critical finding.
func TestSecurityRulesInspectInitContainers(t *testing.T) {
	d := parseOne(t, `
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:`+hardenedSpec+`
    initContainers:
      - name: setup
        image: example/setup:1.0.0
        securityContext:
          privileged: true
          capabilities: {add: [SYS_ADMIN]}
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
`)
	f := Lint([]Doc{d}, Options{})
	for _, id := range []string{"SEC001", "SEC005"} {
		if !hasRule(f, id) {
			t.Errorf("%s not reported for the init container: %+v", id, f)
		}
	}
	for _, x := range f {
		if x.RuleID == "SEC001" && x.Path != "spec.initContainers[0:setup].securityContext.privileged" {
			t.Errorf("SEC001 path = %q", x.Path)
		}
	}
	// The hardened app container alone stays clean.
	clean := parseOne(t, "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:"+hardenedSpec)
	if f := Lint([]Doc{clean}, Options{}); len(f) != 0 {
		t.Fatalf("hardened pod should be clean, got %+v", f)
	}
}

// SEC010 was satisfied when any one container set a seccomp profile, even
// if the others ran unconfined.
func TestSeccompRequiredForEveryContainerWithoutPodDefault(t *testing.T) {
	d := parseOne(t, `
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: a
      image: x:1
      securityContext: {seccompProfile: {type: RuntimeDefault}}
    - name: b
      image: y:1
`)
	if !hasRule(Lint([]Doc{d}, Options{Only: []string{"SEC010"}}), "SEC010") {
		t.Fatal("container b has no seccomp profile but SEC010 did not fire")
	}
}

// PDB matching ignored namespaces and matchExpressions.
func TestPDBMatchingHonoursNamespaceAndExpressions(t *testing.T) {
	deploy := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 3
  template:
    metadata: {labels: {app: web, tier: front}}
`
	cases := []struct {
		name    string
		pdb     string
		wantREL string // "REL006" (no match), "REL007" (match, blocks), "" (match, fine)
	}{
		{"other namespace", "metadata: {name: p, namespace: staging}\nspec: {minAvailable: 1, selector: {matchLabels: {app: web}}}", "REL006"},
		{"same namespace", "metadata: {name: p, namespace: prod}\nspec: {minAvailable: 1, selector: {matchLabels: {app: web}}}", ""},
		{"no namespace on pdb", "metadata: {name: p}\nspec: {minAvailable: 1, selector: {matchLabels: {app: web}}}", ""},
		{"matchExpressions In", "metadata: {name: p, namespace: prod}\nspec:\n  minAvailable: 3\n  selector:\n    matchExpressions:\n      - {key: app, operator: In, values: [web, api]}", "REL007"},
		{"matchExpressions NotIn", "metadata: {name: p, namespace: prod}\nspec:\n  minAvailable: 1\n  selector:\n    matchExpressions:\n      - {key: app, operator: NotIn, values: [web]}", "REL006"},
		{"matchExpressions Exists", "metadata: {name: p, namespace: prod}\nspec:\n  minAvailable: 1\n  selector:\n    matchExpressions:\n      - {key: tier, operator: Exists}", ""},
	}
	for _, c := range cases {
		docs, err := ParseFile("x.yaml", []byte(deploy+"---\napiVersion: policy/v1\nkind: PodDisruptionBudget\n"+c.pdb+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		f := Lint(docs, Options{Only: []string{"REL006", "REL007"}})
		got := ""
		if len(f) > 0 {
			got = f[0].RuleID
		}
		if got != c.wantREL || len(f) > 1 {
			t.Errorf("%s: findings %+v, want %q", c.name, f, c.wantREL)
		}
	}
}

func TestValidateRuleIDs(t *testing.T) {
	if err := ValidateRuleIDs([]string{"REL001", "SEC010"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuleIDs([]string{"SEC01"}); err == nil {
		t.Fatal("unknown rule ID accepted")
	}
}

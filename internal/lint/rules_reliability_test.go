package lint

import "testing"

const goodDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      terminationGracePeriodSeconds: 30
      automountServiceAccountToken: false
      containers:
        - name: web
          image: myregistry/web:1.4.2
          imagePullPolicy: IfNotPresent
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            privileged: false
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            seccompProfile:
              type: RuntimeDefault
`

func TestREL001_MissingResources(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	if !hasRule(ruleResources(d), "REL001") {
		t.Error("expected REL001 to fire when resources are missing")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleResources(good), "REL001") {
		t.Error("did not expect REL001 to fire when requests/limits are set")
	}
}

func TestREL002_003_MissingProbes(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	f := ruleProbes(d)
	if !hasRule(f, "REL002") {
		t.Error("expected REL002 to fire when liveness probe is missing")
	}
	if !hasRule(f, "REL003") {
		t.Error("expected REL003 to fire when readiness probe is missing")
	}

	good := parseOne(t, goodDeployment)
	f = ruleProbes(good)
	if hasRule(f, "REL002") || hasRule(f, "REL003") {
		t.Error("did not expect probe findings when both probes are set")
	}
}

func TestREL002_003_JobExempt(t *testing.T) {
	job := `
apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: myregistry/migrate:1.0.0
`
	d := parseOne(t, job)
	if f := ruleProbes(d); len(f) != 0 {
		t.Errorf("Job should be exempt from probe checks, got %d findings", len(f))
	}
}

func TestREL004_SameProbeEndpoint(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
          livenessProbe:
            httpGet:
              path: /status
              port: 8080
          readinessProbe:
            httpGet:
              path: /status
              port: 8080
`
	d := parseOne(t, bad)
	if !hasRule(ruleProbesSameEndpoint(d), "REL004") {
		t.Error("expected REL004 to fire when liveness and readiness share an endpoint")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleProbesSameEndpoint(good), "REL004") {
		t.Error("did not expect REL004 when probes target different endpoints")
	}
}

func TestREL005_SingleReplica(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	if !hasRule(ruleSingleReplica(d), "REL005") {
		t.Error("expected REL005 to fire for replicas: 1")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleSingleReplica(good), "REL005") {
		t.Error("did not expect REL005 for replicas: 3")
	}
}

func TestREL005_DaemonSetExempt(t *testing.T) {
	ds := `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: myregistry/agent:1.0.0
`
	d := parseOne(t, ds)
	if f := ruleSingleReplica(d); len(f) != 0 {
		t.Error("DaemonSet has no replicas concept; REL005 must not fire on it")
	}
}

func TestREL006_007_PodDisruptionBudget(t *testing.T) {
	noPDB := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	docs, err := ParseFile("t.yaml", []byte(noPDB))
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(ruleDisruptionBudgets(docs), "REL006") {
		t.Error("expected REL006 when no matching PDB exists for a multi-replica Deployment")
	}

	withGoodPDB := noPDB + `
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: web
`
	docs, err = ParseFile("t.yaml", []byte(withGoodPDB))
	if err != nil {
		t.Fatal(err)
	}
	findings := ruleDisruptionBudgets(docs)
	if hasRule(findings, "REL006") {
		t.Error("did not expect REL006 when a matching PDB exists")
	}
	if hasRule(findings, "REL007") {
		t.Error("did not expect REL007 when minAvailable (1) is below replica count (3)")
	}

	withBlockingPDB := noPDB + `
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-pdb
spec:
  minAvailable: 3
  selector:
    matchLabels:
      app: web
`
	docs, err = ParseFile("t.yaml", []byte(withBlockingPDB))
	if err != nil {
		t.Fatal(err)
	}
	findings = ruleDisruptionBudgets(docs)
	if !hasRule(findings, "REL007") {
		t.Error("expected REL007 when minAvailable equals replica count")
	}
}

func TestREL006_SingleReplicaExempt(t *testing.T) {
	single := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	docs, err := ParseFile("t.yaml", []byte(single))
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(ruleDisruptionBudgets(docs), "REL006") {
		t.Error("single-replica workloads should not require a PDB (REL005 already covers redundancy)")
	}
}

func TestREL008_LatestWithAlwaysPull(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:latest
          imagePullPolicy: Always
`
	d := parseOne(t, bad)
	if !hasRule(ruleLatestAlwaysPull(d), "REL008") {
		t.Error("expected REL008 to fire for :latest with imagePullPolicy Always")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleLatestAlwaysPull(good), "REL008") {
		t.Error("did not expect REL008 for a pinned tag")
	}
}

func TestREL009_NoRolloutStrategy(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	if !hasRule(ruleRolloutStrategy(d), "REL009") {
		t.Error("expected REL009 to fire when spec.strategy is absent")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleRolloutStrategy(good), "REL009") {
		t.Error("did not expect REL009 when spec.strategy is set")
	}
}

func TestREL010_ZeroGracePeriod(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 0
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	if !hasRule(ruleTerminationGrace(d), "REL010") {
		t.Error("expected REL010 to fire when terminationGracePeriodSeconds is 0")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleTerminationGrace(good), "REL010") {
		t.Error("did not expect REL010 when terminationGracePeriodSeconds is 30")
	}
}

func TestIsLatestTag(t *testing.T) {
	cases := map[string]bool{
		"myregistry/web:1.4.2":                false,
		"myregistry/web:latest":               true,
		"myregistry/web":                      true,
		"web":                                 true,
		"myregistry/web@sha256:abcd1234":      false,
		"registry.example.com:5000/web:1.4.2": false,
		"registry.example.com:5000/web":       true,
	}
	for image, want := range cases {
		if got := isLatestTag(image); got != want {
			t.Errorf("isLatestTag(%q) = %v, want %v", image, got, want)
		}
	}
}

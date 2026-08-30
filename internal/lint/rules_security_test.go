package lint

import "testing"

func TestSEC001_Privileged(t *testing.T) {
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
          securityContext:
            privileged: true
`
	d := parseOne(t, bad)
	if !hasRule(rulePrivileged(d), "SEC001") {
		t.Error("expected SEC001 to fire when privileged: true")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(rulePrivileged(good), "SEC001") {
		t.Error("did not expect SEC001 when privileged: false")
	}
}

func TestSEC002_RunAsRoot(t *testing.T) {
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
	if !hasRule(ruleRunAsRoot(d), "SEC002") {
		t.Error("expected SEC002 to fire when runAsNonRoot is unset")
	}

	explicitRoot := `
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
          securityContext:
            runAsUser: 0
`
	d = parseOne(t, explicitRoot)
	if !hasRule(ruleRunAsRoot(d), "SEC002") {
		t.Error("expected SEC002 to fire when runAsUser is explicitly 0")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleRunAsRoot(good), "SEC002") {
		t.Error("did not expect SEC002 when runAsNonRoot: true and runAsUser: 1000")
	}
}

func TestSEC003_WritableRootFS(t *testing.T) {
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
	if !hasRule(ruleWritableRootFS(d), "SEC003") {
		t.Error("expected SEC003 to fire when readOnlyRootFilesystem is unset")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleWritableRootFS(good), "SEC003") {
		t.Error("did not expect SEC003 when readOnlyRootFilesystem: true")
	}
}

func TestSEC004_HostNamespaces(t *testing.T) {
	bad := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: web
          image: myregistry/web:1.4.2
`
	d := parseOne(t, bad)
	f := ruleHostNamespaces(d)
	if countRule(f, "SEC004") != 3 {
		t.Errorf("expected 3 SEC004 findings (network/pid/ipc), got %d", countRule(f, "SEC004"))
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleHostNamespaces(good), "SEC004") {
		t.Error("did not expect SEC004 when host namespaces are not shared")
	}
}

func TestSEC005_DangerousCapabilities(t *testing.T) {
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
          securityContext:
            capabilities:
              add: ["SYS_ADMIN", "NET_RAW"]
`
	d := parseOne(t, bad)
	if countRule(ruleDangerousCapabilities(d), "SEC005") != 2 {
		t.Error("expected 2 SEC005 findings, one per dangerous capability")
	}

	safeCap := `
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
          securityContext:
            capabilities:
              add: ["NET_BIND_SERVICE"]
`
	d = parseOne(t, safeCap)
	if hasRule(ruleDangerousCapabilities(d), "SEC005") {
		t.Error("did not expect SEC005 for a non-dangerous capability like NET_BIND_SERVICE")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleDangerousCapabilities(good), "SEC005") {
		t.Error("did not expect SEC005 when no capabilities are added")
	}
}

func TestSEC006_AllowPrivilegeEscalation(t *testing.T) {
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
	if !hasRule(ruleAllowPrivilegeEscalation(d), "SEC006") {
		t.Error("expected SEC006 to fire when allowPrivilegeEscalation is unset")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleAllowPrivilegeEscalation(good), "SEC006") {
		t.Error("did not expect SEC006 when allowPrivilegeEscalation: false")
	}
}

func TestSEC007_SecretEnvVars(t *testing.T) {
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
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-secret
                  key: password
`
	d := parseOne(t, bad)
	if !hasRule(ruleSecretEnvVars(d), "SEC007") {
		t.Error("expected SEC007 to fire when a secret is mounted via env valueFrom.secretKeyRef")
	}

	goodEnvVar := `
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
          env:
            - name: LOG_LEVEL
              value: "info"
`
	d = parseOne(t, goodEnvVar)
	if hasRule(ruleSecretEnvVars(d), "SEC007") {
		t.Error("did not expect SEC007 for a plain non-secret env var")
	}
}

func TestSEC008_AutomountToken(t *testing.T) {
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
	if !hasRule(ruleAutomountToken(d), "SEC008") {
		t.Error("expected SEC008 to fire when automountServiceAccountToken is unset")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleAutomountToken(good), "SEC008") {
		t.Error("did not expect SEC008 when automountServiceAccountToken: false")
	}
}

func TestSEC009_LatestTag(t *testing.T) {
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
`
	d := parseOne(t, bad)
	if !hasRule(ruleLatestTag(d), "SEC009") {
		t.Error("expected SEC009 to fire for :latest tag")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleLatestTag(good), "SEC009") {
		t.Error("did not expect SEC009 for a pinned tag")
	}
}

func TestSEC010_SeccompProfile(t *testing.T) {
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
	if !hasRule(ruleSeccompProfile(d), "SEC010") {
		t.Error("expected SEC010 to fire when no seccomp profile is set")
	}

	good := parseOne(t, goodDeployment)
	if hasRule(ruleSeccompProfile(good), "SEC010") {
		t.Error("did not expect SEC010 when seccompProfile.type: RuntimeDefault is set")
	}

	podLevel := `
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: myregistry/web:1.4.2
`
	d = parseOne(t, podLevel)
	if hasRule(ruleSeccompProfile(d), "SEC010") {
		t.Error("did not expect SEC010 when seccomp is set at the pod level")
	}
}

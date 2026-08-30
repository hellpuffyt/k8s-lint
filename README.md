# k8s-lint

A linter for Kubernetes manifests that explains **the outage each rule
prevents**, not just the rule ID that fired.

## What

`k8s-lint` reads Kubernetes YAML manifests — plain files, multi-document
files, `kubectl get -o yaml` `List` output, or Helm-rendered templates — and
checks them against 20 rules covering reliability and security defaults.
It needs no cluster connection; it only reads files.

## Why

Most Kubernetes manifests are copied from a tutorial and shipped as-is. They
typically have no resource limits (so one pod evicts its neighbours), no
liveness probe (so a wedged process never restarts), a single replica behind
a PodDisruptionBudget that can never be satisfied, or a `:latest` tag (so a
"rollback" silently re-pulls whatever `latest` currently points to instead of
the image that was actually running).

Existing linters print a rule ID and a one-line description. That's not
enough to get a team to act on it. `k8s-lint` instead explains, for every
finding, **what actually breaks in production if you ignore it** — and gives
the exact YAML fix.

## Features

- **20 rules** across reliability (`REL001`-`REL010`) and security
  (`SEC001`-`SEC010`).
- **Multi-document YAML**: `---`-separated files, `kind: List` (and
  `*List`) expansion, Helm-rendered output with blank sections, and clean
  errors (not panics) on malformed YAML.
- **Cross-resource checks**: matches Deployments/StatefulSets against
  PodDisruptionBudgets in the same input by label selector.
- **Filtering**: `--severity`, `--ignore`, `--only`.
- **Three output formats**: human-readable text, JSON, and SARIF 2.1.0 (for
  GitHub code scanning).
- **CI-friendly**: non-zero exit code whenever a finding meets or exceeds
  the severity threshold.
- No cluster connection required — it only lints files.

## Architecture

```
cmd/k8s-lint/        CLI entrypoint: flag parsing, file/directory walking, exit codes
internal/lint/        Rule engine
  parse.go             Multi-document YAML decoding, List-kind expansion, empty-doc skipping
  access.go            Defensive map[string]interface{} navigation helpers
  engine.go             Rule registry, Options (severity/ignore/only), Lint()
  rules_reliability.go Rules REL001-REL010
  rules_security.go    Rules SEC001-SEC010
internal/report/       Renders findings as text, JSON, or SARIF
testdata/               Good and bad example manifests used by tests and CI
```

Manifests are decoded into a generic `map[string]interface{}` tree rather
than typed Kubernetes API structs. Real-world manifests are frequently
partial, hand-edited, or from CRDs the tool doesn't know about; permissive
map navigation degrades gracefully (missing/wrong-typed fields return zero
values) instead of failing to parse a whole file over one unknown field.

## Installation

```sh
go install github.com/hellpuffyt/k8s-lint/cmd/k8s-lint@latest
```

Or build from source:

```sh
git clone https://github.com/hellpuffyt/k8s-lint.git
cd k8s-lint
go build -o k8s-lint ./cmd/k8s-lint
```

## Usage

```sh
# Lint a single file
k8s-lint deployment.yaml

# Lint every .yaml/.yml file under a directory, recursively
k8s-lint ./manifests

# Only fail the build on high-or-worse findings
k8s-lint --severity high ./manifests

# Skip specific rules (e.g. a team that intentionally runs single-replica in dev)
k8s-lint --ignore REL005,REL006 ./manifests

# Run only a subset of rules
k8s-lint --only SEC001,SEC004,SEC005 ./manifests

# Machine-readable output
k8s-lint --format json ./manifests
k8s-lint --format sarif ./manifests > results.sarif

# List every rule this version implements
k8s-lint --list-rules
```

Exit codes: `0` — no findings at or above the severity threshold; `1` —
findings at or above the threshold; `2` — usage error (bad flags, unreadable
file, malformed YAML).

## Rules reference

| ID | Severity | What fails in production if ignored |
|---|---|---|
| REL001 | high | No resource requests/limits: a runaway container OOM-kills unpredictably or evicts neighbours; the scheduler can't bin-pack without requests. |
| REL002 | high | No liveness probe: a wedged (not crashed) process never gets restarted and serves nothing while looking healthy. |
| REL003 | high | No readiness probe: traffic is routed to a pod before it has finished starting up, causing failures during rollout and after restarts. |
| REL004 | medium | Liveness and readiness probes hit the same endpoint: a slow dependency fails both at once, turning a graceful traffic drain into a restart loop. |
| REL005 | medium | `replicas: 1` (or default) on a Deployment/StatefulSet: any node drain, failure, or OOM kill takes the whole workload down. |
| REL006 | medium | No matching PodDisruptionBudget for a multi-replica workload: node drains/upgrades can evict every replica at once. |
| REL007 | high | PDB `minAvailable` equals replica count (or `100%`): blocks all voluntary eviction, so `kubectl drain` and cluster upgrades hang. |
| REL008 | medium | `:latest` tag with `imagePullPolicy: Always` (the default for `latest`): a "rollback" re-pulls whatever `latest` now points to, not what was actually running. |
| REL009 | low | No explicit rollout strategy: the aggressive 25%/25% cluster default applies implicitly. |
| REL010 | high | `terminationGracePeriodSeconds: 0`: SIGKILL immediately, no connection draining, dropped in-flight requests on every rollout/scale-down/drain. |
| SEC001 | critical | `privileged: true`: full host device/kernel access; a compromise escapes the container entirely. |
| SEC002 | high | No `runAsNonRoot: true` (or explicit `runAsUser: 0`): a container-escape bug hands the attacker root inside the container. |
| SEC003 | medium | Writable root filesystem: an attacker with code execution can persist tools/backdoors on disk. |
| SEC004 | critical | `hostNetwork`/`hostPID`/`hostIPC`: the container can see or interfere with other pods and processes on the node. |
| SEC005 | critical | Dangerous capability added (`SYS_ADMIN`, `NET_RAW`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_OVERRIDE`, `ALL`): near-root power inside the container. |
| SEC006 | high | `allowPrivilegeEscalation` not disabled: a process can gain more privilege than its parent (e.g. via setuid). |
| SEC007 | medium | Secret mounted as an env var: inherited by child processes, dumped in crash reports, readable via `/proc/<pid>/environ`. |
| SEC008 | low | `automountServiceAccountToken` left on: a compromised container gets a live API token even if it never calls the API. |
| SEC009 | medium | `:latest` image tag: unauditable, unpinnable, two replicas can silently run different code. |
| SEC010 | low | No seccomp profile: the container gets the runtime's default syscall filtering (often none). |

Run `k8s-lint --list-rules` for the current, authoritative list.

## Examples

```sh
$ k8s-lint testdata/bad/deployment.yaml
[HIGH] REL001 (Deployment)
  resource: legacy-app (namespace: default)
  file:     testdata/bad/deployment.yaml:1
  field:    spec.template.spec.containers[0:legacy-app].resources
  why:      Container has no resource requests and limits set. Without limits, a
            runaway container can consume all node memory/CPU and get OOM-killed
            unpredictably or evict its neighbours; without requests, the scheduler
            cannot bin-pack correctly and may co-locate too many pods on one node.
  fix:
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "500m"
        memory: "256Mi"
...
15 issue(s): 3 critical, 3 high, 6 medium, 3 low
```

## SARIF integration

SARIF 2.1.0 output can be uploaded straight to GitHub code scanning:

```yaml
# .github/workflows/k8s-lint.yml
- name: Install k8s-lint
  run: go install github.com/hellpuffyt/k8s-lint/cmd/k8s-lint@latest

- name: Lint manifests
  run: k8s-lint --format sarif ./manifests > results.sarif
  continue-on-error: true  # let the upload step run even if k8s-lint exits non-zero

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings then show up as annotations on the relevant lines in GitHub's
Security tab and in pull request diffs.

## Testing

```sh
go build ./...
go vet ./...
gofmt -l .      # must print nothing
go test ./... -v
```

Every rule is tested in both directions: it fires on a manifest that
violates it, and it provably does not fire on a hardened one. Known
false-positive guards (Jobs don't need readiness probes, DaemonSets don't
have a replica-count redundancy problem, single-replica workloads don't need
a PDB) are tested explicitly. `testdata/good/` and `testdata/bad/` hold
example manifests used by both the Go tests and the CI smoke job.

## Security

`k8s-lint` only reads local files; it makes no network calls and requires no
cluster credentials. Its findings can reference sensitive-looking field
names (e.g. secret env var names) from the manifests you point it at —
review output before sharing it outside your team. Report vulnerabilities by
opening a GitHub issue.

## License

MIT — see [LICENSE](LICENSE).

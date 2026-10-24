# Production readiness — k8s-lint

Audit of the `audit/production-readiness` branch. Evidence only; the
classification at the end is a proposal for the maintainer to confirm.

- Tested commit: `6248898965384cb4352d405032e2ea4e7cce7697` (this file was
  added in the next commit and changes no code)
- Date: 2026-10-22
- Host: macOS 27 (Apple Silicon), Go 1.27.3. `go.mod` declares `go 1.22`.

## Scope

An offline linter for Kubernetes YAML: multi-document files, `List` /
`*List` expansion, 20 rules (REL001-REL010, SEC001-SEC010) with a "what
breaks" explanation and a YAML fix per finding, cross-document PDB checks,
`--severity`/`--only`/`--ignore`, text/JSON/SARIF output and threshold exit
codes. One dependency (`gopkg.in/yaml.v3`). No network, no cluster access.

## Platforms and prerequisites

- Go 1.22+. Verified locally on macOS arm64.
- CI: Go 1.22/1.23 on ubuntu, Windows and macOS plus a smoke job; not yet
  run on this branch.

## Clean-clone verification

Fresh clone of the branch; README "Build from source", "Testing" and
"Usage" followed (with the repository's `testdata/` standing in for
`./manifests`):

| Command | Exit | Result |
|---|---|---|
| `go build -o k8s-lint ./cmd/k8s-lint`, `go build ./...`, `go vet ./...` | 0 | |
| `gofmt -l .` | 0 | no output |
| `go test ./... -v` | 0 | 63 passed, 0 failed, 0 skipped (tests and subtests) |
| `go test -race ./...` | 0 | |
| `k8s-lint testdata/bad/deployment.yaml` | 1 | `15 issue(s): 3 critical, 3 high, 6 medium, 3 low` (matches README) |
| `k8s-lint testdata/good` | 0 | `No issues found.` |
| `--severity high` / `--ignore REL005,REL006` / `--only SEC001,SEC004,SEC005` on the bad + list + good manifests | 1 / 1 / 1 | 11 / 25 / 3 issues |
| `k8s-lint --only SEC01 testdata/bad` | 2 | `unknown rule ID(s): SEC01` (was exit 0, "No issues found") |
| `--format json` and `--format sarif` piped to `python3 -m json.tool` | 0 | valid JSON |
| `k8s-lint --list-rules \| wc -l` | 0 | 20 |
| `k8s-lint testdata/bad/malformed.yaml` | 2 | positioned YAML error, no panic |
| `k8s-lint --version` | 0 | `k8s-lint 0.1.0` |

Note: linting a directory that contains a malformed file stops with exit 2
for the whole run (documented behaviour: malformed YAML is a usage error).

## Commands executed (working clone)

| Command | Exit | Outcome |
|---|---|---|
| `go test -race -count=1 -v ./...` (baseline) | 0 | 57 passed, 0 failed, 0 skipped |
| `go test -race -count=1 -v ./...` (after) | 0 | 63 passed, 0 failed, 0 skipped |
| `go run honnef.co/go/tools/cmd/staticcheck@latest ./...` (v0.8.2) | 0 | after removing the unused `isWorkload` (U1000, present at baseline) |
| `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` (v1.9.0) | 0 | No vulnerabilities found |
| `go mod verify` | 0 | all modules verified |
| `go run github.com/zricethezav/gitleaks/v8@latest git --redact .` | 0 | no leaks |

All new regression tests except `TestValidateRuleIDs` (new function) were
run against the pre-fix code and failed there; the `--only` typo was also
reproduced with the pre-fix binary (exit 0, "No issues found").

## CI status

- Default branch (`main`): last run `success`.
- Audit branch: pending until pushed. CI file unchanged (already
  `contents: read`).

## Bugs found and fixed

| # | Severity | Bug | Fix | Regression test |
|---|---|---|---|---|
| 1 | High (silent CI pass) | Unknown rule IDs in `--only`/`--ignore` accepted: `--only SEC01` ran nothing and exited 0. | Usage error (exit 2); IDs case-insensitive. | `TestRun_UnknownRuleIDIsUsageError`, `TestValidateRuleIDs` |
| 2 | High (false negative) | Security rules skipped `initContainers`: a privileged init container or one adding `SYS_ADMIN` produced no critical finding. | Security rules iterate containers and init containers. | `TestSecurityRulesInspectInitContainers` |
| 3 | Medium (advertised, missing) | README promises `*List` expansion; only `List` was expanded, so `DeploymentList` items were never linted. | Expand any `*List` kind that has `items`. | `TestTypedListKindsAreExpanded` |
| 4 | Medium (false negative) | SEC010 passed when any one container had a seccomp profile. | Pod-level profile or every container. | `TestSeccompRequiredForEveryContainerWithoutPodDefault` |
| 5 | Medium | PDB matching ignored namespaces (missed REL006 across namespaces) and `matchExpressions` (false REL006, missed REL007). | Namespace check and full selector semantics. | `TestPDBMatchingHonoursNamespaceAndExpressions` |
| 6 | Low | Dead code (`isWorkload`, staticcheck U1000). | Removed. | staticcheck |
| 7 | Docs | README example output was hand-wrapped; vulnerability reports went to public issues. | Real output; `SECURITY.md` with advisory link; limitations section. | — |

## Security review

- Input: untrusted YAML decoded by yaml.v3 into generic maps; malformed
  documents return errors. No code execution, no network.
- File walking: `filepath.Walk` over user-given paths (does not follow
  directory symlinks); reads `.yaml`/`.yml` only.
- Output: may contain names from manifests (documented).
- Secrets: none in tree or history.

## Known limitations

See README "Limitations": document-level line numbers, REL007 ignores
`maxUnavailable: 0`, no HPA awareness for REL005, SEC008 ignores
ServiceAccount objects, `ephemeralContainers` and CRDs not inspected.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Install / build | Documented commands work | clean clone | pass | | |
| 20 rules fire and stay quiet | Each rule positive + negative | `rules_*_test.go` | pass | | `rules_*.go` |
| Multi-doc / List / *List / malformed | Parsed or clean error | `parse_test.go`, `TestTypedListKindsAreExpanded`, malformed run | pass | exit 2 on malformed | `parse.go` |
| Cross-resource PDB | Namespace + selector aware | `TestPDBMatching…` | pass | | `rules_reliability.go` |
| Init containers | Security rules apply | `TestSecurityRulesInspectInitContainers` | pass | | `rules_security.go` |
| Filters | `--severity`, `--only`, `--ignore`; typos rejected | CLI tests, clean clone | pass | | `main.go` |
| Formats | text / JSON / SARIF 2.1.0 valid | report tests, `json.tool` | pass | | `report.go` |
| Exit codes | 0 / 1 / 2 | CLI tests | pass | | `main.go` |
| Static analysis / deps | vet, staticcheck, govulncheck clean | above | pass | | |

## Classification proposal

**Production-Ready for Its Documented Scope** — proposed, pending
independent verification and the CI matrix on this branch; the remaining
rule gaps are listed as limitations rather than claimed.

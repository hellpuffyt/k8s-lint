# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- Unknown rule IDs in `--only`/`--ignore` are a usage error (exit 2); a
  typo previously ran no rules and exited 0. Rule IDs are case-insensitive.
- Typed list kinds (`DeploymentList`, ...) are expanded like `List`.
- Security rules inspect `initContainers` (a privileged init container was
  not reported).
- SEC010 requires a seccomp profile on every container when none is set at
  pod level.
- PodDisruptionBudget matching honours namespaces and `matchExpressions`.

### Changed

- README example output replaced with real output; limitations section.

## [0.1.0] - 2026-08-30

### Added

- Initial release of `k8s-lint`.
- 10 reliability rules (`REL001`-`REL010`): resource requests/limits, liveness
  and readiness probes (including the same-endpoint restart-loop check),
  single-replica workloads, PodDisruptionBudget coverage and blocking
  `minAvailable`, `:latest` + `imagePullPolicy: Always`, missing rollout
  strategy, and `terminationGracePeriodSeconds: 0`.
- 10 security rules (`SEC001`-`SEC010`): `privileged`, root execution,
  writable root filesystem, host namespace sharing, dangerous Linux
  capabilities, `allowPrivilegeEscalation`, secrets as env vars,
  `automountServiceAccountToken`, `:latest` image tags, and missing seccomp
  profiles.
- Multi-document YAML parsing, `List`-kind expansion, and Helm-rendered
  output support with clean handling of empty documents.
- `--severity`, `--ignore`, and `--only` flags for filtering findings.
- Text, JSON, and SARIF 2.1.0 output formats (SARIF for GitHub code
  scanning).
- Non-zero exit code when findings meet or exceed the severity threshold, for
  CI use.

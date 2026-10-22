# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
https://github.com/hellpuffyt/k8s-lint/security/advisories/new

Include the k8s-lint version (`k8s-lint --version`), the command line and a
minimal manifest that reproduces the problem. Please do not open a public
issue for a suspected vulnerability.

## Security model

- k8s-lint only reads the files and directories you pass. It makes no
  network calls and needs no cluster credentials.
- Manifests are untrusted input: they are decoded with `gopkg.in/yaml.v3`
  into generic maps; nothing in a manifest is executed, and a malformed
  document is reported as an error (exit 2) rather than crashing.
- Output can contain names from your manifests (for example the names of
  secret-backed environment variables); review it before sharing.
- A missed finding (false negative) in a security rule is treated as a
  security bug: please report it the same way.

Only the latest release receives fixes.

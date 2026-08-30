# Contributing

Contributions are welcome. This project has no external dependencies beyond
`gopkg.in/yaml.v3`, and aims to stay that way.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .        # must print nothing
go test ./...
```

## Adding a rule

1. Pick an unused ID (`REL0xx` for reliability, `SEC0xx` for security).
2. Implement the rule as a function in `internal/lint/rules_reliability.go`
   or `internal/lint/rules_security.go`. Every finding must include:
   - a stable rule ID and severity,
   - the exact field path the finding applies to,
   - a message that explains **what fails in production** if the issue is
     ignored, not just what the rule checks,
   - a concrete YAML fix snippet.
3. Register the rule in `internal/lint/engine.go` (`AllRules` and either
   `perDocRules` or `crossDocRules`).
4. Add tests proving the rule fires on a bad manifest **and** does not fire
   on a good one. If the rule has a legitimate exemption (e.g. Jobs not
   needing a readiness probe), test that exemption explicitly.
5. Update the rules table in `README.md`.

## Reporting bugs

Please include the manifest (with any secrets redacted/faked) that produced
the incorrect result, the command you ran, and what you expected instead.

## Code style

Run `gofmt` before committing. Keep functions small and prefer explicit,
defensive map navigation (see `internal/lint/access.go`) over reflection or
struct tags, since real-world manifests are frequently incomplete or
hand-edited.

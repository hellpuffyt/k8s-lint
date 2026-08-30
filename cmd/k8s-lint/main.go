// Command k8s-lint lints Kubernetes manifests for reliability and security
// defaults, explaining the production failure each rule prevents.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hellpuffyt/k8s-lint/internal/lint"
	"github.com/hellpuffyt/k8s-lint/internal/report"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("k8s-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		severity  = fs.String("severity", "low", "minimum severity to report and to fail on (low|medium|high|critical)")
		ignore    = fs.String("ignore", "", "comma-separated rule IDs to skip")
		only      = fs.String("only", "", "comma-separated rule IDs to run exclusively")
		format    = fs.String("format", "text", "output format: text|json|sarif")
		showVer   = fs.Bool("version", false, "print version and exit")
		listRules = fs.Bool("list-rules", false, "print all rule IDs and descriptions, then exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: k8s-lint [flags] <file-or-dir> [file-or-dir ...]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *showVer {
		fmt.Fprintln(stdout, "k8s-lint", version)
		return 0
	}
	if *listRules {
		for _, r := range lint.AllRules {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", r.ID, r.Severity, r.Description)
		}
		return 0
	}

	report.ToolVersion = version

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "error: no manifest files or directories given")
		fs.Usage()
		return 2
	}

	minSeverity := lint.Severity(strings.ToLower(*severity))
	if !minSeverity.Valid() {
		fmt.Fprintf(stderr, "error: invalid --severity %q (want one of low, medium, high, critical)\n", *severity)
		return 2
	}

	opts := lint.Options{
		MinSeverity: minSeverity,
		Ignore:      splitCSV(*ignore),
		Only:        splitCSV(*only),
	}

	files, err := collectFiles(paths)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "error: no YAML manifests found in the given paths")
		return 2
	}

	var allDocs []lint.Doc
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading %s: %v\n", f, err)
			return 2
		}
		docs, err := lint.ParseFile(f, content)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		allDocs = append(allDocs, docs...)
	}

	findings := lint.Lint(allDocs, opts)

	switch strings.ToLower(*format) {
	case "text":
		report.WriteText(stdout, findings)
	case "json":
		if err := report.WriteJSON(stdout, findings); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "sarif":
		if err := report.WriteSARIF(stdout, findings); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	default:
		fmt.Fprintf(stderr, "error: invalid --format %q (want text, json, or sarif)\n", *format)
		return 2
	}

	if len(findings) > 0 {
		return 1
	}
	return 0
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// collectFiles expands the given file/directory paths into a sorted, unique
// list of .yaml/.yml files.
func collectFiles(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			continue
		}
		err = filepath.Walk(p, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				if !seen[path] {
					seen[path] = true
					out = append(out, path)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

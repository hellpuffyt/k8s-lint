package lint

import "testing"

func TestParseFile_MultiDocument(t *testing.T) {
	src := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: b
spec: {}
`
	docs, err := ParseFile("multi.yaml", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 docs, got %d", len(docs))
	}
	if docs[0].Kind != "Deployment" || docs[0].Name != "a" {
		t.Errorf("doc0 = %+v", docs[0])
	}
	if docs[1].Kind != "Service" || docs[1].Name != "b" {
		t.Errorf("doc1 = %+v", docs[1])
	}
}

func TestParseFile_SkipsEmptyDocuments(t *testing.T) {
	src := `
---
# just a comment, no content
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
---


---
`
	docs, err := ParseFile("sparse.yaml", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc (empties skipped), got %d: %+v", len(docs), docs)
	}
	if docs[0].Name != "cfg" {
		t.Errorf("expected cfg, got %s", docs[0].Name)
	}
}

func TestParseFile_ExpandsListKind(t *testing.T) {
	src := `
apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: dep-a
    spec: {}
  - apiVersion: v1
    kind: Service
    metadata:
      name: svc-a
    spec: {}
`
	docs, err := ParseFile("list.yaml", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected List to expand into 2 docs, got %d", len(docs))
	}
	if docs[0].Kind != "Deployment" || docs[0].Name != "dep-a" {
		t.Errorf("item0 = %+v", docs[0])
	}
	if docs[1].Kind != "Service" || docs[1].Name != "svc-a" {
		t.Errorf("item1 = %+v", docs[1])
	}
}

func TestParseFile_HelmRenderedMultiDocWithEmptySections(t *testing.T) {
	// Helm templates commonly emit blank documents when a conditional
	// block renders to nothing.
	src := `
---
# Source: chart/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helm-app
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: app:1.0.0
---
# Source: chart/templates/optional-pdb.yaml
---
# Source: chart/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: helm-app-svc
spec:
  selector:
    app: helm-app
`
	docs, err := ParseFile("helm.yaml", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 docs from helm output, got %d", len(docs))
	}
}

func TestParseFile_MalformedYAMLReturnsError(t *testing.T) {
	src := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: [this is not closed
spec: {}
`
	_, err := ParseFile("bad.yaml", []byte(src))
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
	var pe *ParseError
	if !asParseError(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
}

func asParseError(err error, target **ParseError) bool {
	pe, ok := err.(*ParseError)
	if ok {
		*target = pe
	}
	return ok
}

func TestParseFile_TabIndentationIsMalformed(t *testing.T) {
	// YAML disallows tabs for indentation; this must error cleanly, not panic.
	src := "apiVersion: v1\nkind: Pod\nmetadata:\n\tname: bad\n"
	_, err := ParseFile("tabs.yaml", []byte(src))
	if err == nil {
		t.Fatal("expected an error for tab-indented YAML")
	}
}

func TestParseFile_EmptyFile(t *testing.T) {
	docs, err := ParseFile("empty.yaml", []byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("expected 0 docs for empty file, got %d", len(docs))
	}
}

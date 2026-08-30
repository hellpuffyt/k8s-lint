package lint

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// Doc is a single parsed Kubernetes object taken from a YAML document.
type Doc struct {
	Kind       string
	APIVersion string
	Name       string
	Namespace  string
	File       string
	// DocIndex is the zero-based index of the source YAML document within
	// the file (accounting for "---" separators), used for diagnostics.
	DocIndex int
	// Line is the starting line number of this document within the file.
	Line int
	M    map[string]interface{}
}

// ParseErrror is returned for a document that could not be decoded as YAML.
type ParseError struct {
	File     string
	DocIndex int
	Err      error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: document %d: %v", e.File, e.DocIndex, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// ParseFile splits file content into YAML documents and decodes each into a
// Doc. Kubernetes "List" kind objects are expanded so each item becomes its
// own Doc. Empty documents (blank, comment-only, or "null") are skipped
// cleanly. A malformed document returns a *ParseError rather than panicking.
func ParseFile(filename string, content []byte) ([]Doc, error) {
	dec := yaml.NewDecoder(bytesReader(content))
	var docs []Doc
	idx := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return docs, &ParseError{File: filename, DocIndex: idx, Err: err}
		}
		d, skip, perr := decodeNode(&node, filename, idx)
		if perr != nil {
			return docs, perr
		}
		if !skip {
			docs = append(docs, expandLists(d)...)
		}
		idx++
	}
	return docs, nil
}

func decodeNode(node *yaml.Node, filename string, idx int) (Doc, bool, error) {
	// An empty document decodes to a Document node with no content, or a
	// scalar "null"/"~". Treat both as "skip".
	if len(node.Content) == 0 {
		return Doc{}, true, nil
	}
	root := node.Content[0]
	if root.Kind == yaml.ScalarNode && (root.Tag == "!!null" || root.Value == "") {
		return Doc{}, true, nil
	}

	var m map[string]interface{}
	if err := node.Decode(&m); err != nil {
		return Doc{}, false, &ParseError{File: filename, DocIndex: idx, Err: err}
	}
	if len(m) == 0 {
		return Doc{}, true, nil
	}

	d := Doc{
		Kind:       str(m["kind"]),
		APIVersion: str(m["apiVersion"]),
		File:       filename,
		DocIndex:   idx,
		Line:       root.Line,
		M:          m,
	}
	if meta, ok := m["metadata"].(map[string]interface{}); ok {
		d.Name = str(meta["name"])
		d.Namespace = str(meta["namespace"])
	}
	return d, false, nil
}

// expandLists turns a Kubernetes "List" (or "*List", e.g. DeploymentList)
// document produced by `kubectl get -o yaml` or Helm into one Doc per item.
// Non-list documents are returned unchanged.
func expandLists(d Doc) []Doc {
	if d.Kind != "List" {
		return []Doc{d}
	}
	items, _ := d.M["items"].([]interface{})
	out := make([]Doc, 0, len(items))
	for i, it := range items {
		m, ok := it.(map[string]interface{})
		if !ok || len(m) == 0 {
			continue
		}
		item := Doc{
			Kind:       str(m["kind"]),
			APIVersion: str(m["apiVersion"]),
			File:       d.File,
			DocIndex:   d.DocIndex,
			Line:       d.Line,
			M:          m,
		}
		if meta, ok := m["metadata"].(map[string]interface{}); ok {
			item.Name = str(meta["name"])
			item.Namespace = str(meta["namespace"])
		}
		_ = i
		out = append(out, item)
	}
	return out
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

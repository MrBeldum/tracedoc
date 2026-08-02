// Package testsupport provides shared fixture helpers for this repository's
// tests. It is never imported by production code.
package testsupport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Path resolves a repository-relative path from the repository root.
func Path(t *testing.T, elements ...string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Join(append([]string{filepath.Dir(filename), "..", ".."}, elements...)...)
}

// FixturePath resolves a file inside the repository testdata directory.
func FixturePath(t *testing.T, name string) string {
	t.Helper()
	return Path(t, "testdata", name)
}

// WriteJSON marshals value into a temporary file and returns its path.
func WriteJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return WriteRaw(t, data)
}

// WriteRaw stores data in a temporary file and returns its path.
func WriteRaw(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
	return path
}

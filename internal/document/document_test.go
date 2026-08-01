package document

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeek(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Type
		err  string
	}{
		{
			name: "requirements",
			data: `{"document_type":"requirements","schema_version":1}`,
			want: TypeRequirements,
		},
		{
			name: "threat model",
			data: `{"document_type":"threat_model"}`,
			want: TypeThreatModel,
		},
		{
			name: "missing type",
			data: `{"schema_version":1}`,
			err:  "missing document_type",
		},
		{
			name: "unknown type",
			data: `{"document_type":"minutes"}`,
			err:  `unsupported document_type "minutes"`,
		},
		{
			name: "malformed JSON",
			data: `{`,
			err:  "cannot identify document type",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			docType, err := Peek([]byte(test.data))
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Fatalf("expected %q, got %v", test.err, err)
				}
				return
			}
			if err != nil || docType != test.want {
				t.Fatalf("expected %q, got %q (%v)", test.want, docType, err)
			}
		})
	}
}

func TestReadFileBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), MaxBytes+1), 0o644); err != nil {
		t.Fatalf("write oversized document: %v", err)
	}
	if _, err := ReadFile(path, "document"); err == nil ||
		!strings.Contains(err.Error(), "document exceeds") {
		t.Fatalf("expected size rejection, got %v", err)
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "absent.json"), "document"); err == nil {
		t.Fatal("expected missing-file error")
	}
}

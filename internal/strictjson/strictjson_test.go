package strictjson

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sample struct {
	SchemaVersion int `json:"schema_version"`
	Owner         *struct {
		Milestone string `json:"milestone"`
	} `json:"owner"`
	Standards []struct {
		Key string `json:"key"`
	} `json:"standards"`
}

func decodeString(t *testing.T, data string) error {
	t.Helper()
	var out sample
	return Decode([]byte(data), &out)
}

func TestDecodeRejections(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "duplicate root member",
			data: `{"schema_version":1,"schema_version":1}`,
			want: `duplicate JSON object member "schema_version"`,
		},
		{
			name: "duplicate nested member",
			data: `{"owner":{"milestone":"M1","milestone":"M2"}}`,
			want: `duplicate JSON object member "milestone"`,
		},
		{
			name: "case-folded duplicate is still a duplicate",
			data: `{"owner":{"milestone":"M1","Milestone":"M2"}}`,
			want: `non-canonical JSON object member "Milestone"`,
		},
		{
			name: "non-canonical member",
			data: `{"ID":"EXCORE-001"}`,
			want: `non-canonical JSON object member "ID"`,
		},
		{
			name: "unknown member",
			data: `{"unknown":true}`,
			want: `unknown field "unknown"`,
		},
		{
			name: "trailing JSON value",
			data: `{} {}`,
			want: "multiple JSON values",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := decodeString(t, test.data)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}

	t.Run("same member in separate objects", func(t *testing.T) {
		if err := decodeString(t, `{"standards":[{"key":"A"},{"key":"B"}]}`); err != nil {
			t.Fatalf("separate object names should be accepted: %v", err)
		}
	})

	t.Run("nesting limit", func(t *testing.T) {
		data := strings.Repeat(`{"a":`, MaxDepth+2) +
			`null` +
			strings.Repeat(`}`, MaxDepth+2)
		var out any
		err := Decode([]byte(data), &out)
		if err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds depth limit") {
			t.Fatalf("expected nesting-limit rejection, got %v", err)
		}
	})

	t.Run("malformed scalar", func(t *testing.T) {
		if err := decodeString(t, `{"schema_version":[]}`); err == nil {
			t.Fatal("expected malformed scalar to be rejected")
		}
	})
}

func TestDecodeFileSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	data := bytes.Repeat([]byte(" "), 33)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	var out any
	err := DecodeFile(path, 32, "matrix", &out)
	if err == nil || !strings.Contains(err.Error(), "matrix exceeds 32-byte limit") {
		t.Fatalf("expected input-size rejection, got %v", err)
	}
}

func TestDecodeFileMissing(t *testing.T) {
	var out any
	if err := DecodeFile(filepath.Join(t.TempDir(), "absent.json"), 32, "matrix", &out); err == nil {
		t.Fatal("expected missing-file error")
	}
}

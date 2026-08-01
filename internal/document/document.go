// Package document reads document files under the shared size bound and
// identifies their declared document type so the CLI can dispatch to the
// matching schema pipeline.
package document

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MaxBytes bounds the size of every document this tool reads.
const MaxBytes = 8 << 20

// Type identifies a supported document schema family.
type Type string

// Supported document types.
const (
	TypeRequirements Type = "requirements"
	TypeThreatModel  Type = "threat_model"
)

// ReadFile reads at most MaxBytes bytes from path. The label names the
// document in errors.
func ReadFile(path, label string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", label, MaxBytes)
	}
	return data, nil
}

// Peek returns the document_type declared by the JSON document in data.
// This is the one intentionally tolerant decode: the strict per-schema
// decode runs after dispatch.
func Peek(data []byte) (Type, error) {
	var header struct {
		DocumentType string `json:"document_type"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", fmt.Errorf("cannot identify document type: %w", err)
	}
	switch Type(header.DocumentType) {
	case TypeRequirements, TypeThreatModel:
		return Type(header.DocumentType), nil
	case "":
		return "", fmt.Errorf("missing document_type member")
	default:
		return "", fmt.Errorf("unsupported document_type %q", header.DocumentType)
	}
}

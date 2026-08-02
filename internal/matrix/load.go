package matrix

import (
	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/strictjson"
)

// Decode strictly decodes a requirements-matrix document from data. It
// performs lexical enforcement only; call Validate for structural
// validation.
func Decode(data []byte) (Document, error) {
	var result Document
	if err := strictjson.Decode(data, &result); err != nil {
		return Document{}, err
	}
	return result, nil
}

// Load reads and strictly decodes the requirements matrix at path.
func Load(path string) (Document, error) {
	data, err := document.ReadFile(path, "matrix")
	if err != nil {
		return Document{}, err
	}
	return Decode(data)
}

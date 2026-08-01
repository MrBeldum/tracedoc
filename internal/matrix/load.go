package matrix

import (
	"github.com/sofired/reqmatrix/internal/strictjson"
)

// Load reads and strictly decodes the matrix document at path. It performs
// lexical enforcement only; call Validate for structural validation.
func Load(path string) (Document, error) {
	var result Document
	if err := strictjson.DecodeFile(path, MaxDocumentBytes, "matrix", &result); err != nil {
		return Document{}, err
	}
	return result, nil
}

// Package strictjson decodes JSON documents under a strict lexical contract:
// bounded input size, bounded nesting depth, canonical lowercase member names,
// no duplicate members, no unknown fields, and exactly one top-level value.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// MaxDepth bounds JSON nesting for every document this package decodes.
const MaxDepth = 16

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// DecodeFile reads at most maxBytes bytes from path and decodes the single
// JSON value it contains into out. The label names the document in errors.
func DecodeFile(path string, maxBytes int64, label string, out any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("%s exceeds %d-byte limit", label, maxBytes)
	}
	return Decode(data, out)
}

// Decode decodes the single JSON value in data into out under the strict
// lexical contract.
func Decode(data []byte, out any) error {
	if err := rejectNonCanonicalMembers(data); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectNonCanonicalMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	return scanValue(decoder, "$", 0)
}

func scanValue(decoder *json.Decoder, location string, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf(
			"%s: JSON nesting exceeds depth limit %d",
			location,
			MaxDepth,
		)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok {
				return fmt.Errorf("%s: expected JSON object member name", location)
			}
			if !namePattern.MatchString(name) {
				return fmt.Errorf(
					"%s: non-canonical JSON object member %q at byte %d",
					location,
					name,
					decoder.InputOffset(),
				)
			}
			canonicalName := strings.ToLower(name)
			if _, duplicate := names[canonicalName]; duplicate {
				return fmt.Errorf(
					"%s: duplicate JSON object member %q at byte %d",
					location,
					name,
					decoder.InputOffset(),
				)
			}
			names[canonicalName] = struct{}{}
			if err := scanValue(decoder, location+"."+name, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanValue(
				decoder,
				fmt.Sprintf("%s[%d]", location, index),
				depth+1,
			); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("%s: unexpected JSON delimiter %q", location, delim)
	}
}

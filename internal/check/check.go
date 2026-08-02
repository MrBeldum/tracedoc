// Package check provides the shared validation vocabulary used by every
// document validator: an ordered error list, a Checker with the common
// field rules, and small set helpers. Schema-specific rules stay in the
// per-document packages.
package check

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// MaxStringBytes bounds every validated string field in every document.
const MaxStringBytes = 16 << 10

// StableIDPattern is the shared stable-identifier format for requirement
// and threat IDs. Changing it is a schema revision for every document type
// that uses it.
var StableIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]{3}$`)

// Errors is an ordered list of validation failures.
type Errors []string

// Error joins the accumulated failures into one newline-separated message,
// satisfying the error interface so Errors can be reported or wrapped like
// any other error.
func (errs Errors) Error() string {
	return strings.Join(errs, "\n")
}

// Checker accumulates location-prefixed validation failures.
type Checker struct {
	Errs Errors
}

// Add records a failure at location.
func (c *Checker) Add(location, message string) {
	c.Errs = append(c.Errs, location+": "+message)
}

// Addf records a formatted failure at location.
func (c *Checker) Addf(location, format string, args ...any) {
	c.Add(location, fmt.Sprintf(format, args...))
}

// RequiredString enforces a non-blank, bounded string.
func (c *Checker) RequiredString(location, value string) bool {
	if !Nonempty(value) {
		c.Add(location, "expected a non-empty string")
		return false
	}
	if len(value) > MaxStringBytes {
		c.Addf(location, "exceeds %d-byte limit", MaxStringBytes)
		return false
	}
	return true
}

// BoundedControlFreeString enforces RequiredString and additionally rejects
// control and line-separator characters. It reports whether value is safe
// to further validate (for example against a consumer-supplied regular
// expression): a value that fails either check is rejected here, before
// that further check runs, so one malformed value cannot cascade into
// multiple diagnostics. Consumer patterns are policy, not a lexical safety
// net: this check is what keeps unbounded or control-bearing scalar values
// out of rendered output regardless of how permissive a pattern is. List
// items get the same guarantee through StringList, and the renderer's
// escaping functions neutralize the same code points in free-text prose.
func (c *Checker) BoundedControlFreeString(location, value string) bool {
	if !c.RequiredString(location, value) {
		return false
	}
	return c.ControlFreeString(location, value)
}

// ControlFreeString rejects control characters (Unicode category Cc,
// which includes NEL) and the Unicode line and paragraph separators
// (categories Zl and Zp) — every code point that any Markdown consumer
// might treat as a line break. Use it alone when RequiredString has
// already run (for example on StringList items).
func (c *Checker) ControlFreeString(location, value string) bool {
	if strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
	}) >= 0 {
		c.Add(location, "contains a control or line-separator character")
		return false
	}
	return true
}

// StringList enforces a present array of bounded, unique, control-free
// strings; requireItems additionally rejects an empty array. Every list
// item receives the same lexical guarantee as a scalar field validated
// with BoundedControlFreeString, so no free-form identifier list can
// carry a control or line-separator character into rendered output.
func (c *Checker) StringList(location string, values []string, requireItems bool) bool {
	if values == nil || requireItems && len(values) == 0 {
		expectation := "expected an array"
		if requireItems {
			expectation = "expected a non-empty array"
		}
		c.Add(location, expectation)
		return false
	}
	valid := true
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		itemLocation := fmt.Sprintf("%s[%d]", location, index)
		if !c.RequiredString(itemLocation, value) {
			valid = false
		} else if !c.ControlFreeString(itemLocation, value) {
			valid = false
		}
		if _, duplicate := seen[value]; duplicate {
			c.Addf(itemLocation, "duplicate value %q", value)
			valid = false
		}
		seen[value] = struct{}{}
	}
	return valid
}

// Enum enforces membership in an allowed value set.
func (c *Checker) Enum(location, value string, allowed map[string]struct{}) bool {
	if Contains(allowed, value) {
		return true
	}
	c.Addf(location, "unsupported value %q", value)
	return false
}

// InsertUnique adds value to the set, reporting whether it was new.
func (c *Checker) InsertUnique(values map[string]struct{}, value string) bool {
	if Contains(values, value) {
		return false
	}
	values[value] = struct{}{}
	return true
}

// StringSet builds a membership set from values.
func StringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// Contains reports set membership.
func Contains(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}

// Nonempty reports whether value has non-whitespace content.
func Nonempty(value string) bool {
	return strings.TrimSpace(value) != ""
}

// SortedSetDifference returns the sorted members of left absent from right.
func SortedSetDifference(left, right map[string]struct{}) []string {
	var result []string
	for value := range left {
		if !Contains(right, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

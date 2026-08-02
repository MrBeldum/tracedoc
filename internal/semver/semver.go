// Package semver parses and orders Semantic Versioning 2.0.0 version
// strings for document version transitions.
package semver

import (
	"regexp"
	"strings"
)

// Pattern is the schema-owned format for document_version values.
var Pattern = regexp.MustCompile(
	`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
		`(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)` +
		`(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?` +
		`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
)

// Version is a parsed semantic version. The three core components are kept
// as the original digit strings, not converted to int: Pattern forbids
// leading zeros, so comparing them by length and then lexically (the same
// trick compareIdentifier uses for prerelease identifiers) reproduces
// numeric ordering at any magnitude without risking strconv.Atoi overflow
// on a pattern-valid but arbitrarily large component.
type Version struct {
	core       [3]string
	prerelease []string
}

// Parse assumes the value already matches Pattern.
func Parse(value string) Version {
	value, _, _ = strings.Cut(value, "+")
	core, prerelease, hasPrerelease := strings.Cut(value, "-")
	var result Version
	for index, part := range strings.SplitN(core, ".", 3) {
		result.core[index] = part
	}
	if hasPrerelease {
		result.prerelease = strings.Split(prerelease, ".")
	}
	return result
}

// CompareMajor orders two versions by their major component alone, using
// the same length-then-lexical rule as Compare. Callers that only need a
// major-version comparison (for example a schema-change transition rule)
// should use this instead of Compare so they never depend on minor or
// patch ordering.
func CompareMajor(left, right Version) int {
	return compareNumericComponent(left.core[0], right.core[0])
}

// Compare orders two versions per the Semantic Versioning 2.0.0 precedence
// rules, ignoring build metadata.
func Compare(left, right Version) int {
	for index := range left.core {
		if result := compareNumericComponent(left.core[index], right.core[index]); result != 0 {
			return result
		}
	}
	switch {
	case len(left.prerelease) == 0 && len(right.prerelease) == 0:
		return 0
	case len(left.prerelease) == 0:
		return 1
	case len(right.prerelease) == 0:
		return -1
	}
	for index := 0; index < len(left.prerelease) && index < len(right.prerelease); index++ {
		if result := compareIdentifier(left.prerelease[index], right.prerelease[index]); result != 0 {
			return result
		}
	}
	return sign(len(left.prerelease) - len(right.prerelease))
}

func compareIdentifier(left, right string) int {
	leftNumeric := isNumericIdentifier(left)
	rightNumeric := isNumericIdentifier(right)
	switch {
	case leftNumeric && rightNumeric:
		return compareNumericComponent(left, right)
	case leftNumeric:
		return -1
	case rightNumeric:
		return 1
	default:
		return strings.Compare(left, right)
	}
}

// compareNumericComponent orders two all-digit strings numerically without
// converting either to an int. Both Pattern (for the three core version
// components) and the semver prerelease grammar (for numeric identifiers)
// forbid leading zeros, so ordering by length and then lexically equals
// numeric ordering at any magnitude — including magnitudes too large for
// strconv.Atoi, which would otherwise silently overflow to 0.
func compareNumericComponent(left, right string) int {
	if len(left) != len(right) {
		return sign(len(left) - len(right))
	}
	return strings.Compare(left, right)
}

func isNumericIdentifier(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sign(value int) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	default:
		return 0
	}
}

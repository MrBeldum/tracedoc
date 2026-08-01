package matrix

import (
	"strconv"
	"strings"
)

type semver struct {
	numbers    [3]int
	prerelease []string
}

// parseSemver assumes the value already matches MatrixVersionPattern.
func parseSemver(value string) semver {
	value, _, _ = strings.Cut(value, "+")
	core, prerelease, hasPrerelease := strings.Cut(value, "-")
	var result semver
	for index, part := range strings.SplitN(core, ".", 3) {
		result.numbers[index], _ = strconv.Atoi(part)
	}
	if hasPrerelease {
		result.prerelease = strings.Split(prerelease, ".")
	}
	return result
}

// compareSemver orders two versions per the Semantic Versioning 2.0.0
// precedence rules, ignoring build metadata.
func compareSemver(left, right semver) int {
	for index := range left.numbers {
		if left.numbers[index] != right.numbers[index] {
			return sign(left.numbers[index] - right.numbers[index])
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
		// Semver numeric identifiers carry no leading zeros, so ordering by
		// length and then lexically equals numeric ordering at any magnitude.
		if len(left) != len(right) {
			return sign(len(left) - len(right))
		}
		return strings.Compare(left, right)
	case leftNumeric:
		return -1
	case rightNumeric:
		return 1
	default:
		return strings.Compare(left, right)
	}
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

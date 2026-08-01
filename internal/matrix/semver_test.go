package matrix

import "testing"

func TestSemverPrecedence(t *testing.T) {
	ordered := []string{
		"0.9.9",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.9.0",
		"1.10.0",
		"2.0.0",
	}
	for index := 1; index < len(ordered); index++ {
		left := parseSemver(ordered[index-1])
		right := parseSemver(ordered[index])
		if compareSemver(left, right) >= 0 {
			t.Errorf("expected %q < %q", ordered[index-1], ordered[index])
		}
		if compareSemver(right, left) <= 0 {
			t.Errorf("expected %q > %q", ordered[index], ordered[index-1])
		}
	}

	equal := [][2]string{
		{"1.0.0", "1.0.0"},
		{"1.0.0+build.1", "1.0.0"},
		{"1.0.0-rc.1+build.2", "1.0.0-rc.1"},
	}
	for _, pair := range equal {
		if compareSemver(parseSemver(pair[0]), parseSemver(pair[1])) != 0 {
			t.Errorf("expected %q == %q", pair[0], pair[1])
		}
	}
}

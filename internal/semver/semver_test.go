package semver

import "testing"

func TestPrecedence(t *testing.T) {
	ordered := []string{
		"0.9.9",
		"1.0.0-2",
		"1.0.0-11",
		"1.0.0-99999999999999999999999999",
		"1.0.0-0a",
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
		left := Parse(ordered[index-1])
		right := Parse(ordered[index])
		if Compare(left, right) >= 0 {
			t.Errorf("expected %q < %q", ordered[index-1], ordered[index])
		}
		if Compare(right, left) <= 0 {
			t.Errorf("expected %q > %q", ordered[index], ordered[index-1])
		}
	}

	equal := [][2]string{
		{"1.0.0", "1.0.0"},
		{"1.0.0+build.1", "1.0.0"},
		{"1.0.0-rc.1+build.2", "1.0.0-rc.1"},
	}
	for _, pair := range equal {
		if Compare(Parse(pair[0]), Parse(pair[1])) != 0 {
			t.Errorf("expected %q == %q", pair[0], pair[1])
		}
	}

	if Parse("2.4.6").Major() != 2 {
		t.Error("expected major version 2")
	}
}

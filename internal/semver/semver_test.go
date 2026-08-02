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
}

// TestHugeComponentsDoNotOverflow is the regression test for the
// strconv.Atoi overflow bug: a pattern-valid but arbitrarily large major,
// minor, or patch value used to silently become 0 on overflow, so it
// compared as lower than a small version instead of higher.
func TestHugeComponentsDoNotOverflow(t *testing.T) {
	huge := Parse("99999999999999999999.0.0")
	small := Parse("2.0.0")
	if Compare(huge, small) <= 0 {
		t.Fatalf(
			"expected huge major version to sort above %q, got Compare = %d",
			"2.0.0", Compare(huge, small),
		)
	}
	if Compare(small, huge) >= 0 {
		t.Fatalf(
			"expected %q to sort below huge major version, got Compare = %d",
			"2.0.0", Compare(small, huge),
		)
	}
}

func TestCompareMajor(t *testing.T) {
	huge := Parse("99999999999999999999.0.0")
	small := Parse("2.0.0")
	if CompareMajor(huge, small) <= 0 {
		t.Fatalf("expected huge major to compare above small major, got %d", CompareMajor(huge, small))
	}
	if CompareMajor(small, huge) >= 0 {
		t.Fatalf("expected small major to compare below huge major, got %d", CompareMajor(small, huge))
	}

	equalHugeLeft := Parse("99999999999999999999.1.2")
	equalHugeRight := Parse("99999999999999999999.9.9")
	if got := CompareMajor(equalHugeLeft, equalHugeRight); got != 0 {
		t.Fatalf("expected equal huge majors to compare 0, got %d", got)
	}

	if got := CompareMajor(Parse("1.9.9"), Parse("2.0.0")); got != -1 {
		t.Fatalf("expected major 1 < major 2, got %d", got)
	}
	if got := CompareMajor(Parse("2.0.0"), Parse("2.9.9")); got != 0 {
		t.Fatalf("expected equal majors to compare 0 regardless of minor/patch, got %d", got)
	}
}

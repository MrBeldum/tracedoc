package check_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sofired/tracedoc/internal/check"
)

func TestRequiredString(t *testing.T) {
	t.Run("blank value is rejected", func(t *testing.T) {
		c := &check.Checker{}
		if c.RequiredString("field", "   ") {
			t.Fatal("expected whitespace-only value to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: expected a non-empty string" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})

	t.Run("oversized value is rejected", func(t *testing.T) {
		c := &check.Checker{}
		oversized := strings.Repeat("x", check.MaxStringBytes+1)
		if c.RequiredString("field", oversized) {
			t.Fatal("expected oversized value to fail")
		}
		want := fmt.Sprintf("field: exceeds %d-byte limit", check.MaxStringBytes)
		if len(c.Errs) != 1 || c.Errs[0] != want {
			t.Fatalf("expected %q, got %v", want, c.Errs)
		}
	})

	t.Run("valid value passes", func(t *testing.T) {
		c := &check.Checker{}
		if !c.RequiredString("field", "a valid value") {
			t.Fatal("expected valid value to pass")
		}
		if len(c.Errs) != 0 {
			t.Fatalf("expected no errors, got %v", c.Errs)
		}
	})
}

func TestRequiredStringRejectsControlAndSeparatorCharacters(t *testing.T) {
	t.Run("valid value passes", func(t *testing.T) {
		c := &check.Checker{}
		if !c.RequiredString("field", "clean value") {
			t.Fatal("expected clean value to pass")
		}
		if len(c.Errs) != 0 {
			t.Fatalf("expected no errors, got %v", c.Errs)
		}
	})

	t.Run("blank value is rejected before the control-character check runs", func(t *testing.T) {
		c := &check.Checker{}
		if c.RequiredString("field", "") {
			t.Fatal("expected blank value to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: expected a non-empty string" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})

	t.Run("control character is rejected", func(t *testing.T) {
		c := &check.Checker{}
		if c.RequiredString("field", "line one\nline two") {
			t.Fatal("expected control character to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: contains a control or line-separator character" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})
}

func TestStringList(t *testing.T) {
	t.Run("nil is rejected when items are not required", func(t *testing.T) {
		c := &check.Checker{}
		if c.StringList("field", nil, false) {
			t.Fatal("expected nil to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: expected an array" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})

	t.Run("nil is rejected when items are required", func(t *testing.T) {
		c := &check.Checker{}
		if c.StringList("field", nil, true) {
			t.Fatal("expected nil to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: expected a non-empty array" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})

	t.Run("empty non-nil slice is accepted when items are not required", func(t *testing.T) {
		c := &check.Checker{}
		if !c.StringList("field", []string{}, false) {
			t.Fatal("expected empty slice to pass")
		}
		if len(c.Errs) != 0 {
			t.Fatalf("expected no errors, got %v", c.Errs)
		}
	})

	t.Run("empty non-nil slice is rejected when items are required", func(t *testing.T) {
		c := &check.Checker{}
		if c.StringList("field", []string{}, true) {
			t.Fatal("expected empty slice to fail")
		}
		if len(c.Errs) != 1 || c.Errs[0] != "field: expected a non-empty array" {
			t.Fatalf("unexpected errors: %v", c.Errs)
		}
	})

	t.Run("duplicate value is reported at the item location", func(t *testing.T) {
		c := &check.Checker{}
		if c.StringList("field", []string{"a", "a"}, true) {
			t.Fatal("expected duplicate values to fail")
		}
		want := `field[1]: duplicate value "a"`
		if !containsString(c.Errs, want) {
			t.Fatalf("expected %q among %v", want, c.Errs)
		}
	})

	t.Run("blank item is rejected at the item location", func(t *testing.T) {
		c := &check.Checker{}
		if c.StringList("field", []string{"a", ""}, true) {
			t.Fatal("expected blank item to fail")
		}
		want := "field[1]: expected a non-empty string"
		if !containsString(c.Errs, want) {
			t.Fatalf("expected %q among %v", want, c.Errs)
		}
	})
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestEnum(t *testing.T) {
	allowed := check.StringSet("open", "closed")

	t.Run("known value passes", func(t *testing.T) {
		c := &check.Checker{}
		if !c.Enum("field", "open", allowed) {
			t.Fatal("expected known value to pass")
		}
		if len(c.Errs) != 0 {
			t.Fatalf("expected no errors, got %v", c.Errs)
		}
	})

	t.Run("unknown value is rejected", func(t *testing.T) {
		c := &check.Checker{}
		if c.Enum("field", "pending", allowed) {
			t.Fatal("expected unknown value to fail")
		}
		want := `field: unsupported value "pending"`
		if len(c.Errs) != 1 || c.Errs[0] != want {
			t.Fatalf("expected %q, got %v", want, c.Errs)
		}
	})
}

func TestInsertUnique(t *testing.T) {
	c := &check.Checker{}
	values := make(map[string]struct{})

	if !c.InsertUnique(values, "a") {
		t.Fatal("expected the first insert of a value to report it as new")
	}
	if c.InsertUnique(values, "a") {
		t.Fatal("expected the second insert of the same value to report a duplicate")
	}
	if !check.Contains(values, "a") {
		t.Fatal("expected the value to be present in the set after insertion")
	}
}

func TestStringSetAndContains(t *testing.T) {
	set := check.StringSet("a", "b")
	if !check.Contains(set, "a") || !check.Contains(set, "b") {
		t.Fatal("expected constructed members to be present")
	}
	if check.Contains(set, "c") {
		t.Fatal("expected an absent member to be reported as missing")
	}
	if len(check.StringSet()) != 0 {
		t.Fatal("expected an empty set when constructed with no members")
	}
}

func TestNonempty(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "   ", want: false},
		{value: "\t\n", want: false},
		{value: "a", want: true},
		{value: "  a  ", want: true},
	}
	for _, test := range tests {
		if got := check.Nonempty(test.value); got != test.want {
			t.Errorf("Nonempty(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestSortedSetDifference(t *testing.T) {
	t.Run("returns the sorted members of left absent from right", func(t *testing.T) {
		left := check.StringSet("c", "a", "b")
		right := check.StringSet("b")
		got := check.SortedSetDifference(left, right)
		want := []string{"a", "c"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("returns nil, not an empty slice, when there is no difference", func(t *testing.T) {
		left := check.StringSet("a")
		right := check.StringSet("a")
		got := check.SortedSetDifference(left, right)
		if got != nil {
			t.Fatalf("expected a nil result, got %#v", got)
		}
	})

	t.Run("returns nil for an empty left set", func(t *testing.T) {
		got := check.SortedSetDifference(check.StringSet(), check.StringSet("a"))
		if got != nil {
			t.Fatalf("expected a nil result, got %#v", got)
		}
	})
}

func TestControlFreeString(t *testing.T) {
	var c check.Checker
	if !c.ControlFreeString("loc", "plain value with spaces") {
		t.Fatal("plain value rejected")
	}
	for name, value := range map[string]string{
		"newline":             "a\nb",
		"escape":              "a\x1bb",
		"NEL":                 "a\u0085b",
		"line separator":      "a\u2028b",
		"paragraph separator": "a\u2029b",
	} {
		c := check.Checker{}
		if c.ControlFreeString("loc", value) {
			t.Errorf("%s accepted", name)
		}
		if len(c.Errs) != 1 || c.Errs[0] != "loc: contains a control or line-separator character" {
			t.Errorf("%s: unexpected errors %v", name, c.Errs)
		}
	}
}

func TestRequiredStringRejectsControlCharactersRejectsLineSeparators(t *testing.T) {
	var c check.Checker
	if c.RequiredString("loc", "a\u2028b") {
		t.Fatal("line separator accepted")
	}
	if len(c.Errs) != 1 || c.Errs[0] != "loc: contains a control or line-separator character" {
		t.Fatalf("unexpected errors %v", c.Errs)
	}
}

// TestStringListRejectsControlBearingItems pins the generalized invariant:
// every free-form list item gets the same lexical guarantee as a scalar
// field, so no identifier list can carry a control rune into output.
func TestStringListRejectsControlBearingItems(t *testing.T) {
	for name, value := range map[string]string{
		"escape":         "ADR-001\x1bFAKE",
		"line separator": "ADR-001\u2028x",
	} {
		var c check.Checker
		if c.StringList("adrs", []string{value}, false) {
			t.Errorf("%s: control-bearing item accepted", name)
		}
		if len(c.Errs) != 1 ||
			!strings.Contains(c.Errs[0], "contains a control or line-separator character") {
			t.Errorf("%s: unexpected errors %v", name, c.Errs)
		}
	}
}

func TestLexicalURI(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "https URL", value: "https://standards.example.org/spec#section-3"},
		{name: "repository-relative path", value: "../plan.md"},
		{
			name:    "embedded space",
			value:   "https://example.org/a b",
			wantErr: "contains whitespace, a control character, or a backslash",
		},
		{
			name:    "backslash",
			value:   `https://example.org/a\b`,
			wantErr: "contains whitespace, a control character, or a backslash",
		},
		{
			name:    "control character",
			value:   "https://example.org/a\x00b",
			wantErr: "contains whitespace, a control character, or a backslash",
		},
		{
			name:    "user information",
			value:   "https://user@example.org/a",
			wantErr: "opaque URIs, user information, ports, and queries are not allowed",
		},
		{
			name:    "port",
			value:   "https://example.org:8443/a",
			wantErr: "opaque URIs, user information, ports, and queries are not allowed",
		},
		{
			name:    "query",
			value:   "https://example.org/a?b=c",
			wantErr: "opaque URIs, user information, ports, and queries are not allowed",
		},
		{
			name:    "opaque URI",
			value:   "mailto:someone@example.org",
			wantErr: "opaque URIs, user information, ports, and queries are not allowed",
		},
		{
			// Percent-encoded control bytes survive url.Parse and reappear
			// decoded in Path, so the post-parse sweep is what catches them.
			name:    "percent-encoded control character",
			value:   "https://example.org/a%00b",
			wantErr: "contains encoded whitespace or a control character",
		},
		{
			name:    "percent-encoded newline in the fragment",
			value:   "https://example.org/a#b%0Ac",
			wantErr: "contains encoded whitespace or a control character",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := check.LexicalURI(test.value)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected %q, got %v", test.wantErr, err)
			}
		})
	}
}

func TestRepoRelativePath(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "plain path", value: "diagrams/data-flow.md"},
		{
			// Parent segments are deliberately allowed: this tool never
			// opens the path, and sibling documents are a normal target.
			name:  "parent segment",
			value: "../plan.md",
		},
		{name: "blank", value: "  ", wantErr: "expected a non-empty string"},
		{
			name:    "absolute",
			value:   "/etc/passwd",
			wantErr: "expected a relative path",
		},
		{
			name:    "scheme",
			value:   "javascript:alert(1)",
			wantErr: "contains a backslash or a scheme",
		},
		{
			name:    "backslash",
			value:   `diagrams\flow.md`,
			wantErr: "contains a backslash or a scheme",
		},
		{
			name:    "embedded space",
			value:   "diagrams/data flow.md",
			wantErr: "contains whitespace or a control character",
		},
		{
			name:    "control character",
			value:   "diagrams/flow\x1b.md",
			wantErr: "contains whitespace or a control character",
		},
		{
			name:    "line separator",
			value:   "diagrams/flow .md",
			wantErr: "contains whitespace or a control character",
		},
		{
			name:    "oversized",
			value:   strings.Repeat("a", check.MaxStringBytes+1),
			wantErr: "exceeds 16384-byte limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := check.RepoRelativePath(test.value)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected %q, got %v", test.wantErr, err)
			}
		})
	}
}

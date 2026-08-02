package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOptions() Options {
	return Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "matrix.json",
		GeneratorName:     "matrix",
		RegenerateCommand: "matrix render",
		CheckCommand:      "matrix render -check",
	}
}

func TestExecuteRunsRootTemplate(t *testing.T) {
	rendered, err := Execute(
		`{{define "document"}}v {{issueURL "#9"}}{{end}}`,
		testOptions(),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if rendered != "v https://github.com/example/project/issues/9" {
		t.Fatalf("unexpected output %q", rendered)
	}
}

func TestExecuteFailureModes(t *testing.T) {
	t.Run("parse error", func(t *testing.T) {
		if _, err := Execute(`{{define "document"}}{{end`, testOptions(), nil, nil); err == nil {
			t.Fatal("expected template parse error")
		}
	})
	t.Run("missing document define", func(t *testing.T) {
		_, err := Execute(`{{define "other"}}x{{end}}`, testOptions(), nil, nil)
		if err == nil || !strings.Contains(err.Error(), `non-empty "document" template`) {
			t.Fatalf("expected missing-define error, got %v", err)
		}
	})
	t.Run("empty document define", func(t *testing.T) {
		_, err := Execute(`{{define "document"}}  {{end}}`, testOptions(), nil, nil)
		if err == nil || !strings.Contains(err.Error(), `non-empty "document" template`) {
			t.Fatalf("expected empty-define error, got %v", err)
		}
	})
}

func TestReadTemplateBounds(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "big.md.tmpl")
	if err := os.WriteFile(templatePath, make([]byte, MaxTemplateBytes+1), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if _, err := ReadTemplate(templatePath); err == nil ||
		!strings.Contains(err.Error(), "template exceeds") {
		t.Fatalf("expected template-size rejection, got %v", err)
	}
	if _, err := ReadTemplate(filepath.Join(t.TempDir(), "absent.md.tmpl")); err == nil {
		t.Fatal("expected missing-template error")
	}
}

func TestEscapingFunctions(t *testing.T) {
	if got := TableText("a|b*c\nd"); got != `a\|b\*c<br>d` {
		t.Errorf("TableText: got %q", got)
	}
	if got := HTMLText("<b>`x`_y_"); got != "&lt;b&gt;&#96;x&#96;&#95;y&#95;" {
		t.Errorf("HTMLText: got %q", got)
	}
	if got := InlineCode(CodeText("has ` tick|s")); got != "`` has ` tick\\|s ``" {
		t.Errorf("InlineCode: got %q", got)
	}
	if got := InlineValues(nil); got != "None recorded" {
		t.Errorf("InlineValues(nil): got %q", got)
	}
	if got := LinkDestination("a b(c)<d>"); got != "<a b(c)%3Cd%3E>" {
		t.Errorf("LinkDestination: got %q", got)
	}
	if got := LinkLabel("[x]\ny"); got != `\[x\] y` {
		t.Errorf("LinkLabel: got %q", got)
	}
}

// TestLinkDestinationNeutralizesLineBreaks is the regression test for the
// PoC where a newline inside a link destination (reachable via Owner.Issue
// under a permissive consumer issue_pattern) broke CommonMark structure and
// injected a raw Markdown line into the rendered document.
func TestLinkDestinationNeutralizesLineBreaks(t *testing.T) {
	const poc = "https://good.example/9\n# Injected Heading\nmore"
	got := LinkDestination(poc)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("LinkDestination left a raw newline in the result: %q", got)
	}
	for _, want := range []string{"%0A", "# Injected Heading"} {
		if !strings.Contains(got, want) {
			t.Errorf("LinkDestination(%q) = %q, want it to contain %q", poc, got, want)
		}
	}

	t.Run("tab and carriage return", func(t *testing.T) {
		got := LinkDestination("a\tb\rc")
		if strings.ContainsAny(got, "\t\r") {
			t.Fatalf("LinkDestination left a raw tab or CR in the result: %q", got)
		}
		if got != "a%09b%0Dc" {
			t.Errorf("LinkDestination(%q) = %q", "a\tb\rc", got)
		}
	})

	t.Run("newline alone no longer forces the angle-bracket wrapper", func(t *testing.T) {
		got := LinkDestination("a\nb")
		if got != "a%0Ab" {
			t.Errorf("LinkDestination(%q) = %q, want %q", "a\nb", got, "a%0Ab")
		}
	})
}

func TestLinkDestinationEncodesSeparatorsByConstruction(t *testing.T) {
	cases := map[string]string{
		"a\u2028b": "a%E2%80%A8b",
		"a\u2029b": "a%E2%80%A9b",
		"a\u0085b": "a%C2%85b",
		"a\x1bb":   "a%1Bb",
	}
	for input, want := range cases {
		if got := LinkDestination(input); got != want {
			t.Errorf("LinkDestination(%q) = %q, want %q", input, got, want)
		}
	}
}

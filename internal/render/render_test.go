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

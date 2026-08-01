package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofired/reqmatrix/internal/matrix"
	"github.com/sofired/reqmatrix/internal/testsupport"
)

func fixtureOptions() Options {
	return Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "matrix.json",
		GeneratorName:     "reqmatrix",
		RegenerateCommand: "reqmatrix render -config config.json -matrix matrix.json -output matrix.md",
		CheckCommand:      "reqmatrix render -config config.json -matrix matrix.json -output matrix.md -check",
	}
}

func fixtureDocument(t *testing.T) matrix.Document {
	t.Helper()
	doc, err := matrix.Load(testsupport.FixturePath(t, "matrix.json"))
	if err != nil {
		t.Fatalf("load fixture matrix: %v", err)
	}
	return doc
}

func requirementByID(t *testing.T, doc *matrix.Document, id string) *matrix.Requirement {
	t.Helper()
	for index := range doc.Requirements {
		if doc.Requirements[index].ID == id {
			return &doc.Requirements[index]
		}
	}
	t.Fatalf("requirement %s not found", id)
	return nil
}

func TestGoldenRendering(t *testing.T) {
	golden, err := os.ReadFile(testsupport.FixturePath(t, "matrix.md"))
	if err != nil {
		t.Fatalf("read golden Markdown: %v", err)
	}
	rendered, err := Document(fixtureDocument(t), fixtureOptions())
	if err != nil {
		t.Fatalf("render matrix: %v", err)
	}
	if rendered != string(golden) {
		t.Fatal("golden Markdown is stale; regenerate testdata/matrix.md")
	}
}

func TestRenderingEscapesUntrustedContent(t *testing.T) {
	doc := fixtureDocument(t)
	item := &doc.Requirements[0]
	item.Title = "<img src=x onerror=alert(1)> *bold* _em_ [link](bad) | tail"
	item.Interpretation = "Reject <unsafe> & *ambiguous* `input` [link](bad)."
	item.Citations[0].Clause = "section [x] *bold* <tag>"
	item.PlannedVerification.Evidence[0] = "first_line\n<script>alert(1)</script>"
	item.Traceability.ADRs = []string{"ADR-`1`", "ADR-A&B <C>"}
	doc.Standards[0].Title = "Standard <script> *bold*"
	deferred := requirementByID(t, &doc, "EXCORE-002")
	deferred.ApplicabilityRationale = "No <raw> *formatting* [link](bad) | escape."

	rendered, err := Document(doc, fixtureOptions())
	if err != nil {
		t.Fatalf("render edge cases: %v", err)
	}
	for _, want := range []string{
		`&lt;img src=x onerror=alert(1)&gt; \*bold\* \_em\_ \[link\](bad) \| tail`,
		"Reject &lt;unsafe&gt; &amp; \\*ambiguous\\* \\`input\\` \\[link\\](bad).",
		`section \[x\] \*bold\* &lt;tag&gt;`,
		"first\\_line<br>&lt;script&gt;alert(1)&lt;/script&gt;",
		"Standard &lt;script&gt; \\*bold\\*",
		"No &lt;raw&gt; \\*formatting\\* \\[link\\](bad) \\| escape.",
		"`` ADR-`1` ``",
		"`ADR-A&B <C>`",
		"<details>",
		"<br>",
		"## Ownership index",
		"https://github.com/example/project/issues/10",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered Markdown does not contain %q", want)
		}
	}
	for _, unsafe := range []string{"<script>", "<img src=x", "[link](bad)"} {
		if strings.Contains(rendered, unsafe) {
			t.Errorf("rendered Markdown contains unsafe source text %q", unsafe)
		}
	}
}

func TestOwnershipIndex(t *testing.T) {
	doc := fixtureDocument(t)
	sections := newView(doc, fixtureOptions()).Ownership
	indexed := 0
	anchors := make(map[string]struct{}, len(sections))
	for _, section := range sections {
		indexed += len(section.Requirements)
		if _, exists := anchors[section.Anchor]; exists {
			t.Fatalf("duplicate ownership anchor %q", section.Anchor)
		}
		anchors[section.Anchor] = struct{}{}
	}
	if indexed != len(doc.Requirements) {
		t.Fatalf("indexed %d of %d requirements", indexed, len(doc.Requirements))
	}
	if len(sections) < 2 ||
		sections[0].Milestone != "M0" ||
		sections[len(sections)-1].Milestone != "M10" {
		t.Fatalf("unexpected milestone ordering: %#v", sections)
	}
}

func TestConsumerTemplateOverride(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "custom.md.tmpl")
	template := `{{define "matrix"}}custom {{.Document.MatrixVersion}} {{issueURL "#9"}}{{end}}`
	if err := os.WriteFile(templatePath, []byte(template), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	options := fixtureOptions()
	options.TemplatePath = templatePath
	rendered, err := Document(fixtureDocument(t), options)
	if err != nil {
		t.Fatalf("render with consumer template: %v", err)
	}
	want := "custom 0.2.0 https://github.com/example/project/issues/9"
	if rendered != want {
		t.Fatalf("expected %q, got %q", want, rendered)
	}
}

func TestOversizedTemplateIsRejected(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "big.md.tmpl")
	if err := os.WriteFile(templatePath, make([]byte, MaxTemplateBytes+1), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	options := fixtureOptions()
	options.TemplatePath = templatePath
	if _, err := Document(fixtureDocument(t), options); err == nil ||
		!strings.Contains(err.Error(), "template exceeds") {
		t.Fatalf("expected template-size rejection, got %v", err)
	}
}

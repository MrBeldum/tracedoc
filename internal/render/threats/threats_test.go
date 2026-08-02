package threats

import (
	"os"
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/render"
	"github.com/sofired/matrix-service/internal/testsupport"
	threatsdoc "github.com/sofired/matrix-service/internal/threats"
)

func fixtureOptions() render.Options {
	return render.Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "threats.json",
		GeneratorName:     "matrix",
		RegenerateCommand: "matrix render -config config.json -doc threats.json -output threats.md",
		CheckCommand:      "matrix render -config config.json -doc threats.json -output threats.md -check",
	}
}

func fixtureDocument(t *testing.T) threatsdoc.Document {
	t.Helper()
	doc, err := threatsdoc.Load(testsupport.FixturePath(t, "threats.json"))
	if err != nil {
		t.Fatalf("load fixture threat model: %v", err)
	}
	return doc
}

func TestGoldenRendering(t *testing.T) {
	golden, err := os.ReadFile(testsupport.FixturePath(t, "threats.md"))
	if err != nil {
		t.Fatalf("read golden Markdown: %v", err)
	}
	rendered, err := Render(fixtureDocument(t), fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render threat model: %v", err)
	}
	if rendered != string(golden) {
		t.Fatal("golden Markdown is stale; regenerate testdata/threats.md")
	}
}

func TestRenderingEscapesUntrustedContent(t *testing.T) {
	doc := fixtureDocument(t)
	item := &doc.Threats[0]
	item.Title = "<img src=x onerror=alert(1)> *bold* [link](bad) | tail"
	item.Description = "Reject <unsafe> & *ambiguous* `input`."
	item.DispositionRationale = ""
	item.Owner.Milestone = "M1`*|x"
	issue := `#36"><script>alert(1)</script>`
	item.Owner.Issue = &issue
	item.Mitigations.Tests = []string{"suite `x`|y"}
	doc.Assets[0].Name = "Asset <script> *bold*"
	doc.Assets[0].Description = "Holds [secrets](bad) | material."
	doc.TrustBoundaries[0].Name = "Boundary _em_ <tag>"

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render edge cases: %v", err)
	}
	for _, want := range []string{
		`&lt;img src=x onerror=alert(1)&gt; \*bold\* \[link\](bad) \| tail`,
		"Reject &lt;unsafe&gt; &amp; \\*ambiguous\\* \\`input\\`.",
		"Asset &lt;script&gt; &#42;bold&#42;",
		`Holds \[secrets\](bad) \| material.`,
		"Boundary &#95;em&#95; &lt;tag&gt;",
		"`` suite `x`\\|y ``",
		// Owner fields render as escaped table text (backslash-escaped
		// Markdown, then HTML entities).
		"M1\\`\\*\\|x",
		`#36&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`,
		"## Trust boundary index",
		"## Asset index",
		"## Severity: critical",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered Markdown does not contain %q", want)
		}
	}
	for _, unsafe := range []string{"<script>", "<img src=x", "[link](bad)", "[secrets](bad)"} {
		if strings.Contains(rendered, unsafe) {
			t.Errorf("rendered Markdown contains unsafe source text %q", unsafe)
		}
	}
}

// TestRenderRejectsUnvalidatedDocument is the regression test companion to
// the requirements-renderer panic: the threats renderer only survived a nil
// Owner by accident, because text/template recovers panics raised inside
// template funcs into errors. Render must report a descriptive error
// directly, independent of that incidental protection.
func TestRenderRejectsUnvalidatedDocument(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*threatsdoc.Document)
		want   string
	}{
		{
			name:   "nil owner",
			mutate: func(doc *threatsdoc.Document) { doc.Threats[0].Owner = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil mitigations",
			mutate: func(doc *threatsdoc.Document) { doc.Threats[0].Mitigations = nil },
			want:   "must pass validation",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Render panicked on an unvalidated document: %v", r)
				}
			}()
			_, err := Render(doc, fixtureOptions(), "")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

// TestWithdrawalRendering mirrors the requirements-renderer coverage: a
// supersession with an explicitly empty replacement set (a withdrawal) must
// render as "Withdrawn without successor" rather than an empty cell.
func TestWithdrawalRendering(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Supersessions = append(doc.Supersessions, threatsdoc.Supersession{
		RetiredID:      "THRT-901",
		ReplacementIDs: []string{},
		Rationale:      "Withdrawn after the affected surface was removed.",
	})
	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render withdrawal: %v", err)
	}
	if !strings.Contains(rendered, "| `THRT-901` | Withdrawn without successor |") {
		t.Fatal("withdrawal row not rendered as expected")
	}
}

// TestConsumerTemplateOverride mirrors the requirements-renderer coverage:
// Render must use a non-empty templateText argument instead of the embedded
// default template, and the "issueURL" template function must be available
// to it.
func TestConsumerTemplateOverride(t *testing.T) {
	template := `{{define "document"}}custom {{.Document.DocumentVersion}} {{issueURL "#9"}}{{end}}`
	rendered, err := Render(fixtureDocument(t), fixtureOptions(), template)
	if err != nil {
		t.Fatalf("render with consumer template: %v", err)
	}
	want := "custom 0.1.0 https://github.com/example/project/issues/9"
	if rendered != want {
		t.Fatalf("expected %q, got %q", want, rendered)
	}
}

// TestRenderingIsDeterministic guards against the view construction's
// intermediate maps (threatsByAsset, threatsByBoundary, threatsBySeverity)
// leaking Go's randomized map-iteration order into the rendered output.
func TestRenderingIsDeterministic(t *testing.T) {
	first, err := Render(fixtureDocument(t), fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render first pass: %v", err)
	}
	second, err := Render(fixtureDocument(t), fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render second pass: %v", err)
	}
	if first != second {
		t.Fatal("rendering the same document twice produced different output")
	}
}

func TestViewGrouping(t *testing.T) {
	doc := fixtureDocument(t)
	view := newView(doc, fixtureOptions())
	if len(view.SeverityCounts) != 4 {
		t.Fatalf("expected all severities counted, got %#v", view.SeverityCounts)
	}
	if len(view.SeveritySections) != 3 {
		t.Fatalf("expected three populated severity sections, got %d", len(view.SeveritySections))
	}
	if view.SeveritySections[0].Severity != "critical" || !view.SeveritySections[0].First {
		t.Fatalf("unexpected first severity section: %#v", view.SeveritySections[0])
	}
	if len(view.Boundaries) != 1 || len(view.Boundaries[0].Threats) != 2 {
		t.Fatalf("unexpected boundary grouping: %#v", view.Boundaries)
	}
	if len(view.Assets) != 2 || len(view.Assets[0].Threats) != 2 {
		t.Fatalf("unexpected asset grouping: %#v", view.Assets)
	}
}

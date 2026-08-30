package threats

import (
	"os"
	"strings"
	"testing"

	"github.com/sofired/tracedoc/internal/render"
	"github.com/sofired/tracedoc/internal/testsupport"
	threatsdoc "github.com/sofired/tracedoc/internal/threats"
)

func fixtureOptions() render.Options {
	return render.Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "threats.json",
		GeneratorName:     "tracedoc",
		RegenerateCommand: "tracedoc render -config config.json -doc threats.json -output threats.md",
		CheckCommand:      "tracedoc render -config config.json -doc threats.json -output threats.md -check",
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
	item.Impact = "Reject <unsafe> & *ambiguous* `input`."
	item.AbusePath = []string{"Step <one> | *two*"}
	item.Owner.Milestone = "M1`*|x"
	issue := `#36"><script>alert(1)</script>`
	item.Owner.Issue = &issue
	doc.Assets[0].Name = "Asset <script> *bold*"
	doc.Assets[0].Description = "Holds [secrets](bad) | material."
	doc.TrustBoundaries[0].Name = "Boundary _em_ <tag>"
	doc.Controls[0].Title = "Control | `pipe`"
	doc.Observability[0].Redaction = []string{"Never log <secrets> | tokens."}
	doc.Summary = "Summary with <tags> & *marks*."

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render edge cases: %v", err)
	}
	for _, want := range []string{
		`&lt;img src=x onerror=alert(1)&gt; \*bold\* \[link\](bad) \| tail`,
		"Reject &lt;unsafe&gt; &amp; \\*ambiguous\\* \\`input\\`.",
		`Step &lt;one&gt; \| \*two\*`,
		"Asset &lt;script&gt; &#42;bold&#42;",
		`Holds \[secrets\](bad) \| material.`,
		"Boundary &#95;em&#95; &lt;tag&gt;",
		"Control \\| \\`pipe\\`",
		`Never log &lt;secrets&gt; \| tokens.`,
		`Summary with &lt;tags&gt; &amp; \*marks\*.`,
		// Owner fields render as escaped table text (backslash-escaped
		// Markdown, then HTML entities).
		"M1\\`\\*\\|x",
		`#36&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`,
		"## Trust boundaries",
		"## Assets",
		"## Entry points",
		"## Controls",
		"## Priority: critical",
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

// TestDiagramReferencesAreEscaped covers the destination half of a
// reference: a caption is prose, but the target lands in a Markdown link
// destination, where a space or parenthesis would otherwise break the link
// structure.
func TestDiagramReferencesAreEscaped(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Diagrams[0].Caption = "Overview <tag> | *bold*"
	doc.Diagrams[0].Path = "diagrams/data flow (v2).md"

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render diagram references: %v", err)
	}
	if !strings.Contains(rendered, "<diagrams/data flow (v2).md>") {
		t.Error("diagram destination with spaces and parentheses is not wrapped")
	}
	if !strings.Contains(rendered, `Overview &lt;tag&gt; \| \*bold\*`) {
		t.Error("diagram caption is not escaped")
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
			name:   "nil control owner",
			mutate: func(doc *threatsdoc.Document) { doc.Controls[0].Owner = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil evidence owner",
			mutate: func(doc *threatsdoc.Document) { doc.PlannedEvidence[0].Owner = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil scope",
			mutate: func(doc *threatsdoc.Document) { doc.Scope = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil attacker model",
			mutate: func(doc *threatsdoc.Document) { doc.AttackerModel = nil },
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
// intermediate maps (threats by asset, boundary, flow, control, risk and
// priority) leaking Go's randomized map-iteration order into the rendered
// output.
func TestRenderingIsDeterministic(t *testing.T) {
	// Twenty passes shrink the chance that randomized map iteration
	// happens to coincide, which a two-pass comparison could miss.
	first, err := Render(fixtureDocument(t), fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render first pass: %v", err)
	}
	for pass := 0; pass < 19; pass++ {
		next, err := Render(fixtureDocument(t), fixtureOptions(), "")
		if err != nil {
			t.Fatalf("render pass %d: %v", pass+2, err)
		}
		if next != first {
			t.Fatalf("render pass %d differed from the first", pass+2)
		}
	}
}

func TestViewGrouping(t *testing.T) {
	doc := fixtureDocument(t)
	view := newView(doc, fixtureOptions())
	if len(view.PriorityCounts) != 4 {
		t.Fatalf("expected all priorities counted, got %#v", view.PriorityCounts)
	}
	if len(view.Sections) != 3 {
		t.Fatalf("expected three populated priority sections, got %d", len(view.Sections))
	}
	if view.Sections[0].Priority != "critical" || !view.Sections[0].First {
		t.Fatalf("unexpected first priority section: %#v", view.Sections[0])
	}
	if len(view.Boundaries) != 2 || len(view.Boundaries[0].Threats) != 2 {
		t.Fatalf("unexpected boundary grouping: %#v", view.Boundaries)
	}
	if len(view.Assets) != 2 || len(view.Assets[0].Threats) != 2 {
		t.Fatalf("unexpected asset grouping: %#v", view.Assets)
	}
	if len(view.Flows) != 2 || len(view.Flows[0].Threats) != 2 {
		t.Fatalf("unexpected flow grouping: %#v", view.Flows)
	}
	if len(view.EntryPoints) != 2 || len(view.EntryPoints[0].Threats) != 2 {
		t.Fatalf("unexpected entry-point grouping: %#v", view.EntryPoints)
	}
}

// TestReverseTraceabilityGrouping covers the links the view derives rather
// than reads: a decision, risk, or planned-evidence record is reviewed
// through the controls that cite it, which only the view computes.
func TestReverseTraceabilityGrouping(t *testing.T) {
	view := newView(fixtureDocument(t), fixtureOptions())

	if len(view.Controls) != 2 || len(view.Controls[0].Threats) != 1 {
		t.Fatalf("unexpected control grouping: %#v", view.Controls)
	}
	// ADR-102 is cited by CTRL-002; ADR-101 is cited by nothing.
	if len(view.Decisions) != 2 {
		t.Fatalf("unexpected decision count: %#v", view.Decisions)
	}
	if len(view.Decisions[0].Controls) != 0 {
		t.Errorf("ADR-101 should have no citing control, got %#v", view.Decisions[0].Controls)
	}
	if len(view.Decisions[1].Controls) != 1 || view.Decisions[1].Controls[0] != "CTRL-002" {
		t.Errorf("ADR-102 should be cited by CTRL-002, got %#v", view.Decisions[1].Controls)
	}
	if len(view.Evidence) != 2 || len(view.Evidence[0].Controls) != 1 {
		t.Fatalf("unexpected evidence grouping: %#v", view.Evidence)
	}
	if len(view.Risks) != 2 || len(view.Risks[0].Threats) != 1 {
		t.Fatalf("unexpected risk grouping: %#v", view.Risks)
	}
}

// TestReferenceTargetPrefersPath asserts the single-destination collapse a
// validated document guarantees: exactly one member is ever set.
func TestReferenceTargetPrefersPath(t *testing.T) {
	if got := referenceTarget(threatsdoc.Reference{Path: "a.md"}); got != "a.md" {
		t.Errorf("path reference: got %q", got)
	}
	if got := referenceTarget(threatsdoc.Reference{URL: "https://example.org/a"}); got != "https://example.org/a" {
		t.Errorf("url reference: got %q", got)
	}
}

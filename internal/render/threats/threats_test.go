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

// TestRiskIDsAreEscaped is a security regression test. Every other
// identifier this template emits bare is schema-owned with a character
// class that cannot carry Markdown structure. Risk IDs are the exception:
// they follow the consumer-supplied risk_pattern, which validation treats
// as policy rather than a lexical safety net, so a permissive pattern
// admits Markdown metacharacters. Emitting one bare inside a code span let
// it close the span, inject extra pipe-delimited cells, and — defeating the
// point of the reference_hosts allowlist — inject a link to an arbitrary
// destination through a field that is not a reference at all.
func TestRiskIDsAreEscaped(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Risks[0].ID = "R1` | **INJECTED** | [pwn](https://evil.example/x) | y"

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render risk identifiers: %v", err)
	}

	var row string
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, "INJECTED") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("risk row not found in rendered output")
	}

	// The hostile value must sit inside one widened code fence. Asserting
	// its absence would be wrong: the text is still there, it is simply
	// inert as code-span content.
	const fenced = "`` R1` \\| **INJECTED** \\| [pwn](https://evil.example/x) \\| y ``"
	if !strings.Contains(row, fenced) {
		t.Errorf("risk ID is not emitted as a single widened code span:\n%s", row)
	}
	// Row structure must survive: five columns, so six unescaped pipes. An
	// injected pipe would shift every later cell into the wrong column.
	if pipes := strings.Count(row, "|") - strings.Count(row, `\|`); pipes != 6 {
		t.Errorf("risk row has %d unescaped pipes, want 6:\n%s", pipes, row)
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
	if len(view.Assets) != 3 || len(view.Assets[0].Threats) != 2 {
		t.Fatalf("unexpected asset grouping: %#v", view.Assets)
	}
	if len(view.Flows) != 3 || len(view.Flows[0].Threats) != 1 {
		t.Fatalf("unexpected flow grouping: %#v", view.Flows)
	}
	if len(view.EntryPoints) != 3 || len(view.EntryPoints[0].Threats) != 1 {
		t.Fatalf("unexpected entry-point grouping: %#v", view.EntryPoints)
	}

	// EP-001 and EP-003 sit on one boundary and differ only by flow, so
	// they separate exactly when the entry-point rule reads both halves.
	// Grouping them by boundary alone would credit each with both threats.
	for _, want := range []struct{ entryPoint, threat string }{
		{"EP-001", "THRT-001"},
		{"EP-003", "THRT-003"},
	} {
		var got []string
		for _, section := range view.EntryPoints {
			if section.ID != want.entryPoint {
				continue
			}
			for _, threat := range section.Threats {
				got = append(got, threat.ID)
			}
		}
		if len(got) != 1 || got[0] != want.threat {
			t.Errorf("%s should group %s alone, got %v", want.entryPoint, want.threat, got)
		}
	}
}

// TestReverseTraceabilityGrouping covers the links the view derives rather
// than reads: a decision, risk, or planned-evidence record is reviewed
// through the controls that cite it, which only the view computes.
func TestReverseTraceabilityGrouping(t *testing.T) {
	view := newView(fixtureDocument(t), fixtureOptions())

	if len(view.Controls) != 3 || len(view.Controls[0].Threats) != 1 {
		t.Fatalf("unexpected control grouping: %#v", view.Controls)
	}
	// ADR-101 is cited by CTRL-003; ADR-102 by CTRL-002.
	if len(view.Decisions) != 2 {
		t.Fatalf("unexpected decision count: %#v", view.Decisions)
	}
	if len(view.Decisions[0].Controls) != 1 || view.Decisions[0].Controls[0] != "CTRL-003" {
		t.Errorf("ADR-101 should be cited by CTRL-003, got %#v", view.Decisions[0].Controls)
	}
	if len(view.Decisions[1].Controls) != 1 || view.Decisions[1].Controls[0] != "CTRL-002" {
		t.Errorf("ADR-102 should be cited by CTRL-002, got %#v", view.Decisions[1].Controls)
	}
	if len(view.Evidence) != 3 || len(view.Evidence[0].Controls) != 1 {
		t.Fatalf("unexpected evidence grouping: %#v", view.Evidence)
	}
	if len(view.Risks) != 2 || len(view.Risks[0].Threats) != 1 {
		t.Fatalf("unexpected risk grouping: %#v", view.Risks)
	}

	// Every fixture decision is now cited, so the uncited case is exercised
	// here rather than left to the fixture: a record no control references
	// must group to an empty list, never to a nil the template would range
	// over differently.
	uncited := fixtureDocument(t)
	for i := range uncited.Controls {
		uncited.Controls[i].DecisionLinks = nil
	}
	for _, decision := range newView(uncited, fixtureOptions()).Decisions {
		if len(decision.Controls) != 0 {
			t.Errorf("decision %s should have no citing control, got %#v",
				decision.ID, decision.Controls)
		}
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

// TestEveryDeclaredEntityIsAnchored pins the guarantee docs/schema-threat-model.md
// states and that document-wide identifier uniqueness exists to protect: the
// companion anchors every declared entity in one namespace. The rule was
// documented while seven collections went unanchored, so the claim is asserted
// here rather than left to review. A collection added to the schema without an
// anchor fails this test as soon as the fixture declares one.
func TestEveryDeclaredEntityIsAnchored(t *testing.T) {
	doc := fixtureDocument(t)

	ids := map[string]string{}
	add := func(collection, id string) {
		ids[id] = collection
	}
	for _, item := range doc.Assumptions {
		add("assumptions", item.ID)
	}
	for _, item := range doc.Components {
		add("components", item.ID)
	}
	for _, item := range doc.Actors {
		add("actors", item.ID)
	}
	for _, item := range doc.Assets {
		add("assets", item.ID)
	}
	for _, item := range doc.TrustBoundaries {
		add("trust_boundaries", item.ID)
	}
	for _, item := range doc.DataFlows {
		add("data_flows", item.ID)
	}
	for _, item := range doc.EntryPoints {
		add("entry_points", item.ID)
	}
	for _, item := range doc.Decisions {
		add("decisions", item.ID)
	}
	for _, item := range doc.Risks {
		add("risks", item.ID)
	}
	for _, item := range doc.Controls {
		add("controls", item.ID)
	}
	for _, item := range doc.PlannedEvidence {
		add("planned_evidence", item.ID)
	}
	for _, item := range doc.Observability {
		add("observability", item.ID)
	}
	for _, item := range doc.Threats {
		add("threats", item.ID)
	}

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render threat model: %v", err)
	}

	// The fixture is the consumer-neutral document that exercises every
	// record type, so an unpopulated collection means the fixture regressed,
	// not that the collection is exempt.
	const collections = 13
	if seen := len(collectionsOf(ids)); seen != collections {
		t.Fatalf("fixture declares %d collections, want %d", seen, collections)
	}

	for id, collection := range ids {
		anchor := `<a id="` + strings.ToLower(id) + `"></a>`
		if !strings.Contains(rendered, anchor) {
			t.Errorf("%s ID %q is not anchored in the rendered companion", collection, id)
		}
	}
}

func collectionsOf(ids map[string]string) map[string]struct{} {
	seen := map[string]struct{}{}
	for _, collection := range ids {
		seen[collection] = struct{}{}
	}
	return seen
}

// TestRiskIDAnchorsAreEscaped covers the sink anchoring the risk collection
// introduced. Risk IDs are the one identifier format the consumer's own
// pattern defines, so anchoring them puts consumer-controlled text inside an
// HTML attribute; the pattern is checked for anchoring and length only, so it
// can admit a quote. Escaping keeps the value inside the attribute it was
// written into.
func TestRiskIDAnchorsAreEscaped(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Risks[0].ID = `R1"><script>alert(1)</script><a x="`

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render risk identifiers: %v", err)
	}

	// The ID also appears in the row as a code span, where the raw markup is
	// inert and already covered by TestRiskIDsAreEscaped. What must not exist
	// is the attribute closing early and the rest becoming live markup.
	if strings.Contains(rendered, `<a id="r1">`) {
		t.Error("hostile risk ID closed its anchor attribute early")
	}
	const anchor = `<a id="r1&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;a x=&#34;"></a>`
	if !strings.Contains(rendered, anchor) {
		t.Errorf("risk anchor is not escaped as expected; rendered:\n%s", rendered)
	}
}

// TestReviewGuidanceRendering covers the three collections that exist to
// help a reader navigate the model rather than to describe the system: the
// priority calibration, the curated headline list, and the reading list.
// Each resolves identifiers the renderer must not reorder.
func TestReviewGuidanceRendering(t *testing.T) {
	doc := fixtureDocument(t)
	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render review guidance: %v", err)
	}

	for _, want := range []string{
		"## Priority calibration",
		"## Start here",
		"## Where to look",
		// Calibration is emitted in the schema's priority order, not the
		// document's, so a reader always sees the scale top-down.
		"**`critical`**",
		"**`low`**",
		// The headline list keeps document order and resolves to titles.
		"1. [`THRT-001`](#thrt-001)",
		"2. [`THRT-002`](#thrt-002)",
		// A focus path renders its own threat links.
		"`diagrams/data-flow.md`",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered Markdown does not contain %q", want)
		}
	}
}

// TestReviewGuidanceEscaping keeps the new sections inside the same
// injection guarantees as the rest of the document. A focus path is
// consumer-authored free text emitted into a table cell and an inline code
// span, and a calibration definition is prose.
func TestReviewGuidanceEscaping(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Criticality[0].Definition = "Compromise <script> of *everything* | totally"
	doc.Criticality[0].Examples = []string{"Example with `backticks` and | a pipe"}
	doc.FocusPaths[0].Why = "Read <this> first | before anything else"
	doc.FocusPaths[0].Path = "docs/a|b.md"

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render hostile review guidance: %v", err)
	}
	for _, unsafe := range []string{"<script>", "*everything*"} {
		if strings.Contains(rendered, unsafe) {
			t.Errorf("rendered Markdown contains unescaped content %q", unsafe)
		}
	}
	// A pipe inside a focus path must not add a column to its row.
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, "docs/a") && strings.HasPrefix(line, "|") {
			if pipes := strings.Count(line, "|") - strings.Count(line, `\|`); pipes != 4 {
				t.Errorf("focus-path row has %d unescaped pipes, want 4:\n%s", pipes, line)
			}
		}
	}
}

// TestEmptyReviewGuidanceRenders covers the empty case for all three: they
// are optional collections, and an empty one must say so rather than leave
// a bare heading a reader cannot interpret.
func TestEmptyReviewGuidanceRenders(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Criticality = nil
	doc.TopAbusePaths = nil
	doc.FocusPaths = nil

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render empty review guidance: %v", err)
	}
	for _, want := range []string{
		"No priority calibration recorded.",
		"No headline abuse paths recorded.",
		"No focus paths recorded.",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered Markdown does not contain %q", want)
		}
	}
}

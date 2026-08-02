package requirements

import (
	"os"
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/render"
	"github.com/sofired/matrix-service/internal/testsupport"
)

func fixtureOptions() render.Options {
	return render.Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "matrix.json",
		GeneratorName:     "matrix",
		RegenerateCommand: "matrix render -config config.json -doc matrix.json -output matrix.md",
		CheckCommand:      "matrix render -config config.json -doc matrix.json -output matrix.md -check",
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
	rendered, err := Render(fixtureDocument(t), fixtureOptions(), "")
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

	rendered, err := Render(doc, fixtureOptions(), "")
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

func TestOwnershipIndexEscapesUntrustedContent(t *testing.T) {
	doc := fixtureDocument(t)
	item := &doc.Requirements[0]
	item.Owner.Milestone = "M1`*|x"
	issue := `#36"><script>alert(1)</script>`
	item.Owner.Issue = &issue

	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render hostile owner fields: %v", err)
	}
	for _, want := range []string{
		// Table cell: backtick-safe inline code with the pipe neutralized.
		"`` M1`*\\|x ``",
		// Summary line: HTML-entity escaping of the milestone.
		"M1&#96;&#42;&#124;x",
		// HTML href attribute: quote and angle brackets entity-escaped.
		`issues/36&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`,
		// Markdown link destination: angle brackets percent-encoded.
		"%3Cscript%3E",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered Markdown does not contain %q", want)
		}
	}
	if strings.Contains(rendered, `"><script>alert(1)</script>`) {
		t.Error("rendered Markdown contains an unescaped attribute breakout")
	}
}

func TestWithdrawalRendering(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Supersessions = append(doc.Supersessions, matrix.Supersession{
		RetiredID:      "EXCORE-901",
		ReplacementIDs: []string{},
		Rationale:      "Withdrawn after the upstream draft was abandoned.",
	})
	rendered, err := Render(doc, fixtureOptions(), "")
	if err != nil {
		t.Fatalf("render withdrawal: %v", err)
	}
	if !strings.Contains(rendered, "| `EXCORE-901` | Withdrawn without successor |") {
		t.Fatal("withdrawal row not rendered as expected")
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

// TestRenderRejectsUnvalidatedDocument is the regression test for the
// panic that newView used to raise when Render was called on a document
// that had not passed matrix.Validate: item.Owner (and, symmetrically,
// PlannedVerification and Traceability) were dereferenced with no nil
// guard. Render must now report a descriptive error instead of panicking.
func TestRenderRejectsUnvalidatedDocument(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*matrix.Document)
		want   string
	}{
		{
			name:   "nil owner",
			mutate: func(doc *matrix.Document) { doc.Requirements[0].Owner = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil planned verification",
			mutate: func(doc *matrix.Document) { doc.Requirements[0].PlannedVerification = nil },
			want:   "must pass validation",
		},
		{
			name:   "nil traceability",
			mutate: func(doc *matrix.Document) { doc.Requirements[0].Traceability = nil },
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

func TestConsumerTemplateOverride(t *testing.T) {
	template := `{{define "document"}}custom {{.Document.DocumentVersion}} {{issueURL "#9"}}{{end}}`
	rendered, err := Render(fixtureDocument(t), fixtureOptions(), template)
	if err != nil {
		t.Fatalf("render with consumer template: %v", err)
	}
	want := "custom 0.2.0 https://github.com/example/project/issues/9"
	if rendered != want {
		t.Fatalf("expected %q, got %q", want, rendered)
	}
}

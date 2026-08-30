package render

import (
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func testOptions() Options {
	return Options{
		IssueURLBase:      "https://github.com/example/project/issues/",
		SourceName:        "matrix.json",
		GeneratorName:     "tracedoc",
		RegenerateCommand: "tracedoc render",
		CheckCommand:      "tracedoc render -check",
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

// TestEscapersNeutralizeInvisibleRunes pins the by-construction defense
// shared by every escaping function: control runes, line/paragraph
// separators, and bidirectional overrides never survive into rendered
// output, whichever context a document field is emitted in.
func TestEscapersNeutralizeInvisibleRunes(t *testing.T) {
	hazards := map[string]string{
		"escape":         "ADR-001\x1bFAKE",
		"nul":            "ADR-001\x00hidden",
		"line separator": "ADR-001\u2028injected",
		"nel":            "ADR-001\u0085injected",
		"rtl override":   "ADR-001\u202Ereversed",
		"isolate":        "ADR-001\u2066isolated",
	}
	for name, value := range hazards {
		for fnName, fn := range map[string]func(string) string{
			"CodeText":  CodeText,
			"ProseText": ProseText,
			"TableText": TableText,
			"LinkLabel": LinkLabel,
			"HTMLText":  HTMLText,
		} {
			got := fn(value)
			for _, bad := range []rune{'\x1b', '\x00', '\u2028', '\u0085', '\u202E', '\u2066'} {
				if strings.ContainsRune(got, bad) {
					t.Errorf("%s(%s): %q retained %U", fnName, name, got, bad)
				}
			}
			if !strings.Contains(got, "ADR-001") {
				t.Errorf("%s(%s): visible text lost from %q", fnName, name, got)
			}
		}
		if encoded := LinkDestination(value); strings.ContainsAny(encoded, "\x1b\x00") ||
			strings.ContainsRune(encoded, '\u2028') || strings.ContainsRune(encoded, '\u202E') {
			t.Errorf("LinkDestination(%s) retained an invisible rune: %q", name, encoded)
		}
	}

	// InlineValues is the path every identifier list renders through.
	if got := InlineValues([]string{"ADR-001\x1b[31mFAKE"}); strings.ContainsRune(got, '\x1b') {
		t.Errorf("InlineValues retained an escape byte: %q", got)
	}
}

// TestAnchorPairAgrees covers the invariant that makes a same-document link
// resolve: the destination AnchorHref writes must address the id AnchorID
// writes for the same identifier. The two escape for different contexts — an
// HTML attribute and a Markdown destination — so agreement is a property to
// assert, not something the shared input guarantees. A fragment is
// percent-decoded and an attribute value HTML-decoded before the browser
// compares them, so decoding both is what the comparison must model.
func TestAnchorPairAgrees(t *testing.T) {
	ids := []string{
		"THRT-001",
		"CTRL-001",
		"R1",
		// Risk IDs follow the consumer's pattern, which is checked only for
		// anchoring and length. Each of these terminates one of the two
		// contexts if it reaches it unescaped.
		`R1)`,
		`R1 2`,
		`R1"`,
		`R1<a>`,
		`R1&amp;`,
		`R1%29`,
	}
	// A Markdown inline destination ends at a parenthesis or a space, so
	// agreement after decoding is not enough on its own: a raw ")" would
	// decode equal and still truncate the link. Both halves are asserted.
	safe := regexp.MustCompile(`^[A-Za-z0-9\-._~%]*$`)

	for _, id := range ids {
		href := AnchorHref(id)
		if !safe.MatchString(href) {
			t.Errorf("%q: destination %q carries a character that ends a Markdown destination",
				id, href)
		}
		attribute := html.UnescapeString(AnchorID(id))
		destination, err := url.PathUnescape(href)
		if err != nil {
			t.Errorf("%q: destination is not decodable: %v", id, err)
			continue
		}
		if attribute != destination {
			t.Errorf("%q: anchor %q and destination %q do not address the same target",
				id, attribute, destination)
		}
	}
}

// TestAnchorHrefLeavesSchemaOwnedIDsIntact pins that percent-encoding costs
// nothing for the identifiers the schema actually owns: those are the ones a
// reviewer reads and shares, and an encoded destination for THRT-001 would be
// a regression in the rendered companion for no safety gain.
func TestAnchorHrefLeavesSchemaOwnedIDsIntact(t *testing.T) {
	for _, id := range []string{"THRT-001", "AST-001", "TB-001", "ADR-102", "OBS-001"} {
		want := strings.ToLower(id)
		if got := AnchorHref(id); got != want {
			t.Errorf("AnchorHref(%q) = %q, want %q", id, got, want)
		}
	}
}

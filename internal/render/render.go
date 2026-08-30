// Package render is the document-type-neutral Markdown rendering engine:
// the escaping template functions, the template execution contract (a
// "document" root template), and the consumer template-override bounds.
// Per-document-type views and default templates live in subpackages.
package render

import (
	"bytes"
	"fmt"
	"html"
	"os"
	"strings"
	"text/template"
	"text/template/parse"
	"unicode"
)

// MaxTemplateBytes bounds the size of a consumer-supplied template file.
const MaxTemplateBytes = 1 << 20

// RootTemplate is the template name every document template must define.
const RootTemplate = "document"

// Options are the consumer presentation choices the templates receive.
type Options struct {
	IssueURLBase      string
	SourceName        string
	GeneratorName     string
	RegenerateCommand string
	CheckCommand      string
}

// ReadTemplate loads a consumer template file under the size bound.
func ReadTemplate(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) > MaxTemplateBytes {
		return "", fmt.Errorf("template exceeds %d-byte limit", MaxTemplateBytes)
	}
	return string(data), nil
}

// Execute renders data through the template text. The text must define a
// non-empty "document" template; extra supplies document-type-specific
// template functions (for example "owner").
func Execute(
	text string,
	options Options,
	extra template.FuncMap,
	data any,
) (string, error) {
	funcs := templateFuncs(options)
	for name, fn := range extra {
		funcs[name] = fn
	}
	parsed, err := template.New(RootTemplate).Funcs(funcs).Parse(text)
	if err != nil {
		return "", err
	}
	// A file whose content sits entirely in other {{define}} blocks leaves
	// the root "document" template empty, and executing an empty template
	// silently renders nothing. Reject that instead of writing empty output.
	if !definesRoot(parsed) {
		return "", fmt.Errorf("template does not define a non-empty %q template", RootTemplate)
	}

	var output bytes.Buffer
	if err := parsed.ExecuteTemplate(&output, RootTemplate, data); err != nil {
		return "", err
	}
	return output.String(), nil
}

func definesRoot(parsed *template.Template) bool {
	found := parsed.Lookup(RootTemplate)
	if found == nil || found.Tree == nil || found.Tree.Root == nil {
		return false
	}
	for _, node := range found.Tree.Root.Nodes {
		if text, ok := node.(*parse.TextNode); ok &&
			strings.TrimSpace(string(text.Text)) == "" {
			continue
		}
		return true
	}
	return false
}

func templateFuncs(options Options) template.FuncMap {
	return template.FuncMap{
		"htmlText":     HTMLText,
		"inlineCode":   func(value string) string { return InlineCode(CodeText(value)) },
		"inlineValues": InlineValues,
		"issueURL": func(value string) string {
			return options.IssueURLBase + strings.TrimPrefix(value, "#")
		},
		"join":            strings.Join,
		"linkDestination": LinkDestination,
		"linkLabel":       LinkLabel,
		"lower":           strings.ToLower,
		"prose":           ProseText,
		"table":           TableText,
	}
}

// TableText escapes value for a Markdown table cell.
func TableText(value string) string {
	return markdownText(value, "<br>")
}

// HTMLText escapes value for plain-text emission inside raw HTML.
func HTMLText(value string) string {
	value = html.EscapeString(value)
	return neutralizeInvisible(strings.NewReplacer(
		`\`, "&#92;",
		"`", "&#96;",
		`*`, "&#42;",
		`_`, "&#95;",
		`[`, "&#91;",
		`]`, "&#93;",
		`|`, "&#124;",
		`~`, "&#126;",
		"\r\n", " ",
		"\r", " ",
		"\n", " ",
	).Replace(value))
}

// InlineValues renders values as a comma-separated inline-code list.
func InlineValues(values []string) string {
	if len(values) == 0 {
		return "None recorded"
	}
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, InlineCode(CodeText(value)))
	}
	return strings.Join(formatted, ", ")
}

// CodeText neutralizes table and line-break structure inside code spans.
func CodeText(value string) string {
	return neutralizeInvisible(strings.NewReplacer(
		`|`, `\|`,
		"\r\n", " ",
		"\r", " ",
		"\n", " ",
	).Replace(value))
}

// neutralizeInvisible drops the code points that survive Markdown escaping
// yet still alter how rendered output is interpreted or displayed: control
// runes (Cc), the Unicode line and paragraph separators (Zl/Zp), and the
// bidirectional embedding, override, and isolate controls that can reorder
// surrounding text (the "Trojan Source" class). Validation already rejects
// Cc/Zl/Zp in every document field, so this is defense in depth for that
// class and the primary defense for bidirectional controls, which
// validation deliberately allows so that right-to-left content stays
// expressible in prose.
func neutralizeInvisible(value string) string {
	if !strings.ContainsFunc(value, isInvisible) {
		return value
	}
	var cleaned strings.Builder
	cleaned.Grow(len(value))
	for _, r := range value {
		if isInvisible(r) {
			continue
		}
		cleaned.WriteRune(r)
	}
	return cleaned.String()
}

func isInvisible(r rune) bool {
	switch {
	case unicode.IsControl(r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	default:
		return false
	}
}

// InlineCode wraps value in a backtick fence longer than any run it contains.
func InlineCode(value string) string {
	fence := "`"
	for strings.Contains(value, fence) {
		fence += "`"
	}
	if len(fence) > 1 {
		return fence + " " + value + " " + fence
	}
	return fence + value + fence
}

// ProseText escapes value for Markdown prose.
func ProseText(value string) string {
	return markdownText(value, "<br>")
}

// LinkLabel escapes value for a Markdown link label.
func LinkLabel(value string) string {
	return markdownText(value, " ")
}

func markdownText(value, lineBreak string) string {
	value = strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		`*`, `\*`,
		`_`, `\_`,
		`[`, `\[`,
		`]`, `\]`,
		`|`, `\|`,
		`~`, `\~`,
	).Replace(value)
	value = html.EscapeString(value)
	return neutralizeInvisible(strings.NewReplacer(
		"\r\n", lineBreak,
		"\r", lineBreak,
		"\n", lineBreak,
	).Replace(value))
}

// LinkDestination escapes value for a Markdown link destination. Angle
// brackets and the raw control bytes that would otherwise break CommonMark
// line structure are percent-encoded before the <...> wrapper decision, so
// none of them can inject a raw line break into the rendered document; only
// a space or a parenthesis still forces the wrapper. Every control rune
// (Unicode category Cc), the Unicode line and paragraph separators
// (Zl/Zp), and the bidirectional overrides and isolates are encoded
// byte-by-byte, so the function is safe by
// construction even for a caller that skipped upstream validation —
// upstream bounds (check.RequiredString, check.LexicalURI) remain the
// primary defense; this is the belt to their braces.
func LinkDestination(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value))
	for _, r := range value {
		switch {
		case r == '<':
			escaped.WriteString("%3C")
		case r == '>':
			escaped.WriteString("%3E")
		case isInvisible(r):
			for _, encoded := range []byte(string(r)) {
				fmt.Fprintf(&escaped, "%%%02X", encoded)
			}
		default:
			escaped.WriteRune(r)
		}
	}
	result := escaped.String()
	if strings.ContainsAny(result, " ()") {
		return "<" + result + ">"
	}
	return result
}

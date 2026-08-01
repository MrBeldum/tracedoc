// Package render deterministically renders a validated matrix document to
// Markdown. Presentation strings and the issue-link base come from consumer
// configuration; the template itself can be replaced by the consumer.
package render

import (
	"bytes"
	_ "embed"
	"fmt"
	"html"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/sofired/matrix-service/internal/matrix"
)

// MaxTemplateBytes bounds the size of a consumer-supplied template file.
const MaxTemplateBytes = 1 << 20

//go:embed default.md.tmpl
var defaultTemplate string

// Options are the consumer presentation choices the templates receive.
type Options struct {
	IssueURLBase      string
	SourceName        string
	GeneratorName     string
	RegenerateCommand string
	CheckCommand      string
	TemplatePath      string
}

type view struct {
	Document             matrix.Document
	Render               Options
	ApplicabilityCounts  []count
	EvidenceStatusCounts []count
	BoundaryRequirements []matrix.Requirement
	Ownership            []ownershipSection
	Standards            []standardSection
}

type count struct {
	Label string
	Value int
}

type standardSection struct {
	Standard     matrix.Standard
	Requirements []matrix.Requirement
	First        bool
}

type ownershipSection struct {
	Milestone    string
	Workstream   string
	Issue        string
	Anchor       string
	Requirements []matrix.Requirement
}

// Document renders doc with the embedded default template, or with the
// consumer template named by options.TemplatePath when one is set.
func Document(doc matrix.Document, options Options) (string, error) {
	text := defaultTemplate
	if options.TemplatePath != "" {
		data, err := os.ReadFile(options.TemplatePath)
		if err != nil {
			return "", err
		}
		if len(data) > MaxTemplateBytes {
			return "", fmt.Errorf("template exceeds %d-byte limit", MaxTemplateBytes)
		}
		text = string(data)
	}
	parsed, err := template.New("matrix").Funcs(templateFuncs(options)).Parse(text)
	if err != nil {
		return "", err
	}
	// A file whose content sits entirely in other {{define}} blocks leaves
	// the root "matrix" template empty, and executing an empty template
	// silently renders nothing. Reject that instead of writing empty output.
	if !definesMatrix(parsed) {
		return "", fmt.Errorf("template does not define a non-empty %q template", "matrix")
	}

	var output bytes.Buffer
	if err := parsed.ExecuteTemplate(&output, "matrix", newView(doc, options)); err != nil {
		return "", err
	}
	return output.String(), nil
}

func definesMatrix(parsed *template.Template) bool {
	found := parsed.Lookup("matrix")
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
		"htmlText":     htmlPlainText,
		"inlineCode":   func(value string) string { return inlineCode(codeText(value)) },
		"inlineValues": inlineValues,
		"issueURL": func(value string) string {
			return options.IssueURLBase + strings.TrimPrefix(value, "#")
		},
		"join":            strings.Join,
		"linkDestination": linkDestination,
		"linkLabel":       linkLabel,
		"lower":           strings.ToLower,
		"owner":           ownerText,
		"prose":           proseText,
		"table":           tableText,
	}
}

func newView(doc matrix.Document, options Options) view {
	applicabilityCounts := make(map[string]int)
	statusCounts := make(map[string]int)
	requirementsByStandard := make(map[string][]matrix.Requirement, len(doc.Standards))
	requirementsByOwner := make(map[[3]string][]matrix.Requirement)
	result := view{Document: doc, Render: options}

	for _, item := range doc.Requirements {
		applicabilityCounts[item.Applicability]++
		statusCounts[item.EvidenceStatus]++
		requirementsByStandard[item.Standard] = append(requirementsByStandard[item.Standard], item)
		issue := ""
		if item.Owner.Issue != nil {
			issue = *item.Owner.Issue
		}
		ownerKey := [3]string{item.Owner.Milestone, item.Owner.Workstream, issue}
		requirementsByOwner[ownerKey] = append(requirementsByOwner[ownerKey], item)
		if item.Applicability != "applicable" {
			result.BoundaryRequirements = append(result.BoundaryRequirements, item)
		}
	}
	for _, label := range matrix.ApplicabilityOrder {
		result.ApplicabilityCounts = append(
			result.ApplicabilityCounts,
			count{Label: label, Value: applicabilityCounts[label]},
		)
	}
	for _, label := range matrix.EvidenceStatusOrder {
		if statusCounts[label] > 0 {
			result.EvidenceStatusCounts = append(
				result.EvidenceStatusCounts,
				count{Label: label, Value: statusCounts[label]},
			)
		}
	}
	for key, requirements := range requirementsByOwner {
		result.Ownership = append(result.Ownership, ownershipSection{
			Milestone:    key[0],
			Workstream:   key[1],
			Issue:        key[2],
			Requirements: requirements,
		})
	}
	sort.Slice(result.Ownership, func(i, j int) bool {
		left := result.Ownership[i]
		right := result.Ownership[j]
		if left.Milestone != right.Milestone {
			return milestoneOrder(left.Milestone) < milestoneOrder(right.Milestone)
		}
		if left.Workstream != right.Workstream {
			return left.Workstream < right.Workstream
		}
		return left.Issue < right.Issue
	})
	for index := range result.Ownership {
		result.Ownership[index].Anchor = "ownership-" + strconv.Itoa(index+1)
	}
	for _, item := range doc.Standards {
		result.Standards = append(
			result.Standards,
			standardSection{
				Standard:     item,
				Requirements: requirementsByStandard[item.Key],
				First:        len(result.Standards) == 0,
			},
		)
	}
	return result
}

// milestoneOrder sorts milestone labels of the form <prefix><number> by
// their numeric suffix, falling back to lexical order between equal numbers.
func milestoneOrder(value string) int {
	digits := strings.TrimFunc(value, func(r rune) bool {
		return r < '0' || r > '9'
	})
	number, _ := strconv.Atoi(digits)
	return number
}

func tableText(value string) string {
	return markdownText(value, "<br>")
}

func htmlPlainText(value string) string {
	value = html.EscapeString(value)
	return strings.NewReplacer(
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
	).Replace(value)
}

func inlineValues(values []string) string {
	if len(values) == 0 {
		return "None recorded"
	}
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, inlineCode(codeText(value)))
	}
	return strings.Join(formatted, ", ")
}

func codeText(value string) string {
	return strings.NewReplacer(
		`|`, `\|`,
		"\r\n", " ",
		"\r", " ",
		"\n", " ",
	).Replace(value)
}

func inlineCode(value string) string {
	fence := "`"
	for strings.Contains(value, fence) {
		fence += "`"
	}
	if len(fence) > 1 {
		return fence + " " + value + " " + fence
	}
	return fence + value + fence
}

func ownerText(value *matrix.Owner) string {
	parts := []string{value.Milestone, value.Workstream}
	if value.Issue != nil {
		parts = append(parts, *value.Issue)
	}
	for index, part := range parts {
		parts[index] = tableText(part)
	}
	return strings.Join(parts, " / ")
}

func proseText(value string) string {
	return markdownText(value, "<br>")
}

func linkLabel(value string) string {
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
	return strings.NewReplacer(
		"\r\n", lineBreak,
		"\r", lineBreak,
		"\n", lineBreak,
	).Replace(value)
}

func linkDestination(value string) string {
	escaped := strings.NewReplacer("<", "%3C", ">", "%3E").Replace(value)
	if strings.ContainsAny(escaped, " ()\t\r\n") {
		return "<" + escaped + ">"
	}
	return escaped
}

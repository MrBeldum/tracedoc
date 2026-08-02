// Package requirements renders a validated requirements-matrix document to
// Markdown through the shared render engine.
package requirements

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/sofired/tracedoc/internal/matrix"
	"github.com/sofired/tracedoc/internal/render"
)

//go:embed default.md.tmpl
var defaultTemplate string

type view struct {
	Document             matrix.Document
	Render               render.Options
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

// Render renders doc with the embedded default template, or with the
// consumer template text when templateText is non-empty. The doc must
// already have passed matrix.Validate; a document missing required objects
// yields an error, never a panic.
func Render(doc matrix.Document, options render.Options, templateText string) (string, error) {
	if err := requireValidated(doc); err != nil {
		return "", err
	}
	if templateText == "" {
		templateText = defaultTemplate
	}
	extra := template.FuncMap{"owner": ownerText}
	return render.Execute(templateText, options, extra, newView(doc, options))
}

// requireValidated reports an error, rather than letting newView or the
// template dereference a nil pointer, when doc contains a requirement that
// has not passed matrix.Validate. Owner is dereferenced by newView itself
// (to build the ownership index) and by the "owner" template function;
// PlannedVerification and Traceability are dereferenced by the default
// template.
func requireValidated(doc matrix.Document) error {
	for index, item := range doc.Requirements {
		if item.Owner == nil {
			return fmt.Errorf(
				"requirements[%d] has no owner; the document must pass validation before rendering",
				index,
			)
		}
		if item.PlannedVerification == nil {
			return fmt.Errorf(
				"requirements[%d] has no planned verification; the document must pass validation before rendering",
				index,
			)
		}
		if item.Traceability == nil {
			return fmt.Errorf(
				"requirements[%d] has no traceability; the document must pass validation before rendering",
				index,
			)
		}
	}
	return nil
}

func newView(doc matrix.Document, options render.Options) view {
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

func ownerText(value *matrix.Owner) string {
	parts := []string{value.Milestone, value.Workstream}
	if value.Issue != nil {
		parts = append(parts, *value.Issue)
	}
	for index, part := range parts {
		parts[index] = render.TableText(part)
	}
	return strings.Join(parts, " / ")
}

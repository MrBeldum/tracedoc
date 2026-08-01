// Package threats renders a validated threat-model document to Markdown
// through the shared render engine.
package threats

import (
	_ "embed"
	"strings"
	"text/template"

	"github.com/sofired/matrix-service/internal/render"
	"github.com/sofired/matrix-service/internal/threats"
)

//go:embed default.md.tmpl
var defaultTemplate string

type view struct {
	Document          threats.Document
	Render            render.Options
	SeverityCounts    []count
	DispositionCounts []count
	Assets            []entitySection
	Boundaries        []entitySection
	SeveritySections  []severitySection
}

type count struct {
	Label string
	Value int
}

type entitySection struct {
	ID          string
	Name        string
	Description string
	Threats     []threats.Threat
}

type severitySection struct {
	Severity string
	Threats  []threats.Threat
	First    bool
}

// Render renders doc with the embedded default template, or with the
// consumer template text when templateText is non-empty.
func Render(doc threats.Document, options render.Options, templateText string) (string, error) {
	if templateText == "" {
		templateText = defaultTemplate
	}
	extra := template.FuncMap{"owner": ownerText}
	return render.Execute(templateText, options, extra, newView(doc, options))
}

func newView(doc threats.Document, options render.Options) view {
	severityCounts := make(map[string]int)
	dispositionCounts := make(map[string]int)
	threatsByAsset := make(map[string][]threats.Threat, len(doc.Assets))
	threatsByBoundary := make(map[string][]threats.Threat, len(doc.TrustBoundaries))
	threatsBySeverity := make(map[string][]threats.Threat)
	result := view{Document: doc, Render: options}

	for _, item := range doc.Threats {
		severityCounts[item.Severity]++
		dispositionCounts[item.Disposition]++
		threatsBySeverity[item.Severity] = append(threatsBySeverity[item.Severity], item)
		for _, id := range item.AffectedAssets {
			threatsByAsset[id] = append(threatsByAsset[id], item)
		}
		for _, id := range item.TrustBoundaries {
			threatsByBoundary[id] = append(threatsByBoundary[id], item)
		}
	}
	for _, label := range threats.SeverityOrder {
		result.SeverityCounts = append(
			result.SeverityCounts,
			count{Label: label, Value: severityCounts[label]},
		)
	}
	for _, label := range threats.DispositionOrder {
		if dispositionCounts[label] > 0 {
			result.DispositionCounts = append(
				result.DispositionCounts,
				count{Label: label, Value: dispositionCounts[label]},
			)
		}
	}
	for _, item := range doc.Assets {
		result.Assets = append(result.Assets, entitySection{
			ID:          item.ID,
			Name:        item.Name,
			Description: item.Description,
			Threats:     threatsByAsset[item.ID],
		})
	}
	for _, item := range doc.TrustBoundaries {
		result.Boundaries = append(result.Boundaries, entitySection{
			ID:          item.ID,
			Name:        item.Name,
			Description: item.Description,
			Threats:     threatsByBoundary[item.ID],
		})
	}
	for _, severity := range threats.SeverityOrder {
		if len(threatsBySeverity[severity]) == 0 {
			continue
		}
		result.SeveritySections = append(result.SeveritySections, severitySection{
			Severity: severity,
			Threats:  threatsBySeverity[severity],
			First:    len(result.SeveritySections) == 0,
		})
	}
	return result
}

func ownerText(value *threats.Owner) string {
	parts := []string{value.Milestone, value.Workstream}
	if value.Issue != nil {
		parts = append(parts, *value.Issue)
	}
	for index, part := range parts {
		parts[index] = render.TableText(part)
	}
	return strings.Join(parts, " / ")
}

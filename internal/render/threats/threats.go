// Package threats renders a validated threat-model document to Markdown
// through the shared render engine.
package threats

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/sofired/tracedoc/internal/render"
	"github.com/sofired/tracedoc/internal/threats"
)

//go:embed default.md.tmpl
var defaultTemplate string

type view struct {
	Document        threats.Document
	Render          render.Options
	PriorityCounts  []count
	TreatmentCounts []count
	Diagrams        []diagram
	Assets          []assetSection
	Boundaries      []boundarySection
	Flows           []flowSection
	EntryPoints     []entryPoint
	Decisions       []decision
	Risks           []risk
	Controls        []control
	Evidence        []evidence
	Sections        []prioritySection
}

type count struct {
	Label string
	Value int
}

// diagram, decision, and risk each carry a precomputed Target: the single
// destination string derived from the reference's path or url member, so
// the template never has to branch on which member was supplied.
type diagram struct {
	Caption string
	Target  string
}

type decision struct {
	ID       string
	Title    string
	Status   string
	Target   string
	Controls []string
}

type risk struct {
	ID       string
	Title    string
	Target   string
	Controls []string
	Threats  []string
}

// Each section embeds its schema record and adds the threats that analysed
// it, so the template reads one collection rather than indexing two in
// parallel.
type assetSection struct {
	threats.Asset
	Threats []threats.Threat
}

type boundarySection struct {
	threats.Boundary
	Threats []threats.Threat
}

type flowSection struct {
	threats.DataFlow
	Threats []threats.Threat
}

type entryPoint struct {
	threats.EntryPoint
	Threats []threats.Threat
}

type control struct {
	threats.Control
	Threats []string
}

type evidence struct {
	threats.Evidence
	Controls []string
}

type prioritySection struct {
	Priority string
	Threats  []threats.Threat
	First    bool
}

// Render renders doc with the embedded default template, or with the
// consumer template text when templateText is non-empty. The doc must
// already have passed threats.Validate; a document missing required
// objects yields an error, never a panic.
func Render(doc threats.Document, options render.Options, templateText string) (string, error) {
	if err := requireValidated(doc); err != nil {
		return "", err
	}
	if templateText == "" {
		templateText = defaultTemplate
	}
	extra := template.FuncMap{
		"owner": ownerText,
		// add1 numbers an ordered abuse path from 1 rather than 0.
		"add1": func(value int) int { return value + 1 },
	}
	return render.Execute(templateText, options, extra, newView(doc, options))
}

// requireValidated reports an error, rather than letting the "owner"
// template function or the default template dereference a nil pointer,
// when doc contains a record that has not passed threats.Validate.
func requireValidated(doc threats.Document) error {
	unvalidated := func(location string) error {
		return fmt.Errorf(
			"%s has no owner; the document must pass validation before rendering",
			location,
		)
	}
	if doc.Scope == nil {
		return fmt.Errorf("document has no scope; the document must pass validation before rendering")
	}
	if doc.AttackerModel == nil {
		return fmt.Errorf(
			"document has no attacker model; the document must pass validation before rendering",
		)
	}
	for index, item := range doc.Threats {
		if item.Owner == nil {
			return unvalidated(fmt.Sprintf("threats[%d]", index))
		}
	}
	for index, item := range doc.Controls {
		if item.Owner == nil {
			return unvalidated(fmt.Sprintf("controls[%d]", index))
		}
	}
	for index, item := range doc.PlannedEvidence {
		if item.Owner == nil {
			return unvalidated(fmt.Sprintf("planned_evidence[%d]", index))
		}
	}
	return nil
}

func newView(doc threats.Document, options render.Options) view {
	result := view{Document: doc, Render: options}

	priorityCounts := make(map[string]int)
	treatmentCounts := make(map[string]int)
	byAsset := make(map[string][]threats.Threat, len(doc.Assets))
	byBoundary := make(map[string][]threats.Threat, len(doc.TrustBoundaries))
	byFlow := make(map[string][]threats.Threat, len(doc.DataFlows))
	byPriority := make(map[string][]threats.Threat)
	controlThreats := make(map[string][]string, len(doc.Controls))
	riskThreats := make(map[string][]string, len(doc.Risks))

	for _, item := range doc.Threats {
		priorityCounts[item.Priority]++
		treatmentCounts[item.Treatment]++
		byPriority[item.Priority] = append(byPriority[item.Priority], item)
		for _, id := range item.AssetLinks {
			byAsset[id] = append(byAsset[id], item)
		}
		for _, id := range item.BoundaryLinks {
			byBoundary[id] = append(byBoundary[id], item)
		}
		for _, id := range item.FlowLinks {
			byFlow[id] = append(byFlow[id], item)
		}
		for _, id := range item.ControlLinks {
			controlThreats[id] = append(controlThreats[id], item.ID)
		}
		for _, id := range item.RiskLinks {
			riskThreats[id] = append(riskThreats[id], item.ID)
		}
	}

	// Traceability runs the other way too: a decision or a risk is reviewed
	// through the controls that cite it, and planned evidence through the
	// controls that expect it.
	decisionControls := make(map[string][]string, len(doc.Decisions))
	riskControls := make(map[string][]string, len(doc.Risks))
	evidenceControls := make(map[string][]string, len(doc.PlannedEvidence))
	for _, item := range doc.Controls {
		for _, id := range item.DecisionLinks {
			decisionControls[id] = append(decisionControls[id], item.ID)
		}
		for _, id := range item.RiskLinks {
			riskControls[id] = append(riskControls[id], item.ID)
		}
		for _, id := range item.EvidenceLinks {
			evidenceControls[id] = append(evidenceControls[id], item.ID)
		}
	}

	for _, label := range threats.PriorityOrder {
		result.PriorityCounts = append(
			result.PriorityCounts,
			count{Label: label, Value: priorityCounts[label]},
		)
	}
	for _, label := range threats.TreatmentOrder {
		if treatmentCounts[label] > 0 {
			result.TreatmentCounts = append(
				result.TreatmentCounts,
				count{Label: label, Value: treatmentCounts[label]},
			)
		}
	}

	for _, item := range doc.Diagrams {
		result.Diagrams = append(result.Diagrams, diagram{
			Caption: item.Caption,
			Target:  referenceTarget(item.Reference),
		})
	}
	for _, item := range doc.Assets {
		result.Assets = append(result.Assets, assetSection{Asset: item, Threats: byAsset[item.ID]})
	}
	for _, item := range doc.TrustBoundaries {
		result.Boundaries = append(
			result.Boundaries,
			boundarySection{Boundary: item, Threats: byBoundary[item.ID]},
		)
	}
	for _, item := range doc.DataFlows {
		result.Flows = append(result.Flows, flowSection{DataFlow: item, Threats: byFlow[item.ID]})
	}
	for _, item := range doc.EntryPoints {
		result.EntryPoints = append(result.EntryPoints, entryPoint{
			EntryPoint: item,
			Threats:    entryPointThreats(item, doc.Threats),
		})
	}
	for _, item := range doc.Decisions {
		result.Decisions = append(result.Decisions, decision{
			ID: item.ID, Title: item.Title, Status: item.Status,
			Target:   referenceTarget(item.Reference),
			Controls: decisionControls[item.ID],
		})
	}
	for _, item := range doc.Risks {
		result.Risks = append(result.Risks, risk{
			ID: item.ID, Title: item.Title,
			Target:   referenceTarget(item.Reference),
			Controls: riskControls[item.ID],
			Threats:  riskThreats[item.ID],
		})
	}
	for _, item := range doc.Controls {
		result.Controls = append(result.Controls, control{
			Control: item,
			Threats: controlThreats[item.ID],
		})
	}
	for _, item := range doc.PlannedEvidence {
		result.Evidence = append(result.Evidence, evidence{
			Evidence: item,
			Controls: evidenceControls[item.ID],
		})
	}
	for _, priority := range threats.PriorityOrder {
		if len(byPriority[priority]) == 0 {
			continue
		}
		result.Sections = append(result.Sections, prioritySection{
			Priority: priority,
			Threats:  byPriority[priority],
			First:    len(result.Sections) == 0,
		})
	}
	return result
}

// entryPointThreats lists the threats that reach an entry point the way the
// validator's coverage rule counts it: across its boundary and along one of
// its flows.
func entryPointThreats(entry threats.EntryPoint, all []threats.Threat) []threats.Threat {
	var result []threats.Threat
	for _, item := range all {
		if !contains(item.BoundaryLinks, entry.Boundary) {
			continue
		}
		for _, flow := range entry.Flows {
			if contains(item.FlowLinks, flow) {
				result = append(result, item)
				break
			}
		}
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// referenceTarget collapses a reference to its single destination. Validate
// guarantees exactly one member is set; an empty result would mean an
// unvalidated document reached the renderer, which requireValidated and the
// template's own emptiness guard both handle.
func referenceTarget(ref threats.Reference) string {
	if ref.Path != "" {
		return ref.Path
	}
	return ref.URL
}

func ownerText(value *threats.Owner) string {
	parts := []string{value.Principal, value.Milestone, value.Workstream}
	if value.Issue != nil {
		parts = append(parts, *value.Issue)
	}
	for index, part := range parts {
		parts[index] = render.TableText(part)
	}
	return strings.Join(parts, " / ")
}

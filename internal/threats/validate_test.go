package threats_test

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/sofired/tracedoc/internal/check"
	"github.com/sofired/tracedoc/internal/policy"
	"github.com/sofired/tracedoc/internal/testsupport"
	"github.com/sofired/tracedoc/internal/threats"
)

func fixturePolicy(t *testing.T) threats.Policy {
	t.Helper()
	config, err := policy.Load(testsupport.FixturePath(t, "config.json"))
	if err != nil {
		t.Fatalf("load fixture config: %v", err)
	}
	pol, err := config.ThreatsPolicy()
	if err != nil {
		t.Fatalf("compile threats policy: %v", err)
	}
	return pol
}

func fixtureDocument(t *testing.T) threats.Document {
	t.Helper()
	doc, err := threats.Load(testsupport.FixturePath(t, "threats.json"))
	if err != nil {
		t.Fatalf("load fixture threat model: %v", err)
	}
	return doc
}

func fixtureIndex() *threats.RequirementIndex {
	return &threats.RequirementIndex{
		Active: map[string]struct{}{
			"EXCORE-001": {}, "EXCORE-002": {}, "RFCX-001": {}, "PLAN-001": {},
		},
		Retired: map[string]struct{}{"EXCORE-900": {}, "EXCORE-901": {}},
		Replacements: map[string][]string{
			"EXCORE-900": {"EXCORE-001"},
			"EXCORE-901": {},
		},
	}
}

func threatByID(t *testing.T, doc *threats.Document, id string) *threats.Threat {
	t.Helper()
	for index := range doc.Threats {
		if doc.Threats[index].ID == id {
			return &doc.Threats[index]
		}
	}
	t.Fatalf("threat %s not found", id)
	return nil
}

func controlByID(t *testing.T, doc *threats.Document, id string) *threats.Control {
	t.Helper()
	for index := range doc.Controls {
		if doc.Controls[index].ID == id {
			return &doc.Controls[index]
		}
	}
	t.Fatalf("control %s not found", id)
	return nil
}

func TestThreatModelValidation(t *testing.T) {
	pol := fixturePolicy(t)
	if errs := threats.Validate(fixtureDocument(t), pol, fixtureIndex()); len(errs) > 0 {
		t.Fatalf("fixture threat model is invalid:\n%s", errs)
	}
	// Without an index, link checking degrades to format-only and the
	// fixture must still validate.
	if errs := threats.Validate(fixtureDocument(t), pol, nil); len(errs) > 0 {
		t.Fatalf("fixture threat model is invalid without index:\n%s", errs)
	}

	// A withdrawal — a supersession with an explicitly empty replacement
	// set — is a legal ledger entry.
	withdrawal := fixtureDocument(t)
	withdrawal.Supersessions = append(withdrawal.Supersessions, threats.Supersession{
		RetiredID:      "THRT-901",
		ReplacementIDs: []string{},
		Rationale:      "Threat withdrawn after the affected surface was removed.",
	})
	if errs := threats.Validate(withdrawal, pol, fixtureIndex()); len(errs) > 0 {
		t.Fatalf("withdrawal supersession rejected:\n%s", errs)
	}

	tests := []struct {
		name   string
		want   string
		mutate func(*threats.Document)
	}{
		// Document metadata.
		{
			name:   "wrong document type",
			want:   `document_type: expected "threat_model"`,
			mutate: func(doc *threats.Document) { doc.DocumentType = "requirements" },
		},
		{
			name:   "unsupported schema version",
			want:   "schema_version: expected 1",
			mutate: func(doc *threats.Document) { doc.SchemaVersion = 2 },
		},
		{
			name:   "malformed document version",
			want:   "expected a semantic version",
			mutate: func(doc *threats.Document) { doc.DocumentVersion = "1.0.0-01" },
		},
		{
			name:   "invalid review date",
			want:   "expected an RFC 3339 full date",
			mutate: func(doc *threats.Document) { doc.LastReviewed = "2026-02-30" },
		},
		{
			name:   "unknown document status",
			want:   "status: unknown document status",
			mutate: func(doc *threats.Document) { doc.Status = "published" },
		},
		{
			name:   "invalid document owner",
			want:   `owner: invalid principal "security-lead"`,
			mutate: func(doc *threats.Document) { doc.Owner = "security-lead" },
		},
		{
			name:   "blank summary",
			want:   "summary: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Summary = "  " },
		},
		{
			name:   "missing scope",
			want:   "scope: expected an object",
			mutate: func(doc *threats.Document) { doc.Scope = nil },
		},
		{
			name:   "empty in-scope list",
			want:   "scope.in_scope: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Scope.InScope = []string{} },
		},
		{
			name:   "missing attacker model",
			want:   "attacker_model: expected an object",
			mutate: func(doc *threats.Document) { doc.AttackerModel = nil },
		},
		{
			name: "empty attacker non-capabilities",
			want: "attacker_model.non_capabilities: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.AttackerModel.NonCapabilities = []string{}
			},
		},

		// Identifier declaration.
		{
			name:   "duplicate threat ID",
			want:   `duplicate threat ID "THRT-001"`,
			mutate: func(doc *threats.Document) { doc.Threats = append(doc.Threats, doc.Threats[0]) },
		},
		{
			name:   "invalid threat ID format",
			want:   "expected a stable threat ID",
			mutate: func(doc *threats.Document) { doc.Threats[0].ID = "threat-1" },
		},
		{
			name:   "threat ID with a reserved prefix",
			want:   "threat IDs must not use the reserved CTRL- prefix",
			mutate: func(doc *threats.Document) { doc.Threats[0].ID = "CTRL-900" },
		},
		{
			name:   "duplicate component ID",
			want:   `duplicate component ID "COMP-001"`,
			mutate: func(doc *threats.Document) { doc.Components[1].ID = "COMP-001" },
		},
		{
			name:   "invalid actor ID",
			want:   "expected a stable actor ID",
			mutate: func(doc *threats.Document) { doc.Actors[0].ID = "ACT-001" },
		},
		{
			name:   "invalid asset ID",
			want:   "expected a stable asset ID",
			mutate: func(doc *threats.Document) { doc.Assets[0].ID = "ASSET-001" },
		},
		{
			name:   "invalid data-flow ID",
			want:   "expected a stable data flow ID",
			mutate: func(doc *threats.Document) { doc.DataFlows[0].ID = "FLOW-001" },
		},
		{
			name:   "invalid decision ID",
			want:   "expected a stable decision ID",
			mutate: func(doc *threats.Document) { doc.Decisions[0].ID = "ADR-1010101" },
		},
		{
			name:   "invalid risk ID under the consumer pattern",
			want:   `invalid risk "R99"`,
			mutate: func(doc *threats.Document) { doc.Risks[0].ID = "R99" },
		},

		// Topology resolution.
		{
			name:   "boundary source is not a component",
			want:   `trust_boundaries[0].source: unknown component "COMP-404"`,
			mutate: func(doc *threats.Document) { doc.TrustBoundaries[0].Source = "COMP-404" },
		},
		{
			name: "boundary destination is not a component",
			want: `trust_boundaries[0].destination: unknown component "COMP-404"`,
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries[0].Destination = "COMP-404"
			},
		},
		{
			name: "data flow names an unknown boundary",
			want: `data_flows[0].boundaries[0]: unknown trust boundary "TB-404"`,
			mutate: func(doc *threats.Document) {
				doc.DataFlows[0].Boundaries = []string{"TB-404"}
			},
		},
		{
			name:   "entry point names an unknown boundary",
			want:   `entry_points[0].boundary: unknown trust boundary "TB-404"`,
			mutate: func(doc *threats.Document) { doc.EntryPoints[0].Boundary = "TB-404" },
		},
		{
			name: "entry point names an unknown flow",
			want: `entry_points[0].flows[0]: unknown data flow "DF-404"`,
			mutate: func(doc *threats.Document) {
				doc.EntryPoints[0].Flows = []string{"DF-404"}
			},
		},

		// Threat analysis fields.
		{
			name:   "unsupported likelihood",
			want:   `threats[0].likelihood: unsupported value "certain"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].Likelihood = "certain" },
		},
		{
			name:   "unsupported severity",
			want:   `threats[0].severity: unsupported value "critical"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].Severity = "critical" },
		},
		{
			name:   "unsupported priority",
			want:   `threats[0].priority: unsupported value "urgent"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].Priority = "urgent" },
		},
		{
			name:   "unsupported treatment",
			want:   `threats[0].treatment: unsupported value "mitigated"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].Treatment = "mitigated" },
		},
		{
			name:   "missing residual risk",
			want:   "threats[0].residual_risk: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Threats[0].ResidualRisk = "" },
		},
		{
			name:   "empty abuse path",
			want:   "threats[0].abuse_path: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Threats[0].AbusePath = []string{} },
		},
		{
			name:   "missing threat owner",
			want:   "threats[0].owner: expected an object",
			mutate: func(doc *threats.Document) { doc.Threats[0].Owner = nil },
		},
		{
			name:   "missing accountable principal",
			want:   "threats[0].owner.principal: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Threats[0].Owner.Principal = "" },
		},
		{
			name: "invalid accountable principal",
			want: `threats[0].owner.principal: invalid principal "Protocol Owner"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Owner.Principal = "Protocol Owner"
			},
		},
		{
			name:   "invalid milestone",
			want:   "invalid milestone",
			mutate: func(doc *threats.Document) { doc.Threats[0].Owner.Milestone = "M99" },
		},
		{
			name:   "unknown workstream",
			want:   "unknown workstream",
			mutate: func(doc *threats.Document) { doc.Threats[0].Owner.Workstream = "Unknown" },
		},

		// Threat link resolution.
		{
			name:   "empty asset links",
			want:   "threats[0].asset_links: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Threats[0].AssetLinks = []string{} },
		},
		{
			name:   "unknown asset link",
			want:   `unknown asset "AST-404"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].AssetLinks = []string{"AST-404"} },
		},
		{
			name:   "unknown actor link",
			want:   `unknown actor "ACTOR-404"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].ActorLinks = []string{"ACTOR-404"} },
		},
		{
			name:   "unknown boundary link",
			want:   `unknown trust boundary "TB-404"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].BoundaryLinks = []string{"TB-404"} },
		},
		{
			name:   "unknown flow link",
			want:   `unknown data flow "DF-404"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].FlowLinks = []string{"DF-404"} },
		},
		{
			name:   "unknown control link",
			want:   `unknown control "CTRL-404"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].ControlLinks = []string{"CTRL-404"} },
		},
		{
			name:   "unknown risk link",
			want:   `unknown risk "R7"`,
			mutate: func(doc *threats.Document) { doc.Threats[0].RiskLinks = []string{"R7"} },
		},
		{
			name: "unknown planned-evidence link",
			want: `unknown planned evidence "EVD-404"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].EvidenceLinks = []string{"EVD-404"}
			},
		},
		{
			name:   "nil flow links",
			want:   "threats[0].flow_links: expected an array",
			mutate: func(doc *threats.Document) { doc.Threats[0].FlowLinks = nil },
		},

		// Controls, evidence, observability.
		{
			name: "control with no traceability link",
			want: "controls[0]: expected at least one traceability link",
			mutate: func(doc *threats.Document) {
				control := controlByID(t, doc, "CTRL-001")
				control.RequirementLinks = []string{}
				control.DecisionLinks = []string{}
				control.RiskLinks = []string{}
				control.EvidenceLinks = []string{}
			},
		},
		{
			name:   "unknown control status",
			want:   "controls[0].status: unknown control status",
			mutate: func(doc *threats.Document) { doc.Controls[0].Status = "done" },
		},
		{
			name:   "missing control owner",
			want:   "controls[0].owner: expected an object",
			mutate: func(doc *threats.Document) { doc.Controls[0].Owner = nil },
		},
		{
			name: "unresolved control decision link",
			want: `unknown decision "ADR-404"`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-002").DecisionLinks = []string{"ADR-404"}
			},
		},
		{
			name: "unresolved control risk link",
			want: `unknown risk "R9"`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-002").RiskLinks = []string{"R9"}
			},
		},
		{
			name: "unresolved control evidence link",
			want: `unknown planned evidence "EVD-404"`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-001").EvidenceLinks = []string{"EVD-404"}
			},
		},
		{
			name:   "unknown evidence level",
			want:   "planned_evidence[0].level: unknown evidence level",
			mutate: func(doc *threats.Document) { doc.PlannedEvidence[0].Level = "smoke" },
		},
		{
			name:   "unknown evidence status",
			want:   "planned_evidence[0].status: unknown evidence status",
			mutate: func(doc *threats.Document) { doc.PlannedEvidence[0].Status = "done" },
		},
		{
			name: "evidence names an unknown threat",
			want: `unknown threat "THRT-404"`,
			mutate: func(doc *threats.Document) {
				doc.PlannedEvidence[0].ThreatLinks = []string{"THRT-404"}
			},
		},
		{
			name: "observability names an unknown control",
			want: `unknown control "CTRL-404"`,
			mutate: func(doc *threats.Document) {
				doc.Observability[0].ControlLinks = []string{"CTRL-404"}
			},
		},
		{
			name:   "observability without redaction rules",
			want:   "observability[0].redaction: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Observability[0].Redaction = []string{} },
		},

		// Requirement links (cross-document).
		{
			name: "invalid requirement link format",
			want: `invalid requirement ID "excore-1"`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-001").RequirementLinks = []string{"excore-1"}
			},
		},
		{
			name: "unknown requirement link",
			want: `unknown requirement "MISSING-001"`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-001").RequirementLinks = []string{"MISSING-001"}
			},
		},
		{
			name: "retired requirement link names its replacements",
			want: `requirement "EXCORE-900" is retired; replacements: EXCORE-001`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-001").RequirementLinks = []string{"EXCORE-900"}
			},
		},
		{
			name: "withdrawn requirement link",
			want: `requirement "EXCORE-901" was withdrawn without a replacement`,
			mutate: func(doc *threats.Document) {
				controlByID(t, doc, "CTRL-001").RequirementLinks = []string{"EXCORE-901"}
			},
		},

		// References.
		{
			name: "diagram with both path and url",
			want: "diagrams[0]: expected exactly one of path or url, not both",
			mutate: func(doc *threats.Document) {
				doc.Diagrams[0].URL = "https://diagrams.example.org/x.svg"
			},
		},
		{
			name:   "diagram with neither path nor url",
			want:   "diagrams[1]: expected exactly one of path or url",
			mutate: func(doc *threats.Document) { doc.Diagrams[1].URL = "" },
		},
		{
			name: "diagram url on an unlisted host",
			want: `host "diagrams.attacker.example" is not an allowed reference host`,
			mutate: func(doc *threats.Document) {
				doc.Diagrams[1].URL = "https://diagrams.attacker.example/x.svg"
			},
		},
		{
			name: "diagram url without HTTPS",
			want: "expected an HTTPS URL with an absolute path",
			mutate: func(doc *threats.Document) {
				doc.Diagrams[1].URL = "http://diagrams.example.org/x.svg"
			},
		},
		{
			name: "diagram path escaping into a scheme",
			want: "contains a backslash or a scheme",
			mutate: func(doc *threats.Document) {
				doc.Diagrams[0].Path = "javascript:alert(1)"
			},
		},
		{
			name:   "absolute diagram path",
			want:   "expected a relative path",
			mutate: func(doc *threats.Document) { doc.Diagrams[0].Path = "/etc/passwd" },
		},

		// Supersessions.
		{
			name: "supersession retired ID still active",
			want: "retired ID is still active",
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].RetiredID = "THRT-001"
			},
		},
		{
			name: "duplicate retired ID",
			want: `duplicate retired ID "THRT-900"`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions = append(doc.Supersessions, doc.Supersessions[0])
			},
		},
		{
			name: "unknown supersession replacement",
			want: `unknown active ID "THRT-404"`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"THRT-404"}
			},
		},
		{
			name:   "nil supersessions",
			want:   "supersessions: expected an array",
			mutate: func(doc *threats.Document) { doc.Supersessions = nil },
		},

		// Required collections.
		{
			name:   "empty assets array",
			want:   "assets: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Assets = nil },
		},
		{
			name:   "empty components array",
			want:   "components: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Components = nil },
		},
		{
			name:   "empty controls array",
			want:   "controls: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Controls = nil },
		},
		{
			name:   "empty threats array",
			want:   "threats: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.Threats = nil },
		},
		{
			name:   "nil decisions array",
			want:   "decisions: expected an array",
			mutate: func(doc *threats.Document) { doc.Decisions = nil },
		},
		{
			name:   "nil assumptions array",
			want:   "assumptions: expected an array",
			mutate: func(doc *threats.Document) { doc.Assumptions = nil },
		},

		// One required-field miss per newly introduced entity type. These
		// guard the call-site wiring rather than the shared helpers: a
		// copy-pasted body that validated one field twice and skipped
		// another would pass every other test in this table.
		{
			name:   "blank component purpose",
			want:   "components[0].purpose: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Components[0].Purpose = "" },
		},
		{
			name:   "blank actor trust",
			want:   "actors[0].trust: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Actors[0].Trust = "" },
		},
		{
			name:   "blank asset objective",
			want:   "assets[0].objective: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Assets[0].Objective = "" },
		},
		{
			name: "blank boundary implementation state",
			want: "trust_boundaries[0].implementation_state: expected a non-empty string",
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries[0].ImplementationState = ""
			},
		},
		{
			name: "empty boundary security guarantees",
			want: "trust_boundaries[0].security_guarantees: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries[0].SecurityGuarantees = []string{}
			},
		},
		{
			name:   "empty data-flow sequence",
			want:   "data_flows[0].sequence: expected a non-empty array",
			mutate: func(doc *threats.Document) { doc.DataFlows[0].Sequence = []string{} },
		},
		{
			name:   "blank entry-point reached",
			want:   "entry_points[0].reached: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.EntryPoints[0].Reached = "" },
		},
		{
			name:   "blank assumption effect",
			want:   "assumptions[0].effect: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Assumptions[0].Effect = "" },
		},
		{
			name:   "blank decision title",
			want:   "decisions[0].title: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Decisions[0].Title = "" },
		},
		{
			name:   "unsupported decision status",
			want:   `decisions[0].status: unsupported value "closed"`,
			mutate: func(doc *threats.Document) { doc.Decisions[0].Status = "closed" },
		},
		{
			name:   "blank risk title",
			want:   "risks[0].title: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Risks[0].Title = "" },
		},
		{
			name: "blank control implementation note",
			want: "controls[0].implementation_note: expected a non-empty string",
			mutate: func(doc *threats.Document) {
				doc.Controls[0].ImplementationNote = ""
			},
		},
		{
			name:   "blank evidence description",
			want:   "planned_evidence[0].description: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.PlannedEvidence[0].Description = "" },
		},
		{
			name: "empty evidence threat links",
			want: "planned_evidence[0].threat_links: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.PlannedEvidence[0].ThreatLinks = []string{}
			},
		},
		{
			name:   "blank observation alert condition",
			want:   "observability[0].alert_condition: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Observability[0].AlertCondition = "" },
		},
		{
			name: "empty observation control links",
			want: "observability[0].control_links: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.Observability[0].ControlLinks = []string{}
			},
		},
		{
			name:   "blank diagram caption",
			want:   "diagrams[0].caption: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Diagrams[0].Caption = "" },
		},
		{
			name:   "nil observability array",
			want:   "observability: expected an array",
			mutate: func(doc *threats.Document) { doc.Observability = nil },
		},
		{
			// treatment_rationale is optional for "mitigate", but a member
			// that is present must still be a real value.
			name: "blank-but-present treatment rationale",
			want: "threats[0].treatment_rationale: expected a non-empty string",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].TreatmentRationale = "   "
			},
		},

		// Lexical bounds.
		{
			name: "oversized rationale",
			want: "exceeds 16384-byte limit",
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].Rationale = strings.Repeat("x", check.MaxStringBytes+1)
			},
		},
		{
			name:   "blank threat impact",
			want:   "threats[0].impact: expected a non-empty string",
			mutate: func(doc *threats.Document) { doc.Threats[0].Impact = "   " },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)
			errs := threats.Validate(doc, pol, fixtureIndex())
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}

// TestCrossCollectionIDCollisionIsRejected covers the document-wide
// identifier namespace. Distinct per-type prefixes make a collision
// impossible between schema-owned collections, so the only way to express
// one is a risk ID — which follows a consumer pattern — colliding with
// another collection. The rendered companion anchors every entity in one
// namespace, so a collision would silently collapse two anchors into one.
func TestCrossCollectionIDCollisionIsRejected(t *testing.T) {
	permissive := fixturePolicy(t)
	permissive.Risk = regexp.MustCompile(`^[A-Z][A-Z0-9-]*$`)

	doc := fixtureDocument(t)
	doc.Risks[0].ID = "CTRL-001"
	// Keep every link consistent so the collision is the only failure.
	controlByID(t, &doc, "CTRL-002").RiskLinks = []string{"CTRL-001"}
	threatByID(t, &doc, "THRT-002").RiskLinks = []string{"CTRL-001"}

	errs := threats.Validate(doc, permissive, fixtureIndex())
	want := `ID "CTRL-001" is already declared by another collection`
	if !strings.Contains(errs.Error(), want) {
		t.Fatalf("expected %q, got:\n%s", want, errs)
	}
}

// TestCaseOnlyIDCollisionIsRejected covers the half of the anchor namespace
// exact-match uniqueness misses. Anchors are case-folded, so "R1" and "r1"
// are two identifiers addressing one anchor — the silent collapse the
// document-wide check exists to prevent, reachable through any consumer risk
// pattern that admits both cases. Only risk IDs can express this: every other
// collection's format is schema-owned and uppercase.
func TestCaseOnlyIDCollisionIsRejected(t *testing.T) {
	permissive := fixturePolicy(t)
	permissive.Risk = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

	doc := fixtureDocument(t)
	doc.Risks[1].ID = "r1"
	// Keep every link consistent so the collision is the only failure.
	controlByID(t, &doc, "CTRL-003").RiskLinks = []string{"r1"}
	threatByID(t, &doc, "THRT-003").RiskLinks = []string{"r1"}

	errs := threats.Validate(doc, permissive, fixtureIndex())
	if errs == nil {
		t.Fatal("expected a case-only collision to be rejected")
	}
	want := `ID "r1" differs from "R1" only by case`
	if !strings.Contains(errs.Error(), want) {
		t.Fatalf("expected %q, got:\n%s", want, errs)
	}
}

// TestCaseDistinctIDsAreAccepted is the counterpart: the folded check must
// not reject identifiers that merely share a prefix or differ by more than
// case, which would break every consumer risk pattern.
func TestCaseDistinctIDsAreAccepted(t *testing.T) {
	permissive := fixturePolicy(t)
	permissive.Risk = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

	doc := fixtureDocument(t)
	doc.Risks[1].ID = "r10"
	controlByID(t, &doc, "CTRL-003").RiskLinks = []string{"r10"}
	threatByID(t, &doc, "THRT-003").RiskLinks = []string{"r10"}

	if errs := threats.Validate(doc, permissive, fixtureIndex()); errs != nil {
		t.Fatalf("case-distinct IDs should validate, got:\n%s", errs)
	}
}

// TestCoverageRules is the acceptance coverage for the declared-entity
// rules: every collection the switches govern must be rejected when a
// member is declared but never analysed, and accepted once the switch is
// off. The switch half matters as much as the rule: a consumer building a
// model incrementally turns one off rather than deleting the entity.
func TestCoverageRules(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		disable func(*threats.Coverage)
		mutate  func(*threats.Document)
	}{
		{
			name:    "unanalysed asset",
			want:    `assets: asset "AST-002" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.Assets = false },
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").AssetLinks = []string{"AST-001"}
				threatByID(t, doc, "THRT-003").AssetLinks = []string{"AST-001"}
			},
		},
		{
			name:    "unanalysed trust boundary",
			want:    `trust_boundaries: trust boundary "TB-002" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.Boundaries = false },
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").BoundaryLinks = []string{"TB-001"}
				threatByID(t, doc, "THRT-003").BoundaryLinks = []string{"TB-001"}
			},
		},
		{
			name:    "unanalysed data flow",
			want:    `data_flows: data flow "DF-002" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.Flows = false },
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").FlowLinks = []string{"DF-001"}
			},
		},
		{
			name:    "unanalysed control",
			want:    `controls: control "CTRL-003" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.Controls = false },
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-003").ControlLinks = []string{"CTRL-001"}
			},
		},
		{
			name:    "unanalysed risk",
			want:    `risks: risk "R2" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.Risks = false },
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-003").RiskLinks = []string{}
			},
		},
		{
			name:    "unanalysed entry point",
			want:    `entry_points: entry point "EP-002" is declared but never analysed`,
			disable: func(c *threats.Coverage) { c.EntryPoints = false },
			mutate: func(doc *threats.Document) {
				// Break only the flow half of EP-002's match, keeping DF-002
				// and TB-002 analysed by other threats.
				threatByID(t, doc, "THRT-002").FlowLinks = []string{"DF-001"}
				flowOnly := threatByID(t, doc, "THRT-003")
				flowOnly.FlowLinks = []string{"DF-001", "DF-002"}
				flowOnly.BoundaryLinks = []string{"TB-001"}
			},
		},
		{
			name:    "threat with no planned evidence",
			want:    `threats: threat "THRT-001" has no planned evidence naming it`,
			disable: func(c *threats.Coverage) { c.Evidence = false },
			mutate: func(doc *threats.Document) {
				doc.PlannedEvidence[0].ThreatLinks = []string{"THRT-002"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name+" is rejected", func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)
			errs := threats.Validate(doc, fixturePolicy(t), fixtureIndex())
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
		t.Run(test.name+" is allowed with the switch off", func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)
			pol := fixturePolicy(t)
			test.disable(&pol.Coverage)
			errs := threats.Validate(doc, pol, fixtureIndex())
			// Assert only that this rule went quiet. Dropping a link can
			// legitimately trip a different rule that is still switched on
			// (an unanalysed boundary also leaves its entry point
			// unanalysed), which is not what this subtest is about.
			if strings.Contains(errs.Error(), test.want) {
				t.Fatalf("coverage rule ran with its switch off:\n%s", errs)
			}
		})
	}
}

// TestEntryPointCoverageRejectsPartialMatches is the false-positive guard
// the issue calls out by name. An entry point is analysed only when one
// threat both crosses its boundary and travels one of its flows; a threat
// that matches either half alone has not analysed that surface, and
// accepting it would silently certify an unreviewed entry point.
func TestEntryPointCoverageRejectsPartialMatches(t *testing.T) {
	pol := fixturePolicy(t)
	const want = `entry_points: entry point "EP-002" is declared but never analysed`

	// EP-002 sits on TB-002 and is reached by DF-002. THRT-002 is the only
	// threat that matches both halves, so each subtest breaks exactly one
	// half of that match and keeps the other collections covered.
	t.Run("boundary matches but flow does not", func(t *testing.T) {
		doc := fixtureDocument(t)
		threatByID(t, &doc, "THRT-002").FlowLinks = []string{"DF-001"}
		// DF-002 must stay analysed by a threat that does not also cross
		// TB-002, or the data-flow rule fires instead of the one under test.
		flowOnly := threatByID(t, &doc, "THRT-003")
		flowOnly.FlowLinks = []string{"DF-001", "DF-002"}
		flowOnly.BoundaryLinks = []string{"TB-001"}
		errs := threats.Validate(doc, pol, fixtureIndex())
		if !strings.Contains(errs.Error(), want) {
			t.Fatalf("expected %q, got:\n%s", want, errs)
		}
	})

	t.Run("flow matches but boundary does not", func(t *testing.T) {
		doc := fixtureDocument(t)
		threatByID(t, &doc, "THRT-002").BoundaryLinks = []string{"TB-001"}
		// TB-002 must stay analysed by a threat that does not also travel
		// DF-002, or the boundary rule fires instead of the one under test.
		boundaryOnly := threatByID(t, &doc, "THRT-003")
		boundaryOnly.BoundaryLinks = []string{"TB-001", "TB-002"}
		boundaryOnly.FlowLinks = []string{"DF-001"}
		errs := threats.Validate(doc, pol, fixtureIndex())
		if !strings.Contains(errs.Error(), want) {
			t.Fatalf("expected %q, got:\n%s", want, errs)
		}
	})

	t.Run("both halves match", func(t *testing.T) {
		if errs := threats.Validate(fixtureDocument(t), pol, fixtureIndex()); len(errs) > 0 {
			t.Fatalf("fixture entry points should be covered:\n%s", errs)
		}
	})
}

// TestTreatmentCoupling is positive and negative coverage for every
// treatment value: the decision a threat records must be backed by the
// record that decision implies.
func TestTreatmentCoupling(t *testing.T) {
	pol := fixturePolicy(t)

	t.Run("mitigate without a control is rejected", func(t *testing.T) {
		doc := fixtureDocument(t)
		threatByID(t, &doc, "THRT-001").ControlLinks = []string{}
		errs := threats.Validate(doc, pol, fixtureIndex())
		want := "a mitigated threat requires at least one control"
		if !strings.Contains(errs.Error(), want) {
			t.Fatalf("expected %q, got:\n%s", want, errs)
		}
	})

	t.Run("accept without a risk record is rejected", func(t *testing.T) {
		doc := fixtureDocument(t)
		threatByID(t, &doc, "THRT-002").RiskLinks = []string{}
		errs := threats.Validate(doc, pol, fixtureIndex())
		want := "an accepted threat requires at least one risk record"
		if !strings.Contains(errs.Error(), want) {
			t.Fatalf("expected %q, got:\n%s", want, errs)
		}
	})

	// avoid and transfer both record a decision not to build a control, so
	// both must say why.
	for _, treatment := range []string{"accept", "avoid", "transfer"} {
		t.Run(treatment+" without a rationale is rejected", func(t *testing.T) {
			doc := fixtureDocument(t)
			threat := threatByID(t, &doc, "THRT-002")
			threat.Treatment = treatment
			threat.TreatmentRationale = ""
			errs := threats.Validate(doc, pol, fixtureIndex())
			want := "required for " + treatment
			if !strings.Contains(errs.Error(), want) {
				t.Fatalf("expected %q, got:\n%s", want, errs)
			}
		})
		t.Run(treatment+" with a rationale validates cleanly", func(t *testing.T) {
			doc := fixtureDocument(t)
			threat := threatByID(t, &doc, "THRT-002")
			threat.Treatment = treatment
			threat.TreatmentRationale = "Recorded rationale for " + treatment + "."
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("treatment %q with rationale rejected:\n%s", treatment, errs)
			}
		})
	}
}

// TestRatingAndPriorityEnumCoverage exercises every legal value of the
// schema-owned vocabularies positively, so the enums are not tested only by
// what they reject.
func TestRatingAndPriorityEnumCoverage(t *testing.T) {
	pol := fixturePolicy(t)
	for _, rating := range []string{"low", "medium", "high"} {
		t.Run("likelihood "+rating, func(t *testing.T) {
			doc := fixtureDocument(t)
			threatByID(t, &doc, "THRT-003").Likelihood = rating
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("likelihood %q rejected:\n%s", rating, errs)
			}
		})
		t.Run("severity "+rating, func(t *testing.T) {
			doc := fixtureDocument(t)
			threatByID(t, &doc, "THRT-003").Severity = rating
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("severity %q rejected:\n%s", rating, errs)
			}
		})
	}
	for _, priority := range []string{"critical", "high", "medium", "low"} {
		t.Run("priority "+priority, func(t *testing.T) {
			doc := fixtureDocument(t)
			threatByID(t, &doc, "THRT-003").Priority = priority
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("priority %q rejected:\n%s", priority, errs)
			}
		})
	}
	for _, status := range []string{"proposed", "accepted", "rejected", "superseded"} {
		t.Run("decision status "+status, func(t *testing.T) {
			doc := fixtureDocument(t)
			doc.Decisions[0].Status = status
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("decision status %q rejected:\n%s", status, errs)
			}
		})
	}
}

// TestOwnerFieldsAreBoundedAndControlCharacterFree is the security
// regression coverage for consumer-pattern-validated fields: a permissive
// pattern must not let an oversized or control-character-bearing value
// through, because the renderer's guarantees assume validation already
// removed them.
func TestOwnerFieldsAreBoundedAndControlCharacterFree(t *testing.T) {
	pol := fixturePolicy(t)

	t.Run("oversized milestone", func(t *testing.T) {
		doc := fixtureDocument(t)
		doc.Threats[0].Owner.Milestone = strings.Repeat("M", check.MaxStringBytes+1)
		errs := threats.Validate(doc, pol, fixtureIndex())
		if !strings.Contains(errs.Error(), "exceeds 16384-byte limit") {
			t.Fatalf("expected oversized-milestone rejection, got:\n%s", errs)
		}
	})

	t.Run("issue with a control character under a permissive pattern", func(t *testing.T) {
		permissive := pol
		permissive.Issue = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		issue := "#36\nmalicious content"
		doc.Threats[0].Owner.Issue = &issue

		errs := threats.Validate(doc, permissive, fixtureIndex())
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected control-character rejection, got:\n%s", errs)
		}
	})

	t.Run("principal with a control character under a permissive pattern", func(t *testing.T) {
		permissive := pol
		permissive.Owner = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		doc.Threats[0].Owner.Principal = "@owner\x1b[31mred"

		errs := threats.Validate(doc, permissive, fixtureIndex())
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected control-character rejection, got:\n%s", errs)
		}
	})

	t.Run("risk ID with a control character under a permissive pattern", func(t *testing.T) {
		permissive := pol
		permissive.Risk = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		doc.Risks[0].ID = "R1\x1b[31mred"

		errs := threats.Validate(doc, permissive, fixtureIndex())
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected control-character rejection, got:\n%s", errs)
		}
	})
}

// TestReferenceHostAllowlistIsEnforced covers the provenance half of a
// reference: the lexical checks alone would accept any well-formed HTTPS
// URL, and the allowlist is what keeps a document author from pointing a
// governance artifact at an arbitrary destination.
func TestReferenceHostAllowlistIsEnforced(t *testing.T) {
	t.Run("empty allowlist rejects every URL", func(t *testing.T) {
		pol := fixturePolicy(t)
		pol.ReferenceHosts = map[string]struct{}{}

		doc := fixtureDocument(t)
		errs := threats.Validate(doc, pol, fixtureIndex())
		if !strings.Contains(errs.Error(), "is not an allowed reference host") {
			t.Fatalf("expected allowlist rejection, got:\n%s", errs)
		}
	})

	t.Run("repository-relative references need no allowlist", func(t *testing.T) {
		pol := fixturePolicy(t)
		pol.ReferenceHosts = map[string]struct{}{}

		doc := fixtureDocument(t)
		doc.Diagrams[1].URL = ""
		doc.Diagrams[1].Path = "diagrams/token-issuance.md"
		doc.Decisions[1].URL = ""
		doc.Decisions[1].Path = "../decisions/adr-102.md"
		if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
			t.Fatalf("repository-relative references rejected:\n%s", errs)
		}
	})
}

func TestRequirementLinksSkippedWithoutIndex(t *testing.T) {
	doc := fixtureDocument(t)
	controlByID(t, &doc, "CTRL-001").RequirementLinks = []string{"MISSING-001"}
	errs := threats.Validate(doc, fixturePolicy(t), nil)
	if strings.Contains(errs.Error(), "unknown requirement") {
		t.Fatalf("link resolution ran without an index:\n%s", errs)
	}
}

func TestHasRequirementLinks(t *testing.T) {
	doc := fixtureDocument(t)
	if !doc.HasRequirementLinks() {
		t.Fatal("fixture should report requirement links")
	}
	for index := range doc.Controls {
		doc.Controls[index].RequirementLinks = nil
	}
	if doc.HasRequirementLinks() {
		t.Fatal("expected no requirement links after clearing")
	}
}

// TestEverySliceMemberIsRequiredPresent pins the invariant Compare depends
// on. Compare decides "did this document change" with reflect.DeepEqual
// over the whole document, and DeepEqual distinguishes a nil slice from an
// empty one — so if any slice field could survive validation as nil, a
// revision that merely spelled out an omitted array as [] would read as a
// document change and demand a version bump.
//
// Driven by reflection over the struct's own JSON tags rather than a hand
// list: a slice field added to Document in a future schema is covered here
// the day it is added, and fails until it gets a presence check. Walking a
// validated fixture would not do this — the fixture populates everything,
// so nothing would ever be nil to find.
func TestEverySliceMemberIsRequiredPresent(t *testing.T) {
	raw, err := os.ReadFile(testsupport.FixturePath(t, "threats.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	documentType := reflect.TypeOf(threats.Document{})
	for index := 0; index < documentType.NumField(); index++ {
		field := documentType.Field(index)
		if field.Type.Kind() != reflect.Slice {
			continue
		}
		member := strings.Split(field.Tag.Get("json"), ",")[0]
		t.Run("omitted "+member, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if _, present := document[member]; !present {
				t.Fatalf("fixture does not exercise %q", member)
			}
			delete(document, member)

			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode mutated fixture: %v", err)
			}
			doc, err := threats.Decode(encoded)
			if err != nil {
				t.Fatalf("decode mutated fixture: %v", err)
			}

			errs := threats.Validate(doc, fixturePolicy(t), fixtureIndex())
			if !strings.Contains(errs.Error(), member+":") {
				t.Fatalf(
					"omitting %q must be rejected, or Compare will read a later [] as a change; got:\n%s",
					member, errs,
				)
			}
		})
	}
}

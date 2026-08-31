// Package threats defines the threat-model document schema, its structural
// and cross-reference validation (including optional resolution of
// requirement links against a requirements matrix), and its cross-version
// comparison. Consumer-specific policy is supplied through policy.Config.
package threats

// SchemaVersion is the threat-model document schema this release of the
// tool reads, validates, renders, and compares.
const SchemaVersion = 1

// Document is one threat-model snapshot: the reviewable context, the
// architecture graph the review reasons over, the assurance records that
// carry traceability, and the threats themselves.
type Document struct {
	DocumentType    string         `json:"document_type"`
	SchemaVersion   int            `json:"schema_version"`
	DocumentVersion string         `json:"document_version"`
	LastReviewed    string         `json:"last_reviewed"`
	Status          string         `json:"status"`
	Owner           string         `json:"owner"`
	Summary         string         `json:"summary"`
	Scope           *Scope         `json:"scope"`
	Assumptions     []Assumption   `json:"assumptions"`
	OpenQuestions   []string       `json:"open_questions"`
	Diagrams        []Diagram      `json:"diagrams"`
	Components      []Component    `json:"components"`
	Actors          []Actor        `json:"actors"`
	AttackerModel   *AttackerModel `json:"attacker_model"`
	Assets          []Asset        `json:"assets"`
	TrustBoundaries []Boundary     `json:"trust_boundaries"`
	DataFlows       []DataFlow     `json:"data_flows"`
	EntryPoints     []EntryPoint   `json:"entry_points"`
	Decisions       []Decision     `json:"decisions"`
	Risks           []Risk         `json:"risks"`
	Controls        []Control      `json:"controls"`
	PlannedEvidence []Evidence     `json:"planned_evidence"`
	Observability   []Observation  `json:"observability"`
	Threats         []Threat       `json:"threats"`
	Criticality     []Criticality  `json:"criticality"`
	TopAbusePaths   []string       `json:"top_abuse_path_links"`
	FocusPaths      []FocusPath    `json:"focus_paths"`
	Supersessions   []Supersession `json:"supersessions"`
}

// Criticality defines what one priority level means for this project, with
// worked examples. Priority is a schema-owned vocabulary, so a document
// that ranks threats by it without saying what its levels mean leaves the
// most consequential field in the model unfalsifiable: a reader cannot tell
// a miscalibrated ranking from a disagreement about the scale. The level is
// the record's key; there is no separate identifier because nothing links
// to a calibration entry.
type Criticality struct {
	Level      string   `json:"level"`
	Definition string   `json:"definition"`
	Examples   []string `json:"examples"`
}

// FocusPath points a reviewer at a repository location that deserves
// scrutiny, and names the threats that make it worth scrutinising. It is
// the model's link from a threat to where that threat actually lives, which
// no other collection carries: components describe the system, and evidence
// describes what will test it, but neither says where to read. The path is
// the record's key.
type FocusPath struct {
	Path        string   `json:"path"`
	Why         string   `json:"why"`
	ThreatLinks []string `json:"threat_links"`
}

// Scope records what the review covered and what it deliberately did not.
type Scope struct {
	InScope    []string `json:"in_scope"`
	OutOfScope []string `json:"out_of_scope"`
}

// Assumption records a condition the analysis relies on and what follows if
// the condition does not hold.
type Assumption struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Effect    string `json:"effect"`
}

// Reference points at supporting material: either a repository-relative
// path or an HTTPS URL on a consumer-allowlisted host, never both. A
// repository-relative path is version-pinned with the document, so it stays
// reproducible across revisions; an external URL does not, which is why the
// consumer must declare its host before one is accepted.
type Reference struct {
	Path string `json:"path,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Diagram links a reviewed diagram into the rendered companion. The tool
// neither generates nor parses diagram source: it carries the reference and
// renders it as a link.
type Diagram struct {
	Caption string `json:"caption"`
	Reference
}

// Component is one deployable or logical part of the modelled system.
type Component struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Zone     string `json:"zone"`
	Purpose  string `json:"purpose"`
	Evidence string `json:"evidence"`
}

// Actor is a principal that interacts with the system, trusted or not.
type Actor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Trust       string `json:"trust"`
	Description string `json:"description"`
}

// AttackerModel bounds the review by stating what the attacker is assumed
// able to do, and — just as load-bearing — what they are assumed unable to
// do. Both sides are required so the bound is explicit rather than implied.
type AttackerModel struct {
	Capabilities    []string `json:"capabilities"`
	NonCapabilities []string `json:"non_capabilities"`
}

// Asset is a protected asset threats can affect, with the security
// objective that protection is measured against.
type Asset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Objective   string `json:"objective"`
}

// Boundary is a trust boundary between two components, with the data and
// channels that cross it, the guarantees planned for it, and how far those
// guarantees have actually been implemented.
type Boundary struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Source              string   `json:"source"`
	Destination         string   `json:"destination"`
	Data                []string `json:"data"`
	Channels            []string `json:"channels"`
	SecurityGuarantees  []string `json:"security_guarantees"`
	Validation          []string `json:"validation"`
	ImplementationState string   `json:"implementation_state"`
	Evidence            string   `json:"evidence"`
}

// DataFlow is an ordered path through the system, naming the boundaries it
// crosses and the data it carries.
type DataFlow struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Sequence   []string `json:"sequence"`
	Boundaries []string `json:"boundaries"`
	Data       []string `json:"data"`
}

// EntryPoint is an externally reachable surface, tied to the boundary it
// sits on and the flows that reach it.
type EntryPoint struct {
	ID       string   `json:"id"`
	Surface  string   `json:"surface"`
	Reached  string   `json:"reached"`
	Boundary string   `json:"boundary"`
	Flows    []string `json:"flows"`
	Notes    string   `json:"notes"`
	Evidence string   `json:"evidence"`
}

// Decision is an accepted or pending design decision (an ADR) that controls
// may cite as their justification.
type Decision struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Reference
}

// Risk is an entry in the project's risk register that a threat may charge
// residual risk against.
type Risk struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Reference
}

// Control is a planned or existing countermeasure. Its traceability links
// are individually optional but collectively required: a control that
// justifies nothing is not a control.
type Control struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	Status             string   `json:"status"`
	Owner              *Owner   `json:"owner"`
	RequirementLinks   []string `json:"requirement_links"`
	DecisionLinks      []string `json:"decision_links"`
	RiskLinks          []string `json:"risk_links"`
	EvidenceLinks      []string `json:"evidence_links"`
	ImplementationNote string   `json:"implementation_note"`
}

// Evidence is a planned test or other verification that will demonstrate a
// threat is handled. It names the threats it covers so coverage is a
// property of the document rather than of a reviewer's memory.
type Evidence struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Level       string   `json:"level"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	Owner       *Owner   `json:"owner"`
	ThreatLinks []string `json:"threat_links"`
}

// Observation is an observability expectation for one surface: the signals
// operations must be able to see, what must never be logged, and the
// condition that should raise an alert.
type Observation struct {
	ID             string   `json:"id"`
	Surface        string   `json:"surface"`
	Signals        []string `json:"signals"`
	Redaction      []string `json:"redaction"`
	AlertCondition string   `json:"alert_condition"`
	ControlLinks   []string `json:"control_links"`
}

// Threat is one stably identified threat and its abuse path, carrying the
// analysis (likelihood, severity, priority and their rationales), the
// treatment decision, the accountable owner, and the residual risk left
// after treatment.
type Threat struct {
	ID                     string   `json:"id"`
	Title                  string   `json:"title"`
	Source                 string   `json:"source"`
	Prerequisites          string   `json:"prerequisites"`
	Action                 string   `json:"action"`
	Impact                 string   `json:"impact"`
	AbusePath              []string `json:"abuse_path"`
	Likelihood             string   `json:"likelihood"`
	LikelihoodRationale    string   `json:"likelihood_rationale"`
	Severity               string   `json:"severity"`
	ImpactRationale        string   `json:"impact_rationale"`
	Priority               string   `json:"priority"`
	Treatment              string   `json:"treatment"`
	TreatmentRationale     string   `json:"treatment_rationale,omitempty"`
	Owner                  *Owner   `json:"owner"`
	ResidualRisk           string   `json:"residual_risk"`
	ExistingControls       string   `json:"existing_controls"`
	Gaps                   string   `json:"gaps"`
	RecommendedMitigations string   `json:"recommended_mitigations"`
	DetectionIdeas         string   `json:"detection_ideas"`
	ActorLinks             []string `json:"actor_links"`
	AssetLinks             []string `json:"asset_links"`
	BoundaryLinks          []string `json:"boundary_links"`
	FlowLinks              []string `json:"flow_links"`
	ControlLinks           []string `json:"control_links"`
	RiskLinks              []string `json:"risk_links"`
	EvidenceLinks          []string `json:"evidence_links"`
}

// Owner separates the accountable principal — the person answerable for the
// residual risk — from the milestone, issue, and workstream that merely
// route the work. Routing changes as plans change; accountability does not.
type Owner struct {
	Principal  string  `json:"principal"`
	Milestone  string  `json:"milestone"`
	Issue      *string `json:"issue"`
	Workstream string  `json:"workstream"`
}

// Supersession retires a threat ID in favor of its replacements. Entries
// are append-only across accepted revisions.
type Supersession struct {
	RetiredID      string   `json:"retired_id"`
	ReplacementIDs []string `json:"replacement_ids"`
	Rationale      string   `json:"rationale"`
}

// ReachesEntryPoint reports whether this threat reaches entry the way an
// attacker would: across its trust boundary *and* along one of its data
// flows. Matching either half alone does not count — a threat that crosses
// the same boundary by a different route has not analysed this surface.
//
// This is the single definition of that predicate. Both the coverage rule
// that certifies an entry point and the renderer that lists its threats
// call it, so the rendered companion can never disagree with what
// validation accepted.
func (t Threat) ReachesEntryPoint(entry EntryPoint) bool {
	if !containsString(t.BoundaryLinks, entry.Boundary) {
		return false
	}
	for _, flow := range entry.Flows {
		if containsString(t.FlowLinks, flow) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// HasRequirementLinks reports whether any control links to a requirement
// ID. Requirement links hang off controls, not threats: a threat is handled
// because a control addresses it, and that control is what a requirement
// obliges the project to build.
func (doc Document) HasRequirementLinks() bool {
	for _, control := range doc.Controls {
		if len(control.RequirementLinks) > 0 {
			return true
		}
	}
	return false
}

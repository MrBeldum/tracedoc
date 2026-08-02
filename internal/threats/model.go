// Package threats defines the threat-model document schema, its structural
// and cross-reference validation (including optional resolution of
// requirement links against a requirements matrix), and its cross-version
// comparison. Consumer-specific policy is supplied through policy.Config.
package threats

// SchemaVersion is the threat-model document schema this release of the
// tool reads, validates, renders, and compares.
const SchemaVersion = 1

// Document is one threat-model snapshot.
type Document struct {
	DocumentType    string         `json:"document_type"`
	SchemaVersion   int            `json:"schema_version"`
	DocumentVersion string         `json:"document_version"`
	LastReviewed    string         `json:"last_reviewed"`
	Assets          []Asset        `json:"assets"`
	TrustBoundaries []Boundary     `json:"trust_boundaries"`
	Threats         []Threat       `json:"threats"`
	Supersessions   []Supersession `json:"supersessions"`
}

// Asset is a protected asset threats can affect.
type Asset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Boundary is a trust boundary threats can cross.
type Boundary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Threat is one stably identified threat or abuse path.
type Threat struct {
	ID                   string       `json:"id"`
	Title                string       `json:"title"`
	Description          string       `json:"description"`
	Severity             string       `json:"severity"`
	Disposition          string       `json:"disposition"`
	DispositionRationale string       `json:"disposition_rationale,omitempty"`
	AffectedAssets       []string     `json:"affected_assets"`
	TrustBoundaries      []string     `json:"trust_boundaries"`
	Owner                *Owner       `json:"owner"`
	Mitigations          *Mitigations `json:"mitigations"`
}

// Owner routes a threat to its accountable milestone, optional work record,
// and responsibility classification.
type Owner struct {
	Milestone  string  `json:"milestone"`
	Issue      *string `json:"issue"`
	Workstream string  `json:"workstream"`
}

// Mitigations links a threat to its controls and dispositions evidence.
type Mitigations struct {
	ADRs         []string `json:"adrs"`
	Requirements []string `json:"requirements"`
	Tests        []string `json:"tests"`
	Risks        []string `json:"risks"`
}

// Supersession retires a threat ID in favor of its replacements. Entries
// are append-only across accepted revisions.
type Supersession struct {
	RetiredID      string   `json:"retired_id"`
	ReplacementIDs []string `json:"replacement_ids"`
	Rationale      string   `json:"rationale"`
}

// HasRequirementLinks reports whether any threat links to a requirement ID.
func (doc Document) HasRequirementLinks() bool {
	for _, threat := range doc.Threats {
		if threat.Mitigations != nil && len(threat.Mitigations.Requirements) > 0 {
			return true
		}
	}
	return false
}

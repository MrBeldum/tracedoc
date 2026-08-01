// Package matrix defines the versioned requirements-matrix document model,
// its structural and cross-reference validation, and cross-version baseline
// comparison. Consumer-specific policy is supplied through policy.Config.
package matrix

// SchemaVersion is the requirements-matrix document schema this release of
// the tool reads, validates, renders, and compares.
const SchemaVersion = 1

// MaxDocumentBytes bounds the size of a matrix document.
const MaxDocumentBytes = 8 << 20

// MaxStringBytes bounds every validated string field.
const MaxStringBytes = 16 << 10

// Document is one requirements-matrix snapshot.
type Document struct {
	SchemaVersion int            `json:"schema_version"`
	MatrixVersion string         `json:"matrix_version"`
	LastReviewed  string         `json:"last_reviewed"`
	Standards     []Standard     `json:"standards"`
	Requirements  []Requirement  `json:"requirements"`
	Supersessions []Supersession `json:"supersessions"`
}

// Standard is a normative source the matrix decomposes.
type Standard struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	URI   string `json:"uri"`
}

// Requirement is one atomic, stably identified obligation.
type Requirement struct {
	ID                     string        `json:"id"`
	Title                  string        `json:"title"`
	Standard               string        `json:"standard"`
	Citations              []Citation    `json:"citations"`
	Interpretation         string        `json:"interpretation"`
	Applicability          string        `json:"applicability"`
	ApplicabilityRationale string        `json:"applicability_rationale,omitempty"`
	Owner                  *Owner        `json:"owner"`
	PlannedVerification    *Verification `json:"planned_verification"`
	EvidenceStatus         string        `json:"evidence_status"`
	Traceability           *Traceability `json:"traceability"`
}

// Citation is one clause-level normative reference.
type Citation struct {
	Standard string `json:"standard"`
	Clause   string `json:"clause"`
	URI      string `json:"uri"`
}

// Owner routes a requirement to its accountable milestone, optional work
// record, and responsibility classification.
type Owner struct {
	Milestone  string  `json:"milestone"`
	Issue      *string `json:"issue"`
	Workstream string  `json:"workstream"`
}

// Verification records planned verification levels and evidence identifiers.
type Verification struct {
	Levels   []string `json:"levels"`
	Evidence []string `json:"evidence"`
}

// Traceability cross-references decision records, threat controls, and risks.
type Traceability struct {
	ADRs    []string `json:"adrs"`
	Threats []string `json:"threats"`
	Risks   []string `json:"risks"`
}

// Supersession retires a requirement ID in favor of its replacements. Entries
// are append-only across accepted matrix revisions.
type Supersession struct {
	RetiredID      string   `json:"retired_id"`
	ReplacementIDs []string `json:"replacement_ids"`
	Rationale      string   `json:"rationale"`
}

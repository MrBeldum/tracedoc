package threats_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/check"
	"github.com/sofired/matrix-service/internal/policy"
	"github.com/sofired/matrix-service/internal/testsupport"
	"github.com/sofired/matrix-service/internal/threats"
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
		{
			name: "wrong document type",
			want: `document_type: expected "threat_model"`,
			mutate: func(doc *threats.Document) {
				doc.DocumentType = "requirements"
			},
		},
		{
			name: "unsupported schema version",
			want: "schema_version: expected 1",
			mutate: func(doc *threats.Document) {
				doc.SchemaVersion = 2
			},
		},
		{
			name: "malformed document version",
			want: "expected a semantic version",
			mutate: func(doc *threats.Document) {
				doc.DocumentVersion = "1.0.0-01"
			},
		},
		{
			name: "invalid review date",
			want: "expected an RFC 3339 full date",
			mutate: func(doc *threats.Document) {
				doc.LastReviewed = "2026-02-30"
			},
		},
		{
			name: "duplicate threat ID",
			want: `duplicate threat ID "THRT-001"`,
			mutate: func(doc *threats.Document) {
				doc.Threats = append(doc.Threats, doc.Threats[0])
			},
		},
		{
			name: "invalid threat ID format",
			want: "expected a stable threat ID",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].ID = "thrt-1"
			},
		},
		{
			name: "threat ID with asset prefix",
			want: "threat IDs must not use the asset or trust-boundary prefix",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].ID = "AST-009"
			},
		},
		{
			name: "unsupported severity",
			want: `severity: unsupported value "catastrophic"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Severity = "catastrophic"
			},
		},
		{
			name: "unsupported disposition",
			want: `disposition: unsupported value "ignored"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Disposition = "ignored"
			},
		},
		{
			name: "accepted without rationale",
			want: "disposition_rationale: required for accepted",
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").DispositionRationale = ""
			},
		},
		{
			name: "accepted without risk record",
			want: "accepted threat requires at least one risk record",
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").Mitigations.Risks = []string{}
			},
		},
		{
			name: "mitigated without mitigation",
			want: "mitigated threat requires at least one ADR, requirement, or test",
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-001").Mitigations.Requirements = []string{}
				threatByID(t, doc, "THRT-001").Mitigations.Tests = []string{}
			},
		},
		{
			name: "missing owner",
			want: "owner: expected an object",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Owner = nil
			},
		},
		{
			name: "invalid milestone",
			want: "owner.milestone: invalid milestone",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Owner.Milestone = "M12"
			},
		},
		{
			name: "unknown workstream",
			want: "owner.workstream: unknown workstream",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Owner.Workstream = "Unknown"
			},
		},
		{
			name: "empty affected assets",
			want: "affected_assets: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].AffectedAssets = []string{}
			},
		},
		{
			name: "unknown asset",
			want: `unknown asset "AST-999"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].AffectedAssets = []string{"AST-999"}
			},
		},
		{
			name: "unknown trust boundary",
			want: `unknown trust boundary "TB-999"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].TrustBoundaries = []string{"TB-999"}
			},
		},
		{
			name: "nil trust boundaries",
			want: "trust_boundaries: expected an array",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].TrustBoundaries = nil
			},
		},
		{
			name: "duplicate asset ID",
			want: `duplicate asset ID "AST-001"`,
			mutate: func(doc *threats.Document) {
				doc.Assets = append(doc.Assets, doc.Assets[0])
			},
		},
		{
			name: "invalid asset ID",
			want: "expected a stable asset ID",
			mutate: func(doc *threats.Document) {
				doc.Assets[0].ID = "ASSET-1"
			},
		},
		{
			name: "duplicate boundary ID",
			want: `duplicate trust-boundary ID "TB-001"`,
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries = append(doc.TrustBoundaries, doc.TrustBoundaries[0])
			},
		},
		{
			name: "unreferenced asset",
			want: `assets: "AST-003" has no referencing threat`,
			mutate: func(doc *threats.Document) {
				doc.Assets = append(doc.Assets, threats.Asset{
					ID:          "AST-003",
					Name:        "Unused asset",
					Description: "Never referenced by a threat.",
				})
			},
		},
		{
			name: "unreferenced boundary",
			want: `trust_boundaries: "TB-002" has no referencing threat`,
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries = append(doc.TrustBoundaries, threats.Boundary{
					ID:          "TB-002",
					Name:        "Unused boundary",
					Description: "Never referenced by a threat.",
				})
			},
		},
		{
			name: "missing mitigations",
			want: "mitigations: expected an object",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations = nil
			},
		},
		{
			name: "invalid risk",
			want: `invalid risk "R13"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Risks = []string{"R13"}
			},
		},
		{
			name: "invalid requirement link format",
			want: `invalid requirement ID "excore-1"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Requirements = []string{"excore-1"}
			},
		},
		{
			name: "unknown requirement link",
			want: `unknown requirement "MISSING-001"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Requirements = []string{"MISSING-001"}
			},
		},
		{
			name: "retired requirement link",
			want: `requirement "EXCORE-900" is retired; replacements: EXCORE-001`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Requirements = []string{"EXCORE-900"}
			},
		},
		{
			name: "withdrawn requirement link",
			want: `requirement "EXCORE-901" was withdrawn without a replacement`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Requirements = []string{"EXCORE-901"}
			},
		},
		{
			name: "supersession retired ID still active",
			want: "retired ID is still active",
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].RetiredID = "THRT-003"
			},
		},
		{
			name: "duplicate retired ID",
			want: `duplicate retired ID "THRT-900"`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions = append(doc.Supersessions, threats.Supersession{
					RetiredID:      "THRT-900",
					ReplacementIDs: []string{"THRT-002"},
					Rationale:      "Duplicate ledger entry.",
				})
			},
		},
		{
			name: "unknown supersession replacement",
			want: `unknown active ID "THRT-999"`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"THRT-999"}
			},
		},
		{
			name: "oversized rationale",
			want: "disposition_rationale: exceeds 16384-byte limit",
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-002").DispositionRationale =
					strings.Repeat("x", 16385)
			},
		},
		{
			name: "blank description",
			want: "threats[0].description: expected a non-empty string",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Description = ""
			},
		},
		{
			name: "blank mitigations test item",
			want: "mitigations.tests[0]: expected a non-empty string",
			mutate: func(doc *threats.Document) {
				threatByID(t, doc, "THRT-001").Mitigations.Tests = []string{""}
			},
		},
		{
			name: "empty assets array",
			want: "assets: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.Assets = []threats.Asset{}
			},
		},
		{
			name: "empty trust boundaries array",
			want: "trust_boundaries: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.TrustBoundaries = []threats.Boundary{}
			},
		},
		{
			name: "empty threats array",
			want: "threats: expected a non-empty array",
			mutate: func(doc *threats.Document) {
				doc.Threats = []threats.Threat{}
			},
		},
		{
			name: "nil supersessions",
			want: "supersessions: expected an array",
			mutate: func(doc *threats.Document) {
				doc.Supersessions = nil
			},
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

// TestOwnerMilestoneAndIssueAreBoundedAndControlCharacterFree is the
// security-regression coverage for Owner.Milestone and Owner.Issue: before
// this fix they were validated solely by the consumer-supplied pattern, so
// a permissive pattern let an oversized or control-character-bearing value
// straight through, in violation of the documented 16 KiB bound every
// validated string field must observe.
func TestOwnerMilestoneAndIssueAreBoundedAndControlCharacterFree(t *testing.T) {
	pol := fixturePolicy(t)

	t.Run("oversized milestone", func(t *testing.T) {
		doc := fixtureDocument(t)
		doc.Threats[0].Owner.Milestone = strings.Repeat("M", check.MaxStringBytes+1)
		errs := threats.Validate(doc, pol, fixtureIndex())
		if !strings.Contains(errs.Error(), "exceeds 16384-byte limit") {
			t.Fatalf("expected oversized-milestone rejection, got:\n%s", errs)
		}
	})

	t.Run("issue with a control character is rejected even under a permissive pattern", func(t *testing.T) {
		// This is the security-regression test: the pattern below accepts
		// any string, including one carrying a newline, so a value only
		// the length/control-character bound can catch must still be
		// rejected.
		permissive := pol
		permissive.Issue = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		issue := "#36\nmalicious content"
		doc.Threats[0].Owner.Issue = &issue

		errs := threats.Validate(doc, permissive, fixtureIndex())
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected control-character rejection under a permissive pattern, got:\n%s", errs)
		}
	})
}

// TestSeverityLowValidatesCleanly is positive enum coverage: "low" is a
// legal severity value, not just a value that must be rejected when
// unsupported.
func TestSeverityLowValidatesCleanly(t *testing.T) {
	pol := fixturePolicy(t)
	doc := fixtureDocument(t)
	threatByID(t, &doc, "THRT-003").Severity = "low"
	if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
		t.Fatalf("severity %q rejected:\n%s", "low", errs)
	}
}

// TestDispositionRationaleEnumCoverage is positive and negative enum
// coverage for the two disposition values not otherwise exercised by the
// mutation table: "transferred" and "avoided" both require a rationale
// (rationaleRequired in validate.go), and both validate cleanly once one is
// supplied.
func TestDispositionRationaleEnumCoverage(t *testing.T) {
	pol := fixturePolicy(t)
	for _, disposition := range []string{"transferred", "avoided"} {
		t.Run(disposition+" with rationale validates cleanly", func(t *testing.T) {
			doc := fixtureDocument(t)
			threat := threatByID(t, &doc, "THRT-003")
			threat.Disposition = disposition
			threat.DispositionRationale = "Ownership " + disposition + " with a documented rationale."
			if errs := threats.Validate(doc, pol, fixtureIndex()); len(errs) > 0 {
				t.Fatalf("disposition %q with rationale rejected:\n%s", disposition, errs)
			}
		})
		t.Run(disposition+" without rationale is rejected", func(t *testing.T) {
			doc := fixtureDocument(t)
			threat := threatByID(t, &doc, "THRT-003")
			threat.Disposition = disposition
			threat.DispositionRationale = ""
			errs := threats.Validate(doc, pol, fixtureIndex())
			want := "required for " + disposition
			if !strings.Contains(errs.Error(), want) {
				t.Fatalf("expected %q, got:\n%s", want, errs)
			}
		})
	}
}

func TestRequirementLinksSkippedWithoutIndex(t *testing.T) {
	doc := fixtureDocument(t)
	doc.Threats[0].Mitigations.Requirements = []string{"MISSING-001"}
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
	for index := range doc.Threats {
		doc.Threats[index].Mitigations.Requirements = nil
	}
	if doc.HasRequirementLinks() {
		t.Fatal("expected no requirement links after clearing")
	}
}

// TestRiskEntriesAreControlFreeUnderPermissivePattern mirrors the owner
// regression test for the mitigations risks list: a consumer Risk pattern
// is policy, not a lexical safety net.
func TestRiskEntriesAreControlFreeUnderPermissivePattern(t *testing.T) {
	permissive := fixturePolicy(t)
	permissive.Risk = regexp.MustCompile(`(?s)^.*$`)

	doc := fixtureDocument(t)
	threatByID(t, &doc, "THRT-002").Mitigations.Risks = []string{"R12\x1b[31mred"}

	errs := threats.Validate(doc, permissive, fixtureIndex())
	if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
		t.Fatalf("expected control-character rejection for a risk entry, got:\n%s", errs)
	}
}

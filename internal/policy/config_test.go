package policy

import (
	"strings"
	"testing"

	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/testsupport"
	"github.com/sofired/tracedoc/internal/threats"
)

func loadFixtureConfig(t *testing.T) *Config {
	t.Helper()
	config, err := Load(testsupport.FixturePath(t, "config.json"))
	if err != nil {
		t.Fatalf("load fixture config: %v", err)
	}
	return config
}

func reloadMutated(t *testing.T, mutate func(*Config)) error {
	t.Helper()
	config := loadFixtureConfig(t)
	mutate(config)
	_, err := Load(testsupport.WriteJSON(t, config))
	return err
}

func TestFixtureConfigLoads(t *testing.T) {
	config := loadFixtureConfig(t)

	requirements, err := config.RequirementsPolicy()
	if err != nil {
		t.Fatalf("compile requirements policy: %v", err)
	}
	if len(requirements.RequiredStandards) != 3 ||
		requirements.StandardHosts["RFCX"] != "www.rfc-editor.org" ||
		requirements.LocalSources["LOCAL-PLAN"] != "../plan.md" {
		t.Fatalf("unexpected requirements policy: %#v", requirements)
	}
	if requirements.Milestone == nil || !requirements.Milestone.MatchString("M10") ||
		requirements.Milestone.MatchString("M12") {
		t.Fatal("milestone pattern not compiled as configured")
	}

	threatsPolicy, err := config.ThreatsPolicy()
	if err != nil {
		t.Fatalf("compile threats policy: %v", err)
	}
	if len(threatsPolicy.Workstreams) != 2 || threatsPolicy.Risk == nil {
		t.Fatalf("unexpected threats policy: %#v", threatsPolicy)
	}
	if threatsPolicy.Owner == nil || !threatsPolicy.Owner.MatchString("@security-lead") ||
		threatsPolicy.Owner.MatchString("Security Lead") {
		t.Fatal("owner pattern not compiled as configured")
	}
	if len(threatsPolicy.DocumentStatuses) != 2 ||
		len(threatsPolicy.ControlStatuses) != 3 ||
		len(threatsPolicy.EvidenceLevels) != 4 ||
		len(threatsPolicy.EvidenceStatuses) != 2 ||
		len(threatsPolicy.ReferenceHosts) != 2 {
		t.Fatalf("unexpected threat-model vocabularies: %#v", threatsPolicy)
	}
	if threatsPolicy.Limits != (threats.Limits{
		MinCriticalityExamples: 2,
		MinTopAbusePaths:       2,
		MaxTopAbusePaths:       10,
	}) {
		t.Fatalf("unexpected limits: %#v", threatsPolicy.Limits)
	}
	if threatsPolicy.Coverage != (threats.Coverage{
		Assets:      true,
		Boundaries:  true,
		Flows:       true,
		EntryPoints: true,
		Controls:    true,
		Risks:       true,
		Evidence:    true,
		Criticality: true,
	}) {
		t.Fatalf("unexpected coverage switches: %#v", threatsPolicy.Coverage)
	}

	rules := config.TransitionRules()
	if !rules.RequireVersionIncreaseOnChange ||
		!rules.RequireReviewDateAdvanceOnChange ||
		!rules.RequireMajorOnSchemaChange {
		t.Fatalf("unexpected transition rules: %#v", rules)
	}

	for _, docType := range []document.Type{
		document.TypeRequirements,
		document.TypeThreatModel,
	} {
		options, err := config.RenderOptions(docType)
		if err != nil {
			t.Fatalf("render options for %s: %v", docType, err)
		}
		if options.IssueURLBase != "https://github.com/example/project/issues/" ||
			options.GeneratorName != "tracedoc" ||
			options.SourceName == "" {
			t.Fatalf("unexpected render options for %s: %#v", docType, options)
		}
	}
}

func TestMissingSectionsAreRejectedOnUse(t *testing.T) {
	config := loadFixtureConfig(t)
	config.Requirements = nil
	config.ThreatModel = nil
	reloaded, err := Load(testsupport.WriteJSON(t, config))
	if err != nil {
		t.Fatalf("config without sections should load: %v", err)
	}
	if _, err := reloaded.RequirementsPolicy(); err == nil ||
		!strings.Contains(err.Error(), "no requirements section") {
		t.Fatalf("expected missing requirements section error, got %v", err)
	}
	if _, err := reloaded.ThreatsPolicy(); err == nil ||
		!strings.Contains(err.Error(), "no threat_model section") {
		t.Fatalf("expected missing threat_model section error, got %v", err)
	}
	if _, err := reloaded.RenderOptions(document.TypeThreatModel); err == nil {
		t.Fatal("expected missing render section error")
	}
}

func TestConfigRejections(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*Config)
	}{
		{
			name:   "unsupported config version",
			want:   "config_version: expected 1",
			mutate: func(c *Config) { c.ConfigVersion = 2 },
		},
		{
			name: "required standard without source",
			want: `required standard "ORPHAN" has no standard_sources entry`,
			mutate: func(c *Config) {
				c.Requirements.RequiredStandards = append(c.Requirements.RequiredStandards, "ORPHAN")
			},
		},
		{
			name: "duplicate required standard",
			want: `duplicate standard key "RFCX"`,
			mutate: func(c *Config) {
				c.Requirements.RequiredStandards = append(c.Requirements.RequiredStandards, "RFCX")
			},
		},
		{
			name: "source with host and path",
			want: "expected exactly one of host or path, not both",
			mutate: func(c *Config) {
				c.Requirements.StandardSources[0].Path = "plan.md"
			},
		},
		{
			name: "source with neither host nor path",
			want: "expected exactly one of host or path",
			mutate: func(c *Config) {
				c.Requirements.StandardSources[0].Host = ""
			},
		},
		{
			name: "uppercase host",
			want: "expected a lowercase DNS host name",
			mutate: func(c *Config) {
				c.Requirements.StandardSources[0].Host = "Standards.Example.Org"
			},
		},
		{
			name: "absolute local path",
			want: "expected a relative path",
			mutate: func(c *Config) {
				c.Requirements.StandardSources[2].Path = "/etc/passwd"
			},
		},
		{
			name: "local path with scheme",
			want: "contains a backslash or a scheme",
			mutate: func(c *Config) {
				c.Requirements.StandardSources[2].Path = "https://example.org/plan.md"
			},
		},
		{
			name:   "unanchored pattern",
			want:   "milestone_pattern: expected an anchored pattern",
			mutate: func(c *Config) { c.MilestonePattern = "M[0-9]+" },
		},
		{
			name:   "invalid pattern",
			want:   "issue_pattern: invalid pattern",
			mutate: func(c *Config) { c.IssuePattern = "^[$" },
		},
		{
			name:   "oversized pattern",
			want:   "risk_pattern: exceeds 256-byte limit",
			mutate: func(c *Config) { c.RiskPattern = "^" + strings.Repeat("a", 300) + "$" },
		},
		{
			name:   "empty workstreams",
			want:   "workstreams: expected a non-empty array",
			mutate: func(c *Config) { c.Workstreams = nil },
		},
		{
			name: "duplicate workstream",
			want: `duplicate value "Protocol"`,
			mutate: func(c *Config) {
				c.Workstreams = append(c.Workstreams, "Protocol")
			},
		},
		{
			name: "invalid verification level",
			want: `invalid value "Unit Test"`,
			mutate: func(c *Config) {
				c.Requirements.VerificationLevels = append(
					c.Requirements.VerificationLevels, "Unit Test",
				)
			},
		},
		{
			name:   "http issue base",
			want:   "expected an HTTPS URL",
			mutate: func(c *Config) { c.IssueURLBase = "http://example.org/issues/" },
		},
		{
			name: "issue base with query",
			want: "user information, ports, queries, and fragments are not allowed",
			mutate: func(c *Config) {
				c.IssueURLBase = "https://example.org/issues/?x="
			},
		},
		{
			name:   "issue base without trailing slash",
			want:   "expected a path ending in /",
			mutate: func(c *Config) { c.IssueURLBase = "https://example.org/issues" },
		},
		{
			name:   "empty generator name",
			want:   "generator_name: expected a non-empty string",
			mutate: func(c *Config) { c.GeneratorName = " " },
		},
		{
			name:   "empty requirements regenerate command",
			want:   "requirements.render.regenerate_command: expected a non-empty string",
			mutate: func(c *Config) { c.Requirements.Render.RegenerateCommand = " " },
		},
		{
			name:   "control character in threat-model command",
			want:   "threat_model.render.check_command: contains a control character",
			mutate: func(c *Config) { c.ThreatModel.Render.CheckCommand = "matrix\nrender" },
		},
		{
			name:   "empty standard sources array",
			want:   "requirements.standard_sources: expected a non-empty array",
			mutate: func(c *Config) { c.Requirements.StandardSources = []StandardSource{} },
		},
		{
			name:   "nil required standards",
			want:   "requirements.required_standards: expected an array",
			mutate: func(c *Config) { c.Requirements.RequiredStandards = nil },
		},
		{
			name:   "malformed key in standard sources",
			want:   "requirements.standard_sources[0].key: expected a stable standard key",
			mutate: func(c *Config) { c.Requirements.StandardSources[0].Key = "example-core" },
		},
		{
			name:   "malformed key in required standards",
			want:   "requirements.required_standards[0]: expected a stable standard key",
			mutate: func(c *Config) { c.Requirements.RequiredStandards[0] = "example-core" },
		},
		{
			name:   "single-label host",
			want:   "expected a lowercase DNS host name",
			mutate: func(c *Config) { c.Requirements.StandardSources[0].Host = "localhost" },
		},
		{
			name:   "missing owner pattern",
			want:   "threat_model.owner_pattern: expected a non-empty pattern",
			mutate: func(c *Config) { c.ThreatModel.OwnerPattern = "" },
		},
		{
			name:   "unanchored owner pattern",
			want:   "threat_model.owner_pattern: expected an anchored pattern",
			mutate: func(c *Config) { c.ThreatModel.OwnerPattern = "@[a-z]+" },
		},
		{
			name:   "empty document statuses",
			want:   "threat_model.document_statuses: expected a non-empty array",
			mutate: func(c *Config) { c.ThreatModel.DocumentStatuses = nil },
		},
		{
			name:   "malformed control status",
			want:   `threat_model.control_statuses[0]: invalid value "Planned"`,
			mutate: func(c *Config) { c.ThreatModel.ControlStatuses[0] = "Planned" },
		},
		{
			name:   "duplicate evidence level",
			want:   "threat_model.evidence_levels[1]: duplicate value",
			mutate: func(c *Config) { c.ThreatModel.EvidenceLevels[1] = c.ThreatModel.EvidenceLevels[0] },
		},
		{
			name:   "single-label reference host",
			want:   "threat_model.reference_hosts[0]: expected a lowercase DNS host name",
			mutate: func(c *Config) { c.ThreatModel.ReferenceHosts[0] = "localhost" },
		},
		{
			name:   "negative limit",
			want:   "threat_model.limits.min_criticality_examples: expected a non-negative integer",
			mutate: func(c *Config) { c.ThreatModel.Limits.MinCriticalityExamples = -1 },
		},
		{
			name:   "negative headline-list minimum",
			want:   "threat_model.limits.min_top_abuse_paths: expected a non-negative integer",
			mutate: func(c *Config) { c.ThreatModel.Limits.MinTopAbusePaths = -1 },
		},
		{
			name:   "negative headline-list maximum",
			want:   "threat_model.limits.max_top_abuse_paths: expected a non-negative integer",
			mutate: func(c *Config) { c.ThreatModel.Limits.MaxTopAbusePaths = -1 },
		},
		{
			name: "top abuse path maximum below its minimum",
			want: "threat_model.limits.max_top_abuse_paths: must not be smaller than min_top_abuse_paths (9)",
			mutate: func(c *Config) {
				c.ThreatModel.Limits.MinTopAbusePaths = 9
				c.ThreatModel.Limits.MaxTopAbusePaths = 3
			},
		},
		{
			name: "duplicate reference host",
			want: `threat_model.reference_hosts[1]: duplicate host`,
			mutate: func(c *Config) {
				c.ThreatModel.ReferenceHosts[1] = c.ThreatModel.ReferenceHosts[0]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := reloadMutated(t, test.mutate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestConfigRejectsUnknownMember(t *testing.T) {
	_, err := Load(testsupport.WriteRaw(t, []byte(`{"config_version":1,"extra":true}`)))
	if err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
}

// TestEmptyReferenceHostsIsLegal covers the deliberate default: a consumer
// that declares no reference hosts accepts repository-relative references
// only, which is the reproducible choice rather than a misconfiguration.
func TestEmptyReferenceHostsIsLegal(t *testing.T) {
	config := loadFixtureConfig(t)
	config.ThreatModel.ReferenceHosts = nil
	reloaded, err := Load(testsupport.WriteJSON(t, config))
	if err != nil {
		t.Fatalf("config without reference hosts should load: %v", err)
	}
	pol, err := reloaded.ThreatsPolicy()
	if err != nil {
		t.Fatalf("compile threats policy: %v", err)
	}
	if len(pol.ReferenceHosts) != 0 {
		t.Fatalf("expected an empty allowlist, got %#v", pol.ReferenceHosts)
	}
}

// TestLimitBoundaryCasesLoad covers the two shapes a bounds check is
// easiest to get wrong, both of which must be accepted: a minimum with no
// maximum, and a minimum equal to its maximum. The rejection cases sit far
// from the boundary, so without these an off-by-one in either direction —
// treating an unset maximum as a cap of zero, or rejecting min == max —
// would ship undetected.
func TestLimitBoundaryCasesLoad(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "minimum set with no maximum",
			mutate: func(c *Config) {
				c.ThreatModel.Limits.MinTopAbusePaths = 5
				c.ThreatModel.Limits.MaxTopAbusePaths = 0
			},
		},
		{
			name: "minimum equal to maximum",
			mutate: func(c *Config) {
				c.ThreatModel.Limits.MinTopAbusePaths = 3
				c.ThreatModel.Limits.MaxTopAbusePaths = 3
			},
		},
		{
			name:   "every limit unset",
			mutate: func(c *Config) { c.ThreatModel.Limits = Limits{} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := reloadMutated(t, test.mutate); err != nil {
				t.Fatalf("configuration should load: %v", err)
			}
		})
	}
}

// TestLocalPathSharesTheDocumentRule pins the consolidation. The
// configuration's own copy of these rules swept only ASCII space and tab,
// so a path carrying a non-breaking space passed configuration validation
// while the identical text in a document was rejected. Both now run the
// same check, and the configuration keeps only its tighter length bound.
func TestLocalPathSharesTheDocumentRule(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "non-breaking space",
			path: "docs/a b.md",
			want: "contains whitespace or a control character",
		},
		{
			name: "unicode line separator",
			path: "docs/a b.md",
			want: "contains whitespace or a control character",
		},
		{
			name: "absolute",
			path: "/etc/passwd",
			want: "expected a relative path",
		},
		{
			// The configuration's bound, not the document's 16 KiB one:
			// someone editing a config file is better served by the limit
			// that actually applies to them.
			name: "beyond the configuration bound",
			path: strings.Repeat("a", maxValueBytes+1),
			want: "exceeds 256-byte limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := reloadMutated(t, func(c *Config) {
				c.Requirements.StandardSources[2].Path = test.path
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

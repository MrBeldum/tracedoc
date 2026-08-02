package policy

import (
	"strings"
	"testing"

	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/testsupport"
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
			want: "contains whitespace, a control character, a backslash, or a scheme",
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

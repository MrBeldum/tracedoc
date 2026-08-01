package policy

import (
	"strings"
	"testing"

	"github.com/sofired/reqmatrix/internal/testsupport"
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
	policy := config.MatrixPolicy()
	if len(policy.RequiredStandards) != 3 ||
		policy.StandardHosts["RFCX"] != "www.rfc-editor.org" ||
		policy.LocalSources["LOCAL-PLAN"] != "../plan.md" {
		t.Fatalf("unexpected compiled policy: %#v", policy)
	}
	if policy.Milestone == nil || !policy.Milestone.MatchString("M10") ||
		policy.Milestone.MatchString("M12") {
		t.Fatal("milestone pattern not compiled as configured")
	}
	rules := config.TransitionRules()
	if !rules.RequireVersionIncreaseOnChange ||
		!rules.RequireReviewDateAdvanceOnChange ||
		!rules.RequireMajorOnSchemaChange {
		t.Fatalf("unexpected transition rules: %#v", rules)
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
				c.RequiredStandards = append(c.RequiredStandards, "ORPHAN")
			},
		},
		{
			name: "duplicate required standard",
			want: `duplicate standard key "RFCX"`,
			mutate: func(c *Config) {
				c.RequiredStandards = append(c.RequiredStandards, "RFCX")
			},
		},
		{
			name: "source with host and path",
			want: "expected exactly one of host or path, not both",
			mutate: func(c *Config) {
				c.StandardSources[0].Path = "plan.md"
			},
		},
		{
			name: "source with neither host nor path",
			want: "expected exactly one of host or path",
			mutate: func(c *Config) {
				c.StandardSources[0].Host = ""
			},
		},
		{
			name: "uppercase host",
			want: "expected a lowercase DNS host name",
			mutate: func(c *Config) {
				c.StandardSources[0].Host = "Standards.Example.Org"
			},
		},
		{
			name: "single-label host",
			want: "expected a lowercase DNS host name",
			mutate: func(c *Config) {
				c.StandardSources[0].Host = "localhost"
			},
		},
		{
			name: "absolute local path",
			want: "expected a relative path",
			mutate: func(c *Config) {
				c.StandardSources[2].Path = "/etc/passwd"
			},
		},
		{
			name: "local path with scheme",
			want: "contains whitespace, a control character, a backslash, or a scheme",
			mutate: func(c *Config) {
				c.StandardSources[2].Path = "https://example.org/plan.md"
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
				c.VerificationLevels = append(c.VerificationLevels, "Unit Test")
			},
		},
		{
			name:   "http issue base",
			want:   "expected an HTTPS URL",
			mutate: func(c *Config) { c.Render.IssueURLBase = "http://example.org/issues/" },
		},
		{
			name: "issue base with query",
			want: "user information, ports, queries, and fragments are not allowed",
			mutate: func(c *Config) {
				c.Render.IssueURLBase = "https://example.org/issues/?x="
			},
		},
		{
			name:   "issue base without trailing slash",
			want:   "expected a path ending in /",
			mutate: func(c *Config) { c.Render.IssueURLBase = "https://example.org/issues" },
		},
		{
			name:   "empty regenerate command",
			want:   "render.regenerate_command: expected a non-empty string",
			mutate: func(c *Config) { c.Render.RegenerateCommand = " " },
		},
		{
			name:   "control character in command",
			want:   "render.check_command: contains a control character",
			mutate: func(c *Config) { c.Render.CheckCommand = "reqmatrix\nrender" },
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

// Package policy loads and validates the consumer-owned configuration file.
// The configuration is a bounded set of declarative knobs — allowed
// vocabularies, source-host rules, identifier formats, presentation strings,
// and version-transition switches. It is deliberately not a general-purpose
// validation language.
package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/strictjson"
)

// ConfigVersion is the configuration schema this release of the tool reads.
const ConfigVersion = 1

// MaxConfigBytes bounds the size of a configuration document.
const MaxConfigBytes = 1 << 20

const (
	maxPatternBytes = 256
	maxValueBytes   = 256
	maxCommandBytes = 1024
)

var (
	hostPattern = regexp.MustCompile(
		`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`,
	)
	levelPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Config is the consumer-owned policy for one requirements matrix.
type Config struct {
	ConfigVersion      int                `json:"config_version"`
	RequiredStandards  []string           `json:"required_standards"`
	StandardSources    []StandardSource   `json:"standard_sources"`
	MilestonePattern   string             `json:"milestone_pattern"`
	IssuePattern       string             `json:"issue_pattern"`
	RiskPattern        string             `json:"risk_pattern"`
	Workstreams        []string           `json:"workstreams"`
	VerificationLevels []string           `json:"verification_levels"`
	Render             Render             `json:"render"`
	VersionTransitions VersionTransitions `json:"version_transitions"`

	milestone *regexp.Regexp
	issue     *regexp.Regexp
	risk      *regexp.Regexp
}

// StandardSource declares where citations for one standard may point: either
// an exact HTTPS host or an exact repository-relative path, never both.
type StandardSource struct {
	Key  string `json:"key"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}

// Render holds consumer presentation choices used by the default template.
type Render struct {
	IssueURLBase      string `json:"issue_url_base"`
	SourceName        string `json:"source_name"`
	GeneratorName     string `json:"generator_name"`
	RegenerateCommand string `json:"regenerate_command"`
	CheckCommand      string `json:"check_command"`
}

// VersionTransitions selects which cross-version transition rules the
// compare command enforces beyond the always-on identity rules.
type VersionTransitions struct {
	RequireVersionIncreaseOnChange   bool `json:"require_version_increase_on_change"`
	RequireReviewDateAdvanceOnChange bool `json:"require_review_date_advance_on_change"`
	RequireMajorOnSchemaChange       bool `json:"require_major_on_schema_change"`
}

// Load reads, decodes, and validates the configuration at path.
func Load(path string) (*Config, error) {
	var config Config
	if err := strictjson.DecodeFile(path, MaxConfigBytes, "config", &config); err != nil {
		return nil, err
	}
	if errs := config.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("invalid config:\n%s", strings.Join(errs, "\n"))
	}
	return &config, nil
}

// MatrixPolicy converts the configuration into the compiled policy the
// matrix validator consumes.
func (c *Config) MatrixPolicy() matrix.Policy {
	result := matrix.Policy{
		RequiredStandards:  make(map[string]struct{}, len(c.RequiredStandards)),
		StandardHosts:      make(map[string]string),
		LocalSources:       make(map[string]string),
		Workstreams:        make(map[string]struct{}, len(c.Workstreams)),
		VerificationLevels: make(map[string]struct{}, len(c.VerificationLevels)),
		Milestone:          c.milestone,
		Issue:              c.issue,
		Risk:               c.risk,
	}
	for _, key := range c.RequiredStandards {
		result.RequiredStandards[key] = struct{}{}
	}
	for _, source := range c.StandardSources {
		if source.Path != "" {
			result.LocalSources[source.Key] = source.Path
		} else {
			result.StandardHosts[source.Key] = source.Host
		}
	}
	for _, value := range c.Workstreams {
		result.Workstreams[value] = struct{}{}
	}
	for _, value := range c.VerificationLevels {
		result.VerificationLevels[value] = struct{}{}
	}
	return result
}

// TransitionRules converts the configuration into compare-command rules.
func (c *Config) TransitionRules() matrix.TransitionRules {
	return matrix.TransitionRules{
		RequireVersionIncreaseOnChange:   c.VersionTransitions.RequireVersionIncreaseOnChange,
		RequireReviewDateAdvanceOnChange: c.VersionTransitions.RequireReviewDateAdvanceOnChange,
		RequireMajorOnSchemaChange:       c.VersionTransitions.RequireMajorOnSchemaChange,
	}
}

func (c *Config) validate() []string {
	var errs []string
	add := func(location, format string, args ...any) {
		errs = append(errs, location+": "+fmt.Sprintf(format, args...))
	}

	if c.ConfigVersion != ConfigVersion {
		add("config_version", "expected %d", ConfigVersion)
	}

	sourceKeys := make(map[string]struct{}, len(c.StandardSources))
	if len(c.StandardSources) == 0 {
		add("standard_sources", "expected a non-empty array")
	}
	for index, source := range c.StandardSources {
		location := fmt.Sprintf("standard_sources[%d]", index)
		if !matrix.StandardKeyPattern.MatchString(source.Key) {
			add(location+".key", "expected a stable standard key")
		} else if _, duplicate := sourceKeys[source.Key]; duplicate {
			add(location+".key", "duplicate standard key %q", source.Key)
		} else {
			sourceKeys[source.Key] = struct{}{}
		}
		switch {
		case source.Host != "" && source.Path != "":
			add(location, "expected exactly one of host or path, not both")
		case source.Host != "":
			if len(source.Host) > maxValueBytes || !hostPattern.MatchString(source.Host) {
				add(location+".host", "expected a lowercase DNS host name")
			}
		case source.Path != "":
			if err := validateLocalPath(source.Path); err != nil {
				add(location+".path", "%s", err.Error())
			}
		default:
			add(location, "expected exactly one of host or path")
		}
	}

	if c.RequiredStandards == nil {
		add("required_standards", "expected an array")
	}
	seenRequired := make(map[string]struct{}, len(c.RequiredStandards))
	for index, key := range c.RequiredStandards {
		location := fmt.Sprintf("required_standards[%d]", index)
		if !matrix.StandardKeyPattern.MatchString(key) {
			add(location, "expected a stable standard key")
			continue
		}
		if _, duplicate := seenRequired[key]; duplicate {
			add(location, "duplicate standard key %q", key)
		}
		seenRequired[key] = struct{}{}
		if _, ok := sourceKeys[key]; !ok {
			add(location, "required standard %q has no standard_sources entry", key)
		}
	}

	c.milestone = c.compilePattern(&errs, "milestone_pattern", c.MilestonePattern)
	c.issue = c.compilePattern(&errs, "issue_pattern", c.IssuePattern)
	c.risk = c.compilePattern(&errs, "risk_pattern", c.RiskPattern)

	validateValueList(&errs, "workstreams", c.Workstreams, nil)
	validateValueList(&errs, "verification_levels", c.VerificationLevels, levelPattern)

	c.validateRender(add)
	return errs
}

func (c *Config) compilePattern(errs *[]string, location, value string) *regexp.Regexp {
	add := func(format string, args ...any) {
		*errs = append(*errs, location+": "+fmt.Sprintf(format, args...))
	}
	if value == "" {
		add("expected a non-empty pattern")
		return nil
	}
	if len(value) > maxPatternBytes {
		add("exceeds %d-byte limit", maxPatternBytes)
		return nil
	}
	if !strings.HasPrefix(value, "^") || !strings.HasSuffix(value, "$") {
		add("expected an anchored pattern (^...$)")
		return nil
	}
	compiled, err := regexp.Compile(value)
	if err != nil {
		add("invalid pattern: %v", err)
		return nil
	}
	return compiled
}

func validateValueList(errs *[]string, location string, values []string, pattern *regexp.Regexp) {
	if len(values) == 0 {
		*errs = append(*errs, location+": expected a non-empty array")
		return
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		itemLocation := fmt.Sprintf("%s[%d]", location, index)
		switch {
		case strings.TrimSpace(value) == "" || len(value) > maxValueBytes:
			*errs = append(*errs, itemLocation+": expected a non-empty bounded string")
		case hasControlRune(value):
			*errs = append(*errs, itemLocation+": contains a control character")
		case pattern != nil && !pattern.MatchString(value):
			*errs = append(*errs, fmt.Sprintf("%s: invalid value %q", itemLocation, value))
		}
		if _, duplicate := seen[value]; duplicate {
			*errs = append(*errs, fmt.Sprintf("%s: duplicate value %q", itemLocation, value))
		}
		seen[value] = struct{}{}
	}
}

func (c *Config) validateRender(add func(location, format string, args ...any)) {
	base := c.Render.IssueURLBase
	if base == "" {
		add("render.issue_url_base", "expected a non-empty string")
	} else if err := validateIssueURLBase(base); err != nil {
		add("render.issue_url_base", "%s", err.Error())
	}
	validateLine(add, "render.source_name", c.Render.SourceName, maxValueBytes)
	validateLine(add, "render.generator_name", c.Render.GeneratorName, maxValueBytes)
	validateLine(add, "render.regenerate_command", c.Render.RegenerateCommand, maxCommandBytes)
	validateLine(add, "render.check_command", c.Render.CheckCommand, maxCommandBytes)
}

func validateLine(
	add func(location, format string, args ...any),
	location string,
	value string,
	limit int,
) {
	switch {
	case strings.TrimSpace(value) == "":
		add(location, "expected a non-empty string")
	case len(value) > limit:
		add(location, "exceeds %d-byte limit", limit)
	case hasControlRune(value):
		add(location, "contains a control character")
	}
}

func validateIssueURLBase(value string) error {
	if hasControlRune(value) || strings.ContainsAny(value, " \t\\") {
		return fmt.Errorf("contains whitespace, a control character, or a backslash")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" ||
		!hostPattern.MatchString(parsed.Hostname()) {
		return fmt.Errorf("expected an HTTPS URL with a lowercase DNS host")
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("user information, ports, queries, and fragments are not allowed")
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("expected a path ending in /")
	}
	return nil
}

func validateLocalPath(value string) error {
	if len(value) > maxValueBytes {
		return fmt.Errorf("exceeds %d-byte limit", maxValueBytes)
	}
	if hasControlRune(value) ||
		strings.ContainsAny(value, " \t\\") ||
		strings.Contains(value, ":") {
		return fmt.Errorf("contains whitespace, a control character, a backslash, or a scheme")
	}
	if strings.HasPrefix(value, "/") {
		return fmt.Errorf("expected a relative path")
	}
	return nil
}

func hasControlRune(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

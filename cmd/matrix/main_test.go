package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/testsupport"
	"github.com/sofired/matrix-service/internal/threats"
)

func runCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr)
	return exitCode, stdout.String(), stderr.String()
}

func fixtureArgs(t *testing.T) (string, string) {
	t.Helper()
	return testsupport.FixturePath(t, "config.json"), testsupport.FixturePath(t, "matrix.json")
}

func threatsFixture(t *testing.T) string {
	t.Helper()
	return testsupport.FixturePath(t, "threats.json")
}

func loadFixtureMatrix(t *testing.T, path string) matrix.Document {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture matrix: %v", err)
	}
	var doc matrix.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode fixture matrix: %v", err)
	}
	return doc
}

func loadFixtureThreats(t *testing.T) threats.Document {
	t.Helper()
	data, err := os.ReadFile(threatsFixture(t))
	if err != nil {
		t.Fatalf("read fixture threat model: %v", err)
	}
	var doc threats.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode fixture threat model: %v", err)
	}
	return doc
}

func TestHelpAndVersion(t *testing.T) {
	if exitCode, stdout, _ := runCommand(t, "help"); exitCode != 0 ||
		!strings.Contains(stdout, "Usage: matrix") {
		t.Fatalf("unexpected help result %d: %s", exitCode, stdout)
	}
	if exitCode, stdout, _ := runCommand(t, "version"); exitCode != 0 ||
		!strings.Contains(
			stdout,
			"cli-contract 1, requirements-schema 1, threat-model-schema 1, config 1",
		) {
		t.Fatalf("unexpected version result %d: %s", exitCode, stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	if exitCode, _, stderr := runCommand(t); exitCode != 2 ||
		!strings.Contains(stderr, "Usage: matrix") {
		t.Fatalf("expected usage on empty invocation, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(t, "unknown"); exitCode != 2 ||
		!strings.Contains(stderr, `unknown command "unknown"`) {
		t.Fatalf("expected unknown-command rejection, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(t, "validate"); exitCode != 2 ||
		!strings.Contains(stderr, "-config is required") ||
		!strings.Contains(stderr, "-doc is required") {
		t.Fatalf("expected required-flag errors, got %d: %s", exitCode, stderr)
	}
	config, matrixPath := fixtureArgs(t)
	if exitCode, _, stderr := runCommand(
		t, "validate", "-config", config, "-doc", matrixPath, "extra",
	); exitCode != 2 || !strings.Contains(stderr, "unexpected positional arguments") {
		t.Fatalf("expected positional-argument rejection, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(
		t, "render", "-config", config, "-doc", matrixPath,
	); exitCode != 2 || !strings.Contains(stderr, "-output is required") {
		t.Fatalf("expected render required-flag error, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(
		t, "compare", "-config", config,
	); exitCode != 2 ||
		!strings.Contains(stderr, "-baseline is required") ||
		!strings.Contains(stderr, "-candidate is required") {
		t.Fatalf("expected compare required-flag errors, got %d: %s", exitCode, stderr)
	}
}

func TestDocumentTypeDispatch(t *testing.T) {
	config, matrixPath := fixtureArgs(t)

	missingType := testsupport.WriteRaw(t, []byte(`{"schema_version":1}`))
	if exitCode, _, stderr := runCommand(
		t, "validate", "-config", config, "-doc", missingType,
	); exitCode != 2 || !strings.Contains(stderr, "missing document_type") {
		t.Fatalf("expected missing-type rejection, got %d: %s", exitCode, stderr)
	}

	unknownType := testsupport.WriteRaw(t, []byte(`{"document_type":"minutes"}`))
	if exitCode, _, stderr := runCommand(
		t, "validate", "-config", config, "-doc", unknownType,
	); exitCode != 2 || !strings.Contains(stderr, `unsupported document_type "minutes"`) {
		t.Fatalf("expected unknown-type rejection, got %d: %s", exitCode, stderr)
	}

	if exitCode, _, stderr := runCommand(
		t, "compare", "-config", config,
		"-baseline", matrixPath, "-candidate", threatsFixture(t),
	); exitCode != 2 || !strings.Contains(stderr, "document types differ") {
		t.Fatalf("expected type-mismatch rejection, got %d: %s", exitCode, stderr)
	}
}

func TestRejectedConfigThroughCLI(t *testing.T) {
	_, matrixPath := fixtureArgs(t)
	badConfig := testsupport.WriteRaw(t, []byte(`{"config_version":2}`))
	exitCode, _, stderr := runCommand(t, "validate", "-config", badConfig, "-doc", matrixPath)
	if exitCode != 2 || !strings.Contains(stderr, "cannot load config") {
		t.Fatalf("expected config rejection, got %d: %s", exitCode, stderr)
	}
}

func TestValidateRequirements(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	exitCode, stdout, stderr := runCommand(t, "validate", "-config", config, "-doc", matrixPath)
	if exitCode != 0 || !strings.Contains(stdout, "validated 4 requirements") {
		t.Fatalf("fixture validation failed %d: %s%s", exitCode, stdout, stderr)
	}

	doc := loadFixtureMatrix(t, matrixPath)
	doc.Requirements = append(doc.Requirements, doc.Requirements[0])
	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-doc", testsupport.WriteJSON(t, doc),
	)
	if exitCode != 1 || !strings.Contains(stderr, "duplicate requirement ID") {
		t.Fatalf("expected duplicate-ID rejection, got %d: %s", exitCode, stderr)
	}

	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-doc", filepath.Join(t.TempDir(), "absent.json"),
	)
	if exitCode != 2 || !strings.Contains(stderr, "cannot load document") {
		t.Fatalf("expected load failure, got %d: %s", exitCode, stderr)
	}

	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-doc", matrixPath,
		"-requirements", matrixPath,
	)
	if exitCode != 2 ||
		!strings.Contains(stderr, "-requirements applies only to threat-model documents") {
		t.Fatalf("expected -requirements rejection, got %d: %s", exitCode, stderr)
	}
}

func TestValidateThreatModel(t *testing.T) {
	config, matrixPath := fixtureArgs(t)

	exitCode, stdout, stderr := runCommand(
		t, "validate", "-config", config,
		"-doc", threatsFixture(t), "-requirements", matrixPath,
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 3 threats") {
		t.Fatalf("threat-model validation failed %d: %s%s", exitCode, stdout, stderr)
	}

	// The fixture links to requirement IDs, so -requirements is mandatory.
	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-doc", threatsFixture(t),
	)
	if exitCode != 2 ||
		!strings.Contains(stderr, "-requirements is required") {
		t.Fatalf("expected missing -requirements rejection, got %d: %s", exitCode, stderr)
	}

	// Without requirement links, -requirements is optional.
	unlinked := loadFixtureThreats(t)
	for index := range unlinked.Threats {
		unlinked.Threats[index].Mitigations.Requirements = []string{}
	}
	unlinked.Threats[0].Mitigations.ADRs = []string{"ADR-001"}
	exitCode, stdout, stderr = runCommand(
		t, "validate", "-config", config, "-doc", testsupport.WriteJSON(t, unlinked),
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 3 threats") {
		t.Fatalf("unlinked threat model failed %d: %s%s", exitCode, stdout, stderr)
	}

	// Kivaar#5 rejection classes through the CLI.
	rejections := []struct {
		name   string
		want   string
		mutate func(*threats.Document)
	}{
		{
			name: "duplicate threat ID",
			want: "duplicate threat ID",
			mutate: func(doc *threats.Document) {
				doc.Threats = append(doc.Threats, doc.Threats[0])
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
			name: "missing owner",
			want: "owner: expected an object",
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Owner = nil
			},
		},
		{
			name: "unresolved requirement link",
			want: `unknown requirement "MISSING-001"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Mitigations.Requirements = []string{"MISSING-001"}
			},
		},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			doc := loadFixtureThreats(t)
			test.mutate(&doc)
			exitCode, _, stderr := runCommand(
				t, "validate", "-config", config,
				"-doc", testsupport.WriteJSON(t, doc), "-requirements", matrixPath,
			)
			if exitCode != 1 || !strings.Contains(stderr, test.want) {
				t.Fatalf("expected %q with exit 1, got %d: %s", test.want, exitCode, stderr)
			}
		})
	}

	// An invalid requirements matrix behind -requirements is itself exit 1.
	badMatrix := loadFixtureMatrix(t, matrixPath)
	badMatrix.Requirements = append(badMatrix.Requirements, badMatrix.Requirements[0])
	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config,
		"-doc", threatsFixture(t), "-requirements", testsupport.WriteJSON(t, badMatrix),
	)
	if exitCode != 1 ||
		!strings.Contains(stderr, "requirements: ") ||
		!strings.Contains(stderr, "duplicate requirement ID") {
		t.Fatalf("expected invalid requirements rejection, got %d: %s", exitCode, stderr)
	}

	// -requirements must name a requirements document.
	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config,
		"-doc", threatsFixture(t), "-requirements", threatsFixture(t),
	)
	if exitCode != 2 ||
		!strings.Contains(stderr, "-requirements must name a requirements document") {
		t.Fatalf("expected wrong-type -requirements rejection, got %d: %s", exitCode, stderr)
	}
}

func TestRenderRoundTripAndCheck(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	for _, doc := range []struct {
		path string
		noun string
	}{
		{matrixPath, "requirements"},
		{threatsFixture(t), "threats"},
	} {
		outputPath := filepath.Join(t.TempDir(), "out.md")
		exitCode, stdout, stderr := runCommand(
			t, "render", "-config", config, "-doc", doc.path, "-output", outputPath,
		)
		if exitCode != 0 || !strings.Contains(stdout, doc.noun) {
			t.Fatalf("render failed %d: %s%s", exitCode, stdout, stderr)
		}
		exitCode, stdout, stderr = runCommand(
			t, "render", "-config", config, "-doc", doc.path, "-output", outputPath, "-check",
		)
		if exitCode != 0 || !strings.Contains(stdout, "rendered document is current") {
			t.Fatalf("freshness check failed %d: %s%s", exitCode, stdout, stderr)
		}
		if err := os.WriteFile(outputPath, []byte("stale\n"), 0o644); err != nil {
			t.Fatalf("write stale output: %v", err)
		}
		exitCode, _, stderr = runCommand(
			t, "render", "-config", config, "-doc", doc.path, "-output", outputPath, "-check",
		)
		if exitCode != 1 || !strings.Contains(stderr, "is stale") {
			t.Fatalf("expected stale-output rejection, got %d: %s", exitCode, stderr)
		}
	}

	exitCode, _, stderr := runCommand(
		t, "render", "-config", config, "-doc", matrixPath,
		"-output", filepath.Join(t.TempDir(), "absent.md"), "-check",
	)
	if exitCode != 1 || !strings.Contains(stderr, "cannot read rendered document") {
		t.Fatalf("expected missing-output rejection, got %d: %s", exitCode, stderr)
	}

	exitCode, _, stderr = runCommand(
		t, "render", "-config", config, "-doc", matrixPath,
		"-output", filepath.Join(t.TempDir(), "out.md"),
		"-template", filepath.Join(t.TempDir(), "absent.md.tmpl"),
	)
	if exitCode != 2 || !strings.Contains(stderr, "cannot render document") {
		t.Fatalf("expected template failure, got %d: %s", exitCode, stderr)
	}
}

func TestCompareCommand(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	exitCode, stdout, stderr := runCommand(
		t, "compare", "-config", config, "-baseline", matrixPath, "-candidate", matrixPath,
	)
	if exitCode != 0 || !strings.Contains(stdout, "legal successor") {
		t.Fatalf("identical requirements comparison failed %d: %s%s", exitCode, stdout, stderr)
	}

	exitCode, stdout, stderr = runCommand(
		t, "compare", "-config", config,
		"-baseline", threatsFixture(t), "-candidate", threatsFixture(t),
	)
	if exitCode != 0 || !strings.Contains(stdout, "legal successor") {
		t.Fatalf("identical threats comparison failed %d: %s%s", exitCode, stdout, stderr)
	}

	// A snapshot-valid candidate that is an illegal successor: the retained
	// supersession's replacement set changed relative to the baseline.
	candidate := loadFixtureMatrix(t, matrixPath)
	candidate.Supersessions[0].ReplacementIDs = []string{"RFCX-001"}
	candidate.DocumentVersion = "0.3.0"
	candidate.LastReviewed = "2026-08-01"
	exitCode, _, stderr = runCommand(
		t, "compare",
		"-config", config,
		"-baseline", matrixPath,
		"-candidate", testsupport.WriteJSON(t, candidate),
	)
	if exitCode != 1 ||
		!strings.Contains(stderr, `replacement IDs for retired ID "EXCORE-900" changed`) {
		t.Fatalf("expected changed-replacement rejection, got %d: %s", exitCode, stderr)
	}
}

func TestCompareCommandFailureCategories(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	base := loadFixtureMatrix(t, matrixPath)

	// Every mutation below still passes single-snapshot validation, so the
	// asserted failure can only come from the cross-version comparison.
	tests := []struct {
		name   string
		want   string
		mutate func(*matrix.Document)
	}{
		{
			name: "deletion",
			want: `requirement "EXCORE-002" was removed without a retained supersession`,
			mutate: func(doc *matrix.Document) {
				var kept []matrix.Requirement
				for _, item := range doc.Requirements {
					if item.ID != "EXCORE-002" {
						kept = append(kept, item)
					}
				}
				doc.Requirements = kept
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name: "reuse of a retired ID",
			want: `retired requirement ID "EXCORE-900" was reused`,
			mutate: func(doc *matrix.Document) {
				revived := doc.Requirements[0]
				revived.ID = "EXCORE-900"
				doc.Requirements = append(doc.Requirements, revived)
				doc.Supersessions = []matrix.Supersession{}
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name: "version transition",
			want: `does not increase baseline "0.2.0"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Title = "Reject every unauthenticated token request"
				doc.LastReviewed = "2026-08-01"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Requirements = append([]matrix.Requirement(nil), base.Requirements...)
			candidate.Supersessions = append([]matrix.Supersession(nil), base.Supersessions...)
			test.mutate(&candidate)
			exitCode, _, stderr := runCommand(
				t, "compare",
				"-config", config,
				"-baseline", matrixPath,
				"-candidate", testsupport.WriteJSON(t, candidate),
			)
			if exitCode != 1 || !strings.Contains(stderr, test.want) {
				t.Fatalf("expected %q with exit 1, got %d: %s", test.want, exitCode, stderr)
			}
		})
	}
}

func TestCompareCommandRejectsInvalidCandidate(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	candidate := loadFixtureMatrix(t, matrixPath)
	candidate.Requirements = append(candidate.Requirements, candidate.Requirements[0])
	exitCode, _, stderr := runCommand(
		t, "compare",
		"-config", config,
		"-baseline", matrixPath,
		"-candidate", testsupport.WriteJSON(t, candidate),
	)
	if exitCode != 1 ||
		!strings.Contains(stderr, "candidate: ") ||
		!strings.Contains(stderr, "duplicate requirement ID") {
		t.Fatalf("expected invalid-candidate rejection with exit 1, got %d: %s", exitCode, stderr)
	}
}

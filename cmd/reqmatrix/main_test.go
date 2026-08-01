package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofired/reqmatrix/internal/matrix"
	"github.com/sofired/reqmatrix/internal/testsupport"
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

func TestHelpAndVersion(t *testing.T) {
	if exitCode, stdout, _ := runCommand(t, "help"); exitCode != 0 ||
		!strings.Contains(stdout, "Usage: reqmatrix") {
		t.Fatalf("unexpected help result %d: %s", exitCode, stdout)
	}
	if exitCode, stdout, _ := runCommand(t, "version"); exitCode != 0 ||
		!strings.Contains(stdout, "cli-contract 1, schema 1, config 1") {
		t.Fatalf("unexpected version result %d: %s", exitCode, stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	if exitCode, _, stderr := runCommand(t); exitCode != 2 ||
		!strings.Contains(stderr, "Usage: reqmatrix") {
		t.Fatalf("expected usage on empty invocation, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(t, "unknown"); exitCode != 2 ||
		!strings.Contains(stderr, `unknown command "unknown"`) {
		t.Fatalf("expected unknown-command rejection, got %d: %s", exitCode, stderr)
	}
	if exitCode, _, stderr := runCommand(t, "validate"); exitCode != 2 ||
		!strings.Contains(stderr, "-config is required") ||
		!strings.Contains(stderr, "-matrix is required") {
		t.Fatalf("expected required-flag errors, got %d: %s", exitCode, stderr)
	}
	config, matrixPath := fixtureArgs(t)
	if exitCode, _, stderr := runCommand(
		t, "validate", "-config", config, "-matrix", matrixPath, "extra",
	); exitCode != 2 || !strings.Contains(stderr, "unexpected positional arguments") {
		t.Fatalf("expected positional-argument rejection, got %d: %s", exitCode, stderr)
	}
}

func TestValidateCommand(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	exitCode, stdout, stderr := runCommand(t, "validate", "-config", config, "-matrix", matrixPath)
	if exitCode != 0 || !strings.Contains(stdout, "validated 4 requirements") {
		t.Fatalf("fixture validation failed %d: %s%s", exitCode, stdout, stderr)
	}

	doc := loadFixtureDocument(t, matrixPath)
	doc.Requirements = append(doc.Requirements, doc.Requirements[0])
	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-matrix", testsupport.WriteJSON(t, doc),
	)
	if exitCode != 1 || !strings.Contains(stderr, "duplicate requirement ID") {
		t.Fatalf("expected duplicate-ID rejection, got %d: %s", exitCode, stderr)
	}

	exitCode, _, stderr = runCommand(
		t, "validate", "-config", config, "-matrix", filepath.Join(t.TempDir(), "absent.json"),
	)
	if exitCode != 2 || !strings.Contains(stderr, "cannot load matrix") {
		t.Fatalf("expected load failure, got %d: %s", exitCode, stderr)
	}
}

func TestRenderRoundTripAndCheck(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	outputPath := filepath.Join(t.TempDir(), "matrix.md")

	exitCode, stdout, stderr := runCommand(
		t, "render", "-config", config, "-matrix", matrixPath, "-output", outputPath,
	)
	if exitCode != 0 || !strings.Contains(stdout, "rendered 4 requirements") {
		t.Fatalf("render failed %d: %s%s", exitCode, stdout, stderr)
	}

	exitCode, stdout, stderr = runCommand(
		t, "render", "-config", config, "-matrix", matrixPath, "-output", outputPath, "-check",
	)
	if exitCode != 0 || !strings.Contains(stdout, "rendered matrix is current") {
		t.Fatalf("freshness check failed %d: %s%s", exitCode, stdout, stderr)
	}

	if err := os.WriteFile(outputPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("write stale output: %v", err)
	}
	exitCode, _, stderr = runCommand(
		t, "render", "-config", config, "-matrix", matrixPath, "-output", outputPath, "-check",
	)
	if exitCode != 1 || !strings.Contains(stderr, "is stale") {
		t.Fatalf("expected stale-output rejection, got %d: %s", exitCode, stderr)
	}
}

func TestCompareCommand(t *testing.T) {
	config, matrixPath := fixtureArgs(t)
	exitCode, stdout, stderr := runCommand(
		t, "compare", "-config", config, "-baseline", matrixPath, "-candidate", matrixPath,
	)
	if exitCode != 0 || !strings.Contains(stdout, "legal successor") {
		t.Fatalf("identical comparison failed %d: %s%s", exitCode, stdout, stderr)
	}

	// A snapshot-valid candidate that is an illegal successor: the retained
	// supersession's replacement set changed relative to the baseline.
	candidate := loadFixtureDocument(t, matrixPath)
	candidate.Supersessions[0].ReplacementIDs = []string{"RFCX-001"}
	candidate.MatrixVersion = "0.3.0"
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

func loadFixtureDocument(t *testing.T, path string) matrix.Document {
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

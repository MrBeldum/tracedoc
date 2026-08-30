package docscheck

import (
	"maps"
	"strings"
	"testing"
	"testing/fstest"
)

// The fixture repository is a miniature of this one: the same file
// layout, the same self-check step in both workflows, and a changelog
// whose released section matches the embedded toolVersion. Every drift
// test starts from it and changes exactly one thing, so a failure names
// the drift rather than the fixture.
const (
	fixtureAgents = "# tracedoc agent instructions\n" +
		"\n" +
		"`.github/workflows/` holds the CI and release workflows.\n" +
		"\n" +
		"## Validation\n" +
		"\n" +
		"```sh\n" +
		"gofmt -l .\n" +
		"go run ./cmd/tracedoc validate -config testdata/config.json -doc testdata/matrix.json\n" +
		"go run ./cmd/tracedoc compare -config testdata/config.json -baseline testdata/matrix.json -candidate testdata/matrix.json\n" +
		"```\n"

	fixtureChangelog = "# Changelog\n" +
		"\n" +
		"## Unreleased\n" +
		"\n" +
		"## 0.1.0 - 2026-08-02\n" +
		"\n" +
		"Initial release.\n"

	fixtureMain = "package main\n" +
		"\n" +
		"const toolVersion = \"0.1.0\"\n"

	fixtureCLI = "# CLI contract\n" +
		"\n" +
		"## `tracedoc compare -config <path> -baseline <path> -candidate <path>`\n" +
		"\n" +
		"Compares two documents.\n"

	fixtureSchema = "# Document schemas\n" +
		"\n" +
		"See [compare](cli.md#tracedoc-compare--config-path--baseline-path--candidate-path).\n" +
		"\n" +
		"## `threat_model`\n" +
		"\n" +
		"Configured in [config.md](config.md#threat_model).\n"

	fixtureConfig = "# Consumer configuration\n" +
		"\n" +
		"### `threat_model`\n" +
		"\n" +
		"Threat-model section.\n"

	fixtureWorkflow = "name: CI\n" +
		"jobs:\n" +
		"  verify:\n" +
		"    steps:\n" +
		"      - name: Vet\n" +
		"        run: go vet ./...\n" +
		"      - name: Self-check fixture documents\n" +
		"        run: |\n" +
		"          go run ./cmd/tracedoc validate -config testdata/config.json -doc testdata/matrix.json\n" +
		"          go run ./cmd/tracedoc compare -config testdata/config.json -baseline testdata/matrix.json -candidate testdata/matrix.json\n" +
		"      - name: Done\n" +
		"        run: echo done\n"
)

// removed marks a fixture file that an override deletes rather than
// replaces.
const removed = "\x00removed"

// repository builds the fixture repository with overrides applied. An
// override whose content is removed deletes the file.
func repository(overrides map[string]string) fstest.MapFS {
	files := map[string]string{
		"AGENTS.md":                       fixtureAgents,
		"CHANGELOG.md":                    fixtureChangelog,
		"README.md":                       "# tracedoc\n\nSee [the CLI contract](docs/cli.md).\n",
		"cmd/tracedoc/main.go":            fixtureMain,
		"docs/cli.md":                     fixtureCLI,
		"docs/config.md":                  fixtureConfig,
		"docs/schema.md":                  fixtureSchema,
		".github/workflows/ci.yml":        fixtureWorkflow,
		".github/workflows/release.yml":   fixtureWorkflow,
		"testdata/matrix.md":              "# Fixture\n\nSee [plan](../plan.md#132-isolation).\n",
		"internal/docscheck/docscheck.go": "package docscheck\n",
	}
	maps.Copy(files, overrides)

	fsys := make(fstest.MapFS, len(files))
	for name, data := range files {
		if data == removed {
			continue
		}
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

// checkAll runs every check over the fixture repository with overrides
// applied.
func checkAll(t *testing.T, overrides map[string]string) []string {
	t.Helper()
	return CheckAll(repository(overrides))
}

// requireReport fails unless exactly one finding mentions every fragment.
func requireReport(t *testing.T, errs []string, fragments ...string) {
	t.Helper()
	var matched []string
	for _, err := range errs {
		if containsAll(err, fragments) {
			matched = append(matched, err)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("want exactly one finding mentioning %v, got %d in %v", fragments, len(matched), errs)
	}
}

func containsAll(value string, fragments []string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}

func TestCleanRepositoryPassesEveryCheck(t *testing.T) {
	if errs := checkAll(t, nil); len(errs) > 0 {
		t.Fatalf("clean fixture reported %v", errs)
	}
}

// The three tests below reproduce the drifts that motivated this check.
// Each one survived multiple merges in this repository and was found by a
// reader rather than by a gate; each one now fails a test.

// TestCatchesTheRenamedCommandAnchorDrift reproduces the dead anchor that
// docs/schema.md carried from the matrix -> tracedoc rename in fd550ce:
// the link kept the old command name after the heading it pointed at was
// renamed.
func TestCatchesTheRenamedCommandAnchorDrift(t *testing.T) {
	errs := checkAll(t, map[string]string{
		"docs/schema.md": strings.Replace(
			fixtureSchema,
			"cli.md#tracedoc-compare--config-path--baseline-path--candidate-path",
			"cli.md#matrix-compare--config-path--baseline-path--candidate-path",
			1,
		),
	})
	requireReport(t, errs, "docs/schema.md:3", "matrix-compare", "names no heading in docs/cli.md")
}

// TestCatchesTheStagedWorkflowsDrift reproduces AGENTS.md naming
// .github/workflows-staged/, a directory removed in ee1d529. AGENTS.md
// also named a file in that directory as the authoritative source for the
// self-check command list, so following the documented procedure led to a
// path that no longer existed.
func TestCatchesTheStagedWorkflowsDrift(t *testing.T) {
	errs := checkAll(t, map[string]string{
		"AGENTS.md": strings.Replace(
			fixtureAgents,
			"`.github/workflows/` holds",
			"`.github/workflows-staged/` holds",
			1,
		),
	})
	requireReport(t, errs, "AGENTS.md:3", ".github/workflows-staged/", "does not exist in the repository")
}

// TestCatchesTheUnreleasedChangelogDrift reproduces CHANGELOG.md still
// reading "0.1.0 - Unreleased" after v0.1.0 was tagged, released, and had
// binaries published — a claim that outlived the tag by about three weeks
// and contradicted step 1 of this project's own release process.
func TestCatchesTheUnreleasedChangelogDrift(t *testing.T) {
	errs := checkAll(t, map[string]string{
		"CHANGELOG.md": strings.Replace(fixtureChangelog, "## 0.1.0 - 2026-08-02", "## 0.1.0 - Unreleased", 1),
	})
	requireReport(t, errs, "CHANGELOG.md:5", "0.1.0", "Unreleased", "YYYY-MM-DD")
}

func TestCheckLinks(t *testing.T) {
	t.Run("missing file is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nSee [the guide](docs/guide.md).\n",
		})
		requireReport(t, errs, "README.md:3", "docs/guide.md", "does not exist")
	})

	t.Run("same-file anchor is resolved against the document itself", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\n## Usage\n\nSee [usage](#usage) and [none](#missing).\n",
		})
		requireReport(t, errs, "README.md:5", "#missing", "names no heading in README.md")
	})

	t.Run("a link escaping the repository is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nSee [outside](../elsewhere.md).\n",
		})
		requireReport(t, errs, "README.md:3", "escapes the repository")
	})

	t.Run("external and root-absolute targets are left alone", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\n[a](https://example.org/x#y) [b](mailto:x@example.org) [c](/sofired/tracedoc)\n",
		})
		if len(errs) > 0 {
			t.Fatalf("external targets reported %v", errs)
		}
	})

	t.Run("a fragment on a non-Markdown file is left alone", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nSee [the constant](cmd/tracedoc/main.go#L3).\n",
		})
		if len(errs) > 0 {
			t.Fatalf("line anchor reported %v", errs)
		}
	})

	t.Run("anchors resolve into documents outside the checked set", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nSee [fixture](testdata/matrix.md#fixture) and [gone](testdata/matrix.md#absent).\n",
		})
		requireReport(t, errs, "README.md:3", "#absent", "names no heading in testdata/matrix.md")
	})

	t.Run("links inside fenced blocks and code spans are examples, not claims", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nWrite `[text](docs/nowhere.md)` like this:\n\n" +
				"```md\n[text](docs/also-nowhere.md)\n```\n",
		})
		if len(errs) > 0 {
			t.Fatalf("example links reported %v", errs)
		}
	})
}

func TestCheckNamedPaths(t *testing.T) {
	t.Run("a named file that does not exist is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nThe entry point is `cmd/tracedoc/cli.go`.\n",
		})
		requireReport(t, errs, "README.md:3", "cmd/tracedoc/cli.go", "does not exist")
	})

	t.Run("a named directory that exists passes", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"README.md": "# tracedoc\n\nSources live in `internal/docscheck/` and `cmd/tracedoc/main.go`.\n",
		})
		if len(errs) > 0 {
			t.Fatalf("existing paths reported %v", errs)
		}
	})
}

func TestIsRepositoryPath(t *testing.T) {
	roots := map[string]struct{}{
		".github": {}, "cmd": {}, "docs": {}, "internal": {}, "testdata": {},
	}
	for _, testCase := range []struct {
		candidate string
		want      bool
		reason    string
	}{
		{"docs/cli.md", true, "a plain repository path"},
		{".github/workflows/", true, "a directory with a trailing slash"},
		{".github/workflows-staged/ci.yml", true, "the drift this check exists for"},
		{"go.mod", false, "no slash, so not path-shaped enough to judge"},
		{"github.com/sofired/tracedoc", false, "a module path, not a directory here"},
		{"actions/setup-go", false, "a marketplace action reference"},
		{"linux/amd64", false, "a build platform"},
		{"sum.golang.org/lookup", false, "a host name"},
		{"testdata/*.md", false, "a glob"},
		{"https://", false, "a scheme"},
		{"../plan.md", false, "relative to a consumer document, not to this root"},
		{"./docs/cli.md", false, "not written as a repository-root path"},
		{"/etc/passwd", false, "absolute"},
		{"-config testdata/config.json", false, "a flag and its argument"},
		{"tracedoc_<version>_<os>_<arch>/x", false, "a placeholder"},
		{"/", false, "no segments at all"},
	} {
		t.Run(testCase.candidate, func(t *testing.T) {
			if got := isRepositoryPath(testCase.candidate, roots); got != testCase.want {
				t.Errorf("isRepositoryPath(%q) = %v, want %v (%s)", testCase.candidate, got, testCase.want, testCase.reason)
			}
		})
	}
}

func TestCheckChangelog(t *testing.T) {
	t.Run("no section for the released version is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"CHANGELOG.md": "# Changelog\n\n## Unreleased\n",
		})
		requireReport(t, errs, "CHANGELOG.md", "no section for released version 0.1.0")
	})

	t.Run("an unparseable date is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"CHANGELOG.md": strings.Replace(fixtureChangelog, "2026-08-02", "2026-13-02", 1),
		})
		requireReport(t, errs, "CHANGELOG.md:5", "2026-13-02", "YYYY-MM-DD")
	})

	t.Run("a duplicate section for the released version is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"CHANGELOG.md": fixtureChangelog + "\n## 0.1.0 - 2026-08-03\n",
		})
		requireReport(t, errs, "CHANGELOG.md:9", "duplicate section")
	})

	t.Run("the version is read from the toolVersion constant", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"cmd/tracedoc/main.go": "package main\n\nconst toolVersion = \"0.2.0\"\n",
		})
		requireReport(t, errs, "CHANGELOG.md", "no section for released version 0.2.0")
	})

	t.Run("a missing toolVersion constant is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"cmd/tracedoc/main.go": "package main\n\nfunc main() {}\n",
		})
		requireReport(t, errs, "declares no toolVersion constant")
	})
}

func TestCheckSelfCheckCommands(t *testing.T) {
	t.Run("a command AGENTS.md omits is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"AGENTS.md": strings.Replace(fixtureAgents,
				"go run ./cmd/tracedoc compare -config testdata/config.json -baseline testdata/matrix.json -candidate testdata/matrix.json\n", "", 1),
		})
		requireReport(t, errs, "AGENTS.md", "missing self-check command 2 of 2")
	})

	t.Run("a command AGENTS.md words differently is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			"AGENTS.md": strings.Replace(fixtureAgents, "-doc testdata/matrix.json", "-doc testdata/threats.json", 1),
		})
		requireReport(t, errs, "AGENTS.md", "self-check command 1 is", "but .github/workflows/ci.yml runs")
	})

	t.Run("a release workflow that has drifted from CI is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			".github/workflows/release.yml": strings.Replace(fixtureWorkflow,
				"-baseline testdata/matrix.json -candidate testdata/matrix.json\n",
				"-baseline testdata/matrix.json -candidate testdata/matrix.json\n"+
					"          go run ./cmd/tracedoc validate -config testdata/config.json -doc testdata/threats.json\n", 1),
		})
		requireReport(t, errs, ".github/workflows/release.yml", "runs a self-check command .github/workflows/ci.yml does not")
	})

	t.Run("only the named step's run block is read", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			".github/workflows/ci.yml": strings.Replace(fixtureWorkflow,
				"        run: echo done\n",
				"        run: go run ./cmd/tracedoc version\n", 1),
		})
		if len(errs) > 0 {
			t.Fatalf("a command in a later step was read as a self-check: %v", errs)
		}
	})

	t.Run("a workflow without the step is reported", func(t *testing.T) {
		errs := checkAll(t, map[string]string{
			".github/workflows/ci.yml": "name: CI\njobs:\n  verify:\n    steps:\n      - name: Vet\n        run: go vet ./...\n",
		})
		requireReport(t, errs, "has no \"Self-check fixture documents\" step")
	})
}

func TestHeadingSlug(t *testing.T) {
	for _, testCase := range []struct {
		heading string
		want    string
	}{
		{"Shared top-level members", "shared-top-level-members"},
		{"Consumer configuration, version 1", "consumer-configuration-version-1"},
		// An underscore inside a code span is part of the name, not an
		// emphasis marker. Dropping it yields "threatmodel" and reports a
		// live anchor as dead.
		{"`threat_model`", "threat_model"},
		{"`attacker_model`", "attacker_model"},
		{"`actors[]`", "actors"},
		{"`render` (per section)", "render-per-section"},
		{
			"`tracedoc compare -config <path> -baseline <path> -candidate <path>`",
			"tracedoc-compare--config-path--baseline-path--candidate-path",
		},
		{"**Bold** and *italic* and ~~struck~~", "bold-and-italic-and-struck"},
		{"A [linked](https://example.org) word", "a-linked-word"},
	} {
		t.Run(testCase.heading, func(t *testing.T) {
			if got := headingSlug(testCase.heading); got != testCase.want {
				t.Errorf("headingSlug(%q) = %q, want %q", testCase.heading, got, testCase.want)
			}
		})
	}
}

func TestHeadingAnchorsNumbersRepeatedSlugs(t *testing.T) {
	anchors := headingAnchors(blankFencedCode(
		"# References\n\n## References\n\n## References\n\n```md\n## References\n```\n",
	))
	for _, want := range []string{"references", "references-1", "references-2"} {
		if _, ok := anchors[want]; !ok {
			t.Errorf("anchor %q missing from %v", want, anchors)
		}
	}
	if _, ok := anchors["references-3"]; ok {
		t.Errorf("a heading inside a fenced block was counted: %v", anchors)
	}
}

func TestBlankFencedCode(t *testing.T) {
	lines := blankFencedCode("a\n```go\nb\n```\nc\n~~~\nd\n~~~\ne\n")
	want := []string{"a", "", "", "", "c", "", "", "", "e", ""}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(lines), len(want), lines)
	}
	for index := range want {
		if lines[index] != want[index] {
			t.Errorf("line %d = %q, want %q", index+1, lines[index], want[index])
		}
	}
}

func TestDocumentFilesSkipsFixturesAndToolDirectories(t *testing.T) {
	fsys := repository(map[string]string{
		".claude/notes.md": "# Notes\n\n[gone](nowhere.md)\n",
		"dist/README.md":   "# Built\n\n[gone](nowhere.md)\n",
	})
	files, err := DocumentFiles(fsys)
	if err != nil {
		t.Fatalf("collect documents: %v", err)
	}
	for _, file := range files {
		switch file {
		case "testdata/matrix.md", ".claude/notes.md", "dist/README.md":
			t.Errorf("document set includes %s", file)
		}
	}
	if len(files) == 0 {
		t.Fatal("document set is empty")
	}
}

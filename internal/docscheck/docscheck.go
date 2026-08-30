// Package docscheck verifies the claims this repository's own Markdown
// makes about itself. It is repository tooling, not part of the CLI
// contract: nothing in cmd/ imports it, and it never inspects a consumer's
// documents.
//
// The project treats docs/*.md, README.md, and AGENTS.md as versioned
// public contracts, but for its first releases nothing defended them, and
// three false claims survived multiple merges — a link to a heading that
// had been renamed away, a prose reference to a directory that had been
// deleted, and a changelog section still marked unreleased after the tag
// was published. Each was mechanically detectable. This package detects
// them, and internal/docscheck's repository test runs it over the real
// tree so `go test ./...` fails on a regression.
//
// The checks are deliberately narrow. They test claims that are
// verifiably false — a path that does not resolve, an anchor with no
// heading — never writing quality, spelling, or style. A claim about
// behavior ("the template anchors every entity") is outside what any
// documentation linter can reach and belongs in an executable assertion
// next to the behavior itself.
//
// Known limits, so a reader does not mistake silence for a guarantee:
//
//   - Only inline links are resolved. Reference-style links
//     ("[text][ref]"), autolinks, angle-bracket destinations, and link
//     text containing nested brackets are not recognized, so a dead link
//     written that way goes unreported. None appear in this repository's
//     documentation today.
//   - Indented (non-fenced) code blocks are not treated as examples. Every
//     example here uses a fence.
//   - The checks trust the working tree's file identity, not only its path
//     text. Paths are resolved through the given fs.FS, which follows
//     symlinks, so a symlink committed into the tree could point outside
//     it. That is acceptable because this package only ever runs over
//     reviewed, version-controlled content in CI, and reports existence
//     rather than content.
package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/sofired/tracedoc/internal/check"
)

// Repository files the checks read by name. They are constants rather than
// parameters because each check asserts something about this repository's
// layout specifically.
const (
	agentsFile          = "AGENTS.md"
	changelogFile       = "CHANGELOG.md"
	mainFile            = "cmd/tracedoc/main.go"
	ciWorkflowFile      = ".github/workflows/ci.yml"
	releaseWorkflowFile = ".github/workflows/release.yml"
)

// selfCheckStep is the workflow step whose command list AGENTS.md declares
// authoritative.
const selfCheckStep = "Self-check fixture documents"

// selfCheckPrefix identifies a fixture self-check command in both AGENTS.md
// and the workflows.
const selfCheckPrefix = "go run ./cmd/tracedoc"

// CheckAll runs every documentation check against fsys, which must be
// rooted at the repository root. The returned errors are ordered by check
// and then by location, so a failing CI run reads top to bottom.
func CheckAll(fsys fs.FS) check.Errors {
	files, err := DocumentFiles(fsys)
	if err != nil {
		return check.Errors{fmt.Sprintf("docscheck: collect Markdown documents: %v", err)}
	}
	var errs check.Errors
	errs = append(errs, CheckLinks(fsys, files)...)
	errs = append(errs, CheckNamedPaths(fsys, files)...)
	errs = append(errs, CheckChangelog(fsys)...)
	errs = append(errs, CheckSelfCheckCommands(fsys)...)
	return errs
}

// DocumentFiles returns this repository's own Markdown documents in
// lexical order.
//
// It excludes testdata: those Markdown files are golden renderings of
// synthetic fixture documents, already pinned byte-for-byte by
// `render -check`, and their links point into a fictional consumer
// repository rather than this one. It excludes dist, the gitignored
// directory the release workflow builds artifacts into, which a
// contributor may have populated locally. And it excludes dot-directories
// other than .github, which hold tool state rather than documentation.
func DocumentFiles(fsys fs.FS) ([]string, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name == "." {
				return nil
			}
			base := path.Base(name)
			if base == "testdata" || base == "dist" ||
				strings.HasPrefix(base, ".") && base != ".github" {
				return fs.SkipDir
			}
			return nil
		}
		if path.Ext(name) == ".md" {
			files = append(files, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// CheckLinks reports every relative Markdown link in files whose target
// file does not exist, and every "#fragment" that names no heading in its
// target document.
//
// Only the given files are scanned for links, but anchors are resolved
// against any Markdown file they point at, so a document may legitimately
// anchor into one that is not itself checked. Absolute and scheme-bearing
// targets (https:, mailto:, /owner/repo/...) are left alone: verifying
// them needs network access this check deliberately does not take.
func CheckLinks(fsys fs.FS, files []string) check.Errors {
	var checker check.Checker
	anchors := make(map[string]map[string]struct{})
	for _, file := range files {
		lines, err := readDocument(fsys, file)
		if err != nil {
			checker.Addf(file, "read: %v", err)
			continue
		}
		for _, ref := range inlineLinks(lines) {
			location := fmt.Sprintf("%s:%d", file, ref.line)
			if isExternal(ref.target) {
				continue
			}
			target, fragment, _ := strings.Cut(ref.target, "#")
			resolved := file
			if target != "" {
				resolved = path.Join(path.Dir(file), target)
				if resolved == ".." || strings.HasPrefix(resolved, "../") {
					checker.Addf(location, "link %q escapes the repository", ref.target)
					continue
				}
				if _, err := fs.Stat(fsys, resolved); err != nil {
					checker.Addf(location, "link %q points at a file that does not exist", ref.target)
					continue
				}
			}
			if fragment == "" || path.Ext(resolved) != ".md" {
				continue
			}
			known, cached := anchors[resolved]
			if !cached {
				lines, err := readDocument(fsys, resolved)
				if err != nil {
					checker.Addf(location, "link %q targets %s, which cannot be read: %v", ref.target, resolved, err)
					continue
				}
				known = headingAnchors(lines)
				anchors[resolved] = known
			}
			if _, ok := known[fragment]; !ok {
				checker.Addf(location, "link %q names no heading in %s", ref.target, resolved)
			}
		}
	}
	return checker.Errs
}

// CheckNamedPaths reports backticked repository paths in files that do not
// exist. This is the check that catches prose naming a directory after it
// has been moved or deleted.
//
// Deciding which backticked string is a repository path at all is a
// heuristic, and it is tuned to stay quiet rather than to catch
// everything: a candidate must contain a slash, carry no shell or glob
// metacharacters, and begin with a segment that names a real entry at the
// repository root. That last rule is what separates `.github/workflows/`
// from `github.com/sofired/tracedoc`, `actions/setup-go`, and
// `linux/amd64` — prose full of identifiers that look like paths and are
// not. The cost is that a wholly invented top-level directory goes
// unreported; the benefit is that the check never cries wolf, which is
// what keeps a CI gate trusted.
func CheckNamedPaths(fsys fs.FS, files []string) check.Errors {
	var checker check.Checker
	roots, err := rootEntries(fsys)
	if err != nil {
		return check.Errors{fmt.Sprintf("docscheck: read repository root: %v", err)}
	}
	for _, file := range files {
		lines, err := readDocument(fsys, file)
		if err != nil {
			checker.Addf(file, "read: %v", err)
			continue
		}
		for index, line := range lines {
			spans, _ := splitCodeSpans(line)
			for _, candidate := range spans {
				// A trailing "#L120" or "#anchor" names a place inside a
				// file rather than a different file, so the fragment is
				// dropped before the path is resolved.
				target, _, _ := strings.Cut(candidate, "#")
				if !isRepositoryPath(target, roots) {
					continue
				}
				if _, err := fs.Stat(fsys, strings.TrimSuffix(target, "/")); err != nil {
					checker.Addf(
						fmt.Sprintf("%s:%d", file, index+1),
						"names %q, which does not exist in the repository",
						candidate,
					)
				}
			}
		}
	}
	return checker.Errs
}

// CheckChangelog reports a CHANGELOG.md that does not carry a dated
// section for the version the tool reports.
//
// Step 1 of the release process in docs/versioning.md updates the
// changelog and the toolVersion constant together, so once toolVersion
// names a version, that version is released and its changelog section must
// carry a release date. A section still reading "Unreleased" for the
// embedded version is exactly the drift that outlived the v0.1.0 tag by
// three weeks.
func CheckChangelog(fsys fs.FS) check.Errors {
	var checker check.Checker
	version, err := toolVersion(fsys)
	if err != nil {
		return check.Errors{fmt.Sprintf("docscheck: %v", err)}
	}
	lines, err := readDocument(fsys, changelogFile)
	if err != nil {
		return check.Errors{fmt.Sprintf("%s: read: %v", changelogFile, err)}
	}

	found := false
	for index, line := range lines {
		match := changelogHeading.FindStringSubmatch(line)
		if match == nil || match[1] != version {
			continue
		}
		location := fmt.Sprintf("%s:%d", changelogFile, index+1)
		if found {
			checker.Addf(location, "duplicate section for released version %s", version)
			continue
		}
		found = true
		date := strings.TrimSpace(match[2])
		if date == "" {
			checker.Addf(location, "section for released version %s carries no date, expected \"## %s - YYYY-MM-DD\"", version, version)
			continue
		}
		if _, err := time.Parse(time.DateOnly, date); err != nil {
			checker.Addf(
				location,
				"section for released version %s is dated %q, expected a YYYY-MM-DD release date"+
					" (cmd/tracedoc/main.go reports %s, so the release process has already published it)",
				version, date, version,
			)
		}
	}
	if !found {
		checker.Addf(changelogFile, "has no section for released version %s, which %s reports", version, mainFile)
	}
	return checker.Errs
}

// CheckSelfCheckCommands reports divergence between the fixture self-check
// command lists that this repository keeps in three places: the Validation
// block in AGENTS.md and the %q steps of the CI and release workflows.
//
// AGENTS.md declares the CI step authoritative when the lists diverge.
// That tie-breaker only helps a reader who notices the divergence, so this
// check asserts the lists are identical instead of relying on it.
func CheckSelfCheckCommands(fsys fs.FS) check.Errors {
	var checker check.Checker
	reference, err := workflowSelfCheckCommands(fsys, ciWorkflowFile)
	if err != nil {
		return check.Errors{fmt.Sprintf("docscheck: %v", err)}
	}
	if len(reference) == 0 {
		return check.Errors{fmt.Sprintf("%s: the %q step runs no %s command", ciWorkflowFile, selfCheckStep, selfCheckPrefix)}
	}

	documented, err := agentsSelfCheckCommands(fsys)
	if err != nil {
		checker.Addf(agentsFile, "%v", err)
	} else {
		reportCommandDrift(&checker, agentsFile, documented, ciWorkflowFile, reference)
	}

	released, err := workflowSelfCheckCommands(fsys, releaseWorkflowFile)
	if err != nil {
		checker.Addf(releaseWorkflowFile, "%v", err)
	} else {
		reportCommandDrift(&checker, releaseWorkflowFile, released, ciWorkflowFile, reference)
	}
	return checker.Errs
}

// reportCommandDrift records every position at which actual departs from
// expected, naming the source of each list.
func reportCommandDrift(checker *check.Checker, location string, actual []string, referenceName string, expected []string) {
	for index := range max(len(actual), len(expected)) {
		switch {
		case index >= len(actual):
			checker.Addf(location, "is missing self-check command %d of %d, which %s runs: %s",
				index+1, len(expected), referenceName, expected[index])
		case index >= len(expected):
			checker.Addf(location, "runs a self-check command %s does not: %s", referenceName, actual[index])
		case actual[index] != expected[index]:
			checker.Addf(location, "self-check command %d is %q, but %s runs %q",
				index+1, actual[index], referenceName, expected[index])
		}
	}
}

// validationHeading names the AGENTS.md section that lists the self-check
// commands. The scan is scoped to it for the same reason the workflow scan
// is scoped to a named step: a go run ./cmd/tracedoc command written
// elsewhere in AGENTS.md — a render example in prose, say — is not part of
// the documented list, and reading it as one reports command drift and
// names the wrong cause.
const validationHeading = "Validation"

// agentsSelfCheckCommands returns the fixture self-check commands the
// AGENTS.md Validation block tells a contributor to run, in order.
//
// The commands live inside a fenced block, so the section is delimited by
// the prose around the fences rather than by their contents. A "## " line
// inside a fence is an example heading and a "# " line inside one is a
// shell comment; reading either as structure would end the block early and
// report the commands below it as missing.
func agentsSelfCheckCommands(fsys fs.FS) ([]string, error) {
	data, err := fs.ReadFile(fsys, agentsFile)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	lines := splitLines(string(data))
	prose := blankFencedCode(string(data))

	block := -1
	for index, line := range prose {
		if level, text := headingAt(line); level == 2 && text == validationHeading {
			block = index
			break
		}
	}
	if block < 0 {
		return nil, fmt.Errorf("has no %q section", "## "+validationHeading)
	}

	var commands []string
	for index := block + 1; index < len(lines); index++ {
		// A heading at the block's own level or above ends the block.
		if level, _ := headingAt(prose[index]); level > 0 && level <= 2 {
			break
		}
		if trimmed := strings.TrimSpace(lines[index]); strings.HasPrefix(trimmed, selfCheckPrefix) {
			commands = append(commands, trimmed)
		}
	}
	if len(commands) == 0 {
		return nil, fmt.Errorf("documents no %s command in its %q section",
			selfCheckPrefix, "## "+validationHeading)
	}
	return commands, nil
}

// headingAt returns the level and text of the ATX heading on line, or a
// zero level if line carries no heading.
func headingAt(line string) (int, string) {
	match := atxHeading.FindStringSubmatch(line)
	if match == nil {
		return 0, ""
	}
	return len(match[1]), match[2]
}

// workflowSelfCheckCommands returns the fixture self-check commands run by
// the selfCheckStep step of the workflow at name, in order.
//
// It reads the workflow as indented text rather than as YAML, because this
// module carries no dependencies and the standard library has no YAML
// parser. The shape it relies on — a "- name:" step key, a "run: |" block
// scalar, and commands indented under it — is the shape both workflows
// already use, and a change that broke the assumption would make this
// check fail loudly rather than pass silently.
func workflowSelfCheckCommands(fsys fs.FS, name string) ([]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	lines := splitLines(string(data))
	step := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == "- name: "+selfCheckStep {
			step = index
			break
		}
	}
	if step < 0 {
		return nil, fmt.Errorf("%s has no %q step", name, selfCheckStep)
	}

	block := -1
	stepIndent := leadingSpaces(lines[step])
	for index := step + 1; index < len(lines); index++ {
		trimmed := strings.TrimSpace(lines[index])
		// Any sequence item at the step's own indentation starts the next
		// step, named or not.
		if strings.HasPrefix(trimmed, "- ") && leadingSpaces(lines[index]) <= stepIndent {
			break
		}
		// "|-" and "|+" are the chomping variants of the same block
		// scalar, and carry the same commands.
		if strings.HasPrefix(trimmed, "run: |") {
			block = index
			break
		}
	}
	if block < 0 {
		return nil, fmt.Errorf("the %q step of %s has no \"run: |\" block", selfCheckStep, name)
	}

	var commands []string
	indent := leadingSpaces(lines[block])
	for index := block + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if leadingSpaces(line) <= indent {
			break
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, selfCheckPrefix) {
			continue
		}
		// A command split with a trailing backslash would be collected
		// truncated, and then reported as drift against the single-line
		// form in AGENTS.md — a disagreement between two spellings of the
		// same command. Fail on the spelling instead of on the phantom
		// drift.
		if strings.HasSuffix(trimmed, `\`) {
			return nil, fmt.Errorf(
				"a self-check command in %s is continued onto the next line with a backslash;"+
					" keep each command on one line so it can be compared with %s",
				name, agentsFile,
			)
		}
		commands = append(commands, trimmed)
	}
	return commands, nil
}

// toolVersion reads the released tool version from the toolVersion
// constant, parsing the Go source so a reformatting of the declaration
// cannot silently defeat the changelog check.
func toolVersion(fsys fs.FS) (string, error) {
	data, err := fs.ReadFile(fsys, mainFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", mainFile, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), mainFile, data, 0)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", mainFile, err)
	}
	for _, decl := range parsed.Decls {
		declaration, ok := decl.(*ast.GenDecl)
		if !ok || declaration.Tok != token.CONST {
			continue
		}
		for _, spec := range declaration.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range values.Names {
				if name.Name != "toolVersion" || index >= len(values.Values) {
					continue
				}
				literal, ok := values.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return "", fmt.Errorf("the toolVersion constant in %s is not a string literal", mainFile)
				}
				return strconv.Unquote(literal.Value)
			}
		}
	}
	return "", fmt.Errorf("%s declares no toolVersion constant", mainFile)
}

// rootEntries names every entry at the repository root.
func rootEntries(fsys fs.FS) (map[string]struct{}, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = struct{}{}
	}
	return names, nil
}

// isRepositoryPath reports whether candidate should be read as a path into
// this repository. See CheckNamedPaths for why the rule is deliberately
// conservative.
func isRepositoryPath(candidate string, roots map[string]struct{}) bool {
	if !strings.Contains(candidate, "/") || strings.ContainsAny(candidate, notInAPath) {
		return false
	}
	trimmed := strings.TrimSuffix(candidate, "/")
	if trimmed == "" || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "-") {
		return false
	}
	// Reject "." and ".." anywhere, not just as the first segment. Every
	// fs.FS this package is given rejects them too, but relying on that
	// leaves the guarantee to the caller's choice of filesystem rather
	// than to this function.
	for segment := range strings.SplitSeq(trimmed, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	first, _, _ := strings.Cut(trimmed, "/")
	_, known := roots[first]
	return known
}

// notInAPath holds the characters that disqualify a backticked string from
// being read as a repository path: shell and glob metacharacters,
// placeholder brackets, whitespace, and the scheme separator.
const notInAPath = " \t*?[]{}<>$\\:\"'|()!,;&"

var (
	// atxHeading matches an ATX heading, capturing its text without the
	// optional closing hash sequence. This repository uses no setext
	// headings.
	atxHeading = regexp.MustCompile(`^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*$`)

	// inlineLink matches an inline Markdown link or image, capturing the
	// destination without its optional title.
	inlineLink = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]*)(?:\s+"[^"]*")?\)`)

	// linkText matches the same construct, capturing the link text instead
	// of the destination — what a reader sees, and what GitHub slugs when
	// the link sits inside a heading.
	linkText = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)

	// changelogHeading matches a changelog release heading, capturing the
	// version and whatever follows the separating dash. The brackets are
	// optional because Keep a Changelog — which CHANGELOG.md names as its
	// model — writes "## [1.2.3] - 2026-08-02", and a contributor moving
	// this file toward the format it claims to follow must not trip the
	// check.
	changelogHeading = regexp.MustCompile(`^##[ \t]+\[?([^\]\s]+)\]?(?:[ \t]+[-—][ \t]+(.*?))?[ \t]*$`)

	// uriScheme matches the leading scheme of an absolute URI.
	uriScheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)
)

// reference is one inline link found in a document.
type reference struct {
	line   int
	target string
}

// readDocument reads a Markdown file and blanks its fenced code blocks,
// keeping one entry per source line so reported locations stay accurate.
func readDocument(fsys fs.FS, name string) ([]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return blankHTMLComments(blankFencedCode(string(data))), nil
}

// blankHTMLComments empties every HTML comment span, keeping one entry per
// source line. GitHub renders none of it, so a link or heading left inside
// a comment is a note to a future editor rather than a claim the document
// makes.
//
// Fences are blanked first, and an inline code span is consumed whole, so
// neither a comment delimiter shown in a code example nor one written as
// `<!--` in prose opens a comment that would swallow the live links after
// it. Comments, unlike code spans, may span lines.
func blankHTMLComments(lines []string) []string {
	blanked := make([]string, len(lines))
	inComment := false
	for index, line := range lines {
		var prose strings.Builder
		for position := 0; position < len(line); {
			if length := codeSpanAt(line, position); length > 0 {
				if !inComment {
					prose.WriteString(line[position : position+length])
				}
				position += length
				continue
			}
			if inComment {
				if strings.HasPrefix(line[position:], "-->") {
					inComment = false
					position += len("-->")
					continue
				}
				position++
				continue
			}
			if strings.HasPrefix(line[position:], "<!--") {
				inComment = true
				position += len("<!--")
				continue
			}
			prose.WriteByte(line[position])
			position++
		}
		blanked[index] = prose.String()
	}
	return blanked
}

// blankFencedCode replaces every fenced code block, and its fence markers,
// with empty lines. Documentation about Markdown necessarily contains
// Markdown, and a link or heading shown inside a fence is an example
// rather than a claim.
func blankFencedCode(text string) []string {
	lines := splitLines(text)
	blanked := make([]string, len(lines))
	fence := ""
	for index, line := range lines {
		marker := fenceMarker(line)
		switch {
		case fence == "" && marker != "":
			fence = marker
		case fence != "" && marker != "" && marker[0] == fence[0] && len(marker) >= len(fence):
			fence = ""
		case fence == "":
			blanked[index] = line
		default:
			// Inside a fence and not closing it: the pre-allocated empty
			// string already stands in for this line.
		}
	}
	return blanked
}

// fenceMarker returns the leading run of backticks or tildes that opens or
// closes a fenced code block, or "" if line is not a fence.
func fenceMarker(line string) string {
	trimmed := strings.TrimLeft(line, " ")
	if len(line)-len(trimmed) > 3 {
		return ""
	}
	if !strings.HasPrefix(trimmed, "```") && !strings.HasPrefix(trimmed, "~~~") {
		return ""
	}
	return trimmed[:leadingRun(trimmed, trimmed[0])]
}

// splitCodeSpans separates line into the contents of its inline code spans
// and the prose that remains once those spans are removed.
//
// A span is a run of backticks closed by a run of the same length, which
// is what lets prose about Markdown quote Markdown: “​`[text](url)`​“
// shows link syntax literally, and a checker that only understood single
// backticks would read the inner text as a live link and report it as
// dead. This repository's documentation is partly about Markdown, so that
// is a real shape here rather than a theoretical one.
func splitCodeSpans(line string) (spans []string, prose string) {
	var rest strings.Builder
	for index := 0; index < len(line); {
		length := codeSpanAt(line, index)
		if length == 0 {
			rest.WriteByte(line[index])
			index++
			continue
		}
		delimiter := leadingRun(line[index:], '`')
		spans = append(spans, line[index+delimiter:index+length-delimiter])
		index += length
	}
	return spans, rest.String()
}

// codeSpanAt returns the byte length of the inline code span beginning at
// index, delimiters included, or 0 if no span begins there. An unmatched
// run of backticks is literal text rather than a span.
func codeSpanAt(line string, index int) int {
	if line[index] != '`' {
		return 0
	}
	opening := leadingRun(line[index:], '`')
	for scan := index + opening; scan < len(line); {
		if line[scan] != '`' {
			scan++
			continue
		}
		run := leadingRun(line[scan:], '`')
		if run == opening {
			return scan + opening - index
		}
		scan += run
	}
	return 0
}

// leadingRun counts the leading repetitions of char in value.
func leadingRun(value string, char byte) int {
	run := 0
	for run < len(value) && value[run] == char {
		run++
	}
	return run
}

// inlineLinks returns every inline link in lines, ignoring those inside an
// inline code span.
func inlineLinks(lines []string) []reference {
	var refs []reference
	for index, line := range lines {
		_, outsideCode := splitCodeSpans(line)
		for _, match := range inlineLink.FindAllStringSubmatch(outsideCode, -1) {
			if match[1] != "" {
				refs = append(refs, reference{line: index + 1, target: match[1]})
			}
		}
	}
	return refs
}

// headingAnchors returns the fragment identifiers GitHub generates for the
// ATX headings in lines, including the "-1", "-2" suffixes it appends to
// repeats of an earlier slug.
func headingAnchors(lines []string) map[string]struct{} {
	anchors := make(map[string]struct{})
	counts := make(map[string]int)
	for _, line := range lines {
		match := atxHeading.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		slug := headingSlug(match[2])
		if slug == "" {
			continue
		}
		anchor := slug
		if repeats := counts[slug]; repeats > 0 {
			anchor = fmt.Sprintf("%s-%d", slug, repeats)
		}
		counts[slug]++
		anchors[anchor] = struct{}{}
	}
	return anchors
}

// headingSlug computes the fragment identifier GitHub generates for one
// heading: the rendered text, lowercased, stripped of everything that is
// not a letter, digit, hyphen, or underscore, with spaces becoming
// hyphens. Every other character, tabs included, is dropped rather than
// hyphenated, which is what GitHub does.
//
// Underscores survive. They are not emphasis markers inside a word, and
// dropping them turns the real anchor of a heading like `threat_model`
// into "threatmodel" — a false report of a dead link, which is worse for a
// CI gate than missing a real one.
func headingSlug(text string) string {
	text = linkText.ReplaceAllString(text, "$1")
	text = strings.NewReplacer("`", "", "*", "", "~", "").Replace(text)
	var slug strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
			slug.WriteRune(r)
		case r == ' ':
			slug.WriteRune('-')
		}
	}
	return slug.String()
}

// isExternal reports whether target names something outside this
// repository's tree, which these checks do not resolve.
func isExternal(target string) bool {
	return uriScheme.MatchString(target) || strings.HasPrefix(target, "/")
}

// splitLines splits text into lines, tolerating CRLF endings.
func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// leadingSpaces counts the spaces indenting line.
func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

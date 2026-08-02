// Command tracedoc validates, renders, and cross-version-compares versioned
// governance documents — a requirements matrix or a system threat model —
// under a consumer-owned policy configuration. See docs/cli.md for the
// versioned command contract.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sofired/tracedoc/internal/check"
	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/fsio"
	"github.com/sofired/tracedoc/internal/matrix"
	"github.com/sofired/tracedoc/internal/policy"
	"github.com/sofired/tracedoc/internal/render"
	requirementsrender "github.com/sofired/tracedoc/internal/render/requirements"
	threatsrender "github.com/sofired/tracedoc/internal/render/threats"
	"github.com/sofired/tracedoc/internal/threats"
)

// toolVersion is the released tool version. The release process keeps it in
// step with the repository tag; see docs/versioning.md.
const toolVersion = "0.1.0"

// cliContractVersion identifies the command contract in docs/cli.md.
const cliContractVersion = 1

const usageText = `Usage: tracedoc <command> [flags]

Commands:
  validate  -config <path> -doc <path> [-requirements <path>]
            Strictly decode and validate one document snapshot. For a
            threat model that links to requirement IDs, -requirements
            names the requirements matrix that resolves the links.
  render    -config <path> -doc <path> -output <path> [-template <path>] [-check]
            Render the Markdown companion, or with -check verify that the
            existing output is current.
  compare   -config <path> -baseline <path> -candidate <path>
            Validate both snapshots of one document type, then check that
            the candidate is a legal successor of the accepted baseline.
  version   Print the tool, CLI contract, schema, and config versions.

Exit codes: 0 success; 1 validation, comparison, or freshness failure;
2 usage, input, or internal error.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	command, commandArgs := args[0], args[1:]
	switch command {
	case "validate":
		return runValidate(commandArgs, stdout, stderr)
	case "render":
		return runRender(commandArgs, stdout, stderr)
	case "compare":
		return runCompare(commandArgs, stdout, stderr)
	case "version":
		fmt.Fprintf(
			stdout,
			"tracedoc %s (cli-contract %d, requirements-schema %d, threat-model-schema %d, config %d)\n",
			toolVersion,
			cliContractVersion,
			matrix.SchemaVersion,
			threats.SchemaVersion,
			policy.ConfigVersion,
		)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n\n", command)
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func newFlagSet(command string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet("tracedoc "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string, stderr io.Writer) (int, bool) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "error: unexpected positional arguments")
		return 2, false
	}
	return 0, true
}

func requireFlags(stderr io.Writer, pairs ...[2]string) bool {
	valid := true
	for _, pair := range pairs {
		if pair[1] == "" {
			fmt.Fprintf(stderr, "error: -%s is required\n", pair[0])
			valid = false
		}
	}
	return valid
}

func loadConfig(path string, stderr io.Writer) (*policy.Config, int) {
	config, err := policy.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot load config: %v\n", err)
		return nil, 2
	}
	return config, 0
}

// readTyped reads a document file and identifies its declared type.
func readTyped(path, label string, stderr io.Writer) ([]byte, document.Type, int) {
	data, err := document.ReadFile(path, label)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot load %s: %v\n", label, err)
		return nil, "", 2
	}
	docType, err := document.Peek(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s: %v\n", label, err)
		return nil, "", 2
	}
	return data, docType, 0
}

func reportErrors(stderr io.Writer, label string, errs check.Errors) {
	for _, message := range errs {
		fmt.Fprintf(stderr, "error: %s: %s\n", label, message)
	}
}

// loadRequirements decodes and validates a requirements document.
func loadRequirements(
	config *policy.Config,
	data []byte,
	label string,
	stderr io.Writer,
) (matrix.Document, int) {
	pol, err := config.RequirementsPolicy()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return matrix.Document{}, 2
	}
	doc, err := matrix.Decode(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot decode %s: %v\n", label, err)
		return matrix.Document{}, 2
	}
	if errs := matrix.Validate(doc, pol); len(errs) > 0 {
		reportErrors(stderr, label, errs)
		return matrix.Document{}, 1
	}
	return doc, 0
}

// decodeThreats decodes a threat-model document without validating it.
// Split out from loadThreats so a caller that needs to inspect the decoded
// document before validation (for example, to run the requirement-links
// gate in runValidate) can do so without decoding the same bytes twice.
func decodeThreats(data []byte, label string, stderr io.Writer) (threats.Document, int) {
	doc, err := threats.Decode(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot decode %s: %v\n", label, err)
		return threats.Document{}, 2
	}
	return doc, 0
}

// validateThreats validates an already-decoded threat-model document;
// requirements may be nil to skip link resolution.
func validateThreats(
	config *policy.Config,
	doc threats.Document,
	label string,
	requirements *threats.RequirementIndex,
	stderr io.Writer,
) (threats.Document, int) {
	pol, err := config.ThreatsPolicy()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return threats.Document{}, 2
	}
	if errs := threats.Validate(doc, pol, requirements); len(errs) > 0 {
		reportErrors(stderr, label, errs)
		return threats.Document{}, 1
	}
	return doc, 0
}

// loadThreats decodes and validates a threat-model document; requirements
// may be nil to skip link resolution.
func loadThreats(
	config *policy.Config,
	data []byte,
	label string,
	requirements *threats.RequirementIndex,
	stderr io.Writer,
) (threats.Document, int) {
	doc, code := decodeThreats(data, label, stderr)
	if code != 0 {
		return threats.Document{}, code
	}
	return validateThreats(config, doc, label, requirements, stderr)
}

func requirementIndex(doc matrix.Document) *threats.RequirementIndex {
	index := threats.RequirementIndex{
		Active:       make(map[string]struct{}, len(doc.Requirements)),
		Retired:      make(map[string]struct{}, len(doc.Supersessions)),
		Replacements: make(map[string][]string, len(doc.Supersessions)),
	}
	for _, item := range doc.Requirements {
		index.Active[item.ID] = struct{}{}
	}
	for _, item := range doc.Supersessions {
		index.Retired[item.RetiredID] = struct{}{}
		index.Replacements[item.RetiredID] = item.ReplacementIDs
	}
	return &index
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("validate", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	docPath := flags.String("doc", "", "document JSON file")
	requirementsPath := flags.String(
		"requirements", "",
		"requirements matrix that resolves a threat model's requirement links",
	)
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	if !requireFlags(stderr, [2]string{"config", *configPath}, [2]string{"doc", *docPath}) {
		return 2
	}

	config, code := loadConfig(*configPath, stderr)
	if code != 0 {
		return code
	}
	data, docType, code := readTyped(*docPath, "document", stderr)
	if code != 0 {
		return code
	}

	switch docType {
	case document.TypeRequirements:
		if *requirementsPath != "" {
			fmt.Fprintln(stderr, "error: -requirements applies only to threat-model documents")
			return 2
		}
		doc, code := loadRequirements(config, data, "document", stderr)
		if code != 0 {
			return code
		}
		fmt.Fprintf(stdout, "validated %d requirements from %s\n", len(doc.Requirements), *docPath)
	case document.TypeThreatModel:
		doc, code := decodeThreats(data, "document", stderr)
		if code != 0 {
			return code
		}

		var index *threats.RequirementIndex
		if *requirementsPath != "" {
			requirementsData, requirementsType, code := readTyped(
				*requirementsPath, "requirements", stderr,
			)
			if code != 0 {
				return code
			}
			if requirementsType != document.TypeRequirements {
				fmt.Fprintf(
					stderr,
					"error: -requirements must name a requirements document, got %q\n",
					requirementsType,
				)
				return 2
			}
			requirementsDoc, code := loadRequirements(config, requirementsData, "requirements", stderr)
			if code != 0 {
				return code
			}
			index = requirementIndex(requirementsDoc)
		} else if doc.HasRequirementLinks() {
			fmt.Fprintln(
				stderr,
				"error: threat model references requirement IDs; -requirements is required",
			)
			return 2
		}

		doc, code = validateThreats(config, doc, "document", index, stderr)
		if code != 0 {
			return code
		}
		fmt.Fprintf(stdout, "validated %d threats from %s\n", len(doc.Threats), *docPath)
	}
	return 0
}

func runRender(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("render", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	docPath := flags.String("doc", "", "document JSON file")
	outputPath := flags.String("output", "", "rendered Markdown file")
	templatePath := flags.String("template", "", "consumer template file (optional)")
	checkFresh := flags.Bool("check", false, "fail if the rendered Markdown is missing or stale")
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	if !requireFlags(
		stderr,
		[2]string{"config", *configPath},
		[2]string{"doc", *docPath},
		[2]string{"output", *outputPath},
	) {
		return 2
	}

	config, code := loadConfig(*configPath, stderr)
	if code != 0 {
		return code
	}
	data, docType, code := readTyped(*docPath, "document", stderr)
	if code != 0 {
		return code
	}
	options, err := config.RenderOptions(docType)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	templateText := ""
	if *templatePath != "" {
		templateText, err = render.ReadTemplate(*templatePath)
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot render document: %v\n", err)
			return 2
		}
	}

	var rendered string
	var itemCount int
	var itemNoun string
	switch docType {
	case document.TypeRequirements:
		doc, code := loadRequirements(config, data, "document", stderr)
		if code != 0 {
			return code
		}
		rendered, err = requirementsrender.Render(doc, options, templateText)
		itemCount, itemNoun = len(doc.Requirements), "requirements"
	case document.TypeThreatModel:
		doc, code := loadThreats(config, data, "document", nil, stderr)
		if code != 0 {
			return code
		}
		rendered, err = threatsrender.Render(doc, options, templateText)
		itemCount, itemNoun = len(doc.Threats), "threats"
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot render document: %v\n", err)
		return 2
	}

	if *checkFresh {
		current, err := os.ReadFile(*outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot read rendered document: %v\n", err)
			return 1
		}
		if string(current) != rendered {
			fmt.Fprintf(
				stderr,
				"error: %s is stale; run %s\n",
				*outputPath,
				options.RegenerateCommand,
			)
			return 1
		}
		fmt.Fprintf(stdout, "rendered document is current: %s\n", *outputPath)
		return 0
	}

	if err := fsio.WriteFileAtomic(*outputPath, []byte(rendered)); err != nil {
		fmt.Fprintf(stderr, "error: cannot write rendered document: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "rendered %d %s to %s\n", itemCount, itemNoun, *outputPath)
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("compare", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	baselinePath := flags.String("baseline", "", "designated accepted baseline document JSON file")
	candidatePath := flags.String("candidate", "", "candidate document JSON file")
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	if !requireFlags(
		stderr,
		[2]string{"config", *configPath},
		[2]string{"baseline", *baselinePath},
		[2]string{"candidate", *candidatePath},
	) {
		return 2
	}

	config, code := loadConfig(*configPath, stderr)
	if code != 0 {
		return code
	}
	baselineData, baselineType, code := readTyped(*baselinePath, "baseline", stderr)
	if code != 0 {
		return code
	}
	candidateData, candidateType, code := readTyped(*candidatePath, "candidate", stderr)
	if code != 0 {
		return code
	}
	if baselineType != candidateType {
		fmt.Fprintf(
			stderr,
			"error: document types differ: baseline is %q, candidate is %q\n",
			baselineType,
			candidateType,
		)
		return 2
	}

	var errs check.Errors
	var baselineVersion, candidateVersion string
	switch baselineType {
	case document.TypeRequirements:
		baseline, code := loadRequirements(config, baselineData, "baseline", stderr)
		if code != 0 {
			return code
		}
		candidate, code := loadRequirements(config, candidateData, "candidate", stderr)
		if code != 0 {
			return code
		}
		errs = matrix.Compare(baseline, candidate, config.TransitionRules())
		baselineVersion, candidateVersion = baseline.DocumentVersion, candidate.DocumentVersion
	case document.TypeThreatModel:
		baseline, code := loadThreats(config, baselineData, "baseline", nil, stderr)
		if code != 0 {
			return code
		}
		candidate, code := loadThreats(config, candidateData, "candidate", nil, stderr)
		if code != 0 {
			return code
		}
		errs = threats.Compare(baseline, candidate, config.TransitionRules())
		baselineVersion, candidateVersion = baseline.DocumentVersion, candidate.DocumentVersion
	}

	if len(errs) > 0 {
		for _, message := range errs {
			fmt.Fprintf(stderr, "error: %s\n", message)
		}
		return 1
	}
	fmt.Fprintf(
		stdout,
		"candidate %s is a legal successor of baseline %s\n",
		candidateVersion,
		baselineVersion,
	)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

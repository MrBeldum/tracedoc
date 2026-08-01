// Command reqmatrix validates, renders, and cross-version-compares a
// versioned requirements-matrix document under a consumer-owned policy
// configuration. See docs/cli.md for the versioned command contract.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sofired/matrix-service/internal/fsio"
	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/policy"
	"github.com/sofired/matrix-service/internal/render"
)

// toolVersion is the released tool version. The release process keeps it in
// step with the repository tag; see docs/versioning.md.
const toolVersion = "0.1.0"

// cliContractVersion identifies the command contract in docs/cli.md.
const cliContractVersion = 1

const usageText = `Usage: reqmatrix <command> [flags]

Commands:
  validate  -config <path> -matrix <path>
            Strictly decode and validate one matrix snapshot.
  render    -config <path> -matrix <path> -output <path> [-template <path>] [-check]
            Render the Markdown companion, or with -check verify that the
            existing output is current.
  compare   -config <path> -baseline <path> -candidate <path>
            Validate both snapshots, then check that the candidate is a
            legal successor of the accepted baseline.
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
			"reqmatrix %s (cli-contract %d, schema %d, config %d)\n",
			toolVersion,
			cliContractVersion,
			matrix.SchemaVersion,
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
	flags := flag.NewFlagSet("reqmatrix "+command, flag.ContinueOnError)
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

func loadValidated(configPath, matrixPath, label string, stderr io.Writer) (
	matrix.Document,
	*policy.Config,
	int,
) {
	config, err := policy.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot load config: %v\n", err)
		return matrix.Document{}, nil, 2
	}
	doc, err := matrix.Load(matrixPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot load %s: %v\n", label, err)
		return matrix.Document{}, nil, 2
	}
	if errs := matrix.Validate(doc, config.MatrixPolicy()); len(errs) > 0 {
		for _, message := range errs {
			fmt.Fprintf(stderr, "error: %s: %s\n", label, message)
		}
		return matrix.Document{}, nil, 1
	}
	return doc, config, 0
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("validate", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	matrixPath := flags.String("matrix", "", "matrix JSON file")
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	if !requireFlags(stderr, [2]string{"config", *configPath}, [2]string{"matrix", *matrixPath}) {
		return 2
	}

	doc, _, code := loadValidated(*configPath, *matrixPath, "matrix", stderr)
	if code != 0 {
		return code
	}
	fmt.Fprintf(stdout, "validated %d requirements from %s\n", len(doc.Requirements), *matrixPath)
	return 0
}

func runRender(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("render", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	matrixPath := flags.String("matrix", "", "matrix JSON file")
	outputPath := flags.String("output", "", "rendered Markdown file")
	templatePath := flags.String("template", "", "consumer template file (optional)")
	check := flags.Bool("check", false, "fail if the rendered Markdown is missing or stale")
	if code, ok := parseFlags(flags, args, stderr); !ok {
		return code
	}
	if !requireFlags(
		stderr,
		[2]string{"config", *configPath},
		[2]string{"matrix", *matrixPath},
		[2]string{"output", *outputPath},
	) {
		return 2
	}

	doc, config, code := loadValidated(*configPath, *matrixPath, "matrix", stderr)
	if code != 0 {
		return code
	}
	options := render.Options{
		IssueURLBase:      config.Render.IssueURLBase,
		SourceName:        config.Render.SourceName,
		GeneratorName:     config.Render.GeneratorName,
		RegenerateCommand: config.Render.RegenerateCommand,
		CheckCommand:      config.Render.CheckCommand,
		TemplatePath:      *templatePath,
	}
	rendered, err := render.Document(doc, options)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot render matrix: %v\n", err)
		return 2
	}

	if *check {
		current, err := os.ReadFile(*outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot read rendered matrix: %v\n", err)
			return 1
		}
		if string(current) != rendered {
			fmt.Fprintf(
				stderr,
				"error: %s is stale; run %s\n",
				*outputPath,
				config.Render.RegenerateCommand,
			)
			return 1
		}
		fmt.Fprintf(stdout, "rendered matrix is current: %s\n", *outputPath)
		return 0
	}

	if err := fsio.WriteFileAtomic(*outputPath, []byte(rendered)); err != nil {
		fmt.Fprintf(stderr, "error: cannot write rendered matrix: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "rendered %d requirements to %s\n", len(doc.Requirements), *outputPath)
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("compare", stderr)
	configPath := flags.String("config", "", "policy configuration JSON file")
	baselinePath := flags.String("baseline", "", "designated accepted baseline matrix JSON file")
	candidatePath := flags.String("candidate", "", "candidate matrix JSON file")
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

	baseline, config, code := loadValidated(*configPath, *baselinePath, "baseline", stderr)
	if code != 0 {
		return code
	}
	candidate, err := matrix.Load(*candidatePath)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot load candidate: %v\n", err)
		return 2
	}
	if errs := matrix.Validate(candidate, config.MatrixPolicy()); len(errs) > 0 {
		for _, message := range errs {
			fmt.Fprintf(stderr, "error: candidate: %s\n", message)
		}
		return 1
	}

	if errs := matrix.Compare(baseline, candidate, config.TransitionRules()); len(errs) > 0 {
		for _, message := range errs {
			fmt.Fprintf(stderr, "error: %s\n", message)
		}
		return 1
	}
	fmt.Fprintf(
		stdout,
		"candidate %s is a legal successor of baseline %s\n",
		candidate.MatrixVersion,
		baseline.MatrixVersion,
	)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

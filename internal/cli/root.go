// Package cli wires input handling, analysis, filtering, and reporting into
// the planlens command with CI-friendly exit codes.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"planlens/internal/analysis"
	"planlens/internal/engine"
	"planlens/internal/plan"
	"planlens/internal/report"
)

// Version is the planlens release version. It is overridden at build time
// via -ldflags "-X planlens/internal/cli.Version={{.Version}}".
var Version = "0.2.0"

// Exit codes.
const (
	ExitOK    = 0
	ExitGate  = 1
	ExitError = 2
)

type config struct {
	format     string
	categories map[analysis.Category]bool // empty = all
	failOn     map[string]bool            // gate categories: destroy/replacement
	resource   string
	groupBy    string
	verbose    bool
	version    bool
}

// gateNames maps --fail-on values to finding categories. Only objective,
// mechanical gates are supported: no security opinions.
var gateNames = map[string]analysis.Category{
	"destroy":     analysis.CatDestructive,
	"destructive": analysis.CatDestructive,
	"replacement": analysis.CatReplacement,
	"replace":     analysis.CatReplacement,
}

var categoryNames = map[string]analysis.Category{
	string(analysis.CatReplacement): analysis.CatReplacement,
	string(analysis.CatDestructive): analysis.CatDestructive,
	string(analysis.CatSensitive):   analysis.CatSensitive,
	string(analysis.CatCapacity):    analysis.CatCapacity,
	string(analysis.CatBehavioral):  analysis.CatBehavioral,
	string(analysis.CatAccess):      analysis.CatAccess,
	string(analysis.CatUnknown):     analysis.CatUnknown,
	string(analysis.CatMetadata):    analysis.CatMetadata,
	string(analysis.CatCreate):      analysis.CatCreate,
	string(analysis.CatOther):       analysis.CatOther,
}

type failOnList []string

func (f *failOnList) String() string { return strings.Join(*f, ",") }
func (f *failOnList) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// Run executes planlens and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	var cfg config
	var failOn failOnList
	var categories string

	fs := flag.NewFlagSet("planlens", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "PLANLENS — a reviewer-oriented semantic diff for Terraform and OpenTofu plans")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  planlens [flags] [plan.json]     (reads from stdin when no file is given)")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Examples:")
		fmt.Fprintln(stderr, "  tofu show -json tfplan | planlens")
		fmt.Fprintln(stderr, "  planlens --fail-on replacement tfplan.json")
		fmt.Fprintln(stderr, "  planlens --group-by module --format markdown tfplan.json")
	}
	fs.StringVar(&cfg.format, "format", "text", "output format: text, json, or markdown")
	fs.StringVar(&categories, "category", "", "comma-separated filter: only show these change categories")
	fs.Var(&failOn, "fail-on", "exit 1 when findings of this category exist: destroy or replacement (repeatable)")
	fs.StringVar(&cfg.resource, "resource", "", "only show findings for this exact resource address")
	fs.StringVar(&cfg.groupBy, "group-by", "", "group findings by module or type in text output")
	fs.BoolVar(&cfg.verbose, "verbose", false, "expand collapsed low-signal changes")
	fs.BoolVar(&cfg.version, "version", false, "print version")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "error: at most one positional plan file argument is allowed")
		return ExitError
	}
	if cfg.version {
		fmt.Fprintln(stdout, "planlens "+Version)
		return ExitOK
	}
	if cfg.format != "text" && cfg.format != "json" && cfg.format != "markdown" {
		fmt.Fprintf(stderr, "error: invalid --format %q (want text, json, or markdown)\n", cfg.format)
		return ExitError
	}
	cfg.failOn = make(map[string]bool, len(failOn))
	for _, v := range failOn {
		cat, ok := gateNames[strings.ToLower(v)]
		if !ok {
			fmt.Fprintf(stderr, "error: invalid --fail-on %q (want destroy or replacement)\n", v)
			return ExitError
		}
		cfg.failOn[string(cat)] = true
	}
	if categories != "" {
		cfg.categories = make(map[analysis.Category]bool)
		for _, name := range strings.Split(categories, ",") {
			cat, ok := categoryNames[strings.ToLower(strings.TrimSpace(name))]
			if !ok {
				fmt.Fprintf(stderr, "error: unknown category %q in --category\n", name)
				return ExitError
			}
			cfg.categories[cat] = true
		}
	}
	switch cfg.groupBy {
	case "", "none", "module", "type":
	default:
		fmt.Fprintf(stderr, "error: invalid --group-by %q (want module or type)\n", cfg.groupBy)
		return ExitError
	}
	if cfg.groupBy == "none" {
		cfg.groupBy = ""
	}

	p, err := readPlan(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitError
	}

	findings, summary := engine.Analyze(p)
	fullCategories := analysis.CountCategories(findings)

	shown := filterFindings(findings, cfg)

	var errRender error
	switch cfg.format {
	case "json":
		errRender = report.JSON(stdout, shown, summary, fullCategories, p.TerraformVersion, p.FormatVersion, Version)
	case "markdown":
		errRender = report.Markdown(stdout, shown, summary, p.TerraformVersion, p.FormatVersion, report.TextOptions{
			Verbose: cfg.verbose,
			GroupBy: cfg.groupBy,
		})
	default:
		errRender = report.Text(stdout, shown, summary, p.TerraformVersion, p.FormatVersion, report.TextOptions{
			Verbose: cfg.verbose,
			Color:   report.ColorEnabled(),
			GroupBy: cfg.groupBy,
		})
	}
	if errRender != nil {
		fmt.Fprintf(stderr, "error rendering output: %v\n", errRender)
		return ExitError
	}

	// Gates are evaluated against the full findings set, not the filtered
	// view: --resource and --category are display filters, not safety ones.
	for _, f := range findings {
		if cfg.failOn[string(f.Category)] {
			return ExitGate
		}
	}
	return ExitOK
}

// readPlan reads plan JSON from a file path, or stdin when path is empty.
func readPlan(path string) (*plan.Plan, error) {
	if path == "" {
		fi, err := os.Stdin.Stat()
		if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return nil, fmt.Errorf("no input: pass a plan JSON file or pipe one via stdin (e.g. tofu show -json tfplan | planlens)")
		}
		return plan.Parse(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return plan.Parse(f)
}

func filterFindings(findings []analysis.Finding, cfg config) []analysis.Finding {
	var out []analysis.Finding
	for _, f := range findings {
		if len(cfg.categories) > 0 && !cfg.categories[f.Category] {
			continue
		}
		if cfg.resource != "" && f.Address != cfg.resource {
			continue
		}
		out = append(out, f)
	}
	return out
}

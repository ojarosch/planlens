package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"planlens/internal/analysis"
	"planlens/internal/diff"
)

// TextOptions controls text rendering.
type TextOptions struct {
	Verbose bool
	Color   bool
	GroupBy string // "", "module", "type"
}

// color wraps ANSI codes; a disabled colorizer returns input unchanged.
type color struct{ enabled bool }

func (c color) bold(s string) string {
	if !c.enabled {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}
func (c color) dim(s string) string {
	if !c.enabled {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

// ColorEnabled reports whether ANSI colors should be used on stdout.
// Respects NO_COLOR and non-terminal output.
func ColorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

var categoryHeaders = map[analysis.Category]string{
	analysis.CatReplacement: "REPLACEMENT",
	analysis.CatDestructive: "DESTRUCTIVE",
	analysis.CatCapacity:    "CAPACITY",
	analysis.CatBehavioral:  "BEHAVIORAL",
	analysis.CatAccess:      "ACCESS",
	analysis.CatSensitive:   "SENSITIVE",
	analysis.CatOther:       "OTHER CHANGES",
}

// highlightedCategories are rendered as individual findings; everything else
// is collapsed into the LOW-SIGNAL section unless verbose.
var highlightedCategories = []analysis.Category{
	analysis.CatReplacement,
	analysis.CatDestructive,
	analysis.CatCapacity,
	analysis.CatBehavioral,
	analysis.CatAccess,
	analysis.CatSensitive,
	analysis.CatOther,
}

const maxChangesShown = 8

// Text renders the human-readable report.
func Text(w io.Writer, findings []analysis.Finding, summary analysis.Summary, terraformVersion, formatVersion string, opts TextOptions) error {
	c := color{enabled: opts.Color}

	fmt.Fprintln(w, c.bold("PLANLENS"))
	if terraformVersion != "" || formatVersion != "" {
		fmt.Fprintf(w, "%s\n", c.dim(fmt.Sprintf("terraform %s · format %s", terraformVersion, formatVersion)))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.bold("Plan"))
	fmt.Fprintf(w, "%d resource%s affected\n", summary.ResourcesAffected, plural(summary.ResourcesAffected))
	parts := []string{}
	for _, k := range []struct {
		n int
		s string
	}{{summary.Create, "create"}, {summary.Update, "update"}, {summary.Delete, "destroy"}, {summary.Replace, "replace"}, {summary.Read, "read"}} {
		if k.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", k.n, k.s))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no changes")
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
	fmt.Fprintln(w)

	highlighted, collapsed := 0, 0
	for _, cat := range highlightedCategories {
		var section []analysis.Finding
		for _, f := range findings {
			if f.Category == cat {
				section = append(section, f)
			}
		}
		if len(section) == 0 {
			continue
		}
		highlighted += len(section)
		fmt.Fprintln(w, c.bold(categoryHeaders[cat]))
		renderGrouped(w, section, opts)
		fmt.Fprintln(w)
	}

	// LOW-SIGNAL: collapsed noise reduction summary.
	var meta, computed, creates []analysis.Finding
	for _, f := range findings {
		switch f.Category {
		case analysis.CatMetadata:
			meta = append(meta, f)
		case analysis.CatUnknown:
			computed = append(computed, f)
		case analysis.CatCreate:
			creates = append(creates, f)
		}
	}
	collapsed = len(meta) + len(computed) + len(creates)

	if collapsed > 0 {
		fmt.Fprintln(w, c.bold("LOW-SIGNAL"))
		fmt.Fprintln(w, c.dim(fmt.Sprintf("%d change%s collapsed:", collapsed, plural(collapsed))))
		for _, g := range []struct {
			items []analysis.Finding
			label string
		}{{meta, "metadata-only"}, {computed, "computed/unknown-only"}, {creates, "straightforward creates"}} {
			if len(g.items) > 0 {
				fmt.Fprintf(w, "  %d %s\n", len(g.items), g.label)
			}
		}
		if !opts.Verbose {
			fmt.Fprintln(w, "Use --verbose to display them.")
		} else {
			for _, g := range creates {
				renderFinding(w, g)
			}
			for _, f := range computed {
				renderFinding(w, f)
			}
			for _, f := range meta {
				renderFinding(w, f)
			}
		}
		fmt.Fprintln(w)
	}

	if highlighted+collapsed == 0 && summary.ResourcesAffected == 0 {
		fmt.Fprintln(w, "No changes.")
		return nil
	}

	fmt.Fprintln(w, strings.Repeat("─", 30))
	if opts.Verbose || collapsed == 0 {
		fmt.Fprintf(w, "%d change%s shown\n", highlighted+collapsed, plural(highlighted+collapsed))
	} else {
		fmt.Fprintf(w, "%d highlighted · %d collapsed\n", highlighted, collapsed)
	}
	return nil
}

func renderGrouped(w io.Writer, findings []analysis.Finding, opts TextOptions) {
	if opts.GroupBy == "" {
		for _, f := range findings {
			renderFinding(w, f)
		}
		return
	}
	keyOf := func(f analysis.Finding) string {
		if opts.GroupBy == "module" {
			if f.ModuleAddress == "" {
				return "(root module)"
			}
			return f.ModuleAddress
		}
		return f.ResourceType
	}
	var lastKey string
	for _, f := range findings {
		key := keyOf(f)
		if key != lastKey {
			fmt.Fprintln(w, key)
			lastKey = key
		}
		renderFinding(w, f, "  ")
	}
}

// renderFinding prints one finding; pad shifts it under a group header.
func renderFinding(w io.Writer, f analysis.Finding, pads ...string) {
	pad := ""
	if len(pads) > 0 {
		pad = pads[0]
	}
	fmt.Fprintln(w, pad+f.Address)
	if f.Description != "" {
		fmt.Fprintln(w, indentLines(f.Description, pad+"  "))
	}
	shown := f.Changes
	for i, ch := range shown {
		if i == maxChangesShown {
			fmt.Fprintf(w, "%s  … %d more attribute changes\n", pad, len(f.Changes)-i)
			break
		}
		renderChange(w, ch, pad+"  ")
	}
	fmt.Fprintln(w)
}

func renderChange(w io.Writer, ch diff.AttributeChange, pad string) {
	before, after := displayValues(ch)
	if after == "" {
		fmt.Fprintf(w, "%s%s:\n%s  %s\n", pad, ch.Path, pad, before)
		return
	}
	if added, removed, ok := diff.SetDiff(ch); ok && (len(added) > 0 || len(removed) > 0) {
		fmt.Fprintf(w, "%s%s:\n", pad, ch.Path)
		for _, v := range added {
			fmt.Fprintf(w, "%s  + %s\n", pad, v)
		}
		for _, v := range removed {
			fmt.Fprintf(w, "%s  - %s\n", pad, v)
		}
		return
	}
	fmt.Fprintf(w, "%s%s:\n%s  %s → %s\n", pad, ch.Path, pad, before, after)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

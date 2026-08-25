package report

import (
	"fmt"
	"io"
	"strings"

	"planlens/internal/analysis"
	"planlens/internal/diff"
)

var markdownHeaders = map[analysis.Category]string{
	analysis.CatReplacement: "Replacements",
	analysis.CatDestructive: "Destructive",
	analysis.CatCapacity:    "Capacity changes",
	analysis.CatBehavioral:  "Behavioral changes",
	analysis.CatAccess:      "Access changes",
	analysis.CatSensitive:   "Sensitive values",
	analysis.CatOther:       "Other changes",
}

// Markdown renders a pull-request-friendly report. Low-signal findings are
// collapsed into a <details> block; pass Verbose to inline everything.
func Markdown(w io.Writer, findings []analysis.Finding, summary analysis.Summary, terraformVersion, formatVersion string, opts TextOptions) error {
	fmt.Fprintf(w, "## PlanLens\n\n")
	if summary.ResourcesAffected > 0 {
		fmt.Fprintf(w, "**%d resource%s affected**\n\n", summary.ResourcesAffected, plural(summary.ResourcesAffected))
	} else {
		fmt.Fprintf(w, "No changes.\n")
		return nil
	}

	var parts []string
	for _, k := range []struct {
		n int
		s string
	}{{summary.Create, "create"}, {summary.Update, "update"}, {summary.Delete, "destroy"}, {summary.Replace, "replace"}} {
		if k.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", k.n, k.s))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "%s\n\n", strings.Join(parts, " · "))
	}

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
		fmt.Fprintf(w, "### %s\n\n", markdownHeaders[cat])
		for _, f := range section {
			renderMarkdownFinding(w, f)
		}
	}

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
	collapsed := len(meta) + len(computed) + len(creates)

	if collapsed > 0 {
		fmt.Fprintf(w, "<details>\n<summary>%d low-signal change%s</summary>\n\n", collapsed, plural(collapsed))
		for _, g := range []struct {
			items []analysis.Finding
			label string
		}{{creates, "created"}, {computed, "computed-only"}, {meta, "metadata-only"}} {
			for _, f := range g.items {
				if opts.Verbose {
					renderMarkdownFinding(w, f)
				} else {
					fmt.Fprintf(w, "- `%s` (%s)\n", f.Address, g.label)
				}
			}
		}
		fmt.Fprintf(w, "\n</details>\n\n")
	}

	return nil
}

func renderMarkdownFinding(w io.Writer, f analysis.Finding) {
	fmt.Fprintf(w, "- `%s`\n", f.Address)
	if f.ReplacementOrder != "" {
		fmt.Fprintf(w, "  - replacement required (%s)\n", strings.ReplaceAll(f.ReplacementOrder, "-", " → "))
	} else if f.Description != "" {
		for _, line := range strings.Split(f.Description, "\n") {
			fmt.Fprintf(w, "  - %s\n", line)
		}
	}
	shown := f.Changes
	for i, ch := range shown {
		if i == maxChangesShown {
			fmt.Fprintf(w, "  - … %d more attribute changes\n", len(f.Changes)-i)
			break
		}
		before, after := displayValues(ch)
		if after == "" {
			fmt.Fprintf(w, "  - `%s`: %s\n", ch.Path, before)
			continue
		}
		if added, removed, ok := diff.SetDiff(ch); ok && (len(added) > 0 || len(removed) > 0) {
			fmt.Fprintf(w, "  - `%s`:\n", ch.Path)
			for _, v := range added {
				fmt.Fprintf(w, "    - `+ %s`\n", v)
			}
			for _, v := range removed {
				fmt.Fprintf(w, "    - `- %s`\n", v)
			}
			continue
		}
		fmt.Fprintf(w, "  - `%s`: `%s` → `%s`\n", ch.Path, before, after)
	}
}

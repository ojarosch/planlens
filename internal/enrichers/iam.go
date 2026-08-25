// Package enrichers adds resource-specific descriptive detail to findings.
// Enrichers describe the change; they never evaluate whether it is
// acceptable.
package enrichers

import (
	"encoding/json"
	"sort"
	"strings"

	"planlens/internal/analysis"
	"planlens/internal/plan"
)

var iamPolicyResourceTypes = map[string]bool{
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_user_policy":  true,
	"aws_iam_group_policy": true,
}

// IAMPolicy attaches a structural diff of an IAM policy document (actions and
// resources added/removed) to access findings on IAM policy resources. It
// deliberately reports structure only — no wildcards, no risk judgments.
func IAMPolicy(f *analysis.Finding, rc plan.ResourceChange) bool {
	if !iamPolicyResourceTypes[rc.Type] || f.Category != analysis.CatAccess {
		return false
	}
	bm, _ := rc.Change.Before.(map[string]any)
	am, _ := rc.Change.After.(map[string]any)
	if bm == nil || am == nil {
		return false
	}
	beforeDoc := parsePolicyDoc(bm["policy"])
	afterDoc := parsePolicyDoc(am["policy"])
	if beforeDoc == nil && afterDoc == nil {
		return false
	}

	lines := diffLines("actions", allowedActions(beforeDoc), allowedActions(afterDoc))
	resourceLines := diffLines("resources", resourcesOf(beforeDoc), resourcesOf(afterDoc))
	lines = append(lines, resourceLines...)
	if len(lines) == 0 {
		return false
	}
	f.Description = strings.Join(lines, "\n")
	// The structural diff replaces the raw policy blob; keeping both would
	// show the same change twice.
	kept := f.Changes[:0]
	for _, ch := range f.Changes {
		if ch.Path != "policy" {
			kept = append(kept, ch)
		}
	}
	f.Changes = kept
	return true
}

func diffLines(label string, before, after map[string]bool) []string {
	var added, removed []string
	for k := range after {
		if !before[k] {
			added = append(added, k)
		}
	}
	for k := range before {
		if !after[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	var lines []string
	if len(added) > 0 {
		lines = append(lines, label+" added:")
		for _, v := range added {
			lines = append(lines, "  + "+v)
		}
	}
	if len(removed) > 0 {
		lines = append(lines, label+" removed:")
		for _, v := range removed {
			lines = append(lines, "  - "+v)
		}
	}
	return lines
}

func parsePolicyDoc(v any) map[string]any {
	switch p := v.(type) {
	case string:
		var doc map[string]any
		if err := json.Unmarshal([]byte(p), &doc); err != nil {
			return nil
		}
		return doc
	case map[string]any:
		return p
	default:
		return nil
	}
}

func stmtSlice(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func collect(doc map[string]any, fn func(stmt map[string]any)) {
	if s := stmtSlice(doc["Statement"]); len(s) > 0 {
		for _, st := range s {
			fn(st)
		}
	} else if st, ok := doc["Statement"].(map[string]any); ok {
		fn(st)
	}
}

func anyToStringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, it := range t {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func allowedActions(doc map[string]any) map[string]bool {
	out := make(map[string]bool)
	collect(doc, func(stmt map[string]any) {
		if eff, _ := stmt["Effect"].(string); eff == "Allow" {
			for _, a := range anyToStringList(stmt["Action"]) {
				out[a] = true
			}
		}
	})
	return out
}

func resourcesOf(doc map[string]any) map[string]bool {
	out := make(map[string]bool)
	collect(doc, func(stmt map[string]any) {
		if eff, _ := stmt["Effect"].(string); eff == "Allow" {
			for _, r := range anyToStringList(stmt["Resource"]) {
				out[r] = true
			}
		}
	})
	return out
}

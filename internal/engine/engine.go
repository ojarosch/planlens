// Package engine runs the planlens pipeline: parse-level normalization
// already happened; here resource changes become categorized findings using
// a mostly-generic semantic engine plus small descriptive enrichers.
package engine

import (
	"planlens/internal/analysis"
	"planlens/internal/diff"
	"planlens/internal/enrichers"
	"planlens/internal/plan"
	"planlens/internal/semantic"
)

// Analyze returns merged findings and a plan summary.
func Analyze(p *plan.Plan) ([]analysis.Finding, analysis.Summary) {
	ctx := &analysis.Context{Plan: p}
	var findings []analysis.Finding
	for _, rc := range p.ResourceChanges {
		switch plan.Action(rc.Change.Actions) {
		case plan.ActionNoOp, plan.ActionRead:
			continue
		case plan.ActionDelete:
			findings = append(findings, destructiveFinding(rc))
		case plan.ActionReplace:
			findings = append(findings, replacementFinding(rc))
		case plan.ActionCreate:
			findings = append(findings, analysis.Finding{
				ID: "change.create", Category: analysis.CatCreate,
				Address: rc.Address, ModuleAddress: rc.ModuleAddress,
				ResourceType: rc.Type, Title: "Resource created",
				Confidence: analysis.ConfidenceHigh,
			})
		case plan.ActionUpdate:
			findings = append(findings, updateFindings(ctx, rc)...)
		}
	}
	return analysis.Merge(findings), analysis.Summarize(p)
}

func baseFinding(id string, cat analysis.Category, rc plan.ResourceChange) analysis.Finding {
	return analysis.Finding{
		ID: id, Category: cat,
		Address: rc.Address, ModuleAddress: rc.ModuleAddress,
		ResourceType: rc.Type,
		Confidence:   analysis.ConfidenceHigh,
	}
}

// destructiveFinding reports removal. It surfaces a few top-level before
// values so the reviewer can see what is going away.
func destructiveFinding(rc plan.ResourceChange) analysis.Finding {
	f := baseFinding("change.resource-destroy", analysis.CatDestructive, rc)
	f.Title = "Resource will be removed"
	bm, ok := rc.Change.Before.(map[string]any)
	if !ok {
		return f
	}
	for k, v := range bm {
		if len(f.Changes) >= 5 {
			break
		}
		switch v.(type) {
		case string, float64, bool:
			f.Changes = append(f.Changes, diff.AttributeChange{Path: k, Before: v})
		}
	}
	return f
}

// replacementFinding reports replacement with its cause attributes from
// replace_paths and the lifecycle order.
func replacementFinding(rc plan.ResourceChange) analysis.Finding {
	f := baseFinding("change.resource-replacement", analysis.CatReplacement, rc)
	f.Title = "Replacement required"
	order := rc.Change.ReplacementOrder()
	f.ReplacementOrder = order
	if order != "" {
		f.Description = "replacement required · lifecycle: " + order
	} else {
		f.Description = "replacement required"
	}

	res := diff.ResourceAttributes(rc)
	var causes []diff.AttributeChange
	unmapped := false
	for _, rp := range rc.Change.ReplacePaths {
		path := diff.FormatPathAny(rp)
		if ch, found := matchingAttrChange(res, path); found {
			ch.CausesReplacement = true
			causes = append(causes, ch)
		} else {
			unmapped = true
			f.Description += "\ntrigger path:\n  " + path
		}
	}
	if unmapped && len(causes) == 0 && len(rc.Change.ReplacePaths) == 0 {
		f.Description += "\ncause not reported by Terraform"
	}
	f.Changes = causes
	return f
}

// matchingAttrChange finds the attribute diff for a replace path.
func matchingAttrChange(res diff.Result, path string) (diff.AttributeChange, bool) {
	for _, ch := range res.Changes {
		if ch.Path == path || sameTopSegment(ch.Path, path) {
			return ch, true
		}
	}
	return diff.AttributeChange{}, false
}

func sameTopSegment(a, b string) bool {
	top := func(p string) string {
		for i := 0; i < len(p); i++ {
			if p[i] == '.' || p[i] == '[' {
				return p[:i]
			}
		}
		return p
	}
	return top(a) == top(b) && top(a) != ""
}

// updateFindings groups an update's attribute changes into one finding per
// semantic category. All-metadata and all-computed updates collapse into a
// single low-signal finding each.
func updateFindings(ctx *analysis.Context, rc plan.ResourceChange) []analysis.Finding {
	res := diff.ResourceAttributes(rc)
	if len(res.Changes) == 0 {
		return nil
	}

	// Computed-only: every meaningful difference is known-after-apply output.
	allUnknown := true
	for _, ch := range res.Changes {
		if !ch.Unknown {
			allUnknown = false
			break
		}
	}
	if allUnknown {
		f := baseFinding("change.computed-only", analysis.CatUnknown, rc)
		f.Title = "Values only known after apply"
		f.Confidence = analysis.ConfidenceMedium
		f.Changes = res.Changes
		return []analysis.Finding{f}
	}

	// Metadata-only: every changed path is metadata-like. Unknown values
	// disqualify — they may turn out to be anything.
	allMetadata := true
	for _, ch := range res.Changes {
		if ch.Unknown || classifyChange(ch) != analysis.CatMetadata {
			allMetadata = false
			break
		}
	}
	if allMetadata {
		f := baseFinding("change.metadata-only", analysis.CatMetadata, rc)
		f.Title = "Metadata-only change"
		f.Changes = res.Changes
		return []analysis.Finding{f}
	}

	// Mixed update: group by category. Metadata tweaks are dropped here —
	// they are noise next to a meaningful change (the JSON summary still
	// counts the resource). A metadata-only update never reaches this path.
	buckets := make(map[analysis.Category][]diff.AttributeChange)
	var order []analysis.Category
	for _, ch := range res.Changes {
		cat := classifyChange(ch)
		if cat == analysis.CatMetadata {
			continue
		}
		if _, seen := buckets[cat]; !seen {
			order = append(order, cat)
		}
		buckets[cat] = append(buckets[cat], ch)
	}

	var findings []analysis.Finding
	for _, cat := range order {
		f := baseFinding("change."+string(cat), cat, rc)
		f.Title = categoryTitle(cat, rc)
		if cat == analysis.CatOther {
			f.ID = "change.update"
		}
		f.Changes = buckets[cat]
		if res.Truncated {
			f.Description = "attribute diff truncated at the change limit"
		}
		enrich(ctx, &f, rc)
		findings = append(findings, f)
	}
	return findings
}

func classifyChange(ch diff.AttributeChange) analysis.Category {
	if ch.Sensitive {
		return analysis.CatSensitive
	}
	if cat := semantic.ClassifyPath(ch.Path); cat != "" {
		return cat
	}
	return analysis.CatOther
}

func categoryTitle(cat analysis.Category, rc plan.ResourceChange) string {
	switch cat {
	case analysis.CatCapacity:
		return "Capacity change"
	case analysis.CatBehavioral:
		return "Runtime/behavior change"
	case analysis.CatAccess:
		return "Access configuration change"
	case analysis.CatSensitive:
		return "Sensitive value changed"
	default:
		return "Attribute update"
	}
}

// enrich applies small resource-specific describers to a finding.
func enrich(ctx *analysis.Context, f *analysis.Finding, rc plan.ResourceChange) {
	if f.Category == analysis.CatAccess {
		enrichers.IAMPolicy(f, rc)
	}
}

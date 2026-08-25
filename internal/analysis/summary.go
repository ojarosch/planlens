package analysis

import (
	"planlens/internal/plan"
)

// Summary aggregates plan-level counts. Replacements are counted separately
// and are NOT also counted as creates/destroys.
type Summary struct {
	ResourcesAffected int
	Create            int
	Update            int
	Delete            int
	Replace           int
	Read              int
	NoOp              int
}

// Summarize counts normalized actions across all resource changes.
func Summarize(p *plan.Plan) Summary {
	var s Summary
	for _, rc := range p.ResourceChanges {
		switch plan.Action(rc.Change.Actions) {
		case plan.ActionNoOp:
			s.NoOp++
		case plan.ActionRead:
			s.Read++
		case plan.ActionCreate:
			s.Create++
		case plan.ActionUpdate:
			s.Update++
		case plan.ActionDelete:
			s.Delete++
		case plan.ActionReplace:
			s.Replace++
		}
	}
	s.ResourcesAffected = s.Create + s.Update + s.Delete + s.Replace + s.Read
	return s
}

// CountCategories tallies findings per category.
func CountCategories(findings []Finding) map[Category]int {
	counts := make(map[Category]int, 8)
	for _, f := range findings {
		counts[f.Category]++
	}
	return counts
}

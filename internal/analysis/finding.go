// Package analysis defines findings, change categories, and the merge stage.
// Categories describe WHAT kind of change occurred, not whether the
// architecture is good or bad. planlens is a review surface, not a policy
// engine.
package analysis

import (
	"sort"

	"planlens/internal/diff"
	"planlens/internal/plan"
)

// Category is the semantic kind of a finding.
type Category string

const (
	CatReplacement Category = "replacement"
	CatDestructive Category = "destructive"
	CatSensitive   Category = "sensitive"
	CatCapacity    Category = "capacity"
	CatBehavioral  Category = "behavioral"
	CatAccess      Category = "access"
	CatUnknown     Category = "unknown"
	CatMetadata    Category = "metadata"
	CatCreate      Category = "create"
	CatOther       Category = "other"
)

// categoryOrder controls report ordering; low-signal categories come last.
var categoryOrder = map[Category]int{
	CatReplacement: 0,
	CatDestructive: 1,
	CatCapacity:    2,
	CatBehavioral:  3,
	CatAccess:      4,
	CatSensitive:   5,
	CatOther:       6,
	CatUnknown:     7,
	CatMetadata:    8,
	CatCreate:      9,
}

// IsLowSignal reports whether findings of this category are collapsed into
// the noise-reduction section by default.
func (c Category) IsLowSignal() bool {
	switch c {
	case CatMetadata, CatCreate, CatUnknown:
		return true
	}
	return false
}

// Order returns the display rank of a category.
func (c Category) Order() int { return categoryOrder[c] }

// Confidence expresses how sure planlens is about a classification.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Finding is one review-worthy observation about the plan.
type Finding struct {
	ID            string
	Category      Category
	Address       string
	ModuleAddress string
	ResourceType  string
	Title         string
	Description   string
	Confidence    Confidence
	Changes       []diff.AttributeChange
	// ReplacementOrder is "destroy-create" or "create-destroy" for
	// replacement findings; empty otherwise.
	ReplacementOrder string
}

// Context is shared across the pipeline for a single run.
type Context struct {
	Plan *plan.Plan
}

// Merge deduplicates findings: one finding per (address, ID).
func Merge(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := f.Address + "\x00" + f.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return FindingsLess(out[i], out[j]) })
	return out
}

// FindingsLess sorts by category order (review priority), then module,
// address, and ID for stability.
func FindingsLess(a, b Finding) bool {
	if a.Category != b.Category {
		return a.Category.Order() < b.Category.Order()
	}
	if a.ModuleAddress != b.ModuleAddress {
		return a.ModuleAddress < b.ModuleAddress
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	return a.ID < b.ID
}

// Package diff implements a recursive before/after attribute diff over
// Terraform plan JSON values, honoring sensitive and unknown markers.
package diff

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"planlens/internal/plan"
)

// ResourceAttributes diffs one resource change's before/after values.
func ResourceAttributes(rc plan.ResourceChange) Result {
	return Attributes(
		rc.Change.Before,
		rc.Change.After,
		rc.Change.BeforeSensitive,
		rc.Change.AfterSensitive,
		rc.Change.AfterUnknown,
	)
}

// AttributeChange is one changed leaf in a resource's configuration.
type AttributeChange struct {
	Path      string
	Before    any
	After     any
	Sensitive bool
	Unknown   bool
	// CausesReplacement is true when a replace_paths entry matches this
	// attribute.
	CausesReplacement bool `json:"causes_replacement,omitempty"`
}

const DefaultMaxChanges = 200

// Result holds the leaf changes for one resource.
type Result struct {
	Changes   []AttributeChange
	Truncated bool
}

// Attributes diffs before against after. Sensitive markers mirror the value
// structure (bool or map[string]any); a true marker marks the whole subtree.
// afterUnknown has the same shape and means "known only after apply".
func Attributes(before, after, beforeSensitive, afterSensitive, afterUnknown any) Result {
	var r Result
	walk(nil, before, after, beforeSensitive, afterSensitive, afterUnknown,
		false, &r)
	return r
}

func walk(path []string, b, a, sB, sA, uA any, sensitive bool, r *Result) {
	if r.Truncated {
		return
	}

	// Whole-value unknown: the result is only known after apply.
	if truthy(uA) {
		r.add(path, b, nil, sensitive || truthy(sB) || truthy(sA), true)
		return
	}
	sens := sensitive || truthy(sB) || truthy(sA)

	bm, bok := b.(map[string]any)
	am, aok := a.(map[string]any)
	if bok && aok {
		for k := range bm {
			if _, ok := am[k]; ok {
				continue
			}
			// removed key
			walk(append(path, k), bm[k], nil, childMarker(sB, k), nil, childMarker(uA, k), sens, r)
		}
		for k, av := range am {
			bv, present := bm[k]
			if !present {
				bv = nil
			}
			walk(append(path, k), bv, av, childMarker(sB, k), childMarker(sA, k), childMarker(uA, k), sens, r)
		}
		return
	}

	bs, bok2 := b.([]any)
	as, aok2 := a.([]any)
	if bok2 && aok2 {
		// Flat scalar lists (CIDRs, subnets, AZs, members...) stay atomic so
		// reporters can render an added/removed set diff instead of
		// index-wise noise.
		if !reflect.DeepEqual(bs, as) && flatScalars(bs) && flatScalars(as) {
			r.add(path, bs, as, sens, false)
			return
		}
		n := len(bs)
		if len(as) > n {
			n = len(as)
		}
		for i := 0; i < n; i++ {
			idx := strconv.Itoa(i)
			var bv, av any
			var sb, sa any
			if i < len(bs) {
				bv, sb = bs[i], elem(sB, i)
			}
			if i < len(as) {
				av, sa = as[i], elem(sA, i)
			}
			var ua any
			if us, ok := uA.([]any); ok && i < len(us) {
				ua = us[i]
			}
			walk(append(path, idx), bv, av, sb, sa, ua, sens, r)
		}
		return
	}

	if reflect.DeepEqual(b, a) {
		return
	}
	r.add(path, b, a, sens, false)
}

// flatScalars reports whether every element is a scalar (or nil).
func flatScalars(s []any) bool {
	for _, v := range s {
		switch v.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

// add appends a leaf change unless it is a no-change null pair or the cap is
// reached.
func (r *Result) add(path []string, b, a any, sensitive, unknown bool) {
	if r.Truncated {
		return
	}
	if b == nil && a == nil {
		return
	}
	if len(r.Changes) >= DefaultMaxChanges {
		r.Truncated = true
		return
	}
	if sensitive {
		// Drop raw values here so no downstream code can ever leak them;
		// renderers show a placeholder based on the Sensitive flag.
		b, a = nil, nil
	}
	r.Changes = append(r.Changes, AttributeChange{
		Path:      FormatPath(path),
		Before:    b,
		After:     a,
		Sensitive: sensitive,
		Unknown:   unknown,
	})
}

func truthy(v any) bool {
	t, ok := v.(bool)
	return ok && t
}

// childMarker extracts the sensitivity/unknown marker for a map key.
func childMarker(marker any, key string) any {
	switch m := marker.(type) {
	case map[string]any:
		return m[key]
	default:
		return nil
	}
}

// elem extracts the marker for a slice index.
func elem(marker any, i int) any {
	switch m := marker.(type) {
	case []any:
		if i < len(m) {
			return m[i]
		}
	case map[string]any:
		return m[strconv.Itoa(i)]
	}
	return nil
}

// FormatPath renders ["ingress", "0", "cidr_blocks", "1"] as
// "ingress[0].cidr_blocks[1]".
func FormatPath(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(parts[0])
	for _, p := range parts[1:] {
		if _, err := strconv.Atoi(p); err == nil {
			sb.WriteString("[")
			sb.WriteString(p)
			sb.WriteString("]")
		} else {
			sb.WriteString(".")
			sb.WriteString(p)
		}
	}
	return sb.String()
}

// FormatPathAny renders replace_paths entries (which arrive as []any).
func FormatPathAny(parts []any) string {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = fmt.Sprint(p)
	}
	return FormatPath(s)
}

// SetDiff computes added/removed members when a change is a flat list of
// scalar values on both sides. It returns ok=false for anything else
// (sensitive, unknown, replacement causes, nested values), in which case the
// caller falls back to the plain before→after rendering.
func SetDiff(ch AttributeChange) (added, removed []string, ok bool) {
	if ch.Sensitive || ch.Unknown || ch.CausesReplacement {
		return nil, nil, false
	}
	bs, bok := ch.Before.([]any)
	as, aok := ch.After.([]any)
	if !bok && !aok {
		return nil, nil, false
	}
	beforeSet := make(map[string]bool, len(bs))
	for _, v := range bs {
		switch v.(type) {
		case map[string]any, []any:
			return nil, nil, false // nested values are not set-diffable
		}
		beforeSet[fmt.Sprint(v)] = true
	}
	afterSet := make(map[string]bool, len(as))
	for _, v := range as {
		switch v.(type) {
		case map[string]any, []any:
			return nil, nil, false
		}
		afterSet[fmt.Sprint(v)] = true
	}
	for k := range afterSet {
		if !beforeSet[k] {
			added = append(added, k)
		}
	}
	for k := range beforeSet {
		if !afterSet[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed, true
}

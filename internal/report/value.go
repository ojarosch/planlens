// Package report renders analysis results as text, JSON, or Markdown. All
// formats share the same redaction guarantees: sensitive values are dropped
// in the diff engine and never re-enter output.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"planlens/internal/diff"
)

const (
	sensitivePlaceholder = "[sensitive value changed]"
	unknownAfterApply    = "(known after apply)"
)

// displayValues returns the before/after strings safe to print for a change,
// applying sensitive redaction and unknown-value placeholders. An empty
// after string means "render as a single value" (sensitive form).
func displayValues(ch diff.AttributeChange) (string, string) {
	if ch.Sensitive {
		return sensitivePlaceholder, ""
	}
	before := formatValue(ch.Before)
	after := formatValue(ch.After)
	if ch.Unknown {
		after = unknownAfterApply
	}
	return before, after
}

// JSONChange is the machine-readable form of an AttributeChange with set-diff
// detail when available.
type JSONChange struct {
	Path              string `json:"path"`
	Before            any    `json:"before,omitempty"`
	After             any    `json:"after,omitempty"`
	Sensitive         bool   `json:"sensitive,omitempty"`
	Unknown           bool   `json:"unknown,omitempty"`
	CausesReplacement bool   `json:"causes_replacement,omitempty"`
}

// SafeJSONChange converts a change for JSON output. Sensitive raw values are
// never emitted; they were dropped upstream.
func SafeJSONChange(ch diff.AttributeChange) JSONChange {
	out := JSONChange{Path: ch.Path, CausesReplacement: ch.CausesReplacement}
	if ch.Sensitive {
		out.Sensitive = true
		return out // no values emitted at all
	}
	if ch.Unknown {
		out.Before = ch.Before
		out.Unknown = true
		return out
	}
	if added, removed, ok := diff.SetDiff(ch); ok && (len(added) > 0 || len(removed) > 0) {
		out.Before = removed
		out.After = added
		return out
	}
	out.Before = ch.Before
	out.After = ch.After
	return out
}

// formatValue renders a leaf value compactly for text output.
func formatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		return fmt.Sprint(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprint(int64(t))
		}
		return fmt.Sprint(t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "<unprintable>"
		}
		s := string(b)
		const max = 80
		if len(s) > max {
			s = s[:max] + "…"
		}
		return s
	}
}

// indentLines prefixes every line of s with pad.
func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

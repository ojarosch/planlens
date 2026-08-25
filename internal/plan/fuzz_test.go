package plan

import (
	"strings"
	"testing"
)

func FuzzParseBytes(f *testing.F) {
	f.Add([]byte(`{"format_version":"1.2","resource_changes":[{"address":"a","change":{"actions":["update"],"before":{},"after":{}}}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"resource_changes":[{"change":{"actions":["delete","create"],"replace_paths":[["x",0]]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseBytes(data)
		if err != nil {
			return
		}
		for _, rc := range p.ResourceChanges {
			Action(rc.Change.Actions) // must never panic
			ProviderShortName(rc.ProviderName)
		}
	})
}

func TestParseNeverPanicsOnWeirdTypes(t *testing.T) {
	inputs := []string{
		`{"resource_changes": [{"change": {"actions": "not-an-array"}}]}`,
		`{"resource_changes": [{"address": 42}]}`,
		`{"resource_changes": null}`,
		`{"output_changes": {"o": {"actions": [1,2]}}}`,
		`{"format_version": {"nested": true}}`,
	}
	for _, in := range inputs {
		if _, err := ParseBytes([]byte(in)); err == nil && strings.Contains(in, "format_version\": {") {
			t.Errorf("expected type error for %s", in)
		}
		// primary requirement: no panic
	}
}

package diff

import (
	"encoding/json"
	"testing"
)

func FuzzAttributes(f *testing.F) {
	f.Add(`{"a":1}`, `{"a":2}`, `{}`, `{}`, `{"b":true}`)
	f.Add(`[1,2,3]`, `[1]`, `false`, `false`, `[]`)
	f.Add(`"x"`, `null`, `true`, `{"k":true}`, `"?"`)
	f.Add(`{"nested":{"deep":{"list":[1,{"x":"y"}]}}}`, `{"nested":{}}`, `false`, `false`, `false`)
	f.Fuzz(func(t *testing.T, before, after, sB, sA, uA string) {
		var b, a, sb, sa, ua any
		// Inputs are JSON-encoded; malformed fuzz inputs decode to nil.
		_ = json.Unmarshal([]byte(before), &b)
		_ = json.Unmarshal([]byte(after), &a)
		_ = json.Unmarshal([]byte(sB), &sb)
		_ = json.Unmarshal([]byte(sA), &sa)
		_ = json.Unmarshal([]byte(uA), &ua)
		res := Attributes(b, a, sb, sa, ua)
		if len(res.Changes) > DefaultMaxChanges && !res.Truncated {
			t.Fatalf("cap exceeded without truncated flag")
		}
	})
}

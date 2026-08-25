package diff

import (
	"reflect"
	"testing"
)

func TestNestedMapDiff(t *testing.T) {
	res := Attributes(
		map[string]any{
			"settings": map[string]any{"backup_retention": float64(7), "port": float64(5432)},
		},
		map[string]any{
			"settings": map[string]any{"backup_retention": float64(1), "port": float64(5432)},
		},
		nil, nil, nil,
	)
	if len(res.Changes) != 1 {
		t.Fatalf("want 1 change, got %+v", res.Changes)
	}
	if res.Changes[0].Path != "settings.backup_retention" {
		t.Errorf("unexpected path %q", res.Changes[0].Path)
	}
}

func TestSliceDiffAndPathFormat(t *testing.T) {
	res := Attributes(
		map[string]any{"ingress": []any{map[string]any{"cidr_blocks": []any{"10.0.0.0/8"}}}},
		map[string]any{"ingress": []any{map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}}}},
		nil, nil, nil,
	)
	want := "ingress[0].cidr_blocks"
	if len(res.Changes) != 1 || res.Changes[0].Path != want {
		t.Fatalf("want single change at %s, got %+v", want, res.Changes)
	}
	// Flat scalar lists stay atomic so reporters can render set diffs.
	added, removed, ok := SetDiff(res.Changes[0])
	if !ok || len(added) != 1 || added[0] != "0.0.0.0/0" || len(removed) != 1 || removed[0] != "10.0.0.0/8" {
		t.Errorf("set diff wrong: +%v -%v ok=%v", added, removed, ok)
	}
}

func TestNestedListStillExplodesLeaves(t *testing.T) {
	before := map[string]any{"rules": []any{map[string]any{"port": float64(80)}}}
	after := map[string]any{"rules": []any{map[string]any{"port": float64(443)}}}
	res := Attributes(before, after, nil, nil, nil)
	if len(res.Changes) != 1 || res.Changes[0].Path != "rules[0].port" {
		t.Fatalf("nested maps must diff per-leaf: %+v", res.Changes)
	}
}

func TestAddedAndRemovedLeaves(t *testing.T) {
	res := Attributes(
		map[string]any{"keep": "x", "gone": "y"},
		map[string]any{"keep": "x", "new": "z"},
		nil, nil, nil,
	)
	got := map[string][2]any{}
	for _, ch := range res.Changes {
		got[ch.Path] = [2]any{ch.Before, ch.After}
	}
	if g := got["new"]; !reflect.DeepEqual(g, [2]any{nil, "z"}) {
		t.Errorf("added leaf wrong: %+v", g)
	}
	if g := got["gone"]; !reflect.DeepEqual(g, [2]any{"y", nil}) {
		t.Errorf("removed leaf wrong: %+v", g)
	}
	if _, ok := got["keep"]; ok {
		t.Error("unchanged key must not appear")
	}
}

func TestSensitivePropagation(t *testing.T) {
	before := map[string]any{"password": "hunter2", "nested": map[string]any{"secret": "a"}}
	sensitive := map[string]any{"password": true, "nested": true}
	// Change one nested value under a sensitive parent.
	after := map[string]any{"password": "hunter2", "nested": map[string]any{"secret": "b"}}
	res := Attributes(before, after, sensitive, sensitive, nil)
	if len(res.Changes) != 1 {
		t.Fatalf("want 1 change, got %+v", res.Changes)
	}
	if !res.Changes[0].Sensitive {
		t.Error("change nested under sensitive marker must be flagged sensitive")
	}
}

func TestUnknownAfterApply(t *testing.T) {
	res := Attributes(
		map[string]any{"ami": "ami-123"},
		map[string]any{"ami": nil},
		nil, nil,
		map[string]any{"ami": true},
	)
	if len(res.Changes) != 1 {
		t.Fatalf("want 1 change, got %+v", res.Changes)
	}
	ch := res.Changes[0]
	if !ch.Unknown {
		t.Error("expected unknown flag")
	}
	if ch.After != nil {
		t.Errorf("unknown value must not leak the raw representation: %v", ch.After)
	}
}

func TestTruncation(t *testing.T) {
	before := map[string]any{}
	after := map[string]any{}
	for i := 0; i < DefaultMaxChanges+50; i++ {
		before[key(i)] = false
		after[key(i)] = true
	}
	res := Attributes(before, after, nil, nil, nil)
	if len(res.Changes) > DefaultMaxChanges {
		t.Errorf("cap not enforced: %d changes", len(res.Changes))
	}
	if !res.Truncated {
		t.Error("expected truncated flag")
	}
}

func key(i int) string { return "attr" + itoa(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestFormatPathAny(t *testing.T) {
	got := FormatPathAny([]any{"engine_version"})
	if got != "engine_version" {
		t.Errorf("got %q", got)
	}
	got = FormatPathAny([]any{"root_block_device", float64(0), "volume_size"})
	if got != "root_block_device[0].volume_size" {
		t.Errorf("got %q", got)
	}
}

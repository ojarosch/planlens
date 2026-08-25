package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"planlens/internal/analysis"
	"planlens/internal/plan"
)

func load(t *testing.T, name string) ([]analysis.Finding, analysis.Summary) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name, "plan.json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	p, err := plan.ParseBytes(data)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return Analyze(p)
}

func ids(findings []analysis.Finding) map[string]bool {
	out := make(map[string]bool, len(findings))
	for _, f := range findings {
		out[f.ID] = true
	}
	return out
}

func TestFixtureFindings(t *testing.T) {
	cases := []struct {
		fixture string
		want    []string
	}{
		{"no-changes", nil},
		{"basic-create", []string{"change.create"}},
		{"basic-update", []string{"change.behavioral"}}, // instance_type is behavioral
		{"destroy", []string{"change.resource-destroy"}},
		{"replacement-destroy-before-create", []string{"change.resource-replacement"}},
		{"replacement-create-before-destroy", []string{"change.resource-replacement"}},
		{"computed-only", []string{"change.computed-only"}},
		{"metadata-only", []string{"change.metadata-only"}},
		{"aws/security-group-cidr-diff", []string{"change.access"}},
		{"aws/iam-actions-added", []string{"change.access"}},
		{"aws/iam-actions-removed", []string{"change.access"}},
		{"aws/rds-engine-version-change", []string{"change.behavioral"}},
		{"aws/rds-replacement-cause", []string{"change.resource-replacement"}},
		{"aws/ecs-capacity-decrease", []string{"change.capacity"}},
		{"aws/autoscaling-capacity-change", []string{"change.capacity"}},
		{"aws/lambda-runtime-change", []string{"change.behavioral"}},
		{"azure/nsg-cidr-diff", []string{"change.access"}},
		{"demo-ugly-plan", []string{
			"change.resource-replacement",
			"change.resource-destroy",
			"change.capacity",
			"change.behavioral",
			"change.metadata-only",
			"change.create",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			findings, _ := load(t, tc.fixture)
			got := ids(findings)
			for _, id := range tc.want {
				if !got[id] {
					t.Errorf("expected finding %q, got %v", id, got)
				}
				delete(got, id)
			}
			if len(got) > 0 {
				t.Errorf("unexpected extra findings: %v", got)
			}
		})
	}
}

func TestCategoriesMatchMechanics(t *testing.T) {
	cases := []struct {
		fixture string
		id      string
		want    analysis.Category
	}{
		{"destroy", "change.resource-destroy", analysis.CatDestructive},
		{"replacement-destroy-before-create", "change.resource-replacement", analysis.CatReplacement},
		{"basic-create", "change.create", analysis.CatCreate},
		{"metadata-only", "change.metadata-only", analysis.CatMetadata},
		{"computed-only", "change.computed-only", analysis.CatUnknown},
		{"sensitive-values", "change.sensitive", analysis.CatSensitive},
		{"aws/security-group-cidr-diff", "change.access", analysis.CatAccess},
		{"aws/ecs-capacity-decrease", "change.capacity", analysis.CatCapacity},
		{"aws/autoscaling-capacity-change", "change.capacity", analysis.CatCapacity},
		{"aws/lambda-runtime-change", "change.behavioral", analysis.CatBehavioral},
		{"aws/rds-engine-version-change", "change.behavioral", analysis.CatBehavioral},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			findings, _ := load(t, tc.fixture)
			found := false
			for _, f := range findings {
				if f.ID == tc.id {
					if f.Category != tc.want {
						t.Errorf("category = %q, want %q", f.Category, tc.want)
					}
					if f.Confidence == "" {
						t.Error("confidence must be set")
					}
					found = true
				}
			}
			if !found {
				t.Errorf("finding %q not found in %v", tc.id, ids(findings))
			}
		})
	}
}

func TestReplacementOrderDetection(t *testing.T) {
	cases := map[string]string{
		"replacement-destroy-before-create": "destroy-create",
		"replacement-create-before-destroy": "create-destroy",
	}
	for fixture, want := range cases {
		findings, _ := load(t, fixture)
		for _, f := range findings {
			if f.ID == "change.resource-replacement" && f.ReplacementOrder != want {
				t.Errorf("%s: order = %q, want %q", fixture, f.ReplacementOrder, want)
			}
		}
	}
}

func TestReplacementShowsCausesFromReplacePaths(t *testing.T) {
	findings, _ := load(t, "replacement-destroy-before-create")
	var repl *analysis.Finding
	for i := range findings {
		if findings[i].ID == "change.resource-replacement" {
			repl = &findings[i]
		}
	}
	if repl == nil {
		t.Fatal("no replacement finding")
	}
	sawCause := false
	for _, ch := range repl.Changes {
		if ch.Path == "engine_version" && ch.CausesReplacement {
			sawCause = true
			if !strings.Contains(fmt.Sprint(ch.Before), "14.11") || !strings.Contains(fmt.Sprint(ch.After), "16.3") {
				t.Errorf("cause values wrong: %v → %v", ch.Before, ch.After)
			}
		}
	}
	if !sawCause {
		t.Errorf("expected engine_version marked as cause, changes=%+v", repl.Changes)
	}
}

func fmtValue(v any) string { return fmt.Sprint(v) }

// TestSummaryDoesNotDoubleCountReplacements keeps the summary honest.
func TestSummaryDoesNotDoubleCountReplacements(t *testing.T) {
	_, summary := load(t, "replacement-destroy-before-create")
	if summary.Replace != 1 || summary.Create != 0 || summary.Delete != 0 {
		t.Errorf("unexpected summary: %+v", summary)
	}
	if summary.ResourcesAffected != 1 {
		t.Errorf("affected = %d, want 1", summary.ResourcesAffected)
	}
}

// TestIAMStructuralDiff verifies actions added/removed appear without any
// security judgment.
func TestIAMStructuralDiff(t *testing.T) {
	findings, _ := load(t, "aws/iam-actions-added")
	desc := findingDescription(findings, "change.access")
	for _, want := range []string{"actions added:", "+ s3:PutObject", "+ kms:Decrypt"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
	if strings.Contains(desc, "risk") || strings.Contains(desc, "insecure") || strings.Contains(desc, "wildcard") {
		t.Errorf("description must stay judgment-free:\n%s", desc)
	}

	findings, _ = load(t, "aws/iam-actions-removed")
	desc = findingDescription(findings, "change.access")
	if !strings.Contains(desc, "actions removed:") || !strings.Contains(desc, "- s3:GetObjectVersion") {
		t.Errorf("removed action missing:\n%s", desc)
	}
}

func findingDescription(findings []analysis.Finding, id string) string {
	for _, f := range findings {
		if f.ID == id {
			return f.Description
		}
	}
	return ""
}

// TestMixedUpdateFoldsMetadataIntoOther ensures a capacity change plus a tag
// tweak yields one capacity finding, not an extra metadata section.
func TestMixedUpdateFoldsMetadataIntoOther(t *testing.T) {
	p, err := plan.ParseBytes([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "aws_ecs_service.api",
	    "type": "aws_ecs_service",
	    "provider_name": "registry.terraform.io/hashicorp/aws",
	    "change": {
	      "actions": ["update"],
	      "before": {"desired_count": 12, "tags": {"Team": "a"}},
	      "after": {"desired_count": 4, "tags": {"Team": "b"}},
	      "after_unknown": {}
	    }
	  }]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := Analyze(p)
	got := ids(findings)
	if len(got) != 1 || !got["change.capacity"] {
		t.Errorf("want single change.capacity finding, got %v", got)
	}
}

func TestSetDiffInSecurityGroupFixture(t *testing.T) {
	findings, _ := load(t, "aws/security-group-cidr-diff")
	for _, f := range findings {
		if f.ID != "change.access" {
			continue
		}
		var sawSet bool
		for _, ch := range f.Changes {
			if added, removed, ok := setDiffForTest(ch); ok {
				sawSet = true
				if len(added) != 2 || len(removed) != 1 {
					t.Errorf("set diff wrong: +%v -%v", added, removed)
				}
			}
		}
		if !sawSet {
			t.Error("expected at least one collection-aware set diff")
		}
	}
}

func TestDestroyFindingShowsBeforeValues(t *testing.T) {
	findings, _ := load(t, "destroy")
	for _, f := range findings {
		if f.ID == "change.resource-destroy" && len(f.Changes) == 0 {
			t.Error("destroy finding should show some before values")
		}
	}
}

// TestDemoUglyPlanNoiseReduction pins the headline behavior on the demo
// plan: 5 highlighted findings, 41 collapsed low-signal ones, and the
// replacement lifecycle order.
func TestDemoUglyPlanNoiseReduction(t *testing.T) {
	findings, summary := load(t, "demo-ugly-plan")

	if summary.ResourcesAffected != 46 || summary.Replace != 1 || summary.Delete != 2 {
		t.Errorf("unexpected summary: %+v", summary)
	}

	highlighted, collapsed := 0, 0
	var repl *analysis.Finding
	for i := range findings {
		f := &findings[i]
		if f.Category.IsLowSignal() {
			collapsed++
		} else {
			highlighted++
		}
		if f.ID == "change.resource-replacement" {
			repl = f
		}
	}
	if highlighted != 5 || collapsed != 41 {
		t.Errorf("highlighted=%d collapsed=%d, want 5/41", highlighted, collapsed)
	}
	if repl == nil {
		t.Fatal("no replacement finding")
	}
	if repl.ReplacementOrder != "destroy-create" {
		t.Errorf("order = %q, want destroy-create", repl.ReplacementOrder)
	}
	sawCause := false
	for _, ch := range repl.Changes {
		if ch.Path == "engine_version" && ch.CausesReplacement {
			sawCause = true
		}
	}
	if !sawCause {
		t.Error("engine_version must be marked as replacement cause")
	}
}

func TestFindingsSortedByCategoryPriority(t *testing.T) {
	mixed, err := plan.ParseBytes([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address":"a.tags","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["update"],"before":{"tags":{"x":"y"}},"after":{"tags":{"x":"z"}},"after_unknown":{}}},
	    {"address":"b.db","type":"aws_db_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["delete","create"],"before":{"engine_version":"14"},"after":{"engine_version":"16"},"after_unknown":{},"replace_paths":[["engine_version"]]}},
	    {"address":"c.route","type":"aws_route","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["delete"],"before":{"destination_cidr_block":"10.0.0.0/16"},"after":null,"after_unknown":{}}}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := Analyze(mixed)
	if len(fs) < 3 {
		t.Fatalf("want >=3 findings, got %d", len(fs))
	}
	if fs[0].Category != analysis.CatReplacement || fs[1].Category != analysis.CatDestructive {
		t.Errorf("wrong priority order: [%s, %s]", fs[0].Category, fs[1].Category)
	}
}

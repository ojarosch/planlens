package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionNormalization(t *testing.T) {
	cases := []struct {
		actions []string
		want    ActionKind
	}{
		{[]string{"create"}, ActionCreate},
		{[]string{"update"}, ActionUpdate},
		{[]string{"delete"}, ActionDelete},
		{[]string{"delete", "create"}, ActionReplace},
		{[]string{"create", "delete"}, ActionReplace},
		{[]string{"no-op"}, ActionNoOp},
		{[]string{"read"}, ActionRead},
		{[]string{"create", "update"}, ActionUpdate},
		{nil, ActionNoOp},
	}
	for _, tc := range cases {
		if got := Action(tc.actions); got != tc.want {
			t.Errorf("Action(%v) = %v, want %v", tc.actions, got, tc.want)
		}
	}
}

func TestProviderShortName(t *testing.T) {
	cases := map[string]string{
		"registry.terraform.io/hashicorp/aws":    "aws",
		"aws":                                    "aws",
		"registry.terraform.io/hashicorp/google": "google",
		"":                                       "",
	}
	for in, want := range cases {
		if got := ProviderShortName(in); got != want {
			t.Errorf("ProviderShortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "replacement-destroy-before-create", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.TerraformVersion != "1.13.0" || p.FormatVersion != "1.2" {
		t.Errorf("unexpected versions: %+v", p)
	}
	if len(p.ResourceChanges) != 1 {
		t.Fatalf("want 1 resource change, got %d", len(p.ResourceChanges))
	}
	rc := p.ResourceChanges[0]
	if rc.Address != "aws_db_instance.production" {
		t.Errorf("unexpected address %q", rc.Address)
	}
	if Action(rc.Change.Actions) != ActionReplace {
		t.Errorf("expected replacement")
	}
	if ProviderShortName(rc.ProviderName) != "aws" {
		t.Errorf("expected aws provider, got %q", rc.ProviderName)
	}
}

func TestParseRejectsNonPlanInput(t *testing.T) {
	cases := []string{
		``,
		`not json at all`,
		`[1,2,3]`,
		`{"foo": "bar"}`,
	}
	for _, in := range cases {
		if _, err := ParseBytes([]byte(in)); err == nil {
			t.Errorf("expected error for input %q", in)
		} else if strings.Contains(strings.ToLower(err.Error()), "panic") {
			t.Errorf("error mentions panic: %v", err)
		}
	}
}

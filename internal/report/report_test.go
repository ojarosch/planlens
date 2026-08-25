package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"planlens/internal/analysis"
	"planlens/internal/diff"
	"planlens/internal/plan"
)

func sensitiveFixture(t *testing.T) ([]analysis.Finding, analysis.Summary) {
	t.Helper()
	p, err := plan.ParseBytes([]byte(`{
	  "format_version": "1.2",
	  "terraform_version": "1.13.0",
	  "resource_changes": [{
	    "address": "aws_db_instance.app",
	    "mode": "managed",
	    "type": "aws_db_instance",
	    "name": "app",
	    "provider_name": "registry.terraform.io/hashicorp/aws",
	    "change": {
	      "actions": ["update"],
	      "before": {"password": "hunter2", "port": 5432},
	      "after": {"password": "s3cr3t!", "port": 5433},
	      "after_unknown": {},
	      "before_sensitive": {"password": true},
	      "after_sensitive": {"password": true}
	    }
	  }]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return analyzeForTest(p)
}

const secretsJSON = `{
  "format_version": "1.2",
  "resource_changes": [{
    "address": "aws_instance.worker",
    "type": "aws_instance",
    "provider_name": "registry.terraform.io/hashicorp/aws",
    "change": {
      "actions": ["update"],
      "before": {"ami": "ami-123"},
      "after": {"ami": null},
      "after_unknown": {"ami": true},
      "before_sensitive": false,
      "after_sensitive": false
    }
  }]
}`

func TestTextRedactsSensitiveValues(t *testing.T) {
	findings, summary := sensitiveFixture(t)
	var buf bytes.Buffer
	if err := Text(&buf, findings, summary, "1.13.0", "1.2", TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"hunter2", "s3cr3t!"} {
		if strings.Contains(out, secret) {
			t.Errorf("text output leaked %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "[sensitive value changed]") {
		t.Errorf("expected redaction placeholder:\n%s", out)
	}
	if !strings.Contains(out, "port:\n    5432 → 5433") {
		t.Errorf("expected two-line diff format:\n%s", out)
	}
}

func TestMarkdownRedactsSensitiveValues(t *testing.T) {
	findings, summary := sensitiveFixture(t)
	var buf bytes.Buffer
	if err := Markdown(&buf, findings, summary, "", "", TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"hunter2", "s3cr3t!"} {
		if strings.Contains(out, secret) {
			t.Errorf("markdown output leaked %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "Sensitive values") || !strings.Contains(out, "[sensitive value changed]") {
		t.Errorf("markdown missing sensitive section:\n%s", out)
	}
}

func TestJSONRedactsAndSerializes(t *testing.T) {
	findings, summary := sensitiveFixture(t)
	fullCats := analysis.CountCategories(findings)
	var buf bytes.Buffer
	if err := JSON(&buf, findings, summary, fullCats, "1.13.0", "1.2", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"hunter2", "s3cr3t!"} {
		if strings.Contains(out, secret) {
			t.Errorf("json output leaked %q:\n%s", secret, out)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if strings.Contains(out, `"risk"`) {
		t.Error("json output must not contain risk levels anymore")
	}
}

func TestUnknownPlaceholder(t *testing.T) {
	findings, summary := analyzeFixture(t, "computed-only")
	var buf bytes.Buffer
	if err := Text(&buf, findings, summary, "", "", TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(known after apply)") {
		t.Errorf("expected unknown placeholder:\n%s", buf.String())
	}
	// Collapsed by default.
	var collapsed bytes.Buffer
	if err := Text(&collapsed, findings, summary, "", "", TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(collapsed.String(), "computed/unknown-only") {
		t.Errorf("computed-only must be collapsed by default:\n%s", collapsed.String())
	}
}

func TestLowSignalCollapsedByDefault(t *testing.T) {
	findings, summary := analyzeForTest(mustPlan(t, metadataOnlyPlan))
	var buf bytes.Buffer
	if err := Text(&buf, findings, summary, "", "", TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "LOW-SIGNAL") || !strings.Contains(out, "--verbose") {
		t.Errorf("expected collapsed low-signal section:\n%s", out)
	}

	var verbose bytes.Buffer
	if err := Text(&verbose, findings, summary, "", "", TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verbose.String(), "aws_instance.a[0]") {
		t.Errorf("--verbose must expand low-signal findings:\n%s", verbose.String())
	}
}

func TestSetDiffRendering(t *testing.T) {
	ch := diff.AttributeChange{
		Path:   "ingress[0].cidr_blocks",
		Before: []any{"10.0.0.0/8"},
		After:  []any{"10.42.0.0/16", "10.43.0.0/16"},
	}
	added, removed, ok := diff.SetDiff(ch)
	if !ok || len(added) != 2 || len(removed) != 1 {
		t.Fatalf("set diff wrong: +%v -%v ok=%v", added, removed, ok)
	}
	var buf bytes.Buffer
	renderChange(&buf, ch, "")
	for _, want := range []string{"+ 10.42.0.0/16", "+ 10.43.0.0/16", "- 10.0.0.0/8"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in:\n%s", want, buf.String())
		}
	}
}

func TestDisplayValues(t *testing.T) {
	before, after := displayValues(diff.AttributeChange{Path: "pw", Sensitive: true})
	if before != sensitivePlaceholder || after != "" {
		t.Errorf("sensitive change must render single redacted form: %q %q", before, after)
	}
	_, after = displayValues(diff.AttributeChange{Path: "ami", Before: "ami-1", Unknown: true})
	if after != unknownAfterApply {
		t.Errorf("unknown after must be a placeholder: %q", after)
	}
}

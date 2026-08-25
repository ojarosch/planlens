package report

import (
	"os"
	"path/filepath"
	"testing"

	"planlens/internal/analysis"
	"planlens/internal/engine"
	"planlens/internal/plan"
)

const metadataOnlyPlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_instance.a[0]",
      "type": "aws_instance",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {"actions": ["update"], "before": {"tags": {"Env": "dev"}}, "after": {"tags": {"Env": "staging"}}, "after_unknown": {}}
    }
  ]
}`

func mustPlan(t *testing.T, data string) *plan.Plan {
	t.Helper()
	p, err := plan.ParseBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func analyzeForTest(p *plan.Plan) ([]analysis.Finding, analysis.Summary) {
	return engine.Analyze(p)
}

func analyzeFixture(t *testing.T, name string) ([]analysis.Finding, analysis.Summary) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return engine.Analyze(p)
}

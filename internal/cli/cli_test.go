package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", name, "plan.json")
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no changes ok", []string{fixture("no-changes")}, ExitOK},
		{"gate off by default", []string{fixture("destroy")}, ExitOK},
		{"fail-on destroy hits", []string{"--fail-on", "destroy", fixture("destroy")}, ExitGate},
		{"fail-on destructive synonym", []string{"--fail-on", "destructive", fixture("destroy")}, ExitGate},
		{"fail-on replacement hits", []string{"--fail-on", "replacement", fixture("replacement-create-before-destroy")}, ExitGate},
		{"fail-on replace synonym", []string{"--fail-on", "replace", fixture("replacement-destroy-before-create")}, ExitGate},
		{"gate ignores other categories", []string{"--fail-on", "destroy", fixture("aws/lambda-runtime-change")}, ExitOK},
		{"invalid gate rejected", []string{"--fail-on", "high", fixture("no-changes")}, ExitError},
		{"missing file", []string{"/nonexistent/plan.json"}, ExitError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := run(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestMalformedPlanFileIsExecutionError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := writeFile(path, []byte(`{"resource_changes": "not-an-array"}`)); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, path)
	if code != ExitError {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, ExitError, stderr)
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != ExitOK || !strings.Contains(out, Version) {
		t.Errorf("version: code=%d out=%q", code, out)
	}
}

func TestFormatJSON(t *testing.T) {
	code, out, _ := run(t, "--format", "json", fixture("replacement-destroy-before-create"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{`"category": "replacement"`, `"replacement_order": "destroy-create"`, `"categories"`, `"resources_affected"`} {
		if !strings.Contains(out, want) {
			t.Errorf("json output missing %s:\n%s", want, out)
		}
	}
}

func TestFormatMarkdown(t *testing.T) {
	code, out, _ := run(t, "--format", "markdown", fixture("replacement-destroy-before-create"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"## PlanLens", "### Replacements", "`engine_version`"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}

func TestCategoryFilterKeepsFullSummary(t *testing.T) {
	code, out, _ := run(t, "--format", "json", "--category", "replacement", fixture("metadata-only"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, `"change.metadata-only"`) {
		t.Error("--category filter must hide other categories")
	}
	if !strings.Contains(out, `"metadata": 2`) {
		t.Error("summary must still describe the entire plan")
	}
}

func TestResourceFilter(t *testing.T) {
	code, out, _ := run(t, "--format", "json", "--resource", "aws_instance.a[0]", fixture("metadata-only"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, `"aws_instance.b"`) {
		t.Error("--resource filter must exclude other addresses")
	}
}

func TestGroupByModule(t *testing.T) {
	code, out, _ := run(t, "--group-by", "module", fixture("aws/ecs-capacity-decrease"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "module.app") {
		t.Errorf("--group-by module must print module headers:\n%s", out)
	}
}

func TestStdinInput(t *testing.T) {
	code, _, stderr := run(t)
	if code != ExitError && code != ExitOK {
		t.Errorf("unexpected exit %d (stderr: %s)", code, stderr)
	}
}

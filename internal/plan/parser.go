package plan

import (
	"encoding/json"
	"fmt"
	"io"
)

type rawPlan struct {
	FormatVersion    string                     `json:"format_version"`
	TerraformVersion string                     `json:"terraform_version"`
	ResourceChanges  []rawResourceChange        `json:"resource_changes"`
	OutputChanges    map[string]rawOutputChange `json:"output_changes"`
}

type rawResourceChange struct {
	Address       string    `json:"address"`
	ModuleAddress string    `json:"module_address"`
	Mode          string    `json:"mode"`
	Type          string    `json:"type"`
	Name          string    `json:"name"`
	ProviderName  string    `json:"provider_name"`
	Change        rawChange `json:"change"`
	ActionReason  string    `json:"action_reason"`
	DeposedKey    string    `json:"deposed"`
}

type rawChange struct {
	Actions         []string `json:"actions"`
	Before          any      `json:"before"`
	After           any      `json:"after"`
	AfterUnknown    any      `json:"after_unknown"`
	BeforeSensitive any      `json:"before_sensitive"`
	AfterSensitive  any      `json:"after_sensitive"`
	ReplacePaths    [][]any  `json:"replace_paths"`
	Raw             json.RawMessage
}

type rawOutputChange struct {
	Actions []string `json:"actions"`
}

// Parse reads a plan JSON document. It only deserializes the fields planlens
// uses; everything else is ignored.
func Parse(r io.Reader) (*Plan, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses plan JSON from memory.
func ParseBytes(data []byte) (*Plan, error) {
	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("input is not valid JSON: %w", err)
	}
	if _, ok := probe.(map[string]any); !ok {
		return nil, fmt.Errorf("input is valid JSON but not a Terraform/OpenTofu plan (expected a JSON object)")
	}

	var raw rawPlan
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing plan structure: %w", err)
	}

	p := &Plan{
		TerraformVersion: raw.TerraformVersion,
		FormatVersion:    raw.FormatVersion,
		OutputChanges:    make(map[string]OutputChange, len(raw.OutputChanges)),
	}
	for name, oc := range raw.OutputChanges {
		p.OutputChanges[name] = OutputChange{Actions: oc.Actions}
	}
	for _, rc := range raw.ResourceChanges {
		p.ResourceChanges = append(p.ResourceChanges, ResourceChange{
			Address:       rc.Address,
			ModuleAddress: rc.ModuleAddress,
			Mode:          rc.Mode,
			Type:          rc.Type,
			Name:          rc.Name,
			ProviderName:  rc.ProviderName,
			Change: Change{
				Actions:         rc.Change.Actions,
				Before:          rc.Change.Before,
				After:           rc.Change.After,
				AfterUnknown:    rc.Change.AfterUnknown,
				BeforeSensitive: rc.Change.BeforeSensitive,
				AfterSensitive:  rc.Change.AfterSensitive,
				ReplacePaths:    rc.Change.ReplacePaths,
			},
		})
	}
	if p.FormatVersion == "" && len(p.ResourceChanges) == 0 && len(p.OutputChanges) == 0 {
		return nil, fmt.Errorf("input does not look like a Terraform/OpenTofu plan JSON (no resource_changes or output_changes)")
	}
	return p, nil
}

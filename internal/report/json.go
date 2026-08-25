package report

import (
	"encoding/json"
	"io"

	"planlens/internal/analysis"
)

// JSONOutput is the stable machine-readable document. Findings are always
// complete (including low-signal categories) regardless of text collapsing.
type JSONOutput struct {
	Version  string        `json:"version"`
	Plan     JSONPlanInfo  `json:"plan"`
	Summary  JSONSummary   `json:"summary"`
	Findings []JSONFinding `json:"findings"`
}

type JSONPlanInfo struct {
	TerraformVersion string `json:"terraform_version"`
	FormatVersion    string `json:"format_version"`
}

type JSONSummary struct {
	ResourcesAffected int            `json:"resources_affected"`
	Create            int            `json:"create"`
	Update            int            `json:"update"`
	Delete            int            `json:"delete"`
	Replace           int            `json:"replace"`
	Read              int            `json:"read"`
	Categories        map[string]int `json:"categories"`
}

type JSONFinding struct {
	ID               string       `json:"id"`
	Category         string       `json:"category"`
	Confidence       string       `json:"confidence"`
	Address          string       `json:"address"`
	ModuleAddress    string       `json:"module_address,omitempty"`
	ResourceType     string       `json:"resource_type,omitempty"`
	Action           string       `json:"action,omitempty"`
	ReplacementOrder string       `json:"replacement_order,omitempty"`
	Title            string       `json:"title"`
	Description      string       `json:"description,omitempty"`
	Changes          []JSONChange `json:"changes,omitempty"`
}

// JSON renders machine-readable output. fullCategories describes the entire
// plan; findings may be pre-filtered by the caller.
func JSON(w io.Writer, findings []analysis.Finding, fullSummary analysis.Summary, fullCategories map[analysis.Category]int, terraformVersion, formatVersion, version string) error {
	cats := make(map[string]int, len(fullCategories))
	for c, n := range fullCategories {
		cats[string(c)] = n
	}
	out := JSONOutput{
		Version: version,
		Plan: JSONPlanInfo{
			TerraformVersion: terraformVersion,
			FormatVersion:    formatVersion,
		},
		Summary: JSONSummary{
			ResourcesAffected: fullSummary.ResourcesAffected,
			Create:            fullSummary.Create,
			Update:            fullSummary.Update,
			Delete:            fullSummary.Delete,
			Replace:           fullSummary.Replace,
			Read:              fullSummary.Read,
			Categories:        cats,
		},
	}
	out.Findings = make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		jf := JSONFinding{
			ID:            f.ID,
			Category:      string(f.Category),
			Confidence:    string(f.Confidence),
			Address:       f.Address,
			ModuleAddress: f.ModuleAddress,
			ResourceType:  f.ResourceType,
			Title:         f.Title,
			Description:   f.Description,
		}
		if f.ID == "change.resource-replacement" {
			jf.Action = "replace"
			jf.ReplacementOrder = f.ReplacementOrder
		} else if f.ID == "change.resource-destroy" {
			jf.Action = "delete"
		} else if f.ID == "change.create" {
			jf.Action = "create"
		} else {
			jf.Action = "update"
		}
		if len(f.Changes) > 0 {
			jf.Changes = make([]JSONChange, 0, len(f.Changes))
			for _, ch := range f.Changes {
				jf.Changes = append(jf.Changes, SafeJSONChange(ch))
			}
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

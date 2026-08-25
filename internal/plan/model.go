// Package plan models the subset of Terraform/OpenTofu plan JSON that
// planlens needs. Values are kept as `any` so provider-specific analyzers
// can inspect raw structures without planlens deserializing the full schema.
package plan

// Plan is a parsed `terraform show -json` / `tofu show -json` document.
type Plan struct {
	TerraformVersion string
	FormatVersion    string
	ResourceChanges  []ResourceChange
	OutputChanges    map[string]OutputChange
}

// ResourceChange is one entry of resource_changes.
type ResourceChange struct {
	Address       string
	ModuleAddress string
	Mode          string
	Type          string
	Name          string
	ProviderName  string
	Change        Change
}

// Change is the change block of a resource change.
type Change struct {
	Actions         []string
	Before          any
	After           any
	AfterUnknown    any
	BeforeSensitive any
	AfterSensitive  any
	ReplacePaths    [][]any
}

// OutputChange is one entry of output_changes.
type OutputChange struct {
	Actions []string
}

// ActionKind is the normalized form of a Terraform action list.
type ActionKind int

const (
	ActionNoOp ActionKind = iota
	ActionRead
	ActionCreate
	ActionUpdate
	ActionDelete
	ActionReplace
)

// Action normalizes a raw action list. Both ["delete","create"] and
// ["create","delete"] normalize to ActionReplace; the raw ordering remains
// available via Change.Actions.
func Action(actions []string) ActionKind {
	if len(actions) == 0 {
		return ActionNoOp
	}
	has := func(s string) bool {
		for _, a := range actions {
			if a == s {
				return true
			}
		}
		return false
	}
	if has("delete") && has("create") {
		return ActionReplace
	}
	// ["create","update"] is an in-place update; handle it before plain create.
	if has("update") {
		return ActionUpdate
	}
	switch actions[0] {
	case "create":
		return ActionCreate
	case "delete":
		return ActionDelete
	}
	if has("read") {
		return ActionRead
	}
	if has("no-op") {
		return ActionNoOp
	}
	return ActionNoOp
}

// String returns the lowercase name used in summaries.
func (k ActionKind) String() string {
	switch k {
	case ActionRead:
		return "read"
	case ActionCreate:
		return "create"
	case ActionUpdate:
		return "update"
	case ActionDelete:
		return "delete"
	case ActionReplace:
		return "replace"
	default:
		return "no-op"
	}
}

// ReplacementOrder describes the lifecycle direction of a replacement:
// "destroy-create" for ["delete","create"] or "create-destroy" for
// ["create","delete"]. Empty for non-replacements.
func (c Change) ReplacementOrder() string {
	if Action(c.Actions) != ActionReplace {
		return ""
	}
	if len(c.Actions) > 0 && c.Actions[0] == "create" {
		return "create-destroy"
	}
	return "destroy-create"
}

// ProviderShortName reduces
// "registry.terraform.io/hashicorp/aws" to "aws".
func ProviderShortName(providerName string) string {
	for i := len(providerName) - 1; i >= 0; i-- {
		if providerName[i] == '/' {
			return providerName[i+1:]
		}
	}
	return providerName
}

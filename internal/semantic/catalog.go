// Package semantic classifies changed attribute paths into change categories
// using a central, extensible catalog. Classification is descriptive: it says
// what kind of attribute changed, never whether the change is acceptable.
package semantic

import (
	"strings"

	"planlens/internal/analysis"
)

var catalog = map[string]analysis.Category{
	// Capacity — how much of something runs.
	"desired_count":    analysis.CatCapacity,
	"desired_capacity": analysis.CatCapacity,
	"replicas":         analysis.CatCapacity,
	"min_size":         analysis.CatCapacity,
	"max_size":         analysis.CatCapacity,
	"min_capacity":     analysis.CatCapacity,
	"max_capacity":     analysis.CatCapacity,
	"instance_count":   analysis.CatCapacity,
	"node_count":       analysis.CatCapacity,
	"node_group_count": analysis.CatCapacity,
	"worker_count":     analysis.CatCapacity,
	"capacity":         analysis.CatCapacity,
	"read_capacity":    analysis.CatCapacity,
	"write_capacity":   analysis.CatCapacity,

	// Behavioral — what software/runtime actually executes.
	"engine_version":     analysis.CatBehavioral,
	"engine":             analysis.CatBehavioral,
	"runtime":            analysis.CatBehavioral,
	"image":              analysis.CatBehavioral,
	"image_uri":          analysis.CatBehavioral,
	"image_id":           analysis.CatBehavioral,
	"ami":                analysis.CatBehavioral,
	"instance_type":      analysis.CatBehavioral,
	"machine_type":       analysis.CatBehavioral,
	"version":            analysis.CatBehavioral,
	"platform_version":   analysis.CatBehavioral,
	"kubernetes_version": analysis.CatBehavioral,
	"storage_type":       analysis.CatBehavioral,

	// Access — who and what can reach what.
	"cidr_blocks":             analysis.CatAccess,
	"ipv6_cidr_blocks":        analysis.CatAccess,
	"source_address_prefix":   analysis.CatAccess,
	"source_address_prefixes": analysis.CatAccess,
	"security_groups":         analysis.CatAccess,
	"ingress":                 analysis.CatAccess,
	"egress":                  analysis.CatAccess,
	"policy":                  analysis.CatAccess,
	"principals":              analysis.CatAccess,
	"principal_arns":          analysis.CatAccess,
	"members":                 analysis.CatAccess,
	"roles":                   analysis.CatAccess,
	"authorized_networks":     analysis.CatAccess,
	"network_rules":           analysis.CatAccess,
	"ip_restrictions":         analysis.CatAccess,

	// Metadata — low-signal bookkeeping.
	"tags":        analysis.CatMetadata,
	"tags_all":    analysis.CatMetadata,
	"labels":      analysis.CatMetadata,
	"annotations": analysis.CatMetadata,
	"description": analysis.CatMetadata,
	"metadata":    analysis.CatMetadata,
}

// ClassifyPath maps an attribute diff path (e.g. "ingress[0].cidr_blocks")
// to a category. Named segments are checked from leaf upward — so
// "tags.Environment" classifies as metadata even though the leaf is a tag
// key. Unknown names return "" so callers treat them as OTHER.
func ClassifyPath(path string) analysis.Category {
	for _, seg := range namedSegments(path) {
		if cat, ok := catalog[seg]; ok {
			return cat
		}
	}
	return ""
}

// namedSegments returns the non-index names of a formatted path, outermost
// first: "ingress[0].cidr_blocks[1]" → ["ingress", "cidr_blocks"].
func namedSegments(path string) []string {
	var cur strings.Builder
	var out []string
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '[':
			flush()
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 {
				flush()
			}
		default:
			if depth == 0 {
				cur.WriteByte(path[i])
			}
		}
	}
	flush()
	return out
}

# PlanLens

**A reviewer-oriented semantic diff for Terraform and OpenTofu plans.**

Terraform tells you everything that will change. PlanLens helps you find the changes worth reviewing.

```text
$ terraform plan
Plan: 247 to add, 33 to change, 2 to destroy.

$ tofu show -json tfplan | planlens

PLANLENS

Plan
46 resources affected
10 create · 33 update · 2 destroy · 1 replace

REPLACEMENT
aws_db_instance.primary
  replacement required · lifecycle: destroy-create
  engine_version:
    14.9 → 16.4

DESTRUCTIVE
aws_route.private[0]
  destination_cidr_block:
    10.42.0.0/16 → null

CAPACITY
aws_ecs_service.api
  desired_count:
    12 → 4

BEHAVIORAL
module.compute.aws_launch_template.workers
  instance_type:
    m6i.large → m7i.2xlarge

LOW-SIGNAL
41 changes collapsed:
  31 metadata-only
  10 straightforward creates
Use --verbose to display them.

──────────────────────────────
5 highlighted · 41 collapsed
```

## Why PlanLens exists

A realistic plan can contain hundreds of changes of which only a handful matter.
Scrolling through raw `terraform show -json` output makes it easy to miss the one replacement hiding among 200 tag updates.

PlanLens compresses a plan into what a reviewer actually approves:

- what gets **destroyed**
- what gets **replaced**, and *why* (`replace_paths`)
- which direction the replacement runs (`destroy → create`)
- what **capacity** scales up or down
- what **runtime/version** changes
- what **access configuration** changed
- which **sensitive fields** changed
- how much of the rest is **noise**

It answers one question:

> **What meaningful changes am I actually approving?**

## What PlanLens is not

PlanLens is **not a security scanner**. It does not judge whether `0.0.0.0/0`, an IAM wildcard, or a public database is acceptable — it shows you the diff so you (or your scanner) can decide.

```text
├── Trivy / Checkov / OPA   Is the resulting configuration secure?
├── Infracost               How does cost change?
└── PlanLens                What meaningful changes am I approving?
```

Findings carry **categories**, not risk levels. A category describes what kind of change occurred — never whether the architecture is good or bad.

## Installation

**Homebrew** (tap):

```sh
brew install ojarosch/tap/planlens
```

**Download a binary** from [GitHub Releases](https://github.com/ojarosch/planlens/releases) — builds are available for Linux, macOS, and Windows on amd64/arm64, with checksums.

**Go install:**

```sh
go install github.com/ojarosch/planlens/cmd/planlens@latest
```

**From source:**

```sh
git clone https://github.com/ojarosch/planlens && cd planlens
go build -o /usr/local/bin/planlens ./cmd/planlens
```

## Quick start

```sh
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
planlens tfplan.json
```

OpenTofu works identically:

```sh
tofu plan -out=tfplan
tofu show -json tfplan | planlens
```

See noise reduction in action on a realistically ugly 46-resource demo plan:

```sh
planlens testdata/demo-ugly-plan/plan.json
```

PlanLens does not execute Terraform/OpenTofu, never shells out to them, and needs no credentials or network access. Analysis happens entirely locally; plan files may contain sensitive values, and PlanLens treats them accordingly.

## Change categories

| Category      | Meaning                                              |
|---------------|------------------------------------------------------|
| REPLACEMENT   | Terraform must destroy and recreate the resource     |
| DESTRUCTIVE   | Resource disappears                                  |
| CAPACITY      | Counts/sizes changed (desired_count, min/max_size…)  |
| BEHAVIORAL    | Deployed behavior changes (runtime, image, engine…) |
| ACCESS        | Who/what can reach what (cidrs, policies, ingress…) |
| SENSITIVE     | A sensitive-marked value changed                     |
| METADATA      | Tags, labels, descriptions                           |
| UNKNOWN       | Values only known after apply                        |
| CREATE        | New resources                                        |

Low-signal categories (metadata, computed-only, plain creates) are collapsed into a **LOW-SIGNAL** summary by default. `--verbose` expands them. JSON output always contains every finding.

### Replacement causes and order

Replacement is PlanLens's strongest feature. Terraform's plan JSON reports *which attributes force the replacement* (`replace_paths`) and the lifecycle ordering; PlanLens surfaces both:

```text
REPLACEMENT
aws_db_instance.production
  replacement required · lifecycle: destroy-create
  engine_version:
    14.11 → 16.3
```

`["delete","create"]` renders as `destroy-create`; `["create","delete"]` as `create-destroy`. No downtime claims are invented from this.

### Collection-aware diffs

Sets of scalars (CIDRs, subnets, AZs, members) are shown as additions and removals instead of index noise:

```text
ingress[0].cidr_blocks:
  + 10.42.0.0/16
  + 10.43.0.0/16
  - 10.0.0.0/8
```

### IAM policy diffs, without opinions

For IAM policy resources, PlanLens parses the policy document and reports structural changes:

```text
ACCESS
aws_iam_role_policy.deploy
  actions added:
    + s3:DeleteObject
    + kms:Decrypt
```

Wildcards are shown like any other action. Deciding whether they are dangerous belongs to your security tooling.

## CLI options

```text
--format text|json|markdown   output format (default text)
--category LIST               comma-separated filter: only show these categories
--fail-on CAT                 exit 1 when findings exist: destroy or replacement (repeatable)
--resource ADDRESS            exact resource address filter
--group-by module|type        group findings in text output
--verbose                     expand collapsed low-signal changes
--version                     print version
```

## CI integration

Exit codes:

- `0` — analysis completed, no gate violated
- `1` — a `--fail-on` gate matched
- `2` — execution/parsing failure

Gates are objective and mechanical — no security scoring:

```yaml
- name: Terraform plan
  run: terraform plan -out=tfplan

- name: Export plan JSON
  run: terraform show -json tfplan > tfplan.json

- name: Review plan
  run: planlens --fail-on destroy --fail-on replacement tfplan.json
```

Without gates, PlanLens always exits `0`.

## Markdown for pull requests

```sh
planlens --format markdown tfplan.json > review.md
```

Renders headings per category, inline code diffs, and collapses low-signal changes into a `<details>` block. Post it wherever your CI likes — PlanLens has no GitHub/GitLab API integration by design.

## JSON output

```json
{
  "version": "0.2.0",
  "summary": { "resources_affected": 1, "replace": 1, "categories": { "replacement": 1 } },
  "findings": [
    {
      "id": "change.resource-replacement",
      "category": "replacement",
      "confidence": "high",
      "address": "aws_db_instance.production",
      "action": "replace",
      "replacement_order": "destroy-create",
      "changes": [
        { "path": "engine_version", "before": "14.11", "after": "16.3", "causes_replacement": true }
      ]
    }
  ]
}
```

Sensitive values are dropped before serialization and can never appear in any output format.

## Design philosophy

- Parse once, normalize once, classify once.
- Categories describe mechanics, not acceptability. No HIGH/MEDIUM/LOW security theater.
- Sensitive values never survive into output.
- Unknown values are reported as unknown, never guessed.
- Noise reduction is a feature, not a loss of information: JSON stays complete.
- Provider-specific logic is limited to small descriptive enrichers; everything else is one generic semantic catalog.

## Limitations

- Reads only `terraform/tofu show -json` output, not binary plan files.
- The semantic catalog is pragmatic, not exhaustive; unclassified attributes fall under OTHER.
- Collection-aware diffs apply to flat scalar lists; nested structures diff per leaf.
- No state inspection, no provider queries, no drift detection.

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/planlens
```

Fixtures live in `testdata/` (including the `demo-ugly-plan` noise-reduction demo). Fuzz targets cover plan parsing, attribute diffing, and IAM policy parsing.

### Releasing

Releases are cut by tagging; [goreleaser](https://goreleaser.com) builds and publishes binaries automatically:

```sh
git tag -a v0.2.1 -m "v0.2.1"
git push origin v0.2.1
```

Update `CHANGELOG.md` before tagging.

## Roadmap

Planned after v0.2: `planlens compare old.json new.json` (diff two proposed plans), SARIF/markdown posting integrations left to CI, more enrichers.

## License

[Apache License 2.0](LICENSE)

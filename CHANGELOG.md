# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-08-25

### Changed

- Synced CI/release workflows with tfdoctor (actions v7, Trivy security scan,
  renovate).
- Homebrew cask now strips the macOS quarantine flag on install and the README
  documents the manual `xattr` workaround for downloaded binaries.
- Unified `--version` output across the tool family (`planlens 0.2.1`).


## [0.2.0] - 2026-08-25

### Changed

- Refocused from partial security scanning to a reviewer-oriented semantic
  diff: planlens now describes what kind of change occurred instead of judging
  whether it is acceptable.
- Replaced HIGH/MEDIUM/LOW/INFO risk levels with semantic change categories:
  replacement, destructive, capacity, behavioral, access, sensitive, unknown,
  metadata, create, other.
- JSON output: `category`/`confidence` replace `risk`; replacements carry
  `action: "replace"` and `replacement_order`.
- CI gates are now objective and mechanical:
  `--fail-on destroy|destructive|replacement|replace` (repeatable).
- Removed provider analyzer hierarchy; classification comes from one generic
  attribute catalog (`internal/semantic`). Small enrichers remain for IAM.

### Added

- Replacement causes surfaced from Terraform's `replace_paths`, with the
  lifecycle order (`destroy-create` vs `create-destroy`).
- Collection-aware diffs: flat scalar lists render as added/removed members.
- Noise reduction: metadata-only, computed/unknown-only, and plain creates are
  collapsed into a LOW-SIGNAL summary; `--verbose` expands them.
- `--format markdown` for pull requests.
- `--group-by module|type` and `--category` filters.
- Computed-only detection (values only known after apply).
- IAM policy structural diffs (actions/resources added or removed) without
  security judgment.
- Azure NSG/storage/Key Vault/SQL coverage via the generic catalog.
- Demo fixture `testdata/demo-ugly-plan/`.

### Removed

- Security-policy rules (public ingress judgments, IAM wildcard scoring,
  S3/KMS/RDS exposure rules). Use Trivy, Checkov, OPA, or Sentinel for that;
  planlens reviews the change, not the configuration.

## [0.1.0] - 2026-08-25

### Added

- Initial release.
- Terraform/OpenTofu plan JSON parsing (`terraform show -json` /
  `tofu show -json`) with action normalization and replacement detection.
- Recursive before/after attribute diff engine with sensitive-value redaction
  and unknown-after-apply placeholders.
- Text and JSON output formats.
- AWS analyzers: security groups, IAM policies, RDS, S3, KMS.
- Filtering (`--min-risk`, `--resource`) and CI exit codes with
  `--fail-on high|medium|low`.
- Fuzz targets for plan parsing, diffing, and IAM policy parsing.

[Unreleased]: https://github.com/ojarosch/planlens/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ojarosch/planlens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ojarosch/planlens/releases/tag/v0.1.0

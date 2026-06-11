# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-06-11

### Changed

- Promote `v0.1.0` to stable. First major release: the `v1` floating tag now
  exists and tracks the latest `v1.x.x` — consumers pin `@v1` and receive
  non-breaking updates automatically. No functional changes from `v0.1.0`.

## [0.1.0] — 2026-06-11 — Initial release

### Added

- `full-scan.yml` reusable workflow orchestrating all scanner stages with parallel execution and a consolidated gate
- `secrets-scan.yml` — Gitleaks with full-history scan and custom high-signal rules
- `sast.yml` — Semgrep with composed public rulesets (security-audit, owasp-top-ten, secrets, ci) plus language-specific packs
- `deps-scan.yml` — Trivy in filesystem mode for language-native dependency manifests
- `iac-scan.yml` — Checkov for Terraform, Dockerfile, Kubernetes, and CloudFormation
- `container-scan.yml` — Trivy in image mode (opt-in via `container-image` input)
- `sbom.yml` — Syft-generated CycloneDX and SPDX SBOMs
- `self-test.yml` — dogfood workflow running the full pipeline against this repo on every push
- `release.yml` — tag-triggered release workflow that moves the floating major tag
- `severity-gate.sh` — SARIF-consuming gate with baseline-diff support so inherited findings don't block new PRs
- `pr-comment.js` — sticky PR comment aggregating findings per stage with Security-tab links
- Scanner configs in `configs/` — opinionated but extensible defaults for all five gating scanners
- Documentation in `docs/` — architecture, gating policy, usage, and extension guide

### Security

- Every third-party action pinned to a full commit SHA (never a floating tag)
- Zero secrets, tokens, or credentials committed to the repo — public-safe by construction

[Unreleased]: https://github.com/Just-In-N-Out/devsecops-pipeline/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Just-In-N-Out/devsecops-pipeline/releases/tag/v1.0.0
[0.1.0]: https://github.com/Just-In-N-Out/devsecops-pipeline/releases/tag/v0.1.0

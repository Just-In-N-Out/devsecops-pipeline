# devsecops-pipeline

Drop-in DevSecOps pipeline for GitHub Actions — secrets, SAST, dependencies, IaC, containers, and SBOM in one reusable workflow.

[![Self-test](https://github.com/Just-In-N-Out/devsecops-pipeline/actions/workflows/self-test.yml/badge.svg)][self-test]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20%2B%20SPDX-informational)][sbom-wf]
[![Release](https://img.shields.io/github/v/release/Just-In-N-Out/devsecops-pipeline)][releases]

## Quickstart

Paste into `.github/workflows/security.yml` in your repo:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  security:
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/full-scan.yml@v1
    secrets: inherit
    permissions: {contents: write, security-events: write, actions: read, pull-requests: write}
```

Done. Every push and PR now gets six parallel scan stages across five scanners, results in the
Security tab, a sticky summary comment on PRs, and a merge gate on new
high/critical findings.

> The top-level `permissions: contents: read` makes the workflow least-privilege
> by default — without it, the pipeline's own IaC scanner flags your workflow
> (`CKV2_GHA_1`). The `permissions` on the `security` job widens only what the
> scans need.

See it live: [**devsecops-pipeline-demo**][demo] is a sample repo that consumes
this pipeline — a clean `main` (green) and an open PR full of planted findings
(red gate, scan comment, HTML report).

## Inputs

| Input | Type | Default | Description |
| --- | --- | --- | --- |
| `language` | string | `auto` | `python`, `node`, `go`, `java`, `auto`. Controls which SAST language pack runs. `auto` detects from repo contents. |
| `severity-threshold` | string | `high` | `critical`, `high`, `medium`, `low`. Findings at or above this level fail the build. |
| `skip-stages` | string | `""` | Comma-separated list: `secrets,sast,deps,iac,container,sbom`. Opt out of stages. |
| `baseline-branch` | string | `main` | Diff-only mode: only gate on findings not present in this branch. |
| `container-image` | string | `""` | Image ref (e.g. `ghcr.io/org/app:sha`) for the container scan. If empty, the stage is skipped. |
| `fail-on-findings` | boolean | `true` | If `false`, runs in advisory mode — reports but never fails. Useful for rollout. |

No secrets required beyond the automatic `GITHUB_TOKEN` — `secrets: inherit`
covers it.

## What runs

- **secrets** — [Gitleaks] scans the full git history for committed credentials; a deleted secret is still a leaked secret.
- **sast** — [Semgrep] runs composed public rulesets (`security-audit`, `owasp-top-ten`, `secrets`, `ci`) plus a language pack.
- **deps** — [Trivy] filesystem mode reads lockfiles (`package-lock.json`, `requirements.txt`, `go.sum`, `pom.xml`, …) for known-vulnerable dependencies.
- **iac** — [Checkov] checks Terraform, Dockerfiles, Kubernetes manifests, and CloudFormation against hardening policies.
- **container** — [Trivy] image mode scans OS packages and bundled dependencies in your built image (opt-in via `container-image`).
- **sbom** — [Syft] emits CycloneDX + SPDX SBOMs as artifacts (and release assets on tag pushes); informational, never gates.

Every stage outputs SARIF: uploaded as run artifacts, pushed to the GitHub
Security tab per-stage, and evaluated once by a consolidated severity gate.

After every run the gate also renders an **interactive HTML report**
(`security-report` artifact — self-contained, opens offline in any browser):
verdict explainer, severity/stage charts, **new vs fixed vs persisting** delta
against the baseline, a findings trend across recent runs, and a filterable
findings table with per-finding remediation guidance. A condensed version
appears directly on the workflow run page, and PR comments link to it.

## Gating

Findings at or above `severity-threshold` block; below it they warn. With
`baseline-branch` set (the default), only findings **new** relative to that
branch's last scan gate the PR — inherited debt informs instead of blocking.
Severity tiers, the full block/warn matrix, override mechanics, and the
break-glass procedure are in [docs/gating-policy.md](docs/gating-policy.md).

## Running a single stage

Each stage is independently callable with the same gate semantics:

```yaml
permissions:
  contents: read
jobs:
  secrets-only:
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/secrets-scan.yml@v1
    secrets: inherit
    permissions: {contents: read, security-events: write, actions: read, pull-requests: write}
```

Available: `secrets-scan.yml`, `sast.yml`, `deps-scan.yml`, `iac-scan.yml`,
`container-scan.yml`, `sbom.yml`. Details: [docs/usage.md](docs/usage.md).

## Advisory mode for rollout

Turning on a blocking scanner cold on a legacy repo fails every PR. Start
with reporting only:

```yaml
    with:
      fail-on-findings: false
```

Run that for a week, triage the Security tab, then remove the flag — the
first `main` run also seeds the baseline so enforcement starts from "don't
make it worse". Full rollout sequence: [docs/usage.md](docs/usage.md).

## FAQ: "My team has existing findings — how do I not block every PR?"

That's the default behavior, not an option you enable: `baseline-branch:
main` means the gate compares your PR's findings against `main`'s latest
scan and only **new** findings block. The backlog stays visible in the
Security tab and the PR comment (total vs new counts), but it doesn't tax
unrelated PRs. First run on a repo (no baseline yet) gates on everything —
seed the baseline by running once on `main` first, ideally in advisory mode.

## Adding a scanner

The stage contract, a copy-paste workflow template, and the
intentional-failure test for proving your gate wiring:
[docs/extending.md](docs/extending.md). Architecture and design rationale:
[docs/architecture.md](docs/architecture.md).

## License

[MIT](LICENSE) — built by [Justin Issa](https://github.com/Just-In-N-Out).

[self-test]: https://github.com/Just-In-N-Out/devsecops-pipeline/actions/workflows/self-test.yml
[sbom-wf]: .github/workflows/sbom.yml
[releases]: https://github.com/Just-In-N-Out/devsecops-pipeline/releases
[demo]: https://github.com/Just-In-N-Out/devsecops-pipeline-demo
[Gitleaks]: https://github.com/gitleaks/gitleaks
[Semgrep]: https://semgrep.dev
[Trivy]: https://trivy.dev
[Checkov]: https://www.checkov.io
[Syft]: https://github.com/anchore/syft

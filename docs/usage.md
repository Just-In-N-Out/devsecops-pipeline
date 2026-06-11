# Usage guide

Everything a consumer repo needs. All examples pin `@v1` — never reference
`@main`; a floating branch defeats both reproducibility and the supply-chain
posture this pipeline enforces.

## Minimal setup

`.github/workflows/security.yml` in your repo:

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
    permissions:
      contents: write       # sbom release-asset attach on tag pushes
      security-events: write
      actions: read
      pull-requests: write
```

That's the whole integration. Defaults: language auto-detection, `high`
threshold, baseline-diff against `main`, all stages except container (which
is opt-in via `container-image`).

## Inputs

| Input | Type | Default | Description |
| --- | --- | --- | --- |
| `language` | string | `auto` | `python`, `node`, `go`, `java`, `auto`. Picks the Semgrep language pack. `auto` detects from repo contents (`requirements.txt`/`pyproject.toml` → python, `package.json` → node, `go.mod` → go, `pom.xml`/`build.gradle` → java). |
| `severity-threshold` | string | `high` | `critical`, `high`, `medium`, `low`. Findings at or above this level fail the build. |
| `skip-stages` | string | `""` | Comma-separated: `secrets,sast,deps,iac,container,sbom`. Opt out of stages. |
| `baseline-branch` | string | `main` | Diff-only mode: only gate on findings not present in this branch's latest scan. |
| `container-image` | string | `""` | Image ref (e.g. `ghcr.io/org/app:sha`) for the container scan. Empty = stage skipped. |
| `fail-on-findings` | boolean | `true` | `false` runs in advisory mode — full reporting, never fails. |

Secrets: the workflow needs nothing beyond the automatic `GITHUB_TOKEN`;
`secrets: inherit` covers it.

## Recipes

### Gradual rollout on a legacy repo

Existing repos have existing findings. Don't turn on a blocking scanner in
one step — sequence it:

```yaml
# Phase 1 (week 1): observe. Nothing fails; Security tab + PR comments populate.
jobs:
  security:
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/full-scan.yml@v1
    secrets: inherit
    permissions:
      contents: write
      security-events: write
      actions: read
      pull-requests: write
    with:
      fail-on-findings: false
```

Phase 1 also seeds the baseline: the first run on `main` uploads the
`scan-summary` artifact that diff mode needs.

```yaml
# Phase 2 (week 2+): enforce on NEW findings only.
    with:
      baseline-branch: main   # the default — shown for clarity
```

Phase 3: burn down the inherited debt from the Security tab on your own
schedule, then optionally tighten `severity-threshold` to `medium`.

### Python project with a container image

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    outputs:
      image: ghcr.io/${{ github.repository }}:${{ github.sha }}
    steps:
      # ... build and push ghcr.io/<org>/<app>:<sha> ...

  security:
    needs: build
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/full-scan.yml@v1
    secrets: inherit
    permissions:
      contents: write
      security-events: write
      actions: read
      pull-requests: write
    with:
      language: python
      container-image: ${{ needs.build.outputs.image }}
```

The container scan pulls the image anonymously or reuses the runner's
existing registry session. For private GHCR images, log in before the scan
in a prior job on the same runner, or make the package internal-public.

### Terraform-only repo

No app code means most stages have nothing to chew on — skip them and keep
the run fast:

```yaml
jobs:
  security:
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/full-scan.yml@v1
    secrets: inherit
    permissions:
      contents: write
      security-events: write
      actions: read
      pull-requests: write
    with:
      skip-stages: sast,deps,container
      severity-threshold: medium   # IaC findings are cheap to fix pre-apply
```

`secrets` stays on (state files and tfvars are classic leak vectors), `iac`
is the star, and `sbom` still inventories providers/modules.

### Running a single stage independently

Every stage is a standalone reusable workflow with the same gate semantics:

```yaml
jobs:
  secrets-only:
    uses: Just-In-N-Out/devsecops-pipeline/.github/workflows/secrets-scan.yml@v1
    secrets: inherit
    permissions:
      contents: read
      security-events: write
      actions: read
      pull-requests: write
    with:
      severity-threshold: critical
```

Available: `secrets-scan.yml`, `sast.yml` (extra input: `language`),
`deps-scan.yml`, `iac-scan.yml`, `container-scan.yml` (required input:
`container-image`), `sbom.yml` (no inputs, never gates). Standalone stages
post their own per-stage PR comment; `full-scan.yml` consolidates into one.

## Extending suppressions

- **Dependencies (Trivy):** add `.trivyignore.yaml` at your repo root — it
  composes with the pipeline's baseline ignore file automatically. Entry
  format: [`configs/trivy-ignore.yaml`](../configs/trivy-ignore.yaml).
- **IaC (Checkov):** prefer inline `# checkov:skip=CKV_AWS_20: reason`
  comments next to the resource; repo-wide skips belong in a fork of
  [`configs/checkov.yml`](../configs/checkov.yml) via PR.
- **Secrets (Gitleaks):** fixture/testdata paths are already allowlisted;
  further allowlisting goes through a PR to
  [`configs/gitleaks.toml`](../configs/gitleaks.toml).

## FAQ

**The gate fails on findings my PR didn't introduce.**
Either no baseline exists yet (run the pipeline once on `main` — see the
rollout recipe) or the finding genuinely isn't in the baseline (it's new in
your diff, possibly via a dependency bump). The PR comment distinguishes
total vs new counts.

**Where do results live?**
Four places: the PR sticky comment (summary + top findings), the repo's
Security tab → Code scanning (full, queryable, with per-stage categories),
the workflow run page (condensed job summary with verdict and per-stage
table), and run artifacts — `security-report` (interactive HTML report:
charts, baseline delta, trend, per-finding remediation; download and open in
any browser, works offline), `sarif-*` (raw scanner output), and
`scan-summary` (merged JSON).

**Does this work on private repos?**
Yes — GitHub code scanning upload requires GitHub Advanced Security on
private repos; without it, the Security-tab upload step is skipped
gracefully and everything else (gate, comments, artifacts) works.

**How do I add a scanner?**
[extending.md](extending.md).

# Extending the pipeline

How to add a scanner stage, and how to prove the gate still works afterward.

## The contract every stage honors

A stage is a reusable workflow that:

1. Accepts `severity-threshold`, `baseline-branch`, `fail-on-findings`,
   `post-comment` inputs (plus stage-specific ones).
2. Runs its scanner **without letting the scanner decide pass/fail** —
   `exit-code: 0`-style flags or `continue-on-error: true` on the scan step.
3. Produces SARIF and uploads it as artifact `sarif-<stage>`.
4. Uploads the SARIF to the Security tab with `category: <stage>`
   (`continue-on-error`, since fork PRs lack the permission).
5. Runs `scripts/severity-gate.sh` so standalone callers get gate semantics.
6. Posts the per-stage sticky comment when `post-comment` is true.

Every third-party action **must** be pinned to a full commit SHA with a
trailing `# vX.Y.Z` comment. PRs with tag-pinned actions don't merge.

## Template for a new stage

`.github/workflows/<stage>-scan.yml` — replace `STAGE` and the scanner step:

```yaml
name: STAGE scan (ToolName)

on:
  workflow_call:
    inputs:
      severity-threshold:
        type: string
        default: high
      baseline-branch:
        type: string
        default: main
      fail-on-findings:
        type: boolean
        default: true
      post-comment:
        type: boolean
        default: true

permissions:
  contents: read

jobs:
  STAGE:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read
      pull-requests: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3

      # Stages run against the CALLER's repo; fetch this repo's configs and
      # scripts at the exact ref the consumer pinned.
      - name: Resolve pipeline repo and ref
        id: pipeline
        env:
          # Two candidates because the documented home of this value has
          # moved between contexts; whichever is populated wins. Both give
          # "owner/repo/.github/workflows/<file>.yml@<ref>" for the workflow
          # file defining THIS job (i.e. the pipeline repo at the consumer's
          # pinned ref).
          CANDIDATE_A: ${{ github.job_workflow_ref }}
          CANDIDATE_B: ${{ job.workflow_ref }}
        run: |
          ref_path="${CANDIDATE_A:-$CANDIDATE_B}"
          echo "job_workflow_ref candidates: A='$CANDIDATE_A' B='$CANDIDATE_B'"
          if [ -z "$ref_path" ]; then
            echo "::error::Cannot resolve the pipeline workflow ref from the job context"
            exit 1
          fi
          echo "repo=${ref_path%%/.github/*}" >> "$GITHUB_OUTPUT"
          echo "ref=${ref_path##*@}" >> "$GITHUB_OUTPUT"

      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          repository: ${{ steps.pipeline.outputs.repo }}
          ref: ${{ steps.pipeline.outputs.ref }}
          path: .devsecops-pipeline

      - name: Run scanner
        run: |
          mkdir -p sarif-out
          # your-scanner --sarif --output sarif-out/STAGE.sarif
          # The scanner must NOT fail this step on findings — the gate decides.

      - name: Upload SARIF artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: sarif-STAGE
          path: sarif-out/
          if-no-files-found: ignore

      - name: Upload SARIF to Security tab
        if: hashFiles('sarif-out/*.sarif') != ''
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@8aad20d150bbac5944a9f9d289da16a4b0d87c1e # v4.36.2
        with:
          sarif_file: sarif-out/
          category: STAGE

      - name: Severity gate
        env:
          SARIF_DIR: sarif-out
          STAGE_NAME: STAGE
          SEVERITY_THRESHOLD: ${{ inputs.severity-threshold }}
          FAIL_ON_FINDINGS: ${{ inputs.fail-on-findings }}
          BASELINE_BRANCH: ${{ inputs.baseline-branch }}
          BASELINE_ARTIFACT_NAME: scan-summary-STAGE
          SUMMARY_PATH: scan-summary.json
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: bash .devsecops-pipeline/scripts/severity-gate.sh

      - name: Upload scan summary
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: scan-summary-STAGE
          path: scan-summary.json
          if-no-files-found: ignore

      - name: Post PR comment
        if: always() && inputs.post-comment && github.event_name == 'pull_request'
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        env:
          SUMMARY_PATH: scan-summary.json
          STAGE_MARKER: STAGE
        with:
          script: |
            const run = require('./.devsecops-pipeline/scripts/pr-comment.js');
            await run({ github, context, core });
```

## Wiring the stage into full-scan.yml

1. Add a job following the existing pattern: `needs: detect-language`, the
   comma-bounded skip guard
   `if: ${{ !contains(format(',{0},', inputs.skip-stages), ',STAGE,') }}`,
   `uses: ./.github/workflows/STAGE-scan.yml`, `secrets: inherit`, and
   `fail-on-findings: false` / `post-comment: false` (the orchestrator's gate
   decides and comments).
2. Add the job to the gate's `needs:` list.
3. Nothing else: the gate discovers stages from `sarif-*` artifact names, so
   the new stage appears in the summary, the comment, and the verdict
   automatically.
4. Document the stage in README ("What runs") and `docs/usage.md`
   (`skip-stages` value).

## Verifying the gate (intentional failure test)

Adding a scanner that silently never fails is worse than not adding it.
Prove the wiring end-to-end:

1. Create a branch and plant a finding the new scanner must flag at ≥ the
   default threshold. For the existing stages: a `canary.tf` opening
   `0.0.0.0/0` ingress (iac), a fake-but-well-formed `ghp_…` token in a
   tracked file (secrets), a known-vulnerable pin like `lodash@4.17.15` in a
   lockfile (deps). `self-test.yml` carries a commented-out `gate-canary`
   job sketching this for the iac stage.
2. Open a PR. Expect: scan job green (scanners don't fail builds), **gate
   job red**, PR comment showing the finding, Security tab entry under the
   stage's category.
3. Confirm advisory mode: set `fail-on-findings: false` on the branch — the
   gate must go green while still reporting the finding.
4. Close the PR without merging. The canary never lands on `main` (it would
   poison the baseline and allowlist the finding everywhere).

## PR checklist for new stages

- [ ] Workflow follows the template: SARIF out, artifact named
      `sarif-<stage>`, gate script run, no scanner-decided failures
- [ ] Every action SHA-pinned with `# vX.Y.Z` comment
- [ ] Scanner config (if any) added under `configs/` with documented
      defaults and an extension story for consumers
- [ ] Stage wired into `full-scan.yml` (job + gate `needs:` + skip guard)
- [ ] Intentional-failure test performed on a PR (link the run)
- [ ] `self-test.yml` green — the pipeline stays clean on its own repo
- [ ] README + `docs/usage.md` updated
- [ ] CHANGELOG entry under `[Unreleased]`

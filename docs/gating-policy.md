# Gating policy

What blocks a merge, what merely warns, and how to override either — on
purpose, with an audit trail.

## Severity tiers

| Tier | Definition | Typical sources |
| --- | --- | --- |
| **critical** | Exploitable now, catastrophic blast radius: exposed live credentials, RCE-class vulnerabilities, `security-severity` ≥ 9.0 | Gitleaks live-key rules, CVSS 9.x CVEs |
| **high** | Exploitable with modest effort or wide exposure: injection-class SAST findings, CVSS 7.0–8.9, SARIF `error` level | Semgrep OWASP rules, Trivy HIGH CVEs, Checkov internet-exposed resources |
| **medium** | Real weakness needing specific preconditions: CVSS 4.0–6.9, SARIF `warning` level | Most Checkov hardening checks, moderate CVEs |
| **low** | Hygiene and defense-in-depth: CVSS < 4.0, SARIF `note` level | Informational rules, minor misconfigurations |

Classification logic (`security-severity` score first, SARIF `level` as
fallback) is implemented once, in [`scripts/severity-gate.sh`](../scripts/severity-gate.sh) —
see [architecture.md](architecture.md#severity-classification).

## Block / warn / inform matrix

`severity-threshold` sets the blocking line; everything below it is reported
but doesn't gate. Defaults in **bold**.

| Finding tier | threshold: `critical` | **threshold: `high`** | threshold: `medium` | threshold: `low` |
| --- | --- | --- | --- | --- |
| critical | 🚫 block | 🚫 block | 🚫 block | 🚫 block |
| high | ⚠️ warn | 🚫 block | 🚫 block | 🚫 block |
| medium | ⚠️ warn | ⚠️ warn | 🚫 block | 🚫 block |
| low | ⚠️ warn | ⚠️ warn | ⚠️ warn | 🚫 block |

Two modifiers apply on top:

- **`fail-on-findings: false`** turns every 🚫 into ⚠️ — full reporting
  (Security tab, PR comment, artifacts), zero blocking. This is advisory
  mode, intended for rollout (see [usage.md](usage.md)).
- **`baseline-branch`** (default `main`) restricts gating to findings **not
  already present** on that branch. Pre-existing debt informs; new findings
  block. The SBOM stage never gates regardless of settings — it's
  informational by design.

## How to override

In order of preference:

1. **Fix the finding.** Always the cheapest option long-term.
2. **Suppress with provenance.** Each scanner has a config-level suppression
   with room for justification — `configs/trivy-ignore.yaml` entries require
   a `statement` and support `expired_at`; `configs/checkov.yml` documents
   `skip-check`; `configs/gitleaks.toml` has path allowlists for fixtures.
   Suppressions land via PR, so they're reviewed and attributable.
3. **Lower the bar explicitly.** Raise `severity-threshold` or set
   `fail-on-findings: false` in the calling workflow. This is a visible,
   reviewable change to the caller's YAML — not a hidden toggle.

## Break-glass: shipping past a red gate

For genuine emergencies (the hotfix that stops the bleeding is itself
flagged):

1. Flip the call site to advisory: `fail-on-findings: false` **in the
   hotfix PR itself**, so the override is part of the reviewed diff.
2. Require a second approver on that PR — branch-protection "require review
   from code owners" on `.github/workflows/` makes this automatic.
3. Open a tracking issue for the bypassed finding(s) before merging; link it
   in the PR description.
4. Revert the advisory flip in the next PR. The self-test/scan history makes
   un-reverted break-glass merges easy to audit: look for runs where the
   gate warned instead of failed.

A team can formalize this with a `security-break-glass` PR label plus a
small caller-side conditional (`fail-on-findings: ${{ !contains(github.event.pull_request.labels.*.name, 'security-break-glass') }}`),
which keeps the escape hatch labeled, queryable, and impossible to use
silently.

## First-run behavior

If `baseline-branch` is set but no baseline scan artifact exists (first run
on a repo, or artifacts expired), the gate logs a warning and evaluates
**all** findings. To adopt the pipeline on a repo with existing debt, run it
once on the baseline branch (e.g. merge the workflow in advisory mode) so the
baseline artifact exists before enforcement begins — the rollout recipe in
[usage.md](usage.md) walks through this.

#!/usr/bin/env bash
# severity-gate.sh — evaluate SARIF findings against a severity threshold.
#
# Reads every *.sarif under SARIF_DIR, classifies each finding, writes a
# consolidated scan-summary.json, and exits non-zero when findings at or
# above SEVERITY_THRESHOLD exist (unless FAIL_ON_FINDINGS=false).
#
# Baseline-diff mode: when BASELINE_BRANCH is set and a GitHub token is
# available, the latest scan-summary artifact from that branch is fetched and
# only findings NOT present in the baseline count toward the gate. This is
# what lets a legacy repo adopt the pipeline without every PR drowning in
# inherited debt — see docs/gating-policy.md.
#
# Environment:
#   SARIF_DIR           directory tree containing *.sarif files     (required)
#   SEVERITY_THRESHOLD  critical | high | medium | low              (default: high)
#   FAIL_ON_FINDINGS    "true" gates, "false" is advisory           (default: true)
#   BASELINE_BRANCH     branch whose findings are pre-existing debt (default: "" = off)
#   STAGE_NAME          stage label when SARIF_DIR is flat          (default: scan)
#   SUMMARY_PATH        where to write scan-summary.json            (default: ./scan-summary.json)
#   BASELINE_ARTIFACT_NAME  artifact holding the baseline summary   (default: scan-summary)
#   GITHUB_REPOSITORY / GITHUB_TOKEN or GH_TOKEN — required only for baseline fetch
set -euo pipefail

SARIF_DIR="${SARIF_DIR:?SARIF_DIR is required}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-high}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-true}"
BASELINE_BRANCH="${BASELINE_BRANCH:-}"
STAGE_NAME="${STAGE_NAME:-scan}"
SUMMARY_PATH="${SUMMARY_PATH:-./scan-summary.json}"
BASELINE_ARTIFACT_NAME="${BASELINE_ARTIFACT_NAME:-scan-summary}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

case "$SEVERITY_THRESHOLD" in
  critical) THRESHOLD_RANK=4 ;;
  high)     THRESHOLD_RANK=3 ;;
  medium)   THRESHOLD_RANK=2 ;;
  low)      THRESHOLD_RANK=1 ;;
  *) echo "::error::Invalid SEVERITY_THRESHOLD '$SEVERITY_THRESHOLD' (want critical|high|medium|low)"; exit 2 ;;
esac

command -v jq >/dev/null || { echo "::error::jq is required"; exit 2; }

sha256() {
  if command -v sha256sum >/dev/null; then printf %s "$1" | sha256sum | cut -d' ' -f1
  else printf %s "$1" | shasum -a 256 | cut -d' ' -f1; fi
}

# --- 1. Extract findings from every SARIF file -------------------------------
# Severity: prefer the rule's security-severity CVSS-style score; fall back to
# the SARIF level. Fingerprint excludes line numbers so findings survive
# rebases and unrelated edits above them.
EXTRACT_JQ='
def sev_from_score($s): if $s >= 9 then "critical" elif $s >= 7 then "high" elif $s >= 4 then "medium" else "low" end;
def sev_from_level($l): if $l == "error" then "high" elif $l == "warning" then "medium" else "low" end;
[ .runs[]?
  | (.tool.driver.rules // []) as $rules
  | .results[]?
  | . as $r
  | ($r.ruleId // "unknown-rule") as $rid
  | ([ $rules[] | select(.id == $rid) ] | first) as $rule
  | (($rule.properties["security-severity"] // empty | tostring | tonumber? ) // null) as $score
  | (($r.locations[0].physicalLocation.artifactLocation.uri // "unknown") | sub("^\\./"; "")) as $file
  | { stage: $stage,
      ruleId: $rid,
      file: $file,
      line: ($r.locations[0].physicalLocation.region.startLine // 0),
      severity: (if $score != null then sev_from_score($score)
                 else sev_from_level($r.level // $rule.defaultConfiguration.level // "warning") end),
      message: (($r.message.text // "") | .[0:300]) }
]'

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ALL_FINDINGS="$WORKDIR/findings.json"
echo "[]" > "$ALL_FINDINGS"

found_any=false
while IFS= read -r -d '' sarif; do
  found_any=true
  parent="$(basename "$(dirname "$sarif")")"
  case "$parent" in
    sarif-*) stage="${parent#sarif-}" ;;
    *)       stage="$STAGE_NAME" ;;
  esac
  jq --arg stage "$stage" "$EXTRACT_JQ" "$sarif" > "$WORKDIR/one.json" \
    || { echo "::warning::Failed to parse $sarif — skipping"; continue; }
  jq -s 'add' "$ALL_FINDINGS" "$WORKDIR/one.json" > "$WORKDIR/merged.json"
  mv "$WORKDIR/merged.json" "$ALL_FINDINGS"
done < <(find "$SARIF_DIR" -type f -name '*.sarif' -print0)

if [ "$found_any" = false ]; then
  echo "::warning::No SARIF files found under $SARIF_DIR — nothing to gate"
fi

# --- 2. Fingerprint each finding ---------------------------------------------
FP_FINDINGS="$WORKDIR/findings-fp.json"
echo "[]" > "$FP_FINDINGS"
while IFS= read -r row; do
  key="$(jq -r '"\(.ruleId)|\(.file)"' <<<"$row")"
  fp="$(sha256 "$key")"
  jq --arg fp "$fp" '. + {fingerprint: $fp}' <<<"$row" >> "$WORKDIR/fp-lines.json"
done < <(jq -c '.[]' "$ALL_FINDINGS")
[ -s "$WORKDIR/fp-lines.json" ] && jq -s '.' "$WORKDIR/fp-lines.json" > "$FP_FINDINGS"

TOTAL_COUNT="$(jq 'length' "$FP_FINDINGS")"

# --- 3. Baseline diff ---------------------------------------------------------
BASELINE_FPS="$WORKDIR/baseline-fps.json"
echo "[]" > "$BASELINE_FPS"
baseline_applied=false

if [ -n "$BASELINE_BRANCH" ] && [ "$TOTAL_COUNT" -gt 0 ]; then
  if [ -z "$TOKEN" ] || [ -z "${GITHUB_REPOSITORY:-}" ] || ! command -v gh >/dev/null; then
    echo "::warning::Baseline branch '$BASELINE_BRANCH' set but no token/repo/gh available — gating on ALL findings"
  else
    echo "Fetching baseline scan summary from branch '$BASELINE_BRANCH'..."
    export GH_TOKEN="$TOKEN"
    archive_url="$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=$BASELINE_ARTIFACT_NAME&per_page=100" \
      --jq "[.artifacts[] | select(.workflow_run.head_branch == \"$BASELINE_BRANCH\" and .expired == false)] | sort_by(.created_at) | last | .archive_download_url // empty" \
      2>/dev/null || true)"
    if [ -n "$archive_url" ]; then
      if curl -sSfL -H "Authorization: Bearer $TOKEN" -o "$WORKDIR/baseline.zip" "$archive_url" \
         && unzip -q -o "$WORKDIR/baseline.zip" -d "$WORKDIR/baseline" 2>/dev/null \
         && [ -f "$WORKDIR/baseline/scan-summary.json" ]; then
        jq '[.stages[]?.findings[]?.fingerprint] | unique' "$WORKDIR/baseline/scan-summary.json" > "$BASELINE_FPS"
        baseline_applied=true
        echo "Baseline loaded: $(jq 'length' "$BASELINE_FPS") known finding(s)"
      else
        echo "::warning::Failed to download/parse baseline artifact — gating on ALL findings"
      fi
    else
      echo "::warning::No scan-summary artifact found for branch '$BASELINE_BRANCH' (first run?) — gating on ALL findings"
    fi
  fi
fi

# --- 4. Build summary, evaluate threshold -------------------------------------
jq --slurpfile baseline "$BASELINE_FPS" \
   --arg threshold "$SEVERITY_THRESHOLD" \
   --arg baseline_branch "$BASELINE_BRANCH" \
   --argjson baseline_applied "$baseline_applied" \
   --argjson threshold_rank "$THRESHOLD_RANK" '
def rank($s): {critical:4, high:3, medium:2, low:1}[$s];
($baseline[0]) as $bfps
| map(.fingerprint as $fp | . + {new: (($bfps | index($fp)) == null)}) as $findings
| ($findings | map(select(.new and rank(.severity) >= $threshold_rank))) as $violations
| {
    threshold: $threshold,
    baseline_branch: $baseline_branch,
    baseline_applied: $baseline_applied,
    totals: {
      critical: ($findings | map(select(.severity == "critical")) | length),
      high:     ($findings | map(select(.severity == "high"))     | length),
      medium:   ($findings | map(select(.severity == "medium"))   | length),
      low:      ($findings | map(select(.severity == "low"))      | length),
      all: ($findings | length),
      new: ($findings | map(select(.new)) | length),
      violations: ($violations | length)
    },
    stages: ($findings | group_by(.stage) | map({
      key: .[0].stage,
      value: {
        critical: (map(select(.severity == "critical")) | length),
        high:     (map(select(.severity == "high"))     | length),
        medium:   (map(select(.severity == "medium"))   | length),
        low:      (map(select(.severity == "low"))      | length),
        findings: (sort_by(-(rank(.severity))) | .[0:200])
      }
    }) | from_entries)
  }' "$FP_FINDINGS" > "$SUMMARY_PATH"

VIOLATIONS="$(jq -r '.totals.violations' "$SUMMARY_PATH")"
NEW_COUNT="$(jq -r '.totals.new' "$SUMMARY_PATH")"

# --- 5. Report ------------------------------------------------------------------
echo ""
echo "================ severity gate ================"
printf '%-12s %9s %6s %8s %5s\n' "stage" "critical" "high" "medium" "low"
jq -r '.stages | to_entries[] | [.key, .value.critical, .value.high, .value.medium, .value.low] | @tsv' "$SUMMARY_PATH" \
  | while IFS=$'\t' read -r s c h m l; do printf '%-12s %9s %6s %8s %5s\n' "$s" "$c" "$h" "$m" "$l"; done
echo "-----------------------------------------------"
echo "total findings : $TOTAL_COUNT"
if [ "$baseline_applied" = true ]; then
  echo "new vs baseline: $NEW_COUNT (baseline: $BASELINE_BRANCH)"
fi
echo "threshold      : $SEVERITY_THRESHOLD and above"
echo "violations     : $VIOLATIONS"
echo "==============================================="

if [ "$VIOLATIONS" -gt 0 ]; then
  jq -r --argjson tr "$THRESHOLD_RANK" '
    def rank($s): {critical:4, high:3, medium:2, low:1}[$s];
    .stages | to_entries[] | .key as $stage | .value.findings[]
    | select(.new and rank(.severity) >= $tr)
    | "::error file=\(.file),line=\(if .line > 0 then .line else 1 end)::[\($stage)/\(.severity)] \(.ruleId): \(.message)"
  ' "$SUMMARY_PATH"
  if [ "$FAIL_ON_FINDINGS" = "true" ]; then
    echo "::error::Gate FAILED — $VIOLATIONS finding(s) at or above '$SEVERITY_THRESHOLD'"
    exit 1
  fi
  echo "::warning::Advisory mode — $VIOLATIONS finding(s) at or above '$SEVERITY_THRESHOLD' (fail-on-findings=false)"
fi

echo "Gate passed."

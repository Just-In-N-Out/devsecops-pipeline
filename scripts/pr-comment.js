// pr-comment.js — post or update the sticky PR comment with scan results.
//
// Invoked from the gate job via actions/github-script:
//
//   const run = require('./.devsecops-pipeline/scripts/pr-comment.js');
//   await run({ github, context, core });
//
// Consumes the scan-summary.json produced by severity-gate.sh rather than
// re-parsing SARIF — one classifier, one source of truth. Updates a single
// marker-tagged comment in place so a long-lived PR gets one evolving status
// comment instead of one per push.

'use strict';

const fs = require('fs');

const MARKER = '<!-- devsecops-pipeline-comment -->';
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const MAX_FINDINGS_PER_STAGE = 10;

function loadSummary(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function severityBadge(counts) {
  if (counts.critical > 0) return '🔴';
  if (counts.high > 0) return '🟠';
  if (counts.medium > 0) return '🟡';
  if (counts.low > 0) return '🔵';
  return '🟢';
}

// Markdown table cells: strip newlines and pipes from scanner messages.
function cell(text) {
  return String(text).replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
}

function renderFindings(stageData) {
  const findings = (stageData.findings || []).slice(0, MAX_FINDINGS_PER_STAGE);
  if (findings.length === 0) return '_No findings._';
  const rows = findings.map(
    (f) =>
      `| \`${cell(f.file)}\` | ${f.line || '–'} | \`${cell(f.ruleId)}\` | ${f.severity} | ${cell(f.message)} |`
  );
  const overflow =
    (stageData.findings || []).length > MAX_FINDINGS_PER_STAGE
      ? `\n_…and ${stageData.findings.length - MAX_FINDINGS_PER_STAGE} more — see the Security tab._`
      : '';
  return [
    '| file | line | rule | severity | message |',
    '| --- | --- | --- | --- | --- |',
    ...rows,
  ].join('\n') + overflow;
}

function render(summary, repoUrl) {
  const stages = summary.stages || {};
  const totals = summary.totals || { critical: 0, high: 0, medium: 0, low: 0, violations: 0 };
  const failed = totals.violations > 0;
  const securityUrl = `${repoUrl}/security/code-scanning`;

  const lines = [
    MARKER,
    `## ${failed ? '❌' : '✅'} Security scan ${failed ? 'failed' : 'passed'}`,
    '',
    failed
      ? `**${totals.violations}** new finding(s) at or above the \`${summary.threshold}\` threshold block this PR.`
      : `No new findings at or above the \`${summary.threshold}\` threshold.`,
    '',
    '| stage | critical | high | medium | low |',
    '| --- | ---: | ---: | ---: | ---: |',
  ];

  const stageNames = Object.keys(stages).sort();
  for (const name of stageNames) {
    const s = stages[name];
    lines.push(
      `| ${severityBadge(s)} ${name} | ${s.critical} | ${s.high} | ${s.medium} | ${s.low} |`
    );
  }
  if (stageNames.length === 0) {
    lines.push('| _no scan output_ | 0 | 0 | 0 | 0 |');
  }

  lines.push(
    '',
    `**Totals:** ${SEVERITIES.map((s) => `${s}: ${totals[s] || 0}`).join(' · ')}`
  );
  if (summary.baseline_applied) {
    lines.push(
      '',
      `_Baseline diff active against \`${summary.baseline_branch}\` — ${totals.new} of ${totals.all} finding(s) are new._`
    );
  }

  for (const name of stageNames) {
    const s = stages[name];
    const count = (s.findings || []).length;
    lines.push(
      '',
      '<details>',
      `<summary><b>${name}</b> — ${count} finding(s)</summary>`,
      '',
      renderFindings(s),
      '',
      '</details>'
    );
  }

  lines.push(
    '',
    `🔎 Full results: [GitHub Security tab](${securityUrl}) · 📋 \`scan-summary\` artifact on this run`,
    '',
    '<sub>Posted by <a href="https://github.com/Just-In-N-Out/devsecops-pipeline">devsecops-pipeline</a> — this comment updates in place.</sub>'
  );

  return lines.join('\n');
}

async function upsertComment({ github, context, core }, body) {
  const issue_number =
    context.issue?.number ?? context.payload?.pull_request?.number;
  if (!issue_number) {
    core.info('Not running in a pull request context — skipping PR comment.');
    return;
  }
  const { owner, repo } = context.repo;

  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number,
    per_page: 100,
  });
  const existing = comments.find((c) => c.body && c.body.includes(MARKER));

  if (existing) {
    await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
    core.info(`Updated existing scan comment ${existing.id}.`);
  } else {
    await github.rest.issues.createComment({ owner, repo, issue_number, body });
    core.info('Created scan comment.');
  }
}

module.exports = async function run({ github, context, core }) {
  const summaryPath = process.env.SUMMARY_PATH || 'scan-summary.json';
  if (!fs.existsSync(summaryPath)) {
    core.warning(`No scan summary at ${summaryPath} — skipping PR comment.`);
    return;
  }
  const summary = loadSummary(summaryPath);
  const repoUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}`;
  const body = render(summary, repoUrl);
  await upsertComment({ github, context, core }, body);
};

// Exported for local testing (node -e) without the Actions runtime.
module.exports.render = render;

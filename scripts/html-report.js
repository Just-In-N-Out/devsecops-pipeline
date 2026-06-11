// html-report.js — render a self-contained HTML security report.
//
// Pure renderer: reads the data files the gate job already produced and
// writes one report.html with zero runtime dependencies (no chart libraries —
// this pipeline doesn't get to lecture consumers about supply-chain pinning
// while pulling unpinned JS off a CDN). Charts are hand-rolled SVG; the only
// interactivity is a small block of vanilla JS for filtering.
//
// Invoked directly with node (not via actions/github-script):
//
//   SUMMARY_PATH=scan-summary.json SARIF_DIR=sarif \
//   BASELINE_SUMMARY_PATH=baseline-summary.json TREND_PATH=trend.json \
//   OUTPUT_PATH=report.html node scripts/html-report.js
//
// Also appends a condensed markdown version to $GITHUB_STEP_SUMMARY when set,
// so the workflow run page shows the verdict without downloading anything.

'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const COLORS = {
  critical: '#b91c1c',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  ok: '#16a34a',
  muted: '#6b7280',
};
const MAX_TABLE_ROWS = 500;

// ---------- data loading -----------------------------------------------------

function loadJson(p) {
  if (!p || !fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function* walkSarif(dir) {
  if (!dir || !fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkSarif(full);
    else if (entry.name.endsWith('.sarif')) yield full;
  }
}

// Rule metadata from raw SARIF: scan-summary truncates messages and drops
// help text, but remediation guidance lives in the rule objects.
function collectRuleMeta(sarifDir) {
  const meta = {};
  for (const file of walkSarif(sarifDir)) {
    const sarif = loadJson(file);
    if (!sarif) continue;
    for (const run of sarif.runs || []) {
      for (const rule of run.tool?.driver?.rules || []) {
        if (!rule.id || meta[rule.id]) continue;
        const help = rule.help?.text || rule.fullDescription?.text || rule.shortDescription?.text || '';
        const fixedVersion = /fixed version:?\s*([^\n]+)/i.exec(help)?.[1]?.trim() || null;
        meta[rule.id] = {
          name: rule.name || null,
          helpUri: rule.helpUri || null,
          help: help.slice(0, 1500),
          fixedVersion,
        };
      }
    }
  }
  return meta;
}

function flattenFindings(summary) {
  const out = [];
  for (const [stage, data] of Object.entries(summary?.stages || {})) {
    for (const f of data.findings || []) out.push({ ...f, stage });
  }
  return out;
}

function computeDelta(summary, baseline) {
  const current = flattenFindings(summary);
  const currentFps = new Set(current.map((f) => f.fingerprint));
  const baselineFindings = baseline ? flattenFindings(baseline) : [];
  const seen = new Set();
  const fixed = baselineFindings.filter((f) => {
    if (currentFps.has(f.fingerprint) || seen.has(f.fingerprint)) return false;
    seen.add(f.fingerprint);
    return true;
  });
  return {
    newOnes: current.filter((f) => f.new),
    persisting: current.filter((f) => !f.new),
    fixed,
    hasBaseline: !!baseline,
  };
}

// ---------- remediation ------------------------------------------------------

const STAGE_FALLBACK_ADVICE = {
  secrets:
    'Treat the credential as compromised: rotate it now, then remove it from the file. ' +
    'Deleting the line is not enough — it stays in git history. After rotating, consider ' +
    'history rewriting (git filter-repo) if the repo is private, or rely on rotation alone if public.',
  deps:
    'Upgrade the affected package to a fixed version (see advisory link). If no fix exists, ' +
    'check whether the vulnerable code path is reachable, and add a time-boxed entry to ' +
    '.trivyignore.yaml with a statement and expired_at.',
  iac:
    'Apply the hardening change in the IaC source. If the configuration is intentional, add an ' +
    'inline "# checkov:skip=<CHECK_ID>: <reason>" next to the resource so the exception is reviewable.',
  sast:
    'Review the flagged code path and apply the safe pattern from the rule documentation. ' +
    'False positive? Suppress inline with a justification comment per the scanner docs.',
  container:
    'Rebuild on an updated base image or upgrade the affected OS/library package in the image. ' +
    'Most image CVEs disappear by bumping the base tag and rebuilding.',
};

function adviceLink(finding, rule) {
  if (rule?.helpUri) return rule.helpUri;
  const id = finding.ruleId || '';
  if (/^CVE-\d{4}-\d+/.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^CKV\d*_/.test(id)) return `https://www.checkov.io/5.Policy%20Index/all.html`;
  if (finding.stage === 'sast') return `https://semgrep.dev/r?q=${encodeURIComponent(id)}`;
  return null;
}

// ---------- html helpers -----------------------------------------------------

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sevBadge(sev) {
  return `<span class="badge" style="background:${COLORS[sev] || COLORS.muted}">${esc(sev)}</span>`;
}

// ---------- svg charts -------------------------------------------------------

function donutSvg(totals) {
  const entries = SEVERITIES.map((s) => [s, totals[s] || 0]).filter(([, n]) => n > 0);
  const total = entries.reduce((a, [, n]) => a + n, 0);
  if (total === 0) {
    return `<svg viewBox="0 0 120 120" width="160" height="160" role="img" aria-label="no findings">
      <circle cx="60" cy="60" r="44" fill="none" stroke="${COLORS.ok}" stroke-width="16"/>
      <text x="60" y="66" text-anchor="middle" font-size="18" fill="${COLORS.ok}" font-weight="700">0</text></svg>`;
  }
  const C = 2 * Math.PI * 44;
  let offset = 0;
  const segs = entries
    .map(([sev, n]) => {
      const frac = n / total;
      const seg = `<circle cx="60" cy="60" r="44" fill="none" stroke="${COLORS[sev]}" stroke-width="16"
        stroke-dasharray="${(frac * C).toFixed(2)} ${(C - frac * C).toFixed(2)}"
        stroke-dashoffset="${(-offset * C).toFixed(2)}" transform="rotate(-90 60 60)"/>`;
      offset += frac;
      return seg;
    })
    .join('');
  return `<svg viewBox="0 0 120 120" width="160" height="160" role="img" aria-label="findings by severity">
    ${segs}<text x="60" y="66" text-anchor="middle" font-size="20" font-weight="700" fill="#111827">${total}</text></svg>`;
}

function stageBarsSvg(stages) {
  const names = Object.keys(stages).sort();
  if (names.length === 0) return '<p class="empty">No stage data.</p>';
  const max = Math.max(1, ...names.map((n) => SEVERITIES.reduce((a, s) => a + (stages[n][s] || 0), 0)));
  const rowH = 28;
  const labelW = 90;
  const barW = 360;
  const rows = names
    .map((name, i) => {
      const y = i * rowH + 6;
      let x = labelW;
      const segs = SEVERITIES.map((sev) => {
        const n = stages[name][sev] || 0;
        const w = (n / max) * barW;
        const seg = n > 0 ? `<rect x="${x.toFixed(1)}" y="${y}" width="${Math.max(w, 1.5).toFixed(1)}" height="16" fill="${COLORS[sev]}"><title>${name}: ${n} ${sev}</title></rect>` : '';
        x += w;
        return seg;
      }).join('');
      const total = SEVERITIES.reduce((a, s) => a + (stages[name][s] || 0), 0);
      return `<text x="${labelW - 8}" y="${y + 13}" text-anchor="end" font-size="13" fill="#374151">${esc(name)}</text>${segs}
        <text x="${(x + 6).toFixed(1)}" y="${y + 13}" font-size="12" fill="${total ? '#374151' : COLORS.ok}">${total || '✓ 0'}</text>`;
    })
    .join('');
  return `<svg viewBox="0 0 ${labelW + barW + 50} ${names.length * rowH + 10}" width="100%" style="max-width:560px" role="img" aria-label="findings per stage">${rows}</svg>`;
}

function trendSvg(trend) {
  if (!Array.isArray(trend) || trend.length < 2) {
    return `<p class="empty">Not enough history yet — the trend chart appears once at least two scans of the baseline branch have run.</p>`;
  }
  const W = 560, H = 160, padL = 36, padB = 24, padT = 10;
  const xs = (i) => padL + (i * (W - padL - 10)) / (trend.length - 1);
  const series = SEVERITIES.map((sev) => trend.map((t) => t.totals?.[sev] || 0));
  const maxY = Math.max(1, ...series.flat());
  const ys = (v) => H - padB - (v / maxY) * (H - padB - padT);
  const lines = SEVERITIES.map((sev, si) => {
    const pts = series[si].map((v, i) => `${xs(i).toFixed(1)},${ys(v).toFixed(1)}`).join(' ');
    const dots = series[si]
      .map((v, i) => `<circle cx="${xs(i).toFixed(1)}" cy="${ys(v).toFixed(1)}" r="2.5" fill="${COLORS[sev]}"><title>${sev}: ${v} (${esc((trend[i].created_at || '').slice(0, 10))})</title></circle>`)
      .join('');
    return `<polyline points="${pts}" fill="none" stroke="${COLORS[sev]}" stroke-width="2"/>${dots}`;
  }).join('');
  const axis = `<line x1="${padL}" y1="${H - padB}" x2="${W - 10}" y2="${H - padB}" stroke="#d1d5db"/>
    <text x="${padL - 6}" y="${ys(maxY) + 4}" text-anchor="end" font-size="11" fill="#6b7280">${maxY}</text>
    <text x="${padL - 6}" y="${H - padB + 4}" text-anchor="end" font-size="11" fill="#6b7280">0</text>
    <text x="${padL}" y="${H - 6}" font-size="11" fill="#6b7280">${esc((trend[0].created_at || '').slice(0, 10))}</text>
    <text x="${W - 10}" y="${H - 6}" text-anchor="end" font-size="11" fill="#6b7280">${esc((trend[trend.length - 1].created_at || '').slice(0, 10))}</text>`;
  const legend = SEVERITIES.map((s, i) => `<rect x="${padL + i * 90}" y="0" width="10" height="10" fill="${COLORS[s]}"/><text x="${padL + i * 90 + 14}" y="9" font-size="11" fill="#374151">${s}</text>`).join('');
  return `<svg viewBox="0 0 ${W} ${H + 16}" width="100%" style="max-width:600px" role="img" aria-label="findings trend">
    <g transform="translate(0,14)">${axis}${lines}</g>${legend}</svg>`;
}

// ---------- report sections --------------------------------------------------

function gateExplainer(summary) {
  const t = summary.totals || {};
  const verdict = summary.verdict || (t.violations > 0 ? 'fail' : 'pass');
  const advisoryNote =
    verdict === 'advisory'
      ? `<p>⚠️ <b>Advisory mode</b> (<code>fail-on-findings: false</code>): with enforcement on, this run would have <b>FAILED</b>.</p>`
      : '';
  const baselineNote = summary.baseline_applied
    ? `<p>Baseline diff against <code>${esc(summary.baseline_branch)}</code> is active: ${t.new ?? '?'} of ${t.all ?? '?'} finding(s) are new; only new findings count toward the gate.</p>`
    : `<p>No baseline applied${summary.baseline_branch ? ` (no prior scan found for <code>${esc(summary.baseline_branch)}</code>)` : ''} — all findings counted.</p>`;
  const why =
    verdict === 'pass'
      ? `<p>No ${summary.baseline_applied ? 'new ' : ''}findings at or above the <code>${esc(summary.threshold)}</code> threshold.</p>`
      : `<p><b>${t.violations}</b> finding(s) at or above the <code>${esc(summary.threshold)}</code> threshold${verdict === 'fail' ? ' block this build' : ''}. They are tagged <span class="badge" style="background:#111827">gate</span> in the table below.</p>`;
  return `${why}${baselineNote}${advisoryNote}
    <p class="hint">Gate logic: findings are ranked critical &gt; high &gt; medium &gt; low; anything at or above the threshold fails the build unless advisory mode is on. Full policy: docs/gating-policy.md.</p>`;
}

function deltaPanel(delta) {
  if (!delta.hasBaseline) {
    return `<p class="empty">First scan with no usable baseline — every finding is treated as new. This run seeds the baseline for the next one.</p>`;
  }
  const card = (label, n, color, sub) =>
    `<div class="delta-card" style="border-color:${color}"><div class="delta-n" style="color:${color}">${n}</div><div>${label}</div><div class="hint">${sub}</div></div>`;
  const fixedList = delta.fixed.length
    ? `<details><summary>${delta.fixed.length} fixed finding(s)</summary><ul>${delta.fixed
        .slice(0, 25)
        .map((f) => `<li><code>${esc(f.ruleId)}</code> in <code>${esc(f.file)}</code> (${esc(f.severity)})</li>`)
        .join('')}${delta.fixed.length > 25 ? '<li>…</li>' : ''}</ul></details>`
    : '';
  return `<div class="delta-row">
    ${card('new in this run', delta.newOnes.length, delta.newOnes.length ? COLORS.critical : COLORS.ok, 'introduced since baseline — these gate')}
    ${card('fixed since baseline', delta.fixed.length, COLORS.ok, 'present in baseline, gone now 🎉')}
    ${card('persisting debt', delta.persisting.length, COLORS.muted, 'known findings, tracked not blocking')}
  </div>${fixedList}`;
}

function findingsTable(summary, ruleMeta, thresholdRank) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  const findings = flattenFindings(summary).sort(
    (a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0) || a.stage.localeCompare(b.stage)
  );
  if (findings.length === 0) {
    return `<p class="empty" style="color:${COLORS.ok}">✅ No findings anywhere. Clean scan.</p>`;
  }
  const stages = [...new Set(findings.map((f) => f.stage))].sort();
  const rows = findings.slice(0, MAX_TABLE_ROWS).map((f, i) => {
    const rule = ruleMeta[f.ruleId];
    const gates = f.new && (rank[f.severity] || 0) >= thresholdRank;
    const link = adviceLink(f, rule);
    const remediation = `
      ${rule?.fixedVersion ? `<p><b>Fixed version:</b> <code>${esc(rule.fixedVersion)}</code></p>` : ''}
      ${rule?.help ? `<pre class="help">${esc(rule.help)}</pre>` : ''}
      <p>${esc(STAGE_FALLBACK_ADVICE[f.stage] || STAGE_FALLBACK_ADVICE.sast)}</p>
      ${link ? `<p>📖 <a href="${esc(link)}" rel="noopener">Rule / advisory documentation</a></p>` : ''}`;
    return `<tr class="row" data-sev="${esc(f.severity)}" data-stage="${esc(f.stage)}" data-new="${f.new ? 1 : 0}"
        data-text="${esc(`${f.ruleId} ${f.file} ${f.message}`.toLowerCase())}" onclick="toggle(${i})">
      <td>${sevBadge(f.severity)}${f.new ? ' <span class="badge" style="background:#7c3aed">new</span>' : ''}${gates ? ' <span class="badge" style="background:#111827">gate</span>' : ''}</td>
      <td>${esc(f.stage)}</td><td><code>${esc(f.ruleId)}</code></td>
      <td><code>${esc(f.file)}${f.line ? `:${f.line}` : ''}</code></td>
      <td class="msg">${esc(f.message)}</td></tr>
    <tr id="exp-${i}" class="expand" hidden><td colspan="5">${remediation}</td></tr>`;
  });
  const overflow =
    findings.length > MAX_TABLE_ROWS
      ? `<p class="hint">Showing ${MAX_TABLE_ROWS} of ${findings.length} findings — the full set is in the Security tab and the sarif-* artifacts.</p>`
      : '';
  return `<div class="filters">
      <input id="q" type="search" placeholder="filter by rule, file, text…" oninput="applyFilters()">
      <select id="fsev" onchange="applyFilters()"><option value="">all severities</option>${SEVERITIES.map((s) => `<option>${s}</option>`).join('')}</select>
      <select id="fstage" onchange="applyFilters()"><option value="">all stages</option>${stages.map((s) => `<option>${esc(s)}</option>`).join('')}</select>
      <label><input id="fnew" type="checkbox" onchange="applyFilters()"> new only</label>
      <span id="count" class="hint"></span>
    </div>
    <table id="findings"><thead><tr><th>severity</th><th>stage</th><th>rule</th><th>location</th><th>message</th></tr></thead>
    <tbody>${rows.join('')}</tbody></table>${overflow}
    <p class="hint">Click a row for remediation guidance.</p>`;
}

const CLIENT_JS = `
function toggle(i){const r=document.getElementById('exp-'+i);if(r)r.hidden=!r.hidden}
function applyFilters(){
  const q=document.getElementById('q').value.toLowerCase();
  const sev=document.getElementById('fsev').value;
  const stage=document.getElementById('fstage').value;
  const onlyNew=document.getElementById('fnew').checked;
  let shown=0;
  document.querySelectorAll('tr.row').forEach(function(tr,i){
    const ok=(!sev||tr.dataset.sev===sev)&&(!stage||tr.dataset.stage===stage)
      &&(!onlyNew||tr.dataset.new==='1')&&(!q||tr.dataset.text.includes(q));
    tr.hidden=!ok;if(!ok){const e=document.getElementById('exp-'+i);if(e)e.hidden=true}
    if(ok)shown++;
  });
  document.getElementById('count').textContent=shown+' shown';
}`;

const CSS = `
:root{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827}
body{margin:0;background:#f9fafb}
.wrap{max-width:980px;margin:0 auto;padding:24px 20px 60px}
.banner{border-radius:10px;padding:18px 22px;color:#fff;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.banner h1{margin:0;font-size:22px}
.banner .meta{font-size:13px;opacity:.92}
section{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px 22px;margin-top:18px}
section h2{margin:0 0 10px;font-size:16px}
.charts{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.badge{color:#fff;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th{text-align:left;color:#6b7280;font-size:12px;border-bottom:2px solid #e5e7eb;padding:6px 8px}
td{border-bottom:1px solid #f3f4f6;padding:7px 8px;vertical-align:top}
tr.row{cursor:pointer}tr.row:hover{background:#f3f4f6}
tr.expand td{background:#f9fafb;border-left:3px solid #d1d5db}
.msg{max-width:330px}
code{background:#f3f4f6;border-radius:4px;padding:1px 5px;font-size:12px}
pre.help{white-space:pre-wrap;background:#f3f4f6;border-radius:6px;padding:10px;font-size:12px;max-height:220px;overflow:auto}
.filters{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:13px}
.filters input[type=search]{flex:1;min-width:180px;padding:6px 10px;border:1px solid #d1d5db;border-radius:6px}
.filters select{padding:6px;border:1px solid #d1d5db;border-radius:6px}
.delta-row{display:flex;gap:14px;flex-wrap:wrap}
.delta-card{flex:1;min-width:150px;border:2px solid;border-radius:10px;padding:12px 16px;text-align:center}
.delta-n{font-size:30px;font-weight:800}
.empty{color:#6b7280}
.hint{color:#6b7280;font-size:12px}
.legend{display:flex;gap:14px;font-size:13px;flex-wrap:wrap}
.legend span::before{content:'';display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;background:var(--c)}
footer{margin-top:22px;color:#6b7280;font-size:12px;text-align:center}`;

function render({ summary, ruleMeta, delta, trend, runUrl }) {
  const t = summary.totals || {};
  const verdict = summary.verdict || (t.violations > 0 ? 'fail' : 'pass');
  const banner = { pass: COLORS.ok, fail: COLORS.critical, advisory: COLORS.medium }[verdict] || COLORS.muted;
  const title = { pass: '✅ Security scan passed', fail: '❌ Security scan failed', advisory: '⚠️ Advisory: would fail with enforcement on' }[verdict];
  const thresholdRank = { critical: 4, high: 3, medium: 2, low: 1 }[summary.threshold] || 3;
  const legend = SEVERITIES.map((s) => `<span style="--c:${COLORS[s]}">${s}: <b>${t[s] || 0}</b></span>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security report — ${esc(verdict)}</title><style>${CSS}</style></head>
<body><div class="wrap">
  <div class="banner" style="background:${banner}">
    <h1>${title}</h1>
    <div class="meta">threshold <code style="background:rgba(255,255,255,.2);color:#fff">${esc(summary.threshold)}</code>
      · generated ${esc(summary.generated_at || '')}${runUrl ? ` · <a style="color:#fff" href="${esc(runUrl)}">run ↗</a>` : ''}</div>
  </div>
  <section><h2>Why the gate ${verdict === 'pass' ? 'passed' : verdict === 'fail' ? 'failed' : 'warned'}</h2>${gateExplainer(summary)}</section>
  <section><h2>Findings overview</h2>
    <div class="charts">${donutSvg(t)}<div><div class="legend">${legend}</div><br>${stageBarsSvg(summary.stages || {})}</div></div>
  </section>
  <section><h2>Change vs baseline${summary.baseline_branch ? ` (<code>${esc(summary.baseline_branch)}</code>)` : ''}</h2>${deltaPanel(delta)}</section>
  <section><h2>Trend — recent scans</h2>${trendSvg(trend)}</section>
  <section><h2>Findings &amp; remediation</h2>${findingsTable(summary, ruleMeta, thresholdRank)}</section>
  <footer>Generated by <a href="https://github.com/Just-In-N-Out/devsecops-pipeline">devsecops-pipeline</a> — self-contained report, works offline.</footer>
</div><script>${CLIENT_JS}</script></body></html>`;
}

// ---------- job summary (run page) -------------------------------------------

function renderJobSummary({ summary, delta, runUrl }) {
  const t = summary.totals || {};
  const verdict = summary.verdict || (t.violations > 0 ? 'fail' : 'pass');
  const icon = { pass: '✅', fail: '❌', advisory: '⚠️' }[verdict] || '❔';
  const lines = [
    `## ${icon} Security scan: ${verdict.toUpperCase()}`,
    '',
    `**${t.violations || 0}** gating finding(s) · threshold \`${summary.threshold}\`` +
      (summary.baseline_applied ? ` · baseline \`${summary.baseline_branch}\`` : ' · no baseline'),
    '',
    '| stage | critical | high | medium | low |',
    '| --- | ---: | ---: | ---: | ---: |',
  ];
  for (const [name, s] of Object.entries(summary.stages || {}).sort()) {
    lines.push(`| ${name} | ${s.critical} | ${s.high} | ${s.medium} | ${s.low} |`);
  }
  if (Object.keys(summary.stages || {}).length === 0) lines.push('| _clean — no findings_ | 0 | 0 | 0 | 0 |');
  if (delta.hasBaseline) {
    lines.push('', `**Δ vs baseline:** ${delta.newOnes.length} new · ${delta.fixed.length} fixed · ${delta.persisting.length} persisting`);
  }
  lines.push('', `📊 Full interactive report: download the **security-report** artifact${runUrl ? ` from [this run](${runUrl})` : ''}.`);
  return lines.join('\n') + '\n';
}

// ---------- main ---------------------------------------------------------------

function main() {
  const summaryPath = process.env.SUMMARY_PATH || 'scan-summary.json';
  const outputPath = process.env.OUTPUT_PATH || 'report.html';
  const summary = loadJson(summaryPath);
  if (!summary) {
    console.warn(`No scan summary at ${summaryPath} — skipping report generation.`);
    return;
  }
  const ruleMeta = collectRuleMeta(process.env.SARIF_DIR);
  const baseline = loadJson(process.env.BASELINE_SUMMARY_PATH);
  const trend = loadJson(process.env.TREND_PATH) || [];
  const delta = computeDelta(summary, baseline);
  const runUrl =
    process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
      ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
      : null;

  fs.writeFileSync(outputPath, render({ summary, ruleMeta, delta, trend, runUrl }));
  console.log(`Report written to ${outputPath} (${fs.statSync(outputPath).size} bytes)`);

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, renderJobSummary({ summary, delta, runUrl }));
    console.log('Job summary appended.');
  }
}

if (require.main === module) main();
module.exports = { render, renderJobSummary, computeDelta, collectRuleMeta };

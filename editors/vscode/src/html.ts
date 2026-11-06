// The report panel's HTML. Evidence strings come from the scanned site, so they
// are attacker-controlled: every interpolated value goes through esc(), and the
// CSP allows only this document's nonce for styles and scripts. No vscode import.
import { ConformanceRecord, passed, scoreText, verdictOf } from "./record";

export function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function csp(nonce: string): string {
  return ["default-src 'none'", `style-src 'nonce-${nonce}'`, `script-src 'nonce-${nonce}'`].join("; ");
}

const STYLE = `
:root { color-scheme: light dark; }
body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
  color: var(--vscode-foreground); background: var(--vscode-editor-background);
  margin: 0; padding: 20px 24px 40px; line-height: 1.5; }
h1 { font-size: 18px; margin: 0 0 4px; }
h2 { font-size: 14px; margin: 28px 0 8px; padding-bottom: 4px;
  border-bottom: 1px solid var(--vscode-panel-border); }
.meta { color: var(--vscode-descriptionForeground); margin: 0 0 12px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 4px; }
button { font: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
  border: 0; border-radius: 2px; padding: 4px 10px; cursor: pointer; }
button:hover { background: var(--vscode-button-hoverBackground); }
button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
.surface { border: 1px solid var(--vscode-panel-border); border-radius: 4px; padding: 14px 16px; margin: 16px 0; }
.verdict { display: inline-block; font-weight: 700; font-size: 12px; letter-spacing: .04em;
  padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; margin-right: 8px; }
.v-CONFORMANT { color: var(--vscode-testing-iconPassed); }
.v-NON-CONFORMANT { color: var(--vscode-testing-iconFailed); }
.v-UNSCANNABLE { color: var(--vscode-editorWarning-foreground); }
.warn { border-left: 3px solid var(--vscode-editorWarning-foreground); padding: 6px 10px; margin: 10px 0;
  background: var(--vscode-textBlockQuote-background); }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--vscode-panel-border); }
th { color: var(--vscode-descriptionForeground); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
col.c-sev { width: 88px; } col.c-rule { width: 96px; } col.c-act { width: 190px; }
td.rule { font-family: var(--vscode-editor-font-family); white-space: nowrap; font-weight: 600; }
.sev { font-size: 11px; font-weight: 700; }
.sev-CRITICAL, .sev-HIGH { color: var(--vscode-testing-iconFailed); }
.sev-MEDIUM { color: var(--vscode-editorWarning-foreground); }
.sev-LOW { color: var(--vscode-descriptionForeground); }
.ev { font-family: var(--vscode-editor-font-family); font-size: 12px; color: var(--vscode-descriptionForeground);
  overflow-wrap: anywhere; margin-top: 2px; }
td.act { white-space: nowrap; }
td.act button { margin: 0 4px 4px 0; padding: 2px 8px; }
details summary { cursor: pointer; color: var(--vscode-descriptionForeground); margin-top: 16px; }
`;

const SCRIPT = `
const vscode = acquireVsCodeApi();
document.addEventListener('click', (e) => {
  const b = e.target.closest('button[data-act]');
  if (!b) return;
  vscode.postMessage({ act: b.dataset.act, surface: Number(b.dataset.surface || 0), rule: b.dataset.rule || '' });
});
`;

function actions(i: number, rule: string, copy: boolean): string {
  const r = esc(rule);
  return (copy ? `<button data-act="copyFix" data-surface="${i}" data-rule="${r}">Copy fix prompt</button>` : "")
    + `<button class="secondary" data-act="showRule" data-rule="${r}">Rule text</button>`;
}

function surfaceHtml(r: ConformanceRecord, i: number): string {
  const v = verdictOf(r);
  const parts: string[] = [];
  parts.push(`<section class="surface"><h1><span class="verdict v-${esc(v)}">${esc(v)}</span>${esc(r.surface)}</h1>`);
  parts.push(`<p class="meta">${esc(r.standard)} ${esc(r.version)} · ${esc(r.profile)}/${esc(r.level)} · score ${esc(scoreText(r))}`
    + (r.generated_at ? ` · ${esc(r.generated_at)}` : "") + `</p>`);
  if (r.unscannable) {
    parts.push(`<div class="warn">The surface could not be fetched: ${esc(r.unreachable_reason ?? "")}. No verdict and no score.</div></section>`);
    return parts.join("");
  }
  if (r.environment?.degraded) {
    parts.push(`<div class="warn">Degraded environment, the score is not reliable: ${esc(r.environment.reason ?? "")}</div>`);
  }
  for (const v of r.governance_violations ?? []) parts.push(`<div class="warn">Governance violation: ${esc(v)}</div>`);

  const fq = r.fix_queue ?? [];
  parts.push(`<h2>Fix queue (${fq.length})</h2>`);
  if (fq.length) {
    parts.push(`<table><colgroup><col class="c-sev"><col class="c-rule"><col><col class="c-act"></colgroup>`
      + `<thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th></th></tr></thead><tbody>`);
    for (const f of fq) {
      parts.push(`<tr><td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>`
        + `<td class="rule">${esc(f.rule)}</td><td>${esc(f.title)}`
        + (f.observed ? `<div class="ev">observed: ${esc(f.observed)}</div>` : "")
        + (f.expected ? `<div class="ev">expected: ${esc(f.expected)}</div>` : "")
        + `</td><td class="act">${actions(i, f.rule, true)}</td></tr>`);
    }
    parts.push(`</tbody></table>`);
  } else {
    parts.push(`<p class="meta">Nothing to fix.</p>`);
  }

  const un = r.unassessed ?? [];
  parts.push(`<h2>Could not assess (${un.length})</h2>`);
  if (un.length) {
    parts.push(`<table><colgroup><col class="c-sev"><col class="c-rule"><col><col class="c-act"></colgroup>`
      + `<thead><tr><th>Severity</th><th>Rule</th><th>Reason</th><th></th></tr></thead><tbody>`);
    for (const u of un) {
      parts.push(`<tr><td><span class="sev sev-${esc(u.severity)}">${esc(u.severity)}</span></td>`
        + `<td class="rule">${esc(u.rule)}</td><td>${esc(u.title)}`
        + (u.reason ? `<div class="ev">${esc(u.reason)}</div>` : "")
        + `</td><td class="act">${actions(i, u.rule, true)}</td></tr>`);
    }
    parts.push(`</tbody></table>`);
  } else {
    parts.push(`<p class="meta">Every rule in scope was checked.</p>`);
  }

  const ok = passed(r);
  parts.push(`<details><summary>Passed (${ok.length})</summary><table><colgroup><col class="c-rule"><col><col class="c-act"></colgroup><tbody>`);
  for (const p of ok) {
    parts.push(`<tr><td class="rule">${esc(p.rule)}</td><td>${esc(p.title)}</td><td class="act">${actions(i, p.rule, false)}</td></tr>`);
  }
  parts.push(`</tbody></table></details></section>`);
  return parts.join("");
}

export function renderReport(records: ConformanceRecord[], nonce: string): string {
  const body = records.map(surfaceHtml).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp(nonce)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agssh report</title><style nonce="${nonce}">${STYLE}</style></head><body>
<div class="toolbar"><button data-act="copyReport">Copy fix prompt for the whole report</button>
<button class="secondary" data-act="rescan">Rescan</button></div>
${body}
<script nonce="${nonce}">${SCRIPT}</script></body></html>`;
}

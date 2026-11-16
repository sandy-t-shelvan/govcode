'use strict';
// Pure helpers (no vscode dependency) so they can be unit-tested.

const crypto = require('crypto');

// Proposal IDs come from govcode; they are interpolated into a terminal
// command line, so accept only the exact shape govcode generates.
const PROPOSAL_ID = /^p\d{8}-\d{6}-[0-9a-f]{6}$/;
function isProposalId(s) { return typeof s === 'string' && PROPOSAL_ID.test(s); }

// Quote one argument for a POSIX shell.
function shQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

function approveCommand(binary, id) {
  if (!isProposalId(id)) throw new Error('refusing to build an approve command for invalid id ' + JSON.stringify(id));
  return shQuote(binary) + ' approve ' + id;
}

function nonce() { return crypto.randomBytes(18).toString('base64'); }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Banner colours per the classification level at the start of the marking.
function bannerColor(classification) {
  const c = String(classification || '').toUpperCase();
  if (c.startsWith('TOP SECRET')) return { bg: '#FF8C00', fg: '#000000', level: 'TOP SECRET' };
  if (c.startsWith('SECRET')) return { bg: '#C8102E', fg: '#FFFFFF', level: 'SECRET' };
  if (c.startsWith('CONFIDENTIAL')) return { bg: '#0033A0', fg: '#FFFFFF', level: 'CONFIDENTIAL' };
  if (c.startsWith('UNCLASSIFIED')) return { bg: '#007A33', fg: '#FFFFFF', level: 'UNCLASSIFIED' };
  return { bg: '#555555', fg: '#FFFFFF', level: 'UNKNOWN' };
}

// Webview HTML with a strict Content-Security-Policy: no network, no
// inline script except the nonce'd one, styles only from the extension.
function panelHtml({ cspSource, scriptUri, styleUri, classification }) {
  const n = nonce();
  const b = bannerColor(classification);
  const csp = [
    "default-src 'none'",
    `style-src ${cspSource}`,
    `script-src 'nonce-${n}'`,
    "img-src 'none'", "connect-src 'none'", "font-src 'none'", "frame-src 'none'", "form-action 'none'",
  ].join('; ');
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${styleUri}">
<title>govcode</title></head>
<body>
<div class="banner" style="background:${b.bg};color:${b.fg}">${escapeHtml(classification || 'NOT INITIALIZED')}</div>
<div id="log" role="log" aria-live="polite"></div>
<form id="task">
  <textarea id="text" rows="3" placeholder="Describe the change (e.g. fix the off-by-one in SUM-AMOUNTS)"></textarea>
  <div class="row"><label><input type="checkbox" id="plan"> Plan first</label>
  <button type="submit" id="go">Run</button><button type="button" id="cancel">Cancel</button></div>
</form>
<div class="banner" style="background:${b.bg};color:${b.fg}">${escapeHtml(classification || 'NOT INITIALIZED')}</div>
<script nonce="${n}" src="${scriptUri}"></script>
</body></html>`;
}

// Short human summary of a tool event for the activity log.
function describeEvent(ev) {
  const d = (ev && ev.data) || {};
  switch (ev && ev.kind) {
    case 'log': return String(ev.text || '').trimEnd();
    case 'token': return String(ev.text || '').trimEnd();
    case 'edit': return `edited ${d.path}`;
    case 'test': return `tests ${d.exit_code === 0 ? 'PASSED' : 'FAILED'} (exit ${d.exit_code})`;
    case 'command': return `ran: ${d.result && d.result.command} (exit ${d.result && d.result.exit_code})`;
    case 'permission': return `permission ${d.decision}: ${d.tool}(${d.subject}) [${d.rule}]`;
    case 'spillage_blocked': return `SPILLAGE GUARD: ${d.level} content withheld (${d.where})`;
    case 'hook': return `site check ${d.passed ? 'passed' : 'FAILED'}: ${d.command}`;
    case 'plan': return 'plan updated';
    case 'memory_loaded': return `loaded conventions ${d.path}`;
    default: return ev && ev.kind ? ev.kind : '';
  }
}

module.exports = { isProposalId, shQuote, approveCommand, nonce, escapeHtml, bannerColor, panelHtml, describeEvent };

'use strict';
// govcode VS Code extension: a thin UI over `govcode serve --stdio`.
// All policy, sandboxing, signing and audit live in the signed govcode
// binary. This extension holds no trust: it cannot approve changes (that
// is a typed confirmation in a terminal) and it opens no network
// connections.

const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const { RpcClient } = require('./lib/rpc');
const util = require('./lib/util');

let server = null; // { proc, rpc, info }
let panel = null;
let output = null;
let statusItem = null;
let proposalsView = null;

function cfg() {
  const c = vscode.workspace.getConfiguration('govcode');
  return { binary: c.get('binaryPath') || 'govcode', policy: c.get('policyPath') || '' };
}

function workspaceRoot() {
  const f = vscode.workspace.workspaceFolders;
  return f && f.length ? f[0].uri.fsPath : undefined;
}

function childEnv() {
  const env = Object.assign({}, process.env);
  const { policy } = cfg();
  if (policy) env.GOVCODE_POLICY = policy;
  return env;
}

async function ensureServer() {
  if (server) return server;
  const { binary } = cfg();
  const cwd = workspaceRoot();
  if (!cwd) throw new Error('Open the repository folder first.');
  const proc = cp.spawn(binary, ['serve', '--stdio'], { cwd, env: childEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
  const rpc = new RpcClient(proc.stdout, proc.stdin);
  proc.stderr.on('data', (d) => output.append(String(d)));
  proc.on('exit', (code) => {
    output.appendLine(`govcode server exited (${code})`);
    server = null;
    setStatus(null);
  });
  rpc.onRequest('permission.request', async ({ action }) => {
    const pick = await vscode.window.showWarningMessage(
      `govcode policy requires your approval for:\n\n${action}`, { modal: true }, 'Allow', 'Deny');
    return { allow: pick === 'Allow' };
  });
  rpc.onRequest('plan.review', async ({ steps, summary }) => {
    const lines = (steps || []).map((s, i) => `${i + 1}. ${s}`).join('\n');
    const pick = await vscode.window.showInformationMessage(
      `Proposed plan: ${summary}\n\n${lines}`, { modal: true }, 'Approve', 'Reject');
    if (pick === 'Approve') return { approved: true, feedback: '' };
    const fb = await vscode.window.showInputBox({ prompt: 'What should change in the plan?' });
    return { approved: false, feedback: fb || 'rejected without comment' };
  });
  rpc.on('event', (ev) => {
    const line = util.describeEvent(ev);
    if (!line) return;
    const cls = ev.kind === 'log' || ev.kind === 'token' ? 'info' : ev.kind === 'spillage_blocked' ? 'warn' : 'tool';
    post({ type: 'line', cls, text: line });
  });
  rpc.on('run.finished', (r) => {
    const p = r && r.proposal;
    if (p) {
      const blocked = (p.blocked || []).map((b) => '\n  BLOCKED: ' + b).join('');
      post({ type: 'done', ok: p.status === 'ready', text: `Proposal ${p.id}: ${p.status}${blocked}` });
    } else {
      post({ type: 'done', ok: false, text: 'Run ended: ' + ((r && r.error) || 'no changes') });
    }
    if (proposalsView) proposalsView.refresh();
  });
  server = { proc, rpc, info: null };
  const info = await rpc.request('initialize');
  server.info = info;
  setStatus(info);
  if (!info.ready) {
    const failed = (info.checks || []).filter((c) => c.Status === 'FAIL').map((c) => `${c.Name}: ${c.Detail}`);
    output.appendLine('govcode preflight failed:\n  ' + failed.join('\n  '));
    output.show(true);
    throw new Error('govcode preflight failed: ' + (info.error || failed[0] || 'unknown'));
  }
  return server;
}

function setStatus(info) {
  if (!statusItem) return;
  if (!info || !info.ready) {
    statusItem.text = '$(shield) govcode: not ready';
    statusItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else {
    statusItem.text = `$(shield) ${info.classification}`;
    statusItem.tooltip = `govcode ${info.version} — ${info.user}\n${info.repo}\ntwo-person rule: ${info.two_person_rule}`;
    statusItem.backgroundColor = info.classification.startsWith('UNCLASSIFIED') ? undefined : new vscode.ThemeColor('statusBarItem.warningBackground');
  }
  statusItem.show();
}

function post(msg) { if (panel) panel.webview.postMessage(msg); }

async function showPanel(context) {
  if (panel) { panel.reveal(); return panel; }
  panel = vscode.window.createWebviewPanel('govcode.chat', 'govcode', vscode.ViewColumn.Beside, {
    enableScripts: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, 'media'))],
    retainContextWhenHidden: true,
  });
  const media = (f) => panel.webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, 'media', f)));
  let classification = '';
  try { classification = (await ensureServer()).info.classification; } catch (e) { vscode.window.showErrorMessage(e.message); }
  panel.webview.html = util.panelHtml({ cspSource: panel.webview.cspSource, scriptUri: media('panel.js'), styleUri: media('panel.css'), classification });
  panel.webview.onDidReceiveMessage(async (m) => {
    try {
      const s = await ensureServer();
      if (m.type === 'run') {
        s.rpc.request('run', { task: String(m.task), plan: !!m.plan }).catch((e) => post({ type: 'done', ok: false, text: e.message }));
      } else if (m.type === 'cancel') {
        await s.rpc.request('cancel');
      }
    } catch (e) {
      post({ type: 'done', ok: false, text: e.message });
    }
  });
  panel.onDidDispose(() => { panel = null; });
  return panel;
}

// ---- proposals tree and diff review ----

class ProposalsProvider {
  constructor() { this._emitter = new vscode.EventEmitter(); this.onDidChangeTreeData = this._emitter.event; this.details = new Map(); }
  refresh() { this.details.clear(); this._emitter.fire(); }
  getTreeItem(el) { return el; }
  async getChildren(el) {
    let s;
    try { s = await ensureServer(); } catch (e) { return [new vscode.TreeItem(e.message)]; }
    if (!el) {
      const list = await s.rpc.request('proposals.list');
      return list.map((p) => {
        const it = new vscode.TreeItem(`${p.id} [${p.status}]`, vscode.TreeItemCollapsibleState.Collapsed);
        it.description = `${p.proposer}: ${p.task.slice(0, 60)}`;
        it.tooltip = p.task;
        it.contextValue = 'proposal.' + p.status;
        it.proposalId = p.id;
        return it;
      });
    }
    if (el.proposalId && !el.file) {
      const d = await s.rpc.request('proposals.get', { id: el.proposalId });
      this.details.set(el.proposalId, d);
      const items = [];
      const integ = new vscode.TreeItem('integrity: ' + d.integrity);
      items.push(integ);
      for (const b of d.proposal.blocked || []) items.push(new vscode.TreeItem('BLOCKED: ' + b));
      for (const f of d.proposal.files || []) {
        const it = new vscode.TreeItem(f);
        it.file = f;
        it.proposalId = el.proposalId;
        it.command = { command: 'govcode.openDiff', title: 'Open diff', arguments: [el.proposalId, f] };
        items.push(it);
      }
      return items;
    }
    return [];
  }
}

// Read-only content provider: govcode-rev:/<path>?<commit>
class RevisionProvider {
  provideTextDocumentContent(uri) {
    const rev = uri.query;
    if (!/^[0-9a-f]{40}$/.test(rev)) return '';
    const rel = uri.path.replace(/^\//, '');
    return new Promise((resolve) => {
      cp.execFile('git', ['-C', workspaceRoot(), 'show', `${rev}:${rel}`], { maxBuffer: 64 << 20 }, (err, out) => resolve(err ? '' : out));
    });
  }
}

async function openDiff(id, file) {
  const d = proposalsView.details.get(id) || (await (await ensureServer()).rpc.request('proposals.get', { id }));
  const p = d.proposal;
  const left = vscode.Uri.from({ scheme: 'govcode-rev', path: '/' + file, query: p.base });
  const right = vscode.Uri.from({ scheme: 'govcode-rev', path: '/' + file, query: p.head });
  await vscode.commands.executeCommand('vscode.diff', left, right, `${file} (${id})`, { preview: true });
}

function pickId(arg) {
  if (arg && arg.proposalId) return arg.proposalId;
  if (typeof arg === 'string') return arg;
  return vscode.window.showInputBox({ prompt: 'Proposal id', validateInput: (v) => (util.isProposalId(v) ? null : 'not a govcode proposal id') });
}

async function approve(arg) {
  const id = await pickId(arg);
  if (!id) return;
  // Approval runs in a real terminal: govcode requires the reviewer to type
  // "approve" on the TTY, and enforces the two-person rule and integrity
  // checks itself. The extension only opens the terminal.
  const term = vscode.window.createTerminal({ name: `govcode approve ${id}`, cwd: workspaceRoot(), env: cfg().policy ? { GOVCODE_POLICY: cfg().policy } : undefined });
  term.show();
  term.sendText(util.approveCommand(cfg().binary, id), true);
}

async function reject(arg) {
  const id = await pickId(arg);
  if (!id) return;
  const reason = await vscode.window.showInputBox({ prompt: `Reason for rejecting ${id}`, validateInput: (v) => (v.trim() ? null : 'a reason is required') });
  if (!reason) return;
  try {
    await (await ensureServer()).rpc.request('proposals.reject', { id, reason });
    vscode.window.showInformationMessage(`Rejected ${id}`);
    proposalsView.refresh();
  } catch (e) { vscode.window.showErrorMessage(e.message); }
}

async function verifyAudit() {
  try {
    const r = await (await ensureServer()).rpc.request('audit.verify');
    output.appendLine(`audit verify: ${r.ok ? 'OK' : 'FAILED'} — ${r.entries} entries, ${r.anchors} anchors, head ${r.head}`);
    for (const p of r.problems || []) output.appendLine('  FAIL ' + p);
    output.show(true);
    (r.ok ? vscode.window.showInformationMessage : vscode.window.showErrorMessage)(`govcode audit log ${r.ok ? 'verified' : 'verification FAILED'}`);
  } catch (e) { vscode.window.showErrorMessage(e.message); }
}

function activate(context) {
  output = vscode.window.createOutputChannel('govcode');
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 1000);
  statusItem.command = 'govcode.showPanel';
  proposalsView = new ProposalsProvider();
  context.subscriptions.push(
    output, statusItem,
    vscode.window.registerTreeDataProvider('govcode.proposals', proposalsView),
    vscode.workspace.registerTextDocumentContentProvider('govcode-rev', new RevisionProvider()),
    vscode.commands.registerCommand('govcode.showPanel', () => showPanel(context)),
    vscode.commands.registerCommand('govcode.refreshProposals', () => proposalsView.refresh()),
    vscode.commands.registerCommand('govcode.openDiff', openDiff),
    vscode.commands.registerCommand('govcode.approve', approve),
    vscode.commands.registerCommand('govcode.reject', reject),
    vscode.commands.registerCommand('govcode.verifyAudit', verifyAudit),
    vscode.commands.registerCommand('govcode.restartServer', () => { if (server) server.proc.kill(); server = null; return ensureServer(); }),
  );
  setStatus(null);
}

function deactivate() { if (server) server.proc.kill(); }

module.exports = { activate, deactivate, _internal: { ProposalsProvider, RevisionProvider, approve, ensureServer } };

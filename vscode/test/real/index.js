'use strict';
// Runs INSIDE a real VS Code extension host (scripts/e2e/vscode-real.sh),
// not under node --test: it uses the real `vscode` API, the real
// `govcode serve --stdio` and a replayed model on 127.0.0.1.
const vscode = require('vscode');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const results = [];
async function step(name, fn) {
  try { await fn(); results.push(`PASS  ${name}`); } catch (e) { results.push(`FAIL  ${name}: ${e && e.stack || e}`); throw e; }
}

async function run() {
  const out = process.env.GOVCODE_VSC_RESULT;
  try {
    await main();
  } finally {
    if (out) fs.writeFileSync(out, results.join('\n') + '\n');
  }
}

async function main() {
  const ext = vscode.extensions.getExtension('govcode-local.govcode');
  await step('extension is present and activates', async () => {
    assert.ok(ext, 'extension govcode-local.govcode not found');
    await ext.activate();
    assert.ok(ext.isActive);
  });
  const internal = require(path.join(ext.extensionPath, 'extension.js'))._internal;

  await step('all commands are registered', async () => {
    const cmds = new Set(await vscode.commands.getCommands(true));
    for (const c of ['govcode.showPanel', 'govcode.refreshProposals', 'govcode.openDiff', 'govcode.approve',
      'govcode.reject', 'govcode.verifyAudit', 'govcode.restartServer']) assert.ok(cmds.has(c), c);
  });

  let s;
  await step('govcode serve --stdio starts and preflight passes', async () => {
    s = await internal.ensureServer();
    assert.ok(s.info.ready, JSON.stringify(s.info.checks));
    assert.match(s.info.classification, /^UNCLASSIFIED/);
  });

  let id;
  await step('a run produces a ready proposal', async () => {
    const done = new Promise((resolve) => s.rpc.once('run.finished', resolve));
    s.rpc.request('run', { task: 'track_init overruns the callsign buffer for long callsigns; truncate and NUL-terminate.', plan: false });
    const r = await Promise.race([done, new Promise((_, rej) => setTimeout(() => rej(new Error('run timed out')), 120000))]);
    assert.ok(r && r.proposal, JSON.stringify(r));
    assert.strictEqual(r.proposal.status, 'ready', JSON.stringify(r.proposal));
    id = r.proposal.id;
  });

  let file;
  await step('proposals tree lists it; expanding shows integrity ok and the file', async () => {
    const pv = new internal.ProposalsProvider();
    const roots = await pv.getChildren();
    const item = roots.find((x) => x.proposalId === id);
    assert.ok(item, roots.map((x) => x.label).join(', '));
    assert.strictEqual(item.contextValue, 'proposal.ready');
    const kids = await pv.getChildren(item);
    assert.ok(kids.some((k) => k.label === 'integrity: ok'), kids.map((k) => k.label).join(', '));
    const f = kids.find((k) => k.file);
    assert.ok(f, 'no file item');
    file = f.file;
    assert.strictEqual(file, 'track.c');
    assert.strictEqual(f.command.command, 'govcode.openDiff');
  });

  await step('openDiff shows base and head through the govcode-rev provider', async () => {
    await vscode.commands.executeCommand('govcode.openDiff', id, file);
    const tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    assert.ok(tab && tab.input instanceof vscode.TabInputTextDiff, 'active tab is not a diff');
    const left = await vscode.workspace.openTextDocument(tab.input.original);
    const right = await vscode.workspace.openTextDocument(tab.input.modified);
    assert.strictEqual(tab.input.original.scheme, 'govcode-rev');
    assert.match(left.getText(), /strcpy\(t->callsign, callsign\);/);
    assert.match(right.getText(), /strncpy\(t->callsign, callsign, CALLSIGN_LEN - 1\);/);
  });

  await step('showPanel opens the agent webview', async () => {
    await vscode.commands.executeCommand('govcode.showPanel');
    // The webview tab is registered asynchronously after createWebviewPanel.
    let tabs = [];
    for (let i = 0; i < 50; i++) {
      tabs = vscode.window.tabGroups.all.flatMap((g) => g.tabs);
      if (tabs.some((t) => t.input instanceof vscode.TabInputWebview)) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const describe = tabs.map((t) => `${t.label} <${t.input && t.input.constructor && t.input.constructor.name}${t.input && t.input.viewType ? ' ' + t.input.viewType : ''}>`).join(', ');
    const web = tabs.find((t) => t.input instanceof vscode.TabInputWebview);
    assert.ok(web, 'no webview tab: ' + describe);
    assert.match(web.input.viewType, /govcode\.chat$/, describe);
    assert.strictEqual(web.label, 'govcode', describe);
  });

  await step('audit log verifies', async () => {
    const v = await s.rpc.request('audit.verify');
    assert.strictEqual(v.ok, true, JSON.stringify(v));
  });

  await step('the extension cannot approve: approve is not an RPC method', async () => {
    await assert.rejects(s.rpc.request('approve', { id }), (e) => e.code === -32601);
  });

  await step('reject through the server', async () => {
    await s.rpc.request('proposals.reject', { id, reason: 'real VS Code e2e' });
    const list = await s.rpc.request('proposals.list');
    assert.strictEqual(list.find((p) => p.id === id).status, 'rejected');
  });
}

module.exports = { run };

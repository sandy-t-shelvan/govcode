'use strict';
const test = require('node:test');
const assert = require('node:assert');
const u = require('../lib/util');

test('proposal ids are strictly validated', () => {
  assert.ok(u.isProposalId('p20261116-213850-49efe0'));
  for (const bad of ['', 'p1', 'p20261116-213850-49efe0; rm -rf ~', 'p20261116-213850-49EFE0', '$(id)', 'p20261116-213850-49efe0\n', null]) {
    assert.ok(!u.isProposalId(bad), JSON.stringify(bad));
  }
});

test('approve command quotes the binary and refuses injected ids', () => {
  assert.strictEqual(u.approveCommand("/opt/gov code/govcode", 'p20261116-213850-49efe0'), "'/opt/gov code/govcode' approve p20261116-213850-49efe0");
  assert.strictEqual(u.shQuote("a'b"), "'a'\\''b'");
  assert.throws(() => u.approveCommand('govcode', 'p20261116-213850-49efe0 && curl x'));
});

test('webview HTML has a locked-down CSP and escapes the banner', () => {
  const html = u.panelHtml({ cspSource: 'vscode-resource:', scriptUri: 'vscode-resource:/p.js', styleUri: 'vscode-resource:/p.css', classification: 'SECRET//<b>NOFORN</b>' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /script-src 'nonce-[A-Za-z0-9+/=]+'/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.doesNotMatch(html, /<b>NOFORN/);
  assert.match(html, /SECRET\/\/&lt;b&gt;NOFORN/);
  assert.strictEqual((html.match(/class="banner"/g) || []).length, 2, 'banner top and bottom');
});

test('banner colours follow the level', () => {
  assert.strictEqual(u.bannerColor('TOP SECRET//SCI').level, 'TOP SECRET');
  assert.strictEqual(u.bannerColor('SECRET//NOFORN').bg, '#C8102E');
  assert.strictEqual(u.bannerColor('UNCLASSIFIED//FOUO').level, 'UNCLASSIFIED');
});

test('events are summarised', () => {
  assert.match(u.describeEvent({ kind: 'spillage_blocked', data: { level: 'TOP SECRET', where: 'read_file x' } }), /SPILLAGE GUARD: TOP SECRET/);
  assert.match(u.describeEvent({ kind: 'permission', data: { decision: 'deny', tool: 'run_command', subject: 'curl', rule: 'default' } }), /permission deny/);
  assert.strictEqual(u.describeEvent({ kind: 'log', text: 'hi\n' }), 'hi');
});

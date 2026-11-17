'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');
const path = require('path');
const mock = require('./mock-vscode');

const orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  if (req === 'vscode') return path.join(__dirname, 'mock-vscode.js');
  return orig.call(this, req, ...rest);
};
const ext = require('../extension');
const pkg = require('../package.json');

test('activate registers every contributed command', () => {
  ext.activate({ subscriptions: [], extensionPath: path.join(__dirname, '..') });
  for (const c of pkg.contributes.commands) assert.ok(mock._registered.has(c.command), c.command);
});

test('approve opens a terminal with the quoted binary and validated id', async () => {
  await mock._registered.get('govcode.approve')('p20261116-213850-49efe0');
  const t = mock._terminals.at(-1);
  assert.deepStrictEqual(t.sent, ["'/opt/govcode/bin/govcode' approve p20261116-213850-49efe0"]);
});

test('approve with a crafted id never reaches the terminal', async () => {
  const before = mock._terminals.length;
  await assert.rejects(mock._registered.get('govcode.approve')('p20261116-213850-49efe0; curl evil'));
  assert.strictEqual(mock._terminals.length, before + 1);
  assert.deepStrictEqual(mock._terminals.at(-1).sent, [], 'nothing typed into the terminal');
});

test('workspace trust is required and the extension runs only locally', () => {
  assert.strictEqual(pkg.capabilities.untrustedWorkspaces.supported, false);
  assert.deepStrictEqual(pkg.extensionKind, ['workspace']);
  assert.strictEqual(pkg.dependencies, undefined, 'no npm dependencies');
  assert.strictEqual(pkg.devDependencies, undefined, 'no npm devDependencies');
});

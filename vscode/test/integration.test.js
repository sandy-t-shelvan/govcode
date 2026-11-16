'use strict';
// End-to-end against the real binary: set GOVCODE_BIN to run it (CI does).
const test = require('node:test');
const assert = require('node:assert');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { RpcClient } = require('../lib/rpc');

const BIN = process.env.GOVCODE_BIN;

test('real govcode serve --stdio: initialize and list', { skip: !BIN && 'set GOVCODE_BIN' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'govcode-vsc-'));
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(repo);
  fs.writeFileSync(path.join(repo, 'a.c'), 'int a;\n');
  const git = (...a) => cp.execFileSync('git', ['-C', repo, ...a]);
  git('init', '-q', '-b', 'main'); git('add', '-A'); git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base');
  const env = Object.assign({}, process.env, { GOVCODE_KEY: path.join(dir, 'k.key') });
  const policy = path.join(dir, 'policy.json');
  cp.execFileSync(BIN, ['init', '-o', policy], { cwd: repo, env });
  env.GOVCODE_POLICY = policy;
  cp.execFileSync(BIN, ['keygen', '--register', '-o', env.GOVCODE_KEY], { cwd: repo, env });
  const proc = cp.spawn(BIN, ['serve', '--stdio'], { cwd: repo, env });
  const rpc = new RpcClient(proc.stdout, proc.stdin);
  try {
    const info = await rpc.request('initialize');
    assert.ok(info.ready, JSON.stringify(info.checks));
    assert.match(info.classification, /^UNCLASSIFIED/);
    assert.deepStrictEqual(await rpc.request('proposals.list'), []);
    const v = await rpc.request('audit.verify');
    assert.strictEqual(v.ok, true);
    await assert.rejects(rpc.request('approve', { id: 'p20261116-213850-49efe0' }), (e) => e.code === -32601);
  } finally {
    proc.kill();
  }
});

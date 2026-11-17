'use strict';
// The extension must never open network connections or load remote code.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const sources = ['extension.js', ...fs.readdirSync(path.join(root, 'lib')).map((f) => 'lib/' + f), 'media/panel.js', 'media/panel.css'];

test('no network modules, fetch, or remote URLs', () => {
  for (const f of sources) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    for (const mod of ['http', 'https', 'net', 'tls', 'dgram', 'http2', 'dns']) {
      assert.ok(!new RegExp(`require\\(['"](node:)?${mod}['"]\\)`).test(src), `${f} requires ${mod}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(src), `${f} calls fetch`);
    assert.ok(!/\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b/.test(src), `${f} uses a network API`);
    assert.ok(!/https?:\/\/(?!www\.w3\.org\/2000\/svg)/.test(src), `${f} contains a remote URL`);
  }
});

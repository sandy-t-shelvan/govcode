'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { PassThrough } = require('stream');
const { RpcClient } = require('../lib/rpc');

// Wire a client to a scripted fake server.
function pair(serverFn) {
  const toServer = new PassThrough();
  const toClient = new PassThrough();
  const client = new RpcClient(toClient, toServer);
  let buf = '';
  toServer.setEncoding('utf8');
  toServer.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      serverFn(JSON.parse(line), (m) => toClient.write(JSON.stringify(Object.assign({ jsonrpc: '2.0' }, m)) + '\n'), toClient);
    }
  });
  return { client, toClient };
}

test('request/response and errors', async () => {
  const { client } = pair((m, send) => {
    if (m.method === 'ok') send({ id: m.id, result: { v: m.params.x * 2 } });
    else send({ id: m.id, error: { code: -32601, message: 'unknown method' } });
  });
  assert.deepStrictEqual(await client.request('ok', { x: 21 }), { v: 42 });
  await assert.rejects(client.request('nope'), (e) => e.code === -32601);
});

test('notifications and server->client requests', async () => {
  const answers = [];
  const { client } = pair((m, send) => {
    if (m.method === 'run') {
      send({ method: 'event', params: { kind: 'log', text: 'working' } });
      send({ id: 's-1', method: 'permission.request', params: { action: 'run_command(gcc)' } });
    } else if (m.id === 's-1') {
      answers.push(m.result);
      send({ id: 1, result: { done: true } });
    }
  });
  const events = [];
  client.on('event', (e) => events.push(e));
  client.onRequest('permission.request', async ({ action }) => ({ allow: action.includes('gcc') }));
  assert.deepStrictEqual(await client.request('run', { task: 't' }), { done: true });
  assert.deepStrictEqual(events, [{ kind: 'log', text: 'working' }]);
  assert.deepStrictEqual(answers, [{ allow: true }]);
});

test('unknown server request gets an error, garbage is reported, close rejects pending', async () => {
  const replies = [];
  const { client, toClient } = pair((m) => replies.push(m));
  const bad = [];
  client.on('protocolError', (l) => bad.push(l));
  toClient.write('{"jsonrpc":"2.0","id":"s-9","method":"plan.review","params":{}}\n');
  toClient.write('not json\nnull\n');
  await new Promise((r) => setTimeout(r, 20));
  assert.strictEqual(replies[0].error.code, -32601);
  assert.strictEqual(bad.length, 2);
  const p = client.request('hang');
  toClient.end();
  await assert.rejects(p, /closed/);
});

test('split and merged chunks are reassembled', async () => {
  const { client, toClient } = pair(() => {});
  const got = [];
  client.on('event', (e) => got.push(e.n));
  toClient.write('{"jsonrpc":"2.0","method":"event","params":{"n":1}}\n{"jsonrpc":"2.0","met');
  toClient.write('hod":"event","params":{"n":2}}\n');
  await new Promise((r) => setTimeout(r, 20));
  assert.deepStrictEqual(got, [1, 2]);
});

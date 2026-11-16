'use strict';
// JSON-RPC 2.0 client for `govcode serve --stdio`, newline-delimited.
// Transport-agnostic: give it a readable and a writable stream. No
// network: the extension only ever talks to a child process's pipes.

const { EventEmitter } = require('events');

class RpcClient extends EventEmitter {
  constructor(readable, writable) {
    super();
    this.w = writable;
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = new Map();
    this.buf = '';
    readable.setEncoding && readable.setEncoding('utf8');
    readable.on('data', (chunk) => this._onData(chunk));
    readable.on('end', () => this._fail(new Error('govcode server closed')));
  }

  // onRequest registers a handler for server->client requests
  // (permission.request, plan.review). It may return a value or a Promise.
  onRequest(method, fn) { this.handlers.set(method, fn); }

  request(method, params) {
    const id = this.nextId++;
    const msg = { jsonrpc: '2.0', id, method };
    if (params !== undefined) msg.params = params;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this._write(msg);
    });
  }

  _write(msg) { this.w.write(JSON.stringify(msg) + '\n'); }

  _onData(chunk) {
    this.buf += chunk;
    let i;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (line) this._onLine(line);
    }
  }

  _onLine(line) {
    let m;
    try { m = JSON.parse(line); } catch (e) { this.emit('protocolError', line); return; }
    if (m === null || typeof m !== 'object') { this.emit('protocolError', line); return; }
    if (m.method && m.id !== undefined) { this._serveRequest(m); return; }
    if (m.method) { this.emit('notification', m.method, m.params); this.emit(m.method, m.params); return; }
    const p = this.pending.get(m.id);
    if (!p) return;
    this.pending.delete(m.id);
    if (m.error) {
      const err = new Error(m.error.message);
      err.code = m.error.code;
      p.reject(err);
    } else {
      p.resolve(m.result);
    }
  }

  async _serveRequest(m) {
    const fn = this.handlers.get(m.method);
    if (!fn) {
      this._write({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'no handler for ' + m.method } });
      return;
    }
    try {
      const result = await fn(m.params || {});
      this._write({ jsonrpc: '2.0', id: m.id, result });
    } catch (e) {
      this._write({ jsonrpc: '2.0', id: m.id, error: { code: -32603, message: String((e && e.message) || e) } });
    }
  }

  _fail(err) {
    for (const p of this.pending.values()) p.reject(err);
    this.pending.clear();
    this.emit('closed', err);
  }
}

module.exports = { RpcClient };

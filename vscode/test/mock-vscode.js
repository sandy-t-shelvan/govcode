'use strict';
// Minimal stand-in for the `vscode` module, enough to activate the
// extension and observe what it registers and sends to terminals.
const registered = new Map();
const terminals = [];
class EventEmitter { constructor() { this.l = []; this.event = (f) => this.l.push(f); } fire(v) { this.l.forEach((f) => f(v)); } }
const vscode = {
  _registered: registered, _terminals: terminals,
  EventEmitter,
  ThemeColor: class { constructor(id) { this.id = id; } },
  TreeItem: class { constructor(label, state) { this.label = label; this.collapsibleState = state; } },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  ViewColumn: { Beside: -2 },
  Uri: { file: (p) => ({ fsPath: p, scheme: 'file' }), from: (o) => o },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: process.cwd() } }],
    getConfiguration: () => ({ get: (k) => ({ binaryPath: '/opt/govcode/bin/govcode', policyPath: '' }[k]) }),
    registerTextDocumentContentProvider: () => ({ dispose() {} }),
  },
  window: {
    createOutputChannel: () => ({ append() {}, appendLine() {}, show() {}, dispose() {} }),
    createStatusBarItem: () => ({ show() {}, dispose() {} }),
    registerTreeDataProvider: () => ({ dispose() {} }),
    showInputBox: async () => undefined,
    showErrorMessage: () => {}, showInformationMessage: () => {}, showWarningMessage: async () => undefined,
    createTerminal: (opts) => { const t = { opts, sent: [], show() {}, sendText(s) { this.sent.push(s); } }; terminals.push(t); return t; },
  },
  commands: {
    registerCommand: (id, fn) => { registered.set(id, fn); return { dispose() {} }; },
    executeCommand: async () => {},
  },
};
module.exports = vscode;

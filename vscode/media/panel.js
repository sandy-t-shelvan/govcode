// Runs inside the webview. Talks only to the extension via postMessage.
(function () {
  const vscode = acquireVsCodeApi();
  const log = document.getElementById('log');
  const form = document.getElementById('task');
  const text = document.getElementById('text');
  const plan = document.getElementById('plan');
  const go = document.getElementById('go');

  function add(cls, s) {
    const div = document.createElement('div');
    div.className = 'entry ' + cls;
    div.textContent = s; // textContent: never interpret model output as HTML
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const t = text.value.trim();
    if (!t) return;
    add('user', '> ' + t);
    go.disabled = true;
    vscode.postMessage({ type: 'run', task: t, plan: plan.checked });
  });
  document.getElementById('cancel').addEventListener('click', () => vscode.postMessage({ type: 'cancel' }));

  window.addEventListener('message', (e) => {
    const m = e.data || {};
    if (m.type === 'line') add(m.cls || 'info', m.text);
    if (m.type === 'done') { go.disabled = false; add(m.ok ? 'ok' : 'err', m.text); }
  });
})();

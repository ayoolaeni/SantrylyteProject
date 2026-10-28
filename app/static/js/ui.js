// Small DOM helpers. Untrusted content (log messages, raw_message, etc.) must always be
// set via textContent / this el() helper's text children — never innerHTML (NFR5.6: logs are hostile).
export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => (node.dataset[dk] = dv));
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) node.setAttribute(k, v);
  });
  (Array.isArray(children) ? children : [children]).forEach((child) => {
    if (child === undefined || child === null) return;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  });
  return node;
}

export function priorityPill(priority) {
  return el('span', { class: `pill pill-${priority}` }, priority);
}

export function formatTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleString();
}

export function formatMinutes(mins) {
  if (mins === null || mins === undefined) return '-';
  if (mins < 60) return `${mins}m`;
  return `${(mins / 60).toFixed(1)}h`;
}

export function timeAgo(iso) {
  if (!iso) return 'never';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

let toastStack = null;
// kind: 'alert' (red, default), 'info' (blue) or 'ok' (green)
export function showToast(title, body, onClick, kind = 'alert') {
  if (!toastStack) toastStack = document.getElementById('toast-stack');
  if (!toastStack) return;
  const cls = kind === 'info' ? 'toast toast-info' : kind === 'ok' ? 'toast toast-ok' : 'toast';
  const toast = el('div', { class: cls, role: 'status', onclick: onClick }, [
    el('div', { style: 'font-weight:600;' }, title),
    el('div', { class: 'text-muted', style: 'font-size:0.82rem;' }, body),
  ]);
  toastStack.appendChild(toast);
  while (toastStack.children.length > 4) toastStack.firstChild.remove();
  setTimeout(() => toast.remove(), 8000);
}

// A modal dialog. `build(body)` fills the body; `onSave()` may throw to show an error (dialog stays
// open) or return false to stay open without an error.
export function openModal({ title, build, saveLabel = 'Save', onSave, wide = false, hideSave = false }) {
  const errorBox = el('div', { class: 'modal-error' });
  const body = el('div', { class: 'modal-body' });
  const close = () => backdrop.remove();
  const saveBtn = el('button', { class: 'primary', type: 'button' }, saveLabel);
  const modal = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', style: wide ? 'width:min(1000px,100%)' : undefined }, [
    el('div', { class: 'modal-head' }, [
      el('h2', {}, title),
      el('button', { class: 'ghost small', type: 'button', 'aria-label': 'Close', onclick: close }, '✕'),
    ]),
    body,
    el('div', { class: 'modal-foot' }, [
      errorBox,
      el('button', { type: 'button', onclick: close }, hideSave ? 'Close' : 'Cancel'),
      hideSave ? null : saveBtn,
    ]),
  ]);
  const backdrop = el('div', { class: 'modal-backdrop', onclick: (e) => { if (e.target === backdrop) close(); } }, modal);
  saveBtn.addEventListener('click', async () => {
    errorBox.textContent = '';
    saveBtn.disabled = true;
    try {
      // onSave may return false to keep the dialog open (e.g. a "Run test" button).
      if ((await onSave()) !== false) close();
    } catch (err) {
      errorBox.textContent = err.message || String(err);
    } finally {
      saveBtn.disabled = false;
    }
  });
  document.addEventListener('keydown', function onKey(e) {
    if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); }
  });
  build(body);
  document.body.appendChild(backdrop);
  const first = body.querySelector('input, select, textarea');
  if (first) first.focus();
  return { close, body };
}

export function field(label, input, hint) {
  return el('div', { class: 'field' }, [el('label', {}, label), input, hint ? el('div', { class: 'hint' }, hint) : null]);
}

export function select(options, value, attrs = {}) {
  // options: array of [value, label] or plain strings
  return el(
    'select',
    attrs,
    options.map((o) => {
      const [v, label] = Array.isArray(o) ? o : [o, o];
      return el('option', { value: v, selected: String(v) === String(value ?? '') ? 'selected' : undefined }, label);
    })
  );
}

export function notifyBrowser(title, body) {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    new Notification(title, { body });
  } else if (Notification.permission !== 'denied') {
    Notification.requestPermission().then((perm) => {
      if (perm === 'granted') new Notification(title, { body });
    });
  }
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

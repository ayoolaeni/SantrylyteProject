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

let toastStack = null;
export function showToast(title, body, onClick) {
  if (!toastStack) toastStack = document.getElementById('toast-stack');
  if (!toastStack) return;
  const toast = el('div', { class: 'toast', role: 'status', onclick: onClick }, [
    el('div', { style: 'font-weight:600;' }, title),
    el('div', { class: 'text-muted', style: 'font-size:0.82rem;' }, body),
  ]);
  toastStack.appendChild(toast);
  setTimeout(() => toast.remove(), 8000);
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

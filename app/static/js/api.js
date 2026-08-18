// Thin fetch wrapper for the JSON API: injects the CSRF header and normalises errors.
function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : null;
}

export async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  const method = (options.method || 'GET').toUpperCase();
  if (options.body !== undefined && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && method !== 'HEAD') {
    const token = csrfToken();
    if (token) headers['X-CSRFToken'] = token;
  }

  const resp = await fetch('/api/v1' + path, {
    ...options,
    method,
    headers,
    credentials: 'same-origin',
  });

  if (resp.status === 204) return null;

  const isJson = (resp.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? await resp.json().catch(() => null) : await resp.blob();

  if (!resp.ok) {
    const message = (data && data.error && data.error.message) || resp.statusText || 'Request failed';
    const err = new Error(message);
    err.code = data && data.error && data.error.code;
    err.status = resp.status;
    err.details = data && data.error && data.error.details;
    throw err;
  }
  return data;
}

export const api = {
  get: (path) => apiFetch(path),
  post: (path, body) => apiFetch(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  patch: (path, body) => apiFetch(path, { method: 'PATCH', body: JSON.stringify(body) }),
  del: (path) => apiFetch(path, { method: 'DELETE' }),
};

export function qs(params) {
  const usp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === '') return;
    usp.set(k, v);
  });
  const s = usp.toString();
  return s ? `?${s}` : '';
}

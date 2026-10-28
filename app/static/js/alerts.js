import { api, qs } from './api.js';
import { el, priorityPill, formatTime, clear } from './ui.js';
import { connectLive, subscribe } from './socket.js';

const PRIORITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const STATUS_OPTIONS = ['NEW', 'ACKNOWLEDGED', 'ESCALATED', 'DISMISSED'];

const state = {
  priority: [],
  event_type: '',
  status: '',
  src_ip: '',
  source_id: '',
  q: '',
  from: '',
  to: '',
  page: 1,
  per_page: 50,
};
const selected = new Set();
let lastResult = null;

function readStateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('priority')) state.priority = params.get('priority').split(',');
  ['event_type', 'status', 'src_ip', 'source_id', 'q', 'from', 'to'].forEach((k) => {
    if (params.get(k)) state[k] = params.get(k);
  });
  if (params.get('page')) state.page = parseInt(params.get('page'), 10) || 1;
}

function writeStateToUrl() {
  const params = new URLSearchParams();
  if (state.priority.length) params.set('priority', state.priority.join(','));
  ['event_type', 'status', 'src_ip', 'source_id', 'q', 'from', 'to'].forEach((k) => {
    if (state[k]) params.set(k, state[k]);
  });
  if (state.page > 1) params.set('page', state.page);
  const s = params.toString();
  window.history.replaceState(null, '', s ? `?${s}` : window.location.pathname);
}

function buildFilterBar() {
  const bar = document.getElementById('filter-bar');
  clear(bar);

  const priorityGroup = el('div', {}, [
    el('label', {}, 'Priority'),
    el(
      'div',
      { class: 'flex' },
      PRIORITY_OPTIONS.map((p) =>
        el('label', { style: 'font-size:0.8rem; font-weight:400; display:flex; gap:4px; align-items:center;' }, [
          el('input', {
            type: 'checkbox',
            checked: state.priority.includes(p) ? 'checked' : undefined,
            style: 'width:auto;',
            onchange: (e) => {
              if (e.target.checked) state.priority.push(p);
              else state.priority = state.priority.filter((x) => x !== p);
              refresh();
            },
          }),
          p,
        ])
      )
    ),
  ]);

  const statusSelect = el(
    'select',
    { onchange: (e) => { state.status = e.target.value; refresh(); } },
    [el('option', { value: '' }, 'Any status')].concat(
      STATUS_OPTIONS.map((s) => el('option', { value: s, selected: state.status === s ? 'selected' : undefined }, s))
    )
  );

  const srcIpInput = el('input', {
    type: 'text',
    placeholder: 'Source IP',
    value: state.src_ip,
    onchange: (e) => { state.src_ip = e.target.value.trim(); refresh(); },
  });

  const qInput = el('input', {
    type: 'search',
    placeholder: 'Search message…',
    value: state.q,
    onchange: (e) => { state.q = e.target.value.trim(); refresh(); },
  });

  const fromInput = el('input', {
    type: 'datetime-local',
    value: state.from,
    onchange: (e) => { state.from = e.target.value; refresh(); },
  });
  const toInput = el('input', {
    type: 'datetime-local',
    value: state.to,
    onchange: (e) => { state.to = e.target.value; refresh(); },
  });

  bar.appendChild(priorityGroup);
  bar.appendChild(el('div', {}, [el('label', {}, 'Status'), statusSelect]));
  bar.appendChild(el('div', {}, [el('label', {}, 'Source IP'), srcIpInput]));
  bar.appendChild(el('div', { style: 'flex:1; min-width:200px;' }, [el('label', {}, 'Search'), qInput]));
  bar.appendChild(el('div', {}, [el('label', {}, 'From'), fromInput]));
  bar.appendChild(el('div', {}, [el('label', {}, 'To'), toInput]));
  bar.appendChild(
    el('div', {}, [
      el('label', {}, ' '),
      el('div', { class: 'btn-row' }, [
        el('button', { onclick: () => bulkAction('acknowledge') }, 'Acknowledge selected'),
        el('button', { onclick: () => bulkAction('dismiss') }, 'Dismiss selected'),
        el('button', { class: 'ghost', onclick: () => { window.location.href = '/alerts'; } }, 'Clear filters'),
      ]),
    ])
  );
}

async function bulkAction(action) {
  if (!selected.size) return;
  const ids = Array.from(selected);
  if (action === 'acknowledge') {
    await Promise.all(ids.map((id) => api.post(`/events/${id}/acknowledge`)));
  } else if (action === 'dismiss') {
    const reason = window.prompt('Reason for dismissing as false positive:');
    if (!reason) return;
    await Promise.all(ids.map((id) => api.post(`/events/${id}/dismiss`, { reason })));
  }
  selected.clear();
  await refresh();
}

function eventRow(event) {
  const checkbox = el('input', {
    type: 'checkbox',
    onclick: (e) => {
      e.stopPropagation();
      if (e.target.checked) selected.add(event.event_id);
      else selected.delete(event.event_id);
    },
  });
  const row = el('tr', { class: 'clickable', id: `event-${event.event_id}` }, [
    el('td', {}, checkbox),
    el('td', {}, formatTime(event.timestamp)),
    el('td', {}, priorityPill(event.priority_level)),
    el('td', {}, String(event.severity_score)),
    el('td', {}, event.event_type),
    el('td', {}, event.src_ip || '-'),
    el('td', { style: 'max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;' }, event.message || ''),
    el('td', {}, event.status),
    el('td', {}, [
      el('button', { onclick: (e) => { e.stopPropagation(); acknowledgeOne(event.event_id); } }, 'Ack'),
      ' ',
      el('button', { onclick: (e) => { e.stopPropagation(); dismissOne(event.event_id); } }, 'Dismiss'),
      ' ',
      el('button', { class: 'primary', onclick: (e) => { e.stopPropagation(); createIncident(event.event_id); } }, 'Incident'),
    ]),
  ]);
  row.addEventListener('click', () => window.location.assign(`/alerts#event-${event.event_id}`));
  return row;
}

async function acknowledgeOne(id) {
  await api.post(`/events/${id}/acknowledge`);
  await refresh();
}

async function dismissOne(id) {
  const reason = window.prompt('Reason for dismissing as false positive:');
  if (!reason) return;
  await api.post(`/events/${id}/dismiss`, { reason });
  await refresh();
}

async function createIncident(id) {
  const incident = await api.post(`/events/${id}/create-incident`, {});
  window.location.href = `/incidents/${incident.reference}`;
}

function renderTable() {
  const tbody = document.getElementById('alerts-body');
  clear(tbody);
  (lastResult.data || []).forEach((event) => tbody.appendChild(eventRow(event)));

  const pager = document.getElementById('pager');
  clear(pager);
  const totalPages = Math.max(1, Math.ceil(lastResult.total / lastResult.per_page));
  pager.appendChild(el('span', { class: 'text-muted' }, `Page ${lastResult.page} of ${totalPages} (${lastResult.total} total)`));
  if (lastResult.page > 1) {
    pager.appendChild(el('button', { onclick: () => { state.page -= 1; refresh(); } }, 'Previous'));
  }
  if (lastResult.page < totalPages) {
    pager.appendChild(el('button', { onclick: () => { state.page += 1; refresh(); } }, 'Next'));
  }
}

async function refresh() {
  writeStateToUrl();
  const params = {
    priority: state.priority.join(','),
    event_type: state.event_type,
    status: state.status,
    src_ip: state.src_ip,
    source_id: state.source_id,
    q: state.q,
    from: state.from ? new Date(state.from).toISOString() : '',
    to: state.to ? new Date(state.to).toISOString() : '',
    sort: '-severity_score',
    page: state.page,
    per_page: state.per_page,
  };
  lastResult = await api.get(`/events${qs(params)}`);
  renderTable();
}

function setupSocket() {
  const socket = connectLive();
  socket.on('connect', () => subscribe(['all_events']));
  socket.on('event:new', () => {
    if (state.page === 1) refresh();
  });
}

readStateFromUrl();
buildFilterBar();
setupSocket();
refresh();

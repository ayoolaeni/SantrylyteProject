import { api, qs } from './api.js';
import { el, priorityPill, formatTime, clear, select, showToast } from './ui.js';
import { connectLive, subscribe } from './socket.js';

const TRANSITIONS = {
  NEW: ['ACKNOWLEDGED'],
  ACKNOWLEDGED: ['INVESTIGATING', 'FALSE_POSITIVE'],
  INVESTIGATING: ['ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'],
  ESCALATED: ['INVESTIGATING', 'RESOLVED'],
  RESOLVED: ['CLOSED', 'INVESTIGATING'],
  FALSE_POSITIVE: ['CLOSED'],
  CLOSED: ['INVESTIGATING'],
};
const TRANSITION_LABELS = {
  ACKNOWLEDGED: 'Acknowledge', INVESTIGATING: 'Start investigating', ESCALATED: 'Escalate',
  RESOLVED: 'Resolve', FALSE_POSITIVE: 'Mark false positive', CLOSED: 'Close',
};
const STATE_LABELS = {
  NEW: 'New', ACKNOWLEDGED: 'Acknowledged', INVESTIGATING: 'Investigating', ESCALATED: 'Escalated',
  RESOLVED: 'Resolved', FALSE_POSITIVE: 'False positive', CLOSED: 'Closed',
};
const OPEN_STATES = 'NEW,ACKNOWLEDGED,INVESTIGATING,ESCALATED';
const REQUIRES_SUMMARY = new Set(['RESOLVED', 'FALSE_POSITIVE']);

const me = JSON.parse(document.getElementById('current-user').textContent);
const canWork = me.role === 'ADMIN' || me.role === 'ANALYST';

let assignableCache = null;
async function assignableUsers() {
  if (!canWork) return [];
  if (!assignableCache) assignableCache = api.get('/users/assignable').catch(() => []);
  return assignableCache;
}

function stateBadge(state) {
  const cls = { NEW: 'status-bad', ACKNOWLEDGED: 'status-warn', INVESTIGATING: 'status-wait', ESCALATED: 'status-bad',
    RESOLVED: 'status-ok', FALSE_POSITIVE: 'status-off', CLOSED: 'status-off' }[state] || 'status-off';
  return el('span', { class: `status ${cls}` }, STATE_LABELS[state] || state);
}

function assigneeSelect(users, currentId, onChange) {
  const options = [['', 'Unassigned']].concat(users.map((u) => [u.user_id, `${u.full_name}${u.user_id === me.user_id ? ' (me)' : ''} · ${u.role.toLowerCase()}`]));
  const sel = select(options, currentId ?? '', { 'aria-label': 'Assignee', style: 'min-width:190px;' });
  sel.addEventListener('click', (e) => e.stopPropagation());
  sel.addEventListener('change', async (e) => {
    e.stopPropagation();
    sel.disabled = true;
    try {
      await onChange(sel.value ? parseInt(sel.value, 10) : null);
    } catch (err) {
      window.alert(err.message);
    } finally {
      sel.disabled = false;
    }
  });
  return sel;
}

// ---------- Incident list page ----------
async function initList() {
  const root = document.getElementById('incidents-list-root');
  const params = new URLSearchParams(window.location.search);
  const state = {
    state: params.get('state') || 'open',
    priority: params.get('priority') || '',
    // Analysts start on their own queue; admins (who dispatch) and viewers see everything.
    assigned_to: params.get('assigned_to') || (me.role === 'ANALYST' ? 'me' : 'all'),
  };
  const users = await assignableUsers();

  function writeUrl() {
    const p = new URLSearchParams();
    Object.entries(state).forEach(([k, v]) => { if (v) p.set(k, v); });
    window.history.replaceState(null, '', `?${p.toString()}`);
  }

  const assignedOptions = [['me', 'Assigned to me'], ['unassigned', 'Unassigned'], ['all', 'Everyone']]
    .concat(users.filter((u) => u.user_id !== me.user_id).map((u) => [String(u.user_id), `Assigned to ${u.full_name}`]));
  const stateOptions = [['open', 'Open (not closed)'], ['', 'Any state']].concat(Object.entries(STATE_LABELS));
  const priorityOptions = [['', 'Any priority'], 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

  const bar = el('div', { class: 'filter-bar' }, [
    el('div', {}, [el('label', {}, 'Assigned'), select(assignedOptions, state.assigned_to, { onchange: (e) => { state.assigned_to = e.target.value; load(); } })]),
    el('div', {}, [el('label', {}, 'State'), select(stateOptions, state.state, { onchange: (e) => { state.state = e.target.value; load(); } })]),
    el('div', {}, [el('label', {}, 'Priority'), select(priorityOptions, state.priority, { onchange: (e) => { state.priority = e.target.value; load(); } })]),
  ]);
  const summary = el('div', { class: 'muted-small', style: 'margin-bottom:8px;' });
  const tbody = el('tbody');
  const headers = ['Reference', 'Title', 'Priority', 'State', 'Assignee', 'Created'];
  const tableWrap = el('div', { class: 'card', style: 'overflow-x:auto;' }, el('table', {}, [
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    tbody,
  ]));

  async function load() {
    writeUrl();
    const query = { priority: state.priority, per_page: 200 };
    if (state.assigned_to && state.assigned_to !== 'all') query.assigned_to = state.assigned_to;
    query.state = state.state === 'open' ? OPEN_STATES : state.state;
    const res = await api.get(`/incidents${qs(query)}`);
    clear(tbody);
    summary.textContent = `${res.total} incident${res.total === 1 ? '' : 's'}`;
    if (!res.data.length) {
      tbody.appendChild(el('tr', {}, el('td', { colspan: headers.length, class: 'empty' },
        state.assigned_to === 'me' ? 'Nothing assigned to you right now.' : 'No incidents match these filters.')));
      return;
    }
    res.data.forEach((inc) => {
      const assigneeCell = canWork
        ? assigneeSelect(users, inc.assigned_to, async (userId) => {
          await api.post(`/incidents/${inc.reference}/assign`, { user_id: userId });
          showToast('Assignment saved', `${inc.reference} → ${userId ? users.find((u) => u.user_id === userId)?.full_name : 'Unassigned'}`, null, 'ok');
          load();
        })
        : (inc.assignee_name || 'Unassigned');
      tbody.appendChild(el('tr', { class: 'clickable', onclick: () => (window.location.href = `/incidents/${inc.reference}`) }, [
        el('td', { style: 'white-space:nowrap;' }, inc.reference),
        el('td', {}, inc.title),
        el('td', {}, priorityPill(inc.priority_level)),
        el('td', {}, stateBadge(inc.state)),
        el('td', {}, assigneeCell),
        el('td', { style: 'white-space:nowrap;' }, formatTime(inc.created_at)),
      ]));
    });
  }

  clear(root);
  root.appendChild(bar);
  root.appendChild(summary);
  root.appendChild(tableWrap);
  await load();

  let reloadTimer = null;
  const reload = () => { clearTimeout(reloadTimer); reloadTimer = setTimeout(load, 500); };
  const socket = connectLive();
  socket.on('connect', () => subscribe(['incidents']));
  socket.on('incident:created', reload);
  socket.on('incident:updated', reload);
}

// ---------- Incident detail page ----------
function describeAction(a) {
  switch (a.action_type) {
    case 'CREATED': return 'Incident created';
    case 'ASSIGNED': return a.from_value ? `Reassigned from ${a.from_value} to ${a.to_value}` : `Assigned to ${a.to_value}`;
    case 'UNASSIGNED': return `Unassigned (was ${a.from_value || 'nobody'})`;
    case 'COMMENTED': return 'Comment';
    case 'EVENT_LINKED': return `Linked event #${a.to_value}`;
    case 'REOPENED': return 'Reopened';
    default:
      return a.to_value ? `${STATE_LABELS[a.to_value] || a.to_value}` : a.action_type;
  }
}

async function initDetail() {
  const root = document.getElementById('incident-root');
  const reference = root.dataset.reference;
  const users = await assignableUsers();

  async function render() {
    const incident = await api.get(`/incidents/${reference}`);
    root.dataset.incidentId = String(incident.incident_id);
    clear(root);
    root.appendChild(buildDetail(incident));
  }

  function row(label, value) {
    return el('tr', {}, [el('th', { style: 'width:160px;' }, label), el('td', { class: 'wrap-anywhere' }, value || '-')]);
  }

  function buildDetail(incident) {
    const event = incident.originating_event || {};

    async function transition(toState) {
      let resolution_summary;
      if (REQUIRES_SUMMARY.has(toState)) {
        resolution_summary = window.prompt(`Describe what was found and done (required to mark as ${STATE_LABELS[toState]}):`);
        if (!resolution_summary) return;
      }
      try {
        await api.post(`/incidents/${reference}/transition`, { to_state: toState, resolution_summary });
        await render();
      } catch (err) {
        window.alert(err.message);
      }
    }

    async function assign(userId, note = '') {
      try {
        await api.post(`/incidents/${reference}/assign`, { user_id: userId, note });
      } catch (err) {
        window.alert(err.message);
        return;
      }
      const name = userId ? (users.find((u) => u.user_id === userId)?.full_name || 'user') : 'nobody';
      showToast('Assignment saved', `${reference} is now assigned to ${name}${note ? ', with your note' : ''}.`, null, 'ok');
      await render();
    }

    async function comment() {
      const text = document.getElementById('comment-text').value.trim();
      if (!text) return;
      await api.post(`/incidents/${reference}/comment`, { comment: text });
      await render();
    }

    const why = [
      ...(event.matched_rules || []).map((r) => el('li', {}, `Rule "${r.name}" (+${r.weight})`)),
      ...(event.modifiers_applied || []).map((m) => el('li', {}, `${m.name.replace(/_/g, ' ')}: ${m.effect}${m.asset ? ` (${m.asset})` : ''}`)),
    ];

    const eventCard = el('div', { class: 'card' }, [
      el('div', { class: 'flex-between' }, [
        el('h2', { style: 'margin:0; font-size:1.15rem;' }, incident.title),
        priorityPill(incident.priority_level),
      ]),
      el('div', { class: 'text-muted mt-1' }, `${incident.reference} · opened ${formatTime(incident.created_at)}`),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, 'Originating event'),
      el('table', {}, [
        row('Timestamp', formatTime(event.timestamp)),
        row('Event type', event.event_type),
        row('Source IP', event.src_ip),
        row('Target IP / port', [event.dest_ip, event.dest_port].filter(Boolean).join(':')),
        row('Username', event.username),
        row('Hostname', event.hostname),
        row('Log source', event.source_name),
        row('HTTP', event.http_method ? `${event.http_method} ${event.http_path} -> ${event.http_status}` : null),
      ]),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, 'Raw log line'),
      el('pre', { class: 'raw-message' }, event.raw_message || ''),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, `Why ${incident.priority_level}? (event score ${event.severity_score})`),
      why.length ? el('ul', {}, why) : el('div', { class: 'muted-small' }, 'No rule matched; created manually.'),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, `Related events (${(incident.linked_events || []).length})`),
      (incident.linked_events || []).length
        ? el('ul', {}, incident.linked_events.map((e) => el('li', {}, `#${e.event_id} · ${e.event_type} · ${e.priority_level} · ${formatTime(e.timestamp)}`)))
        : el('div', { class: 'muted-small' }, 'Repeats of the same attack are grouped here automatically.'),
    ]);

    // Reopening a closed incident is ADMIN-only (enforced server-side too).
    const allowed = incident.state === 'CLOSED' && me.role !== 'ADMIN' ? [] : (TRANSITIONS[incident.state] || []);
    const transitions = canWork
      ? allowed.map((s) => el('button', { class: s === 'ESCALATED' || s === 'FALSE_POSITIVE' ? '' : 'primary', onclick: () => transition(s) }, TRANSITION_LABELS[s] || s))
      : [];

    // The note left by whoever assigned it to the current assignee (latest assignment).
    const actions = incident.actions || [];
    const lastAssignment = actions.slice().reverse().find((a) => a.action_type === 'ASSIGNED' || a.action_type === 'UNASSIGNED');
    const handover = lastAssignment && lastAssignment.action_type === 'ASSIGNED' && lastAssignment.comment ? lastAssignment : null;
    const notes = actions.filter((a) => a.comment && (a.action_type === 'COMMENTED' || a.action_type === 'ASSIGNED')).reverse();

    const handoverBox = handover
      ? el('div', { class: 'help', style: 'margin:10px 0 0;' }, [
        el('h3', {}, incident.assigned_to === me.user_id
          ? `Note for you from ${handover.actor_name || 'the assigner'}`
          : `Handover note from ${handover.actor_name || 'the assigner'} to ${handover.to_value}`),
        el('div', { class: 'wrap-anywhere', style: 'white-space:pre-wrap;' }, handover.comment),
        el('div', { class: 'muted-small mt-1' }, formatTime(handover.created_at)),
      ])
      : null;

    let assignBlock;
    if (canWork) {
      const options = [['', 'Unassigned']].concat(users.map((u) => [u.user_id, `${u.full_name}${u.user_id === me.user_id ? ' (me)' : ''} · ${u.role.toLowerCase()}`]));
      const picker = select(options, incident.assigned_to ?? '', { 'aria-label': 'Assignee' });
      const noteIn = el('textarea', { rows: 2, placeholder: 'Note for the person you assign (optional), e.g. "Check if this IP logged in anywhere else"' });
      const assignBtn = el('button', { class: 'primary', onclick: async () => {
        assignBtn.disabled = true;
        await assign(picker.value ? parseInt(picker.value, 10) : null, noteIn.value.trim());
        assignBtn.disabled = false;
      } }, 'Assign');
      assignBlock = el('div', { class: 'mt-1' }, [
        picker,
        el('div', { class: 'mt-1' }, noteIn),
        el('div', { class: 'btn-row mt-1' }, [
          assignBtn,
          incident.assigned_to !== me.user_id ? el('button', { onclick: () => assign(me.user_id) }, 'Assign to me') : null,
        ]),
        el('div', { class: 'muted-small mt-1' }, 'The assignee is notified instantly, sees your note, and finds the incident under Incidents → "Assigned to me".'),
      ]);
    } else {
      assignBlock = null;
    }

    const notesBlock = el('div', {}, [
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, `Notes (${notes.length})`),
      notes.length
        ? el('ul', { class: 'timeline' }, notes.map((a) => el('li', {}, [
          el('div', { class: 'wrap-anywhere', style: 'white-space:pre-wrap;' }, a.comment),
          el('div', { class: 'text-muted' }, `${a.actor_name || 'system'}${a.action_type === 'ASSIGNED' ? ` (when assigning to ${a.to_value})` : ''} · ${formatTime(a.created_at)}`),
        ])))
        : el('div', { class: 'muted-small' }, 'No notes yet.'),
      canWork ? el('textarea', { id: 'comment-text', class: 'mt-1', rows: 3, placeholder: 'Add a note: what did you check or find?' }) : null,
      canWork ? el('button', { class: 'mt-1', onclick: comment }, 'Add note') : null,
    ]);

    const actionsCard = el('div', { class: 'card' }, [
      el('h3', { style: 'margin-top:0; font-size:0.95rem;' }, 'Status'),
      stateBadge(incident.state),
      transitions.length ? el('div', { class: 'btn-row mt-1' }, transitions) : null,
      incident.resolution_summary ? el('div', { class: 'mt-1 muted-small' }, `Resolution: ${incident.resolution_summary}`) : null,
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, 'Assigned to'),
      el('div', { style: 'font-weight:600;' }, incident.assignee_name || 'Nobody yet'),
      handoverBox,
      assignBlock,
      notesBlock,
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, 'Audit timeline'),
      el('ul', { class: 'timeline' }, (incident.actions || []).slice().reverse().map((a) => el('li', {}, [
        el('div', { style: 'font-weight:600;' }, describeAction(a)),
        el('div', { class: 'text-muted' }, `${a.actor_name || 'system'} · ${formatTime(a.created_at)}`),
        a.comment ? el('div', {}, a.comment) : null,
      ]))),
    ]);

    return el('div', {}, [
      el('div', { class: 'topbar' }, [
        el('a', { href: '/incidents' }, '← All incidents'),
      ]),
      el('div', { class: 'two-col' }, [eventCard, actionsCard]),
    ]);
  }

  await render();

  const socket = connectLive();
  socket.on('connect', () => subscribe(['incidents']));
  socket.on('incident:updated', (payload) => {
    if (!payload || payload.reference === reference || String(payload.incident_id) === root.dataset.incidentId) {
      render();
    }
  });
}

if (document.getElementById('incidents-list-root')) initList();
if (document.getElementById('incident-root')) initDetail();

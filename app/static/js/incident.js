import { api, qs } from './api.js';
import { el, priorityPill, formatTime, clear } from './ui.js';
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
const REQUIRES_SUMMARY = new Set(['RESOLVED', 'FALSE_POSITIVE']);

// ---------- Incident list page ----------
async function initList() {
  const root = document.getElementById('incidents-list-root');
  const params = new URLSearchParams(window.location.search);
  const state = {
    state: params.get('state') || '',
    priority: params.get('priority') || '',
    assigned_to: params.get('assigned_to') || 'me',
  };

  function buildFilters() {
    const bar = el('div', { class: 'filter-bar' }, [
      el('div', {}, [
        el('label', {}, 'Assigned'),
        el(
          'select',
          { onchange: (e) => { state.assigned_to = e.target.value; load(); } },
          ['me', 'all'].map((v) => el('option', { value: v, selected: state.assigned_to === v ? 'selected' : undefined }, v === 'me' ? 'Assigned to me' : 'All'))
        ),
      ]),
      el('div', {}, [
        el('label', {}, 'State'),
        el(
          'select',
          { onchange: (e) => { state.state = e.target.value; load(); } },
          [['', 'Not closed']].concat([
            ['NEW', 'New'], ['ACKNOWLEDGED', 'Acknowledged'], ['INVESTIGATING', 'Investigating'],
            ['ESCALATED', 'Escalated'], ['RESOLVED', 'Resolved'], ['FALSE_POSITIVE', 'False positive'], ['CLOSED', 'Closed'],
          ]).map(([v, label]) => el('option', { value: v, selected: state.state === v ? 'selected' : undefined }, label))
        ),
      ]),
    ]);
    root.appendChild(bar);
  }

  const tableWrap = el('div', { class: 'card', style: 'overflow-x:auto;' });
  const table = el('table', {}, [
    el('thead', {}, el('tr', {}, ['Reference', 'Title', 'Priority', 'State', 'Assignee', 'Created'].map((h) => el('th', {}, h)))),
    el('tbody', { id: 'incidents-body' }),
  ]);
  tableWrap.appendChild(table);

  async function load() {
    const query = { assigned_to: state.assigned_to === 'all' ? '' : 'me', priority: state.priority };
    if (state.state) query.state = state.state;
    else query.state = 'NEW,ACKNOWLEDGED,INVESTIGATING,ESCALATED';
    const res = await api.get(`/incidents${qs(query)}`);
    const tbody = document.getElementById('incidents-body');
    clear(tbody);
    res.data.forEach((inc) => {
      tbody.appendChild(
        el('tr', { class: 'clickable', onclick: () => (window.location.href = `/incidents/${inc.reference}`) }, [
          el('td', {}, inc.reference),
          el('td', {}, inc.title),
          el('td', {}, priorityPill(inc.priority_level)),
          el('td', {}, inc.state),
          el('td', {}, inc.assignee_name || '-'),
          el('td', {}, formatTime(inc.created_at)),
        ])
      );
    });
  }

  clear(root);
  buildFilters();
  root.appendChild(tableWrap);
  await load();
}

// ---------- Incident detail page ----------
async function initDetail() {
  const root = document.getElementById('incident-root');
  const reference = root.dataset.reference;

  async function render() {
    const incident = await api.get(`/incidents/${reference}`);
    clear(root);
    root.appendChild(buildDetail(incident));
  }

  function buildDetail(incident) {
    const event = incident.originating_event || {};

    const eventCard = el('div', { class: 'card' }, [
      el('div', { class: 'flex-between' }, [
        el('h2', { style: 'margin:0; font-size:1.1rem;' }, incident.title),
        priorityPill(incident.priority_level),
      ]),
      el('div', { class: 'text-muted mt-1' }, `${incident.reference} · originating event #${incident.originating_event_id}`),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, 'Originating event'),
      el('table', {}, [
        row('Timestamp', formatTime(event.timestamp)),
        row('Event type', event.event_type),
        row('Src IP', event.src_ip),
        row('Dest IP / port', [event.dest_ip, event.dest_port].filter(Boolean).join(':')),
        row('Username', event.username),
        row('Hostname', event.hostname),
        row('HTTP', event.http_method ? `${event.http_method} ${event.http_path} -> ${event.http_status}` : null),
      ]),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, 'Raw message'),
      el('pre', { class: 'raw-message' }, event.raw_message || ''),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, `Why ${incident.priority_level} (score ${event.severity_score})?`),
      el(
        'ul',
        {},
        (event.matched_rules || []).map((r) => el('li', {}, `${r.name} (+${r.weight})`))
      ),
      el(
        'ul',
        {},
        (event.modifiers_applied || []).map((m) => el('li', {}, `${m.name}: ${m.effect}`))
      ),
      el('h3', { class: 'mt-2', style: 'font-size:0.9rem;' }, 'Linked events'),
      el(
        'ul',
        {},
        (incident.linked_events || []).map((e) => el('li', {}, `#${e.event_id} · ${e.event_type} · ${formatTime(e.timestamp)}`))
      ),
      el('div', { class: 'mt-2 flex' }, [
        el('input', { type: 'number', id: 'link-event-id', placeholder: 'Event ID to link', style: 'width:160px;' }),
        el('button', { onclick: linkEvent }, 'Link event'),
      ]),
    ]);

    const actionsCard = el('div', { class: 'card' }, [
      el('h3', { style: 'margin-top:0; font-size:0.95rem;' }, 'State'),
      el('div', {}, priorityPill(incident.state)),
      el('div', { class: 'flex mt-1', id: 'transition-buttons' }, buildTransitionButtons(incident)),
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, 'Assignee'),
      el('div', {}, incident.assignee_name || 'Unassigned'),
      el('div', { class: 'flex mt-1' }, [
        el('input', { type: 'number', id: 'assign-user-id', placeholder: 'User ID', style: 'width:120px;' }),
        el('button', { onclick: assign }, 'Assign'),
      ]),
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, 'Comment'),
      el('textarea', { id: 'comment-text', rows: 3 }),
      el('button', { class: 'mt-1', onclick: comment }, 'Add comment'),
      el('h3', { class: 'mt-2', style: 'font-size:0.95rem;' }, 'Audit timeline'),
      el(
        'ul',
        { class: 'timeline' },
        (incident.actions || [])
          .slice()
          .reverse()
          .map((a) => el('li', {}, [
            el('div', { style: 'font-weight:600;' }, `${a.action_type}${a.to_value ? ' -> ' + a.to_value : ''}`),
            el('div', { class: 'text-muted' }, `${a.actor_name || 'system'} · ${formatTime(a.created_at)}`),
            a.comment ? el('div', {}, a.comment) : null,
          ]))
      ),
    ]);

    async function transition(toState) {
      let resolution_summary;
      if (REQUIRES_SUMMARY.has(toState)) {
        resolution_summary = window.prompt(`Resolution summary required to move to ${toState}:`);
        if (!resolution_summary) return;
      }
      try {
        await api.post(`/incidents/${reference}/transition`, { to_state: toState, resolution_summary });
        await render();
      } catch (err) {
        window.alert(err.message);
      }
    }

    function buildTransitionButtons(inc) {
      return (TRANSITIONS[inc.state] || []).map((s) =>
        el('button', { class: 'primary', onclick: () => transition(s) }, s.replace('_', ' '))
      );
    }

    async function assign() {
      const id = document.getElementById('assign-user-id').value;
      await api.post(`/incidents/${reference}/assign`, { user_id: id ? parseInt(id, 10) : null });
      await render();
    }

    async function comment() {
      const text = document.getElementById('comment-text').value.trim();
      if (!text) return;
      await api.post(`/incidents/${reference}/comment`, { comment: text });
      await render();
    }

    async function linkEvent() {
      const id = document.getElementById('link-event-id').value;
      if (!id) return;
      await api.post(`/incidents/${reference}/link-event`, { event_id: parseInt(id, 10) });
      await render();
    }

    return el('div', { class: 'two-col' }, [eventCard, actionsCard]);
  }

  function row(label, value) {
    return el('tr', {}, [el('th', { style: 'width:160px;' }, label), el('td', {}, value || '-')]);
  }

  await render();

  const socket = connectLive();
  socket.on('connect', () => subscribe(['incidents']));
  // Cheap to just refetch this one incident whenever any incident changes.
  socket.on('incident:updated', () => render());
}

if (document.getElementById('incidents-list-root')) initList();
if (document.getElementById('incident-root')) initDetail();

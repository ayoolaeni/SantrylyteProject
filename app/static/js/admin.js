import { api, qs } from './api.js';
import { el, clear, formatTime, timeAgo, openModal, field, select, showToast, priorityPill } from './ui.js';

const ROLES = ['ADMIN', 'ANALYST', 'VIEWER'];
const ROLE_HELP = {
  ADMIN: 'Full access, including these admin pages.',
  ANALYST: 'Works alerts and incidents; can be assigned incidents.',
  VIEWER: 'Read-only: dashboards, alerts, incidents and reports.',
};

function help(title, children) {
  return el('div', { class: 'help' }, [el('h3', {}, title), ...children]);
}

function serverHost() {
  return window.location.hostname || 'SENTRYLITE-HOST';
}

async function confirmAndRun(message, fn) {
  if (!window.confirm(message)) return;
  try {
    await fn();
  } catch (err) {
    window.alert(err.message);
  }
}

// =====================================================================
// Log sources
// =====================================================================
const SOURCE_STATUS = {
  RECEIVING: ['status-ok', 'Receiving logs'],
  SILENT: ['status-warn', 'Silent'],
  WAITING: ['status-wait', 'Waiting for first log'],
  DISABLED: ['status-off', 'Disabled'],
};

function connectionGuide(source, meta, token) {
  const host = serverHost();
  const local = host === 'localhost' || host === '127.0.0.1';
  const tokenText = token || '<the ingest token shown when the source was created>';
  return el('div', {}, [
    local ? el('div', { class: 'help' }, [
      'You are browsing on this computer (localhost). Other machines must use this computer\'s network IP address instead of ',
      el('code', {}, host), '.',
    ]) : null,
    el('h3', { class: 'section-title' }, 'Option A: send logs over syslog (Linux servers, firewalls, routers)'),
    el('div', { class: 'muted-small' }, `On a Linux server, add this line to /etc/rsyslog.d/90-sentrylite.conf, then run "sudo systemctl restart rsyslog". The server must send from ${source.host_identifier} (or log with that hostname).`),
    el('pre', { class: 'code' }, `*.* @${host}:${meta.syslog_udp_port}      # UDP\n# or, for TCP:\n*.* @@${host}:${meta.syslog_tcp_port}`),
    el('div', { class: 'muted-small' }, 'Quick test from that server:'),
    el('pre', { class: 'code' }, `logger -n ${host} -P ${meta.syslog_udp_port} "SentryLite test message"`),
    el('h3', { class: 'section-title mt-2' }, 'Option B: send logs over HTTPS/HTTP (applications, scripts)'),
    el('pre', { class: 'code' }, `curl -X POST http://${host}:${window.location.port || 80}${meta.ingest_path} \\\n  -H "Authorization: Bearer ${tokenText}" \\\n  -H "Content-Type: text/plain" \\\n  --data-binary @/var/log/auth.log`),
    el('div', { class: 'muted-small' }, 'Send one log line per line of text (up to 500 per request), or JSON {"message": "..."}'),
  ]);
}

async function initSources() {
  const root = document.getElementById('admin-sources-root');
  const meta = await api.get('/sources/meta');
  const typeOptions = meta.source_types.map((t) => [t.value, t.value]);
  const typeHelp = Object.fromEntries(meta.source_types.map((t) => [t.value, t.description]));

  root.appendChild(help('What is a log source?', [
    el('div', {}, 'A log source is any machine or application that sends its activity logs to SentryLite: a web server, a firewall, a Windows domain controller, your own app. SentryLite reads every line, scores it with the detection rules and raises alerts.'),
    el('ol', {}, [
      el('li', {}, [el('b', {}, 'Register'), ' the machine below (its IP address or hostname, and its log format).']),
      el('li', {}, [el('b', {}, 'Connect'), ': point its logs at SentryLite (click "How to connect" for copy-paste instructions).']),
      el('li', {}, [el('b', {}, 'Confirm'), ': the status turns green "Receiving logs". Use "Send test event" to check the pipeline at any time.']),
    ]),
    el('div', { class: 'muted-small mt-1' }, `A source that sends nothing for ${meta.silent_minutes} minutes turns orange "Silent", often the first sign a server is down or an attacker switched logging off.`),
  ]));

  const stats = el('div', { class: 'stat-inline card', style: 'margin-bottom:16px;' });
  const toolbar = el('div', { class: 'flex-between', style: 'margin-bottom:10px;' }, [
    el('h2', { class: 'section-title', style: 'margin:0;' }, 'Registered sources'),
    el('button', { class: 'primary', onclick: () => editSource() }, '+ Add log source'),
  ]);
  const tbody = el('tbody');
  const table = el('div', { class: 'card', style: 'overflow-x:auto;' }, el('table', {}, [
    el('thead', {}, el('tr', {}, ['Source', 'Format', 'Status', 'Events (24h)', 'Last log', 'Actions'].map((h) => el('th', {}, h)))),
    tbody,
  ]));
  const unregBox = el('div', { class: 'card mt-3' });

  root.append(stats, toolbar, table, unregBox);

  function editSource(existing = null, prefill = {}) {
    const nameInput = el('input', { type: 'text', value: existing?.name ?? prefill.name ?? '', placeholder: 'e.g. Web server 01 (nginx)' });
    const hostInput = el('input', { type: 'text', value: existing?.host_identifier ?? prefill.host ?? '', placeholder: 'e.g. 192.168.1.20 or web01' });
    const typeSelect = select(typeOptions, existing?.source_type ?? prefill.type ?? 'SYSLOG');
    const typeHint = el('div', { class: 'hint' }, typeHelp[typeSelect.value]);
    typeSelect.addEventListener('change', () => { typeHint.textContent = typeHelp[typeSelect.value]; });

    openModal({
      title: existing ? `Edit ${existing.name}` : 'Add a log source',
      saveLabel: existing ? 'Save changes' : 'Create source',
      build: (body) => body.append(el('div', { class: 'form-grid' }, [
        field('Name', nameInput, 'A friendly name people will recognise.'),
        field('IP address or hostname', hostInput, 'How SentryLite recognises this machine: the IP it sends from, or the hostname written in its logs.'),
        el('div', { class: 'field' }, [el('label', {}, 'Log format'), typeSelect, typeHint]),
      ])),
      onSave: async () => {
        const payload = { name: nameInput.value.trim(), host_identifier: hostInput.value.trim(), source_type: typeSelect.value };
        if (!payload.name || !payload.host_identifier) throw new Error('Name and IP/hostname are required.');
        if (existing) {
          await api.patch(`/sources/${existing.source_id}`, payload);
          showToast('Source updated', payload.name, null, 'ok');
        } else {
          const created = await api.post('/sources', payload);
          setTimeout(() => showConnect(created, created.ingest_token), 50);
        }
        await load();
      },
    });
  }

  function showConnect(source, token = null) {
    openModal({
      title: `Connect ${source.name}`,
      hideSave: true,
      wide: true,
      build: (body) => {
        if (token) {
          body.appendChild(el('div', { class: 'flash flash-success' }, [
            el('b', {}, 'Ingest token (copy it now, it is shown only once): '),
            el('code', { class: 'inline wrap-anywhere' }, token),
          ]));
        }
        body.appendChild(connectionGuide(source, meta, token));
      },
    });
  }

  async function sendTest(source) {
    try {
      await api.post(`/sources/${source.source_id}/test-event`);
      showToast('Test event sent', `A sample ${source.source_type} line was processed as if ${source.name} sent it. Watch the status and the dashboard.`, null, 'ok');
      setTimeout(load, 1500);
    } catch (err) {
      window.alert(err.message);
    }
  }

  async function load() {
    const [res, unreg] = await Promise.all([api.get('/sources'), api.get('/sources/unregistered')]);
    const sources = res.data;
    const counts = sources.reduce((acc, s) => { acc[s.status] = (acc[s.status] || 0) + 1; return acc; }, {});
    clear(stats);
    stats.append(
      el('div', {}, [el('b', {}, String(sources.length)), 'registered']),
      el('div', {}, [el('b', { style: 'color:var(--ok)' }, String(counts.RECEIVING || 0)), 'receiving']),
      el('div', {}, [el('b', { style: 'color:var(--high)' }, String(counts.SILENT || 0)), 'silent']),
      el('div', {}, [el('b', { style: 'color:var(--low)' }, String(counts.WAITING || 0)), 'waiting for first log']),
      el('div', {}, [el('b', {}, String(unreg.length)), 'unregistered senders']),
    );

    clear(tbody);
    if (!sources.length) {
      tbody.appendChild(el('tr', {}, el('td', { colspan: 6, class: 'empty' }, 'No sources yet. Click "+ Add log source", or run the Attack Simulator to see one appear.')));
    }
    sources.forEach((s) => {
      const [cls, label] = SOURCE_STATUS[s.status] || ['status-off', s.status];
      tbody.appendChild(el('tr', {}, [
        el('td', {}, [el('div', { style: 'font-weight:600;' }, s.name), el('div', { class: 'muted-small' }, s.host_identifier)]),
        el('td', {}, [el('div', {}, s.source_type), el('div', { class: 'muted-small', style: 'max-width:260px;' }, s.type_description)]),
        el('td', {}, el('span', { class: `status ${cls}` }, label)),
        el('td', {}, el('a', { href: `/alerts?source_id=${s.source_id}`, title: 'Show these events' }, String(s.events_24h))),
        el('td', { title: formatTime(s.last_seen_at) }, timeAgo(s.last_seen_at)),
        el('td', {}, el('div', { class: 'btn-row' }, [
          el('button', { class: 'small', onclick: () => showConnect(s) }, 'How to connect'),
          el('button', { class: 'small', onclick: () => sendTest(s), disabled: s.is_enabled ? undefined : 'disabled' }, 'Send test event'),
          el('button', { class: 'small', onclick: () => editSource(s) }, 'Edit'),
          el('button', { class: 'small', onclick: () => confirmAndRun(`${s.is_enabled ? 'Disable' : 'Enable'} ${s.name}?`, async () => { await api.patch(`/sources/${s.source_id}`, { is_enabled: !s.is_enabled }); await load(); }) }, s.is_enabled ? 'Disable' : 'Enable'),
          el('button', { class: 'small', onclick: () => confirmAndRun(`Issue a new ingest token for ${s.name}? The old token stops working immediately.`, async () => { const r = await api.post(`/sources/${s.source_id}/rotate-token`); showConnect(s, r.ingest_token); }) }, 'New token'),
          el('button', { class: 'small', onclick: () => confirmAndRun(`Delete ${s.name}? Its past events are kept.`, async () => { await api.del(`/sources/${s.source_id}`); await load(); }) }, 'Delete'),
        ])),
      ]));
    });

    clear(unregBox);
    unregBox.append(
      el('h2', { class: 'section-title' }, 'Unregistered senders (last 24h)'),
      el('div', { class: 'muted-small', style: 'margin-bottom:8px;' }, 'Machines whose logs arrived but are not registered yet. Their events are still analysed; registering them gives them a name, a format and silence monitoring.'),
      unreg.length
        ? el('table', {}, [
          el('thead', {}, el('tr', {}, ['Hostname in logs', 'Events (24h)', 'Last log', ''].map((h) => el('th', {}, h)))),
          el('tbody', {}, unreg.map((u) => el('tr', {}, [
            el('td', {}, u.hostname || '(no hostname in log line)'),
            el('td', {}, String(u.events_24h)),
            el('td', {}, timeAgo(u.last_seen_at)),
            el('td', {}, u.hostname ? el('button', { class: 'small primary', onclick: () => editSource(null, { name: u.hostname, host: u.hostname }) }, 'Register') : null),
          ]))),
        ])
        : el('div', { class: 'empty' }, 'None. Every sender is registered.'),
    );
  }

  await load();
  setInterval(load, 20000);
}

// =====================================================================
// Detection rules
// =====================================================================
let RULE_META = null;
const MULTI_OPS = new Set(['in', 'not_in', 'in_cidr', 'not_in_cidr']);
const NO_VALUE_OPS = new Set(['exists', 'is_null']);
const NUMERIC_OPS = new Set(['gt', 'gte', 'lt', 'lte']);

function fieldMeta(name) {
  return RULE_META.fields.find((f) => f.name === name) || { name, label: name, type: 'text' };
}
function opLabel(op) {
  return (RULE_META.operators.find((o) => o.op === op) || { label: op }).label;
}
function userName(id) {
  return (RULE_META.users.find((u) => u.user_id === id) || { full_name: `user #${id}` }).full_name;
}
function valueText(v) {
  if (Array.isArray(v)) return v.join(', ');
  if (v === true) return '';
  return String(v ?? '');
}

function clauseText(c) {
  if (!c.field) return '(group)';
  const val = NO_VALUE_OPS.has(c.op) ? '' : ` "${valueText(c.value)}"`;
  return `${fieldMeta(c.field).label} ${opLabel(c.op)}${val}`;
}

function correlationText(corr) {
  if (!corr) return '';
  const by = fieldMeta(corr.group_by).label.toLowerCase();
  if (corr.type === 'threshold') return `more than ${corr.count} times in ${corr.window_seconds}s from the same ${by}`;
  if (corr.type === 'distinct_count') return `more than ${corr.count} different ${fieldMeta(corr.distinct_field).label.toLowerCase()} values in ${corr.window_seconds}s from the same ${by}`;
  if (corr.type === 'sequence') return `after at least ${corr.min_count} earlier matching events (${clauseText(corr.first || {})}) in ${corr.window_seconds}s from the same ${by}`;
  return '';
}

function conditionSummary(condition) {
  const key = ['all', 'any', 'none'].find((k) => k in condition);
  let text;
  if (key) {
    const joiner = key === 'any' ? ' OR ' : ' AND ';
    text = condition[key].map(clauseText).join(joiner);
    if (key === 'none') text = `NOT (${text})`;
  } else if (condition.field) {
    text = clauseText(condition);
  } else {
    text = '(custom)';
  }
  return condition.correlation ? `${text} · ${correlationText(condition.correlation)}` : text;
}

function actionTags(rule) {
  const a = rule.actions || {};
  const tags = [el('span', { class: 'tag' }, `${rule.weight >= 0 ? '+' : ''}${rule.weight} risk`)];
  if (a.suppress) tags.push(el('span', { class: 'tag tag-warn' }, 'Suppress (auto-dismiss)'));
  if (a.min_priority) tags.push(el('span', { class: 'tag tag-action' }, `Priority ≥ ${a.min_priority}`));
  if (a.create_incident) tags.push(el('span', { class: 'tag tag-action' }, `Open incident${a.incident_priority ? ` (${a.incident_priority})` : ''}`));
  if (a.assign_to) tags.push(el('span', { class: 'tag tag-action' }, `Assign → ${userName(a.assign_to)}`));
  const notify = [...(a.notify_roles || []).map((r) => `all ${r.toLowerCase()}s`), ...(a.notify_user_ids || []).map(userName)];
  if (notify.length) tags.push(el('span', { class: 'tag tag-action' }, `Notify ${notify.join(', ')}`));
  return tags;
}

function priorityForScore(score) {
  const t = RULE_META.thresholds;
  if (score >= t.CRITICAL) return 'CRITICAL';
  if (score >= t.HIGH) return 'HIGH';
  if (score >= t.MEDIUM) return 'MEDIUM';
  if (score >= t.LOW) return 'LOW';
  return 'INFORMATIONAL';
}

// Can the builder edit this condition, or does it need the JSON editor?
function builderCompatible(condition) {
  const key = ['all', 'any'].find((k) => k in condition);
  if (!key) return false;
  if (Object.keys(condition).some((k) => k !== key && k !== 'correlation')) return false;
  if (!condition[key].every((c) => c.field && c.op)) return false;
  const corr = condition.correlation;
  return !corr || corr.type === 'threshold' || corr.type === 'distinct_count';
}

function parseValue(fieldName, op, raw) {
  if (NO_VALUE_OPS.has(op)) return true;
  const type = fieldMeta(fieldName).type;
  const toNum = (s) => {
    const n = Number(s);
    if (Number.isNaN(n)) throw new Error(`"${s}" is not a number`);
    return n;
  };
  if (MULTI_OPS.has(op)) {
    const parts = String(raw).split(',').map((s) => s.trim()).filter(Boolean);
    if (!parts.length) throw new Error('Enter at least one value (comma-separated).');
    return type === 'number' && !op.includes('cidr') ? parts.map(toNum) : parts;
  }
  if (String(raw).trim() === '') throw new Error(`Enter a value for "${fieldMeta(fieldName).label}".`);
  if (type === 'number' || NUMERIC_OPS.has(op)) return toNum(raw);
  return String(raw).trim();
}

function conditionRow(clause, onRemove) {
  const fieldSel = select(RULE_META.fields.map((f) => [f.name, f.label]), clause.field || 'event_type');
  const opSel = select(RULE_META.operators.map((o) => [o.op, o.label]), clause.op || 'eq');
  const valueWrap = el('div');
  let valueInput;

  function renderValue(initial) {
    clear(valueWrap);
    const op = opSel.value;
    if (NO_VALUE_OPS.has(op)) {
      valueInput = null;
      valueWrap.appendChild(el('span', { class: 'muted-small' }, '(no value needed)'));
      return;
    }
    if (fieldSel.value === 'event_type' && (op === 'eq' || op === 'neq')) {
      valueInput = select(RULE_META.event_types, initial ?? 'AUTH_FAILURE');
    } else {
      const placeholder = MULTI_OPS.has(op) ? 'value1, value2, …' : op === 'regex' ? 'e.g. (?i)union\\s+select' : 'value';
      valueInput = el('input', { type: 'text', value: initial !== undefined ? valueText(initial) : '', placeholder });
    }
    valueWrap.appendChild(valueInput);
  }
  renderValue(clause.value);
  fieldSel.addEventListener('change', () => renderValue(undefined));
  opSel.addEventListener('change', () => renderValue(valueInput ? valueInput.value : undefined));

  const row = el('div', { class: 'cond-row' }, [fieldSel, opSel, valueWrap, el('button', { class: 'small', type: 'button', title: 'Remove condition', onclick: () => onRemove(row) }, '✕')]);
  row.read = () => ({ field: fieldSel.value, op: opSel.value, value: parseValue(fieldSel.value, opSel.value, valueInput ? valueInput.value : '') });
  return row;
}

function openRuleEditor(rule, onSaved) {
  const isNew = !rule.rule_id;
  const condition = rule.condition || { all: [{ field: 'event_type', op: 'eq', value: 'AUTH_FAILURE' }] };
  const actions = rule.actions || {};
  let advanced = !builderCompatible(condition);

  // --- basics
  const nameIn = el('input', { type: 'text', value: rule.name || '', placeholder: 'e.g. Login from blocked country' });
  const catSel = select(RULE_META.categories, rule.category || 'AUTHENTICATION');
  const mitreIn = el('input', { type: 'text', value: rule.mitre_technique || '', placeholder: 'e.g. T1110 (optional)' });
  const descIn = el('textarea', { rows: 2, placeholder: 'What this rule detects and why it matters' });
  descIn.value = rule.description || '';
  const enabledIn = el('input', { type: 'checkbox', checked: rule.is_enabled === false ? undefined : 'checked' });

  // --- WHEN (builder)
  const key = 'any' in condition ? 'any' : 'all';
  const matchSel = select([['all', 'ALL of these are true'], ['any', 'ANY of these is true']], key);
  const rowsBox = el('div');
  const removeRow = (row) => { if (rowsBox.children.length > 1) row.remove(); };
  const addRow = (clause = {}) => rowsBox.appendChild(conditionRow(clause, removeRow));
  if (!advanced) condition[key].forEach((c) => addRow(c));
  const addBtn = el('button', { type: 'button', class: 'small', onclick: () => addRow() }, '+ Add condition');

  // --- REPEATS (correlation)
  const corr = condition.correlation || {};
  const corrTypeSel = select([
    ['', 'Every single matching event'],
    ['threshold', 'Only when it happens repeatedly'],
    ['distinct_count', 'Only when it hits many different values'],
  ], advanced ? '' : (corr.type || ''));
  const countIn = el('input', { type: 'number', min: 1, value: corr.count ?? 5 });
  const windowIn = el('input', { type: 'number', min: 1, value: corr.window_seconds ?? 120 });
  const groupSel = select(RULE_META.fields.map((f) => [f.name, f.label]), corr.group_by || 'src_ip');
  const distinctSel = select(RULE_META.fields.map((f) => [f.name, f.label]), corr.distinct_field || 'dest_port');
  const corrDetail = el('div', { class: 'mt-1' });
  function renderCorr() {
    clear(corrDetail);
    const t = corrTypeSel.value;
    if (!t) return;
    corrDetail.appendChild(el('div', { class: 'sentence' }, t === 'threshold'
      ? ['Fire when it happens more than', countIn, 'times within', windowIn, 'seconds from the same', groupSel]
      : ['Fire when the same', groupSel, 'hits more than', countIn, 'different', distinctSel, 'values within', windowIn, 'seconds']));
  }
  corrTypeSel.addEventListener('change', renderCorr);
  renderCorr();

  // --- advanced JSON
  const jsonIn = el('textarea', { rows: 10, style: 'font-family:var(--mono); font-size:0.82rem;' });
  jsonIn.value = JSON.stringify(condition, null, 2);

  // --- THEN
  const weightIn = el('input', { type: 'number', min: -100, max: 200, value: rule.weight ?? 40 });
  const weightHint = el('div', { class: 'hint' });
  const updateWeightHint = () => {
    const w = Number(weightIn.value) || 0;
    weightHint.textContent = `On its own this makes an event ${priorityForScore(w)} (score ${w}). Scores from all matching rules add up; ≥${RULE_META.thresholds.CRITICAL} is CRITICAL.`;
  };
  weightIn.addEventListener('input', updateWeightHint);
  updateWeightHint();

  const minPrioSel = select([['', "Don't change"]].concat(RULE_META.priorities.slice(0, 4).map((p) => [p, `At least ${p}`])), actions.min_priority || '');
  const incidentChk = el('input', { type: 'checkbox', checked: actions.create_incident ? 'checked' : undefined });
  const incPrioSel = select([['', 'Same as the event']].concat(RULE_META.priorities.slice(0, 4)), actions.incident_priority || '');
  const assignable = RULE_META.users.filter((u) => u.assignable);
  const assignSel = select([['', 'Nobody (assign manually)']].concat(assignable.map((u) => [u.user_id, `${u.full_name} (${u.role.toLowerCase()})`])), actions.assign_to || '');
  const roleChecks = ROLES.map((r) => {
    const box = el('input', { type: 'checkbox', value: r, checked: (actions.notify_roles || []).includes(r) ? 'checked' : undefined });
    return { r, box, node: el('label', { class: 'check' }, [box, `Everyone with role ${r}`]) };
  });
  const userChecks = RULE_META.users.map((u) => {
    const box = el('input', { type: 'checkbox', value: u.user_id, checked: (actions.notify_user_ids || []).includes(u.user_id) ? 'checked' : undefined });
    return { u, box, node: el('label', { class: 'check' }, [box, `${u.full_name} (${u.role.toLowerCase()})`]) };
  });
  const suppressChk = el('input', { type: 'checkbox', checked: actions.suppress ? 'checked' : undefined });
  const responseBox = el('div');
  const syncSuppress = () => {
    responseBox.style.opacity = suppressChk.checked ? '0.4' : '1';
    responseBox.querySelectorAll('input, select').forEach((n) => { n.disabled = suppressChk.checked; });
  };
  suppressChk.addEventListener('change', syncSuppress);

  const whenBlock = el('div', { class: 'builder-block' });
  function renderWhen() {
    clear(whenBlock);
    whenBlock.append(
      el('div', { class: 'flex-between' }, [
        el('h3', {}, '1. WHEN an event matches…'),
        el('button', { type: 'button', class: 'small ghost', onclick: () => {
          if (!advanced) {
            try { jsonIn.value = JSON.stringify(readCondition(), null, 2); } catch (_) { /* keep last JSON */ }
          }
          advanced = !advanced;
          renderWhen();
        } }, advanced ? 'Use the simple builder' : 'Edit as JSON (advanced)'),
      ]),
    );
    if (advanced) {
      whenBlock.append(
        el('div', { class: 'muted-small' }, 'Condition in JSON. Supports nested all/any/none groups and the "sequence" pattern. The simple builder handles flat lists and repeat thresholds.'),
        jsonIn,
      );
      return;
    }
    whenBlock.append(
      el('div', { class: 'muted-small' }, 'Pick the event fields to check. Example: Event type is AUTH_FAILURE and Username is one of root, admin.'),
      el('div', { class: 'sentence', style: 'margin-bottom:8px;' }, ['Match when', matchSel]),
      rowsBox, addBtn,
      el('div', { class: 'builder-block' }, [
        el('h3', {}, '2. REPEATS (optional): a pattern over time'),
        el('div', { class: 'muted-small' }, 'Brute force or scanning is many events, not one. Make the rule fire only once a threshold is passed.'),
        corrTypeSel, corrDetail,
      ]),
    );
  }

  function readCondition() {
    if (advanced) {
      try {
        return JSON.parse(jsonIn.value);
      } catch (err) {
        throw new Error(`The JSON condition is not valid: ${err.message}`);
      }
    }
    const clauses = [...rowsBox.children].map((r) => r.read());
    const cond = { [matchSel.value]: clauses };
    const t = corrTypeSel.value;
    if (t) {
      cond.correlation = {
        type: t,
        group_by: groupSel.value,
        count: parseInt(countIn.value, 10),
        window_seconds: parseInt(windowIn.value, 10),
      };
      if (t === 'distinct_count') cond.correlation.distinct_field = distinctSel.value;
    }
    return cond;
  }

  function readActions() {
    if (suppressChk.checked) return { suppress: true };
    const a = {};
    if (minPrioSel.value) a.min_priority = minPrioSel.value;
    if (incidentChk.checked || assignSel.value) a.create_incident = true;
    if (a.create_incident && incPrioSel.value) a.incident_priority = incPrioSel.value;
    if (assignSel.value) a.assign_to = parseInt(assignSel.value, 10);
    const roles = roleChecks.filter((c) => c.box.checked).map((c) => c.r);
    if (roles.length) a.notify_roles = roles;
    const users = userChecks.filter((c) => c.box.checked).map((c) => c.u.user_id);
    if (users.length) a.notify_user_ids = users;
    return a;
  }

  openModal({
    title: isNew ? 'New detection rule' : `Edit rule: ${rule.name}`,
    saveLabel: isNew ? 'Create rule' : 'Save rule',
    wide: true,
    build: (body) => {
      body.append(
        el('div', { class: 'form-grid' }, [
          field('Rule name', nameIn),
          field('Category', catSel),
          field('MITRE ATT&CK technique', mitreIn, 'Optional reference for analysts'),
        ]),
        el('div', { class: 'mt-1' }, field('Description', descIn)),
        el('label', { class: 'check' }, [enabledIn, 'Rule is enabled (applies to new events within 30 seconds)']),
        whenBlock,
        el('div', { class: 'builder-block' }, [
          el('h3', {}, '3. THEN do this'),
          el('div', { class: 'form-grid' }, [field('Add to the risk score', weightIn, '')]),
          weightHint,
          el('label', { class: 'check mt-1' }, [suppressChk, el('span', {}, [el('b', {}, 'Suppress: '), 'this is known, harmless activity. Auto-dismiss matching events (no alert, no incident).'])]),
          responseBox,
        ]),
      );
      responseBox.append(
        el('div', { class: 'form-grid mt-1' }, [
          field('Raise the event priority', minPrioSel, 'Force a minimum priority whatever the score'),
          el('div', { class: 'field' }, [
            el('label', {}, 'Incident'),
            el('label', { class: 'check' }, [incidentChk, 'Open an incident automatically']),
            incPrioSel,
            el('div', { class: 'hint' }, 'Repeats from the same source are grouped into one open incident.'),
          ]),
          field('Assign the incident to', assignSel, 'They are notified instantly.'),
        ]),
        el('div', { class: 'field mt-1' }, [
          el('label', {}, 'Send a real-time notification to'),
          el('div', { class: 'form-grid' }, [el('div', {}, roleChecks.map((c) => c.node)), el('div', {}, userChecks.map((c) => c.node))]),
        ]),
      );
      renderWhen();
      syncSuppress();
    },
    onSave: async () => {
      const payload = {
        name: nameIn.value.trim(),
        category: catSel.value,
        mitre_technique: mitreIn.value.trim() || null,
        description: descIn.value.trim() || null,
        is_enabled: enabledIn.checked,
        condition: readCondition(),
        weight: Number(weightIn.value),
        actions: readActions(),
      };
      if (!payload.name) throw new Error('Give the rule a name.');
      if (isNew) await api.post('/rules', payload);
      else await api.patch(`/rules/${rule.rule_id}`, payload);
      showToast(isNew ? 'Rule created' : 'Rule saved', `${payload.name} applies to new events within 30 seconds.`, null, 'ok');
      await onSaved();
    },
  });
}

function openRuleTester(rule) {
  const samples = RULE_META.sample_events;
  const sampleSel = select([['', 'Choose a sample event…']].concat(Object.keys(samples)), '');
  const eventIdIn = el('input', { type: 'number', placeholder: 'or an event ID from the Alert Queue' });
  const jsonIn = el('textarea', { rows: 8, style: 'font-family:var(--mono); font-size:0.82rem;' });
  jsonIn.value = JSON.stringify(samples[Object.keys(samples)[0]], null, 2);
  sampleSel.addEventListener('change', () => { if (sampleSel.value) jsonIn.value = JSON.stringify(samples[sampleSel.value], null, 2); });
  const result = el('div', { class: 'mt-2' });

  openModal({
    title: `Test rule: ${rule.name}`,
    saveLabel: 'Run test',
    wide: true,
    build: (body) => body.append(
      el('div', { class: 'muted-small' }, `Rule checks: ${conditionSummary(rule.condition)}`),
      el('div', { class: 'form-grid mt-1' }, [field('Sample event', sampleSel), field('Real event', eventIdIn)]),
      el('div', { class: 'mt-1' }, field('Event fields (JSON)', jsonIn)),
      result,
    ),
    onSave: async () => {
      const body = eventIdIn.value ? { event_id: parseInt(eventIdIn.value, 10) } : (() => {
        try { return { sample_event: JSON.parse(jsonIn.value) }; } catch (e) { throw new Error(`Event JSON is not valid: ${e.message}`); }
      })();
      const r = await api.post(`/rules/${rule.rule_id}/test`, body);
      clear(result);
      result.append(
        el('div', { class: `flash ${r.matched ? 'flash-success' : 'flash-error'}` }, r.matched
          ? `MATCH: this event would get +${r.weight} risk${r.would_suppress ? ' and be auto-dismissed' : ''}${r.would_create_incident ? ' and open an incident' : ''}.`
          : 'NO MATCH: this rule would not fire for this event.'),
        r.clauses.length ? el('ul', {}, r.clauses.map((c) => el('li', { class: c.passed ? 'clause-pass' : 'clause-fail' },
          c.group ? `${c.passed ? '✔' : '✘'} nested group` : `${c.passed ? '✔' : '✘'} ${clauseText(c)}  (event has: ${c.actual === undefined || c.actual === null ? 'nothing' : JSON.stringify(c.actual)})`))) : null,
        r.correlation_note ? el('div', { class: 'muted-small' }, r.correlation_note) : null,
      );
      return false; // keep the dialog open to show the result
    },
  });
}

async function initRules() {
  const root = document.getElementById('admin-rules-root');
  RULE_META = await api.get('/rules/meta');
  const t = RULE_META.thresholds;

  root.appendChild(help('How detection rules work', [
    el('div', {}, 'Every incoming log event is checked against all enabled rules. Each rule reads like a sentence:'),
    el('ol', {}, [
      el('li', {}, [el('b', {}, 'WHEN'), ' the event matches some conditions (e.g. event type is a failed login, user is root)…']),
      el('li', {}, [el('b', {}, 'REPEATS'), ' (optional) …and it happens more than N times in M seconds (brute force, scanning)…']),
      el('li', {}, [el('b', {}, 'THEN'), ' add risk points, and optionally raise the priority, open an incident, assign it to someone, notify people, or suppress known-harmless noise.']),
    ]),
    el('div', { class: 'mt-1' }, ['Risk points from all matching rules add up to the event\'s score: ',
      priorityPill('CRITICAL'), ` ≥ ${t.CRITICAL}  `, priorityPill('HIGH'), ` ≥ ${t.HIGH}  `, priorityPill('MEDIUM'), ` ≥ ${t.MEDIUM}  `, priorityPill('LOW'), ` ≥ ${t.LOW}. A CRITICAL event always opens an incident.`]),
  ]));

  const search = el('input', { type: 'search', placeholder: 'Search rules…', style: 'max-width:260px;' });
  const catFilter = select([['', 'All categories']].concat(RULE_META.categories), '');
  root.appendChild(el('div', { class: 'flex-between', style: 'margin-bottom:10px; gap:10px; flex-wrap:wrap;' }, [
    el('div', { class: 'flex' }, [search, catFilter]),
    el('button', { class: 'primary', onclick: () => openRuleEditor({}, load) }, '+ New rule'),
  ]));

  const tbody = el('tbody');
  root.appendChild(el('div', { class: 'card', style: 'overflow-x:auto;' }, el('table', {}, [
    el('thead', {}, el('tr', {}, ['On', 'Rule', 'When', 'Then', 'Hits (24h)', ''].map((h) => el('th', {}, h)))),
    tbody,
  ])));

  let rules = [];
  function render() {
    const q = search.value.trim().toLowerCase();
    clear(tbody);
    const shown = rules.filter((r) => (!catFilter.value || r.category === catFilter.value)
      && (!q || `${r.name} ${r.description || ''} ${r.category}`.toLowerCase().includes(q)));
    if (!shown.length) tbody.appendChild(el('tr', {}, el('td', { colspan: 6, class: 'empty' }, 'No rules match.')));
    shown.forEach((rule) => {
      const toggle = el('input', { type: 'checkbox', checked: rule.is_enabled ? 'checked' : undefined, title: 'Enable / disable', onchange: async (e) => {
        try {
          await api.patch(`/rules/${rule.rule_id}`, { is_enabled: e.target.checked });
          rule.is_enabled = e.target.checked;
          showToast(`Rule ${e.target.checked ? 'enabled' : 'disabled'}`, rule.name, null, 'ok');
        } catch (err) {
          e.target.checked = !e.target.checked;
          window.alert(err.message);
        }
      } });
      tbody.appendChild(el('tr', { style: rule.is_enabled ? '' : 'opacity:0.55;' }, [
        el('td', {}, toggle),
        el('td', { style: 'min-width:200px;' }, [
          el('div', { style: 'font-weight:600;' }, rule.name),
          el('div', {}, [el('span', { class: 'tag' }, rule.category), rule.mitre_technique ? el('span', { class: 'tag' }, rule.mitre_technique) : null]),
          rule.description ? el('div', { class: 'muted-small' }, rule.description) : null,
        ]),
        el('td', { class: 'muted-small', style: 'max-width:340px;' }, conditionSummary(rule.condition)),
        el('td', { style: 'max-width:260px;' }, actionTags(rule)),
        el('td', {}, [el('div', { style: 'font-weight:600;' }, String(rule.hits_24h)), el('div', { class: 'muted-small' }, rule.last_triggered_at ? timeAgo(rule.last_triggered_at) : '')]),
        el('td', {}, el('div', { class: 'btn-row' }, [
          el('button', { class: 'small', onclick: () => openRuleEditor(rule, load) }, 'Edit'),
          el('button', { class: 'small', onclick: () => openRuleTester(rule) }, 'Test'),
          el('button', { class: 'small', onclick: () => openRuleEditor({ ...rule, rule_id: undefined, name: `${rule.name} (copy)` }, load) }, 'Duplicate'),
          el('button', { class: 'small', onclick: () => confirmAndRun(`Delete rule "${rule.name}"? This cannot be undone.`, async () => { await api.del(`/rules/${rule.rule_id}`); await load(); }) }, 'Delete'),
        ])),
      ]));
    });
  }

  async function load() {
    rules = (await api.get('/rules')).data;
    render();
  }
  search.addEventListener('input', render);
  catFilter.addEventListener('change', render);
  await load();
}

// =====================================================================
// Critical assets
// =====================================================================
const IMPORTANCE = [
  ['1.5', 'Important (×1.5)'],
  ['2', 'Very important (×2)'],
  ['3', 'Mission-critical (×3)'],
  ['custom', 'Custom…'],
];
function importanceLabel(m) {
  const found = IMPORTANCE.find(([v]) => Number(v) === Number(m));
  return found ? found[1] : `Custom (×${m})`;
}
const KIND_LABEL = { ip: 'Single IP address', network: 'Network range', hostname: 'Hostname' };

async function initAssets() {
  const root = document.getElementById('admin-assets-root');

  root.appendChild(help('What are critical assets?', [
    el('div', {}, 'Some machines matter more than others: the domain controller, the payment server, the customer database. Mark them here and SentryLite multiplies the risk score of any attack that targets them, so those alerts rise to the top of the queue.'),
    el('ul', {}, [
      el('li', {}, ['Identify an asset by a single IP (', el('code', {}, '10.0.0.10'), '), a whole network range (', el('code', {}, '10.0.0.0/24'), ') or a hostname (', el('code', {}, 'db01'), ').']),
      el('li', {}, 'It matches when the event\'s target IP or hostname is the asset.'),
      el('li', {}, ['Example: a port scan scoring 40 (', priorityPill('MEDIUM'), ') against a ×2 asset becomes 80 (', priorityPill('HIGH'), ').']),
    ]),
  ]));

  // --- check tool
  const checkIn = el('input', { type: 'text', placeholder: 'IP address or hostname, e.g. 10.0.0.10', style: 'max-width:320px;' });
  const checkOut = el('div', { class: 'mt-1' });
  async function runCheck() {
    if (!checkIn.value.trim()) return;
    try {
      const r = await api.get(`/assets/check${qs({ target: checkIn.value.trim(), score: 40 })}`);
      clear(checkOut);
      checkOut.append(r.matched
        ? el('div', { class: 'flash flash-success' }, [`${r.target} is protected as "${r.asset.label}" (×${r.asset.criticality_multiplier}). An attack scoring ${r.example.base_score} (`, priorityPill(r.example.base_priority), `) against it becomes ${r.example.final_score} (`, priorityPill(r.example.final_priority), ').'])
        : el('div', { class: 'flash flash-error' }, `${r.target} is not a critical asset. Attacks against it keep their normal score.`));
    } catch (err) {
      window.alert(err.message);
    }
  }
  checkIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCheck(); });
  root.appendChild(el('div', { class: 'card', style: 'margin-bottom:16px;' }, [
    el('h2', { class: 'section-title' }, 'Check an address'),
    el('div', { class: 'flex' }, [checkIn, el('button', { onclick: runCheck }, 'Check')]),
    checkOut,
  ]));

  root.appendChild(el('div', { class: 'flex-between', style: 'margin-bottom:10px;' }, [
    el('h2', { class: 'section-title', style: 'margin:0;' }, 'Protected assets'),
    el('button', { class: 'primary', onclick: () => editAsset() }, '+ Add critical asset'),
  ]));
  const tbody = el('tbody');
  root.appendChild(el('div', { class: 'card', style: 'overflow-x:auto;' }, el('table', {}, [
    el('thead', {}, el('tr', {}, ['On', 'Asset', 'Matches', 'Importance', 'Threats (24h)', 'Last threat', ''].map((h) => el('th', {}, h)))),
    tbody,
  ])));

  function editAsset(existing = null) {
    const labelIn = el('input', { type: 'text', value: existing?.label || '', placeholder: 'e.g. Payment server' });
    const idIn = el('input', { type: 'text', value: existing?.identifier || '', placeholder: '10.0.0.30  or  10.0.5.0/24  or  pay01' });
    const current = existing ? String(Number(existing.criticality_multiplier)) : '1.5';
    const preset = IMPORTANCE.some(([v]) => v === current) ? current : 'custom';
    const impSel = select(IMPORTANCE, preset);
    const customIn = el('input', { type: 'number', min: 1, max: 5, step: 0.1, value: existing ? existing.criticality_multiplier : 2.5 });
    const customWrap = el('div', { hidden: preset === 'custom' ? undefined : 'hidden' }, field('Custom multiplier (1 to 5)', customIn));
    impSel.addEventListener('change', () => { customWrap.hidden = impSel.value !== 'custom'; });

    openModal({
      title: existing ? `Edit ${existing.label}` : 'Add a critical asset',
      saveLabel: existing ? 'Save' : 'Add asset',
      build: (body) => body.append(el('div', { class: 'form-grid' }, [
        field('Name', labelIn, 'What people call this machine'),
        field('IP, network range or hostname', idIn, 'Matched against the target of each event'),
        field('How important is it?', impSel, 'Attack scores against it are multiplied by this'),
        customWrap,
      ])),
      onSave: async () => {
        const payload = {
          label: labelIn.value.trim(),
          identifier: idIn.value.trim(),
          criticality_multiplier: impSel.value === 'custom' ? Number(customIn.value) : Number(impSel.value),
        };
        if (!payload.label || !payload.identifier) throw new Error('Name and IP/range/hostname are required.');
        if (existing) await api.patch(`/assets/${existing.asset_id}`, payload);
        else await api.post('/assets', payload);
        showToast(existing ? 'Asset updated' : 'Asset added', `${payload.label} (${payload.identifier})`, null, 'ok');
        await load();
      },
    });
  }

  async function load() {
    const res = await api.get('/assets');
    clear(tbody);
    if (!res.data.length) tbody.appendChild(el('tr', {}, el('td', { colspan: 7, class: 'empty' }, 'No critical assets yet.')));
    res.data.forEach((a) => {
      const toggle = el('input', { type: 'checkbox', checked: a.is_enabled ? 'checked' : undefined, onchange: async (e) => {
        await api.patch(`/assets/${a.asset_id}`, { is_enabled: e.target.checked });
        await load();
      } });
      tbody.appendChild(el('tr', { style: a.is_enabled ? '' : 'opacity:0.55;' }, [
        el('td', {}, toggle),
        el('td', { style: 'font-weight:600;' }, a.label),
        el('td', {}, [el('code', { class: 'inline' }, a.identifier), el('div', { class: 'muted-small' }, KIND_LABEL[a.kind] || '')]),
        el('td', {}, importanceLabel(a.criticality_multiplier)),
        el('td', {}, a.threats_24h ? el('b', { style: 'color:var(--critical)' }, String(a.threats_24h)) : '0'),
        el('td', {}, a.last_threat_at ? timeAgo(a.last_threat_at) : '-'),
        el('td', {}, el('div', { class: 'btn-row' }, [
          el('button', { class: 'small', onclick: () => editAsset(a) }, 'Edit'),
          el('button', { class: 'small', onclick: () => confirmAndRun(`Remove "${a.label}" from critical assets?`, async () => { await api.del(`/assets/${a.asset_id}`); await load(); }) }, 'Delete'),
        ])),
      ]));
    });
  }
  await load();
}

// =====================================================================
// Users
// =====================================================================
async function initUsers() {
  const root = document.getElementById('admin-users-root');
  root.appendChild(help('Roles', [el('ul', {}, ROLES.map((r) => el('li', {}, [el('b', {}, r), `: ${ROLE_HELP[r]}`])))]));
  root.appendChild(el('div', { class: 'flex-between', style: 'margin-bottom:10px;' }, [
    el('h2', { class: 'section-title', style: 'margin:0;' }, 'Accounts'),
    el('button', { class: 'primary', onclick: () => addUser() }, '+ Add user'),
  ]));
  const tbody = el('tbody');
  root.appendChild(el('div', { class: 'card', style: 'overflow-x:auto;' }, el('table', {}, [
    el('thead', {}, el('tr', {}, ['Name', 'Username', 'Email', 'Role', 'Status', 'Last login', ''].map((h) => el('th', {}, h)))),
    tbody,
  ])));

  function addUser() {
    const usernameIn = el('input', { type: 'text', placeholder: 'e.g. jdoe' });
    const fullNameIn = el('input', { type: 'text', placeholder: 'e.g. Jane Doe' });
    const emailIn = el('input', { type: 'text', placeholder: 'jane@example.com' });
    const roleSel = select(ROLES, 'ANALYST');
    const roleHint = el('div', { class: 'hint' }, ROLE_HELP.ANALYST);
    roleSel.addEventListener('change', () => { roleHint.textContent = ROLE_HELP[roleSel.value]; });
    openModal({
      title: 'Add a user',
      saveLabel: 'Create user',
      build: (body) => body.append(el('div', { class: 'form-grid' }, [
        field('Full name', fullNameIn), field('Username', usernameIn), field('Email', emailIn),
        el('div', { class: 'field' }, [el('label', {}, 'Role'), roleSel, roleHint]),
      ])),
      onSave: async () => {
        const user = await api.post('/users', {
          username: usernameIn.value.trim(), email: emailIn.value.trim(), full_name: fullNameIn.value.trim(), role: roleSel.value,
        });
        await load();
        openModal({
          title: `${user.full_name} created`,
          hideSave: true,
          build: (body) => body.append(
            el('div', {}, 'Give them these sign-in details. They must choose a new password the first time they sign in.'),
            el('pre', { class: 'code' }, `Address:  ${window.location.origin}\nUsername: ${user.username}\nPassword: ${user.temporary_password}`),
            el('div', { class: 'muted-small' }, 'This temporary password is shown only once.'),
          ),
        });
      },
    });
  }

  async function load() {
    const res = await api.get('/users?per_page=200');
    clear(tbody);
    res.data.forEach((user) => {
      const roleSel = select(ROLES, user.role, { onchange: async (e) => {
        try {
          await api.patch(`/users/${user.user_id}`, { role: e.target.value });
          showToast('Role changed', `${user.full_name} is now ${e.target.value}`, null, 'ok');
        } catch (err) {
          window.alert(err.message);
        }
      } });
      tbody.appendChild(el('tr', { style: user.is_active ? '' : 'opacity:0.55;' }, [
        el('td', { style: 'font-weight:600;' }, user.full_name),
        el('td', {}, user.username),
        el('td', {}, user.email),
        el('td', {}, roleSel),
        el('td', {}, el('span', { class: `status ${user.is_active ? 'status-ok' : 'status-off'}` }, user.is_active ? 'Active' : 'Deactivated')),
        el('td', {}, user.last_login_at ? timeAgo(user.last_login_at) : 'never'),
        el('td', {}, user.is_active
          ? el('button', { class: 'small', onclick: () => confirmAndRun(`Deactivate ${user.full_name}? They will no longer be able to sign in.`, async () => { await api.del(`/users/${user.user_id}`); await load(); }) }, 'Deactivate')
          : el('button', { class: 'small', onclick: () => confirmAndRun(`Reactivate ${user.full_name}?`, async () => { await api.patch(`/users/${user.user_id}`, { is_active: true }); await load(); }) }, 'Reactivate')),
      ]));
    });
  }
  await load();
}

if (document.getElementById('admin-sources-root')) initSources();
if (document.getElementById('admin-rules-root')) initRules();
if (document.getElementById('admin-users-root')) initUsers();
if (document.getElementById('admin-assets-root')) initAssets();

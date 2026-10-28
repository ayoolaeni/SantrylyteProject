import { api } from './api.js';
import { el, clear, showToast, priorityPill } from './ui.js';
import { connectLive, subscribe } from './socket.js';

const root = document.getElementById('simulator-root');
const counters = { events: 0, alerts: 0, incidents: 0 };
const PRIORITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const byPriority = Object.fromEntries(PRIORITY_ORDER.map((p) => [p, 0]));

const liveBox = el('div', { class: 'card', style: 'margin-bottom:16px;' });
const bgBox = el('div', { class: 'card', style: 'margin-bottom:16px;' });
const grid = el('div', { class: 'scenario-grid' });

function renderLive() {
  clear(liveBox);
  liveBox.append(
    el('div', { class: 'flex-between' }, [
      el('h2', { class: 'section-title', style: 'margin:0;' }, 'What SentryLite has seen since you opened this page'),
      el('button', { class: 'small ghost', onclick: () => { Object.keys(counters).forEach((k) => (counters[k] = 0)); PRIORITY_ORDER.forEach((p) => (byPriority[p] = 0)); renderLive(); } }, 'Reset'),
    ]),
    el('div', { class: 'stat-inline mt-1' }, [
      el('div', {}, [el('b', {}, String(counters.events)), 'events analysed']),
      el('div', {}, [el('b', { style: 'color:var(--high)' }, String(counters.alerts)), 'high/critical alerts']),
      el('div', {}, [el('b', { style: 'color:var(--critical)' }, String(counters.incidents)), 'incidents opened']),
      el('div', { class: 'flex', style: 'gap:6px; flex-wrap:wrap;' }, PRIORITY_ORDER.filter((p) => byPriority[p]).map((p) => el('span', {}, [priorityPill(p), ` ${byPriority[p]}`]))),
    ]),
  );
}

let bgTimer = null;
function renderBackground(status) {
  clear(bgBox);
  clearInterval(bgTimer);
  const minutesSel = el('select', { style: 'width:auto;' }, [5, 10, 15, 30, 60].map((m) => el('option', { value: m, selected: m === 10 ? 'selected' : undefined }, `${m} minutes`)));
  const statusText = el('span', { class: `status ${status.running ? 'status-ok' : 'status-off'}` },
    status.running ? `Running: ${Math.ceil(status.seconds_left / 60)} min left (started by ${status.started_by})` : 'Off');
  bgBox.append(
    el('h2', { class: 'section-title' }, ['Continuous background traffic ', statusText]),
    el('div', { class: 'muted-small', style: 'margin-bottom:10px;' },
      'Keeps a steady flow of everyday logins and page views, with a small attack every 30–60 seconds, so the dashboard looks alive during a presentation.'),
    status.running
      ? el('button', { class: 'danger', onclick: async () => renderBackground(await api.post('/simulate/background', { action: 'stop' })) }, 'Stop background traffic')
      : el('div', { class: 'flex' }, [
        el('button', { class: 'primary', onclick: async () => {
          try {
            const s = await api.post('/simulate/background', { action: 'start', minutes: parseInt(minutesSel.value, 10) });
            showToast('Background traffic started', `Running for ${minutesSel.value} minutes`, null, 'ok');
            renderBackground(s);
          } catch (err) { window.alert(err.message); }
        } }, 'Start background traffic'),
        el('span', { class: 'muted-small' }, 'for'), minutesSel,
      ]),
  );
  if (status.running) {
    bgTimer = setInterval(async () => renderBackground(await api.get('/simulate/background')), 30000);
  }
}

function scenarioCard(s) {
  const btn = el('button', { class: 'danger' }, '▶ Launch attack');
  const result = el('div', { class: 'muted-small' });
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Launching…';
    try {
      const r = await api.post('/simulate', { scenario: s.id });
      result.textContent = `Sent ${r.lines} log lines from attacker ${r.attacker_ip} over ~${Math.max(1, Math.round(r.duration_seconds))}s.`;
      showToast(`Simulation started: ${r.name}`, `Attacker ${r.attacker_ip}. Watch the dashboard and alerts.`, () => (window.location.href = '/'), 'info');
      setTimeout(() => { btn.disabled = false; btn.textContent = '▶ Launch again'; }, Math.max(2000, r.duration_seconds * 1000));
    } catch (err) {
      btn.disabled = false;
      btn.textContent = '▶ Launch attack';
      window.alert(err.message);
    }
  });
  return el('div', { class: `card scenario${s.id === 'kill_chain' ? ' featured' : ''}` }, [
    el('div', { class: 'flex-between' }, [el('h3', {}, s.name), s.id === 'kill_chain' ? el('span', { class: 'tag tag-warn' }, 'Best for demos') : null]),
    el('div', { class: 'muted-small' }, s.mitre),
    el('div', {}, s.description),
    el('div', { class: 'expect' }, [el('b', {}, 'What you should see: '), s.expect]),
    el('div', { class: 'actions' }, [btn]),
    result,
  ]);
}

async function init() {
  const data = await api.get('/simulate/scenarios');
  root.append(liveBox, bgBox, el('h2', { class: 'section-title' }, 'Attack scenarios'), grid);
  renderLive();
  renderBackground(data.background);
  const ordered = data.scenarios.slice().sort((a, b) => (a.id === 'kill_chain' ? -1 : b.id === 'kill_chain' ? 1 : 0));
  ordered.forEach((s) => grid.appendChild(scenarioCard(s)));

  const socket = connectLive();
  socket.on('connect', () => subscribe(['all_events', 'priority_high', 'priority_critical', 'incidents']));
  socket.on('event:new', (batch) => {
    counters.events += batch.length;
    batch.forEach((e) => { if (e.priority_level in byPriority) byPriority[e.priority_level] += 1; });
    renderLive();
  });
  socket.on('alert:high', () => { counters.alerts += 1; renderLive(); });
  socket.on('incident:created', () => { counters.incidents += 1; renderLive(); });
}

init();

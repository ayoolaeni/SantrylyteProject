import { api, qs } from './api.js';
import { connectLive, onBackfill, subscribe, trackLastSeen } from './socket.js';
import { el, priorityPill, clear } from './ui.js';

const COLORS = { CRITICAL: '#e5484d', HIGH: '#f76808', MEDIUM: '#f5d90a', LOW: '#3b9eff', INFORMATIONAL: '#8b98a5' };
const PRIORITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const MAX_FEED_ROWS = 200;
const GRID = '#2a3441';
const TICK = '#8b98a5';

let feedPaused = false;
let feedBuffer = [];
const seenIds = new Set();
let volumeChart = null;
let priorityChart = null;
let sourcesChart = null;
let attackersChart = null;

// ---------- KPI cards ----------
function kpiCard(value, label, href, alert = false) {
  return el('a', { class: `card kpi-card${alert ? ' alert' : ''}`, href }, [
    el('div', { class: 'kpi-value' }, String(value)),
    el('div', { class: 'kpi-label' }, label),
  ]);
}

function minutes(value) {
  if (value === null || value === undefined) return '-';
  return value < 120 ? `${value}m` : `${(value / 60).toFixed(1)}h`;
}

async function loadSummary() {
  const s = await api.get('/stats/summary');
  const row = document.getElementById('kpi-row');
  clear(row);
  const crit = s.open_incidents_by_priority.CRITICAL || 0;
  row.appendChild(kpiCard(crit, 'Open critical incidents', '/incidents?assigned_to=all&priority=CRITICAL', crit > 0));
  row.appendChild(kpiCard(s.open_incidents_by_priority.HIGH || 0, 'Open high incidents', '/incidents?assigned_to=all&priority=HIGH'));
  row.appendChild(kpiCard(s.my_open_incidents ?? 0, 'Assigned to me', '/incidents?assigned_to=me'));
  row.appendChild(kpiCard(s.unassigned_open_incidents ?? 0, 'Unassigned incidents', '/incidents?assigned_to=unassigned'));
  row.appendChild(kpiCard(s.events_last_24h, 'Events (24h)', '/alerts'));
  row.appendChild(kpiCard(minutes(s.mtta_minutes), 'Mean time to acknowledge', '/reports'));
  row.appendChild(kpiCard(minutes(s.mttr_minutes), 'Mean time to resolve', '/reports'));
}

let summaryTimer = null;
function scheduleSummary(delay = 800) {
  clearTimeout(summaryTimer);
  summaryTimer = setTimeout(() => loadSummary().catch(() => {}), delay);
}

// ---------- events-per-minute chart (stacked bars, live) ----------
function minuteKey(date) {
  const d = new Date(date);
  d.setSeconds(0, 0);
  return d.getTime();
}
const minuteLabel = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
let volumeKeys = [];

function ensureVolumeChart() {
  if (volumeChart) return volumeChart;
  volumeChart = new window.Chart(document.getElementById('volume-chart'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: PRIORITIES.map((p) => ({ label: p, data: [], backgroundColor: COLORS[p], stack: 'events', borderWidth: 0 })),
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { stacked: true, ticks: { color: TICK, maxTicksLimit: 12 }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: TICK, precision: 0 }, grid: { color: GRID } },
      },
      plugins: { legend: { labels: { color: '#e6edf3', boxWidth: 12 } } },
    },
  });
  return volumeChart;
}

function updateVolumeTotal() {
  const chart = ensureVolumeChart();
  const total = chart.data.datasets.reduce((sum, ds) => sum + ds.data.reduce((a, b) => a + b, 0), 0);
  document.getElementById('volume-total').textContent = `${total} events in the last hour`;
}

async function loadTimeseries() {
  const res = await api.get('/stats/timeseries?interval=1m&window=1h');
  const chart = ensureVolumeChart();
  volumeKeys = res.series.map((p) => new Date(p.bucket).getTime());
  chart.data.labels = volumeKeys.map(minuteLabel);
  PRIORITIES.forEach((p, i) => {
    chart.data.datasets[i].data = res.series.map((pt) => pt[p] || 0);
  });
  chart.update('none');
  updateVolumeTotal();
}

function addToVolume(event) {
  const chart = ensureVolumeChart();
  const key = minuteKey(event.timestamp || Date.now());
  let idx = volumeKeys.indexOf(key);
  if (idx === -1) {
    if (volumeKeys.length && key < volumeKeys[0]) return; // older than the window
    // new minute: roll the window forward
    while (volumeKeys.length && volumeKeys[volumeKeys.length - 1] < key) {
      const next = volumeKeys[volumeKeys.length - 1] + 60000;
      volumeKeys.push(next);
      chart.data.labels.push(minuteLabel(next));
      chart.data.datasets.forEach((ds) => ds.data.push(0));
      if (volumeKeys.length > 60) {
        volumeKeys.shift();
        chart.data.labels.shift();
        chart.data.datasets.forEach((ds) => ds.data.shift());
      }
    }
    idx = volumeKeys.indexOf(key);
    if (idx === -1) {
      volumeKeys.push(key);
      chart.data.labels.push(minuteLabel(key));
      chart.data.datasets.forEach((ds) => ds.data.push(0));
      idx = volumeKeys.length - 1;
    }
  }
  const p = PRIORITIES.indexOf(event.priority_level);
  if (p >= 0) chart.data.datasets[p].data[idx] += 1;
}

// ---------- priority doughnut (live) ----------
function ensurePriorityChart() {
  if (priorityChart) return priorityChart;
  priorityChart = new window.Chart(document.getElementById('priority-chart'), {
    type: 'doughnut',
    data: { labels: PRIORITIES, datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: PRIORITIES.map((p) => COLORS[p]), borderWidth: 0 }] },
    options: { animation: false, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#e6edf3', boxWidth: 12 } } } },
  });
  return priorityChart;
}

async function loadPriorityDistribution() {
  const res = await api.get('/stats/priority-distribution?window=24h');
  const chart = ensurePriorityChart();
  chart.data.datasets[0].data = PRIORITIES.map((p) => res[p] || 0);
  chart.update('none');
}

// ---------- horizontal bar helpers ----------
function hbar(canvasId, color) {
  return new window.Chart(document.getElementById(canvasId), {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: color, borderWidth: 0 }] },
    options: {
      indexAxis: 'y',
      animation: false,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: TICK, precision: 0 }, grid: { color: GRID } },
        y: { ticks: { color: '#e6edf3' }, grid: { display: false } },
      },
    },
  });
}

async function loadTopSources() {
  const res = await api.get('/stats/top-sources?limit=6&window=24h');
  if (!sourcesChart) sourcesChart = hbar('sources-chart', '#3b9eff');
  sourcesChart.data.labels = res.map((r) => (r.registered ? r.source_name : `${r.source_name} (unregistered)`));
  sourcesChart.data.datasets[0].data = res.map((r) => r.count);
  sourcesChart.update('none');
}

async function loadTopAttackers() {
  const res = await api.get('/stats/top-attackers?limit=7&window=24h');
  if (!attackersChart) attackersChart = hbar('attackers-chart', '#e5484d');
  attackersChart.data.labels = res.map((r) => `${r.src_ip} (${r.count})`);
  attackersChart.data.datasets[0].data = res.map((r) => Math.round(r.total_severity));
  attackersChart.update('none');
}

let rankingTimer = null;
function scheduleRankings() {
  clearTimeout(rankingTimer);
  rankingTimer = setTimeout(() => {
    loadTopSources().catch(() => {});
    loadTopAttackers().catch(() => {});
  }, 1500);
}

// ---------- live feed ----------
function feedRow(event, isNew) {
  const target = event.src_ip ? `/alerts?src_ip=${encodeURIComponent(event.src_ip)}` : '/alerts';
  return el('tr', { class: `clickable${isNew ? ' flash-row' : ''}`, onclick: () => (window.location.href = target), title: 'Open in the Alert Queue' }, [
    el('td', { style: 'white-space:nowrap;' }, new Date(event.timestamp).toLocaleTimeString()),
    el('td', {}, priorityPill(event.priority_level)),
    el('td', {}, event.event_type),
    el('td', {}, event.src_ip || '-'),
    el('td', { style: 'max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;', title: event.message || '' }, event.message || ''),
  ]);
}

function renderFeed(newIds = new Set()) {
  const tbody = document.getElementById('feed-body');
  clear(tbody);
  feedBuffer.slice(0, MAX_FEED_ROWS).forEach((event) => tbody.appendChild(feedRow(event, newIds.has(event.event_id))));
  document.getElementById('feed-empty').hidden = feedBuffer.length > 0;
  document.getElementById('feed-count').textContent = feedBuffer.length ? `showing ${Math.min(feedBuffer.length, MAX_FEED_ROWS)}` : '';
}

function pushEvents(events, { live = true } = {}) {
  const fresh = events.filter((e) => !seenIds.has(e.event_id));
  if (!fresh.length) return;
  fresh.forEach((e) => {
    seenIds.add(e.event_id);
    trackLastSeen(e.timestamp);
  });
  if (live) {
    fresh.forEach((e) => {
      addToVolume(e);
      const p = PRIORITIES.indexOf(e.priority_level);
      if (p >= 0 && priorityChart) priorityChart.data.datasets[0].data[p] += 1;
    });
    if (volumeChart) {
      volumeChart.update('none');
      updateVolumeTotal();
    }
    if (priorityChart) priorityChart.update('none');
    scheduleRankings();
    scheduleSummary();
  }
  // newest first
  const sorted = fresh.slice().sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  feedBuffer = sorted.concat(feedBuffer).slice(0, MAX_FEED_ROWS);
  if (!feedPaused) renderFeed(live ? new Set(fresh.map((e) => e.event_id)) : new Set());
}

async function loadRecentEvents() {
  const res = await api.get(`/events${qs({ per_page: 50, sort: '-timestamp' })}`);
  pushEvents(res.data || [], { live: false });
  renderFeed();
}

function setupFeedControls() {
  const btn = document.getElementById('feed-pause-toggle');
  btn.addEventListener('click', () => {
    feedPaused = !feedPaused;
    btn.textContent = feedPaused ? 'Resume' : 'Pause';
    if (!feedPaused) renderFeed();
  });
}

// ---------- socket ----------
function setLive(on) {
  const ind = document.getElementById('dash-live');
  ind.className = `live ${on ? 'on' : 'off'}`;
  ind.textContent = on ? 'Live: updating in real time' : 'Disconnected: retrying…';
}

function setupSocket() {
  const socket = connectLive();
  if (socket.connected) setLive(true);
  socket.on('connect', () => {
    setLive(true);
    subscribe(['all_events', 'priority_high', 'priority_critical', 'incidents']);
  });
  socket.on('disconnect', () => setLive(false));
  socket.on('connect_error', () => setLive(false));
  socket.on('event:new', (batch) => pushEvents(batch));
  socket.on('incident:created', () => scheduleSummary(200));
  socket.on('incident:updated', () => scheduleSummary(200));
  socket.on('stats:tick', () => scheduleSummary(100));
  onBackfill((events) => pushEvents(events));
}

async function init() {
  setupFeedControls();
  ensureVolumeChart();
  ensurePriorityChart();
  setupSocket();
  await Promise.all([
    loadSummary(), loadTimeseries(), loadPriorityDistribution(), loadTopSources(), loadTopAttackers(), loadRecentEvents(),
  ]).catch(() => {});
  // Re-sync with the server periodically so the charts self-correct even if a live message was missed.
  setInterval(() => loadTimeseries().catch(() => {}), 30000);
  setInterval(() => loadPriorityDistribution().catch(() => {}), 30000);
  setInterval(scheduleRankings, 30000);
}

init();

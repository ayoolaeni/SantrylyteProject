import { api } from './api.js';
import { connectLive, onBackfill, subscribe, trackLastSeen } from './socket.js';
import { el, priorityPill, showToast, notifyBrowser, clear } from './ui.js';

const COLORS = { CRITICAL: '#e5484d', HIGH: '#f76808', MEDIUM: '#f5d90a', LOW: '#3b9eff', INFORMATIONAL: '#8b98a5' };
const PRIORITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const MAX_FEED_ROWS = 200;

let feedPaused = false;
let feedBuffer = [];
let volumeChart = null;
let priorityChart = null;
let sourcesChart = null;

function kpiCard(value, label, href) {
  return el('a', { class: 'card kpi-card', href }, [
    el('div', { class: 'kpi-value' }, String(value)),
    el('div', { class: 'kpi-label' }, label),
  ]);
}

async function loadSummary() {
  const summary = await api.get('/stats/summary');
  const row = document.getElementById('kpi-row');
  clear(row);
  row.appendChild(kpiCard(summary.open_incidents_by_priority.CRITICAL || 0, 'Open Critical', '/alerts?priority=CRITICAL'));
  row.appendChild(kpiCard(summary.open_incidents_by_priority.HIGH || 0, 'Open High', '/alerts?priority=HIGH'));
  row.appendChild(kpiCard(summary.events_last_24h, 'Events (24h)', '/alerts'));
  row.appendChild(kpiCard(summary.mtta_minutes === null ? '-' : `${summary.mtta_minutes}m`, 'MTTA', '/incidents'));
  row.appendChild(kpiCard(summary.mttr_minutes === null ? '-' : `${summary.mttr_minutes}m`, 'MTTR', '/incidents'));
}

function ensureVolumeChart() {
  if (volumeChart) return volumeChart;
  const ctx = document.getElementById('volume-chart');
  volumeChart = new window.Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: PRIORITIES.map((p) => ({
        label: p,
        data: [],
        borderColor: COLORS[p],
        backgroundColor: COLORS[p] + '55',
        fill: true,
        stack: 'events',
        tension: 0.25,
        pointRadius: 0,
      })),
    },
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#8b98a5', maxTicksLimit: 8 }, grid: { color: '#2a3441' } },
        y: { stacked: true, ticks: { color: '#8b98a5' }, grid: { color: '#2a3441' } },
      },
      plugins: { legend: { labels: { color: '#e6edf3' } } },
    },
  });
  return volumeChart;
}

async function loadTimeseries() {
  const res = await api.get('/stats/timeseries?interval=1m&window=1h');
  const chart = ensureVolumeChart();
  const points = res.series.slice(-60);
  chart.data.labels = points.map((p) => new Date(p.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  PRIORITIES.forEach((p, i) => {
    chart.data.datasets[i].data = points.map((pt) => pt[p] || 0);
  });
  chart.update('none');
}

function ensurePriorityChart() {
  if (priorityChart) return priorityChart;
  const ctx = document.getElementById('priority-chart');
  priorityChart = new window.Chart(ctx, {
    type: 'doughnut',
    data: { labels: PRIORITIES, datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: PRIORITIES.map((p) => COLORS[p]) }] },
    options: { animation: false, plugins: { legend: { position: 'bottom', labels: { color: '#e6edf3' } } } },
  });
  return priorityChart;
}

async function loadPriorityDistribution() {
  const res = await api.get('/stats/priority-distribution?window=24h');
  const chart = ensurePriorityChart();
  chart.data.datasets[0].data = PRIORITIES.map((p) => res[p] || 0);
  chart.update('none');
}

function ensureSourcesChart() {
  if (sourcesChart) return sourcesChart;
  const ctx = document.getElementById('sources-chart');
  sourcesChart = new window.Chart(ctx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Events', data: [], backgroundColor: '#3b9eff' }] },
    options: {
      indexAxis: 'y',
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b98a5' }, grid: { color: '#2a3441' } },
        y: { ticks: { color: '#e6edf3' }, grid: { display: false } },
      },
    },
  });
  return sourcesChart;
}

async function loadTopSources() {
  const res = await api.get('/stats/top-sources?limit=10&window=24h');
  const chart = ensureSourcesChart();
  chart.data.labels = res.map((r) => r.source_name);
  chart.data.datasets[0].data = res.map((r) => r.count);
  chart.update('none');
}

function feedRow(event) {
  const row = el('tr', { class: 'clickable', onclick: () => (window.location.href = `/alerts#event-${event.event_id}`) }, [
    el('td', {}, new Date(event.timestamp).toLocaleTimeString()),
    el('td', {}, priorityPill(event.priority_level)),
    el('td', {}, event.event_type),
    el('td', {}, event.src_ip || '-'),
    el('td', { style: 'max-width:360px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;' }, event.message || ''),
  ]);
  return row;
}

function renderFeed() {
  const tbody = document.getElementById('feed-body');
  clear(tbody);
  feedBuffer.slice(0, MAX_FEED_ROWS).forEach((event) => tbody.appendChild(feedRow(event)));
}

function pushToFeed(events) {
  events.forEach((event) => trackLastSeen(event.timestamp));
  if (feedPaused) return;
  feedBuffer = events.concat(feedBuffer).slice(0, MAX_FEED_ROWS);
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

function setupSocket() {
  const socket = connectLive();
  socket.on('connect', () => subscribe(['all_events', 'priority_high', 'priority_critical', 'incidents']));

  socket.on('event:new', (batch) => pushToFeed(batch));

  socket.on('alert:high', (event) => {
    showToast(`${event.priority_level} alert`, event.message || event.event_type, () => (window.location.href = '/alerts'));
    notifyBrowser(`SentryLite: ${event.priority_level} alert`, event.message || event.event_type);
  });

  socket.on('incident:created', () => loadSummary());
  socket.on('stats:tick', () => {
    loadSummary();
  });

  onBackfill((events) => pushToFeed(events));
}

async function init() {
  setupFeedControls();
  setupSocket();
  await Promise.all([loadSummary(), loadTimeseries(), loadPriorityDistribution(), loadTopSources()]);
  setInterval(loadTimeseries, 15000);
  setInterval(loadPriorityDistribution, 30000);
  setInterval(loadTopSources, 30000);
}

init();

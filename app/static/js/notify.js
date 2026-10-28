// Loaded on every signed-in page: real-time connection indicator, the "assigned to me"
// sidebar badge, and pop-up notifications (high/critical alerts, incidents assigned to me).
import { api } from './api.js';
import { connectLive, subscribe } from './socket.js';
import { notifyBrowser, showToast } from './ui.js';

const me = JSON.parse(document.getElementById('current-user').textContent);
const indicator = document.getElementById('live-indicator');
const badge = document.getElementById('my-incidents-badge');

function setLive(state) {
  if (!indicator) return;
  indicator.className = `live ${state}`;
  indicator.textContent = state === 'on' ? 'Live' : 'Reconnecting…';
}

let badgeTimer = null;
function refreshBadge() {
  clearTimeout(badgeTimer);
  badgeTimer = setTimeout(async () => {
    try {
      const summary = await api.get('/stats/summary');
      if (badge) badge.textContent = summary.my_open_incidents ? String(summary.my_open_incidents) : '';
      document.dispatchEvent(new CustomEvent('sentrylite:summary', { detail: summary }));
    } catch (_) {
      /* badge is best-effort */
    }
  }, 300);
}

// Collapse bursts (a brute force fires a dozen HIGH alerts in seconds) into one toast.
let alertBurst = { count: 0, timer: null, last: null };
function onHighAlert(event) {
  alertBurst.count += 1;
  alertBurst.last = event;
  if (alertBurst.timer) return;
  alertBurst.timer = setTimeout(() => {
    const { count, last } = alertBurst;
    alertBurst = { count: 0, timer: null, last: null };
    const title = count > 1 ? `${count} new high/critical alerts` : `${last.priority_level} alert`;
    const body = `${last.event_type} from ${last.src_ip || 'unknown'}: ${last.message || ''}`.slice(0, 160);
    showToast(title, body, () => (window.location.href = '/alerts?priority=CRITICAL,HIGH'));
    if (last.priority_level === 'CRITICAL') notifyBrowser(`SentryLite: ${title}`, body);
  }, 700);
}

const socket = connectLive();
socket.on('connect', () => {
  setLive('on');
  subscribe(['priority_high', 'priority_critical', 'incidents']);
  refreshBadge();
});
socket.on('disconnect', () => setLive('off'));
socket.on('connect_error', () => setLive('off'));

socket.on('alert:high', onHighAlert);

socket.on('notify', (note) => {
  if (note.user_id && note.user_id !== me.user_id) return;
  showToast(note.title, note.body || '', () => { if (note.link) window.location.href = note.link; }, 'info');
  notifyBrowser(`SentryLite: ${note.title}`, note.body || '');
  refreshBadge();
});

socket.on('incident:created', refreshBadge);
socket.on('incident:updated', refreshBadge);

refreshBadge();

// Wraps the global `io` from vendor/socket.io.min.js (loaded as a classic script before this module).
import { api, qs } from './api.js';

let socketInstance = null;
let lastEventTimestamp = null;
let hasConnectedBefore = false;
const backfillCallbacks = [];

export function onBackfill(cb) {
  backfillCallbacks.push(cb);
}

export function connectLive() {
  if (socketInstance) return socketInstance;
  socketInstance = window.io('/live');

  socketInstance.on('connect', () => {
    if (hasConnectedBefore && lastEventTimestamp) {
      // Reconnection backfill (§9): fetch anything that may have been missed while disconnected.
      api
        .get(`/events${qs({ from: lastEventTimestamp, per_page: 100, sort: '-timestamp' })}`)
        .then((res) => {
          if (res && res.data && res.data.length) {
            const chronological = res.data.slice().reverse();
            backfillCallbacks.forEach((cb) => cb(chronological));
          }
        })
        .catch(() => {});
    }
    hasConnectedBefore = true;
  });

  return socketInstance;
}

export function subscribe(rooms) {
  if (socketInstance) socketInstance.emit('subscribe', { rooms });
}

export function trackLastSeen(iso) {
  if (!iso) return;
  if (!lastEventTimestamp || iso > lastEventTimestamp) lastEventTimestamp = iso;
}

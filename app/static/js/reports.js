import { api, qs } from './api.js';
import { el, clear, priorityPill, formatTime, showToast } from './ui.js';

const root = document.getElementById('reports-root');

function ymd(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// The picked dates are whole days in the viewer's own time zone.
function rangeParams(from, to) {
  return {
    from: new Date(`${from}T00:00:00`).toISOString(),
    to: new Date(`${to}T23:59:59.999`).toISOString(),
  };
}

function presets() {
  const today = new Date();
  const daysAgo = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d; };
  return [
    ['Today', ymd(today), ymd(today)],
    ['Last 7 days', ymd(daysAgo(6)), ymd(today)],
    ['Last 30 days', ymd(daysAgo(29)), ymd(today)],
    ['This month', ymd(new Date(today.getFullYear(), today.getMonth(), 1)), ymd(today)],
  ];
}

// JSON objects come back with keys sorted alphabetically; show priorities by severity instead.
const SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
function bySeverity(counts) {
  return SEVERITY.map((p) => [p, counts[p] || 0]);
}

function minutes(v) {
  if (v === null || v === undefined) return '-';
  return v < 120 ? `${v} min` : `${(v / 60).toFixed(1)} h`;
}

function kpi(value, label) {
  return el('div', { class: 'card' }, [el('div', { class: 'kpi-value', style: 'font-size:1.6rem; font-weight:700;' }, String(value)), el('div', { class: 'kpi-label text-muted', style: 'font-size:0.85rem;' }, label)]);
}

// A small table whose count column carries a proportional bar.
function countTable(title, rows, labelHeader, render = (v) => v) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return el('div', { class: 'card' }, [
    el('h3', { class: 'section-title' }, title),
    rows.length
      ? el('table', {}, [
        el('thead', {}, el('tr', {}, [el('th', {}, labelHeader), el('th', { style: 'width:45%;' }, 'Count')])),
        el('tbody', {}, rows.map(([label, count]) => el('tr', {}, [
          el('td', {}, render(label)),
          el('td', { class: 'bar-cell' }, [el('div', { class: 'bar', style: `width:${(count / max) * 100}%;` }), el('span', {}, String(count))]),
        ]))),
      ])
      : el('div', { class: 'empty' }, 'Nothing in this period.'),
  ]);
}

function renderReport(report) {
  const box = document.getElementById('report-body');
  clear(box);
  const s = report.summary;

  box.appendChild(el('div', { class: 'muted-small', style: 'margin-bottom:10px;' },
    `Period ${formatTime(report.range.from)} to ${formatTime(report.range.to)} · generated ${formatTime(report.generated_at)}`));

  box.appendChild(el('div', { class: 'grid kpi-row' }, [
    kpi(s.events_total, 'Events analysed'),
    kpi(s.events_high_or_critical, 'High / critical events'),
    kpi(s.unique_attackers, 'Unique source IPs'),
    kpi(s.incidents_total, 'Incidents opened'),
    kpi(s.incidents_open, 'Still open'),
    kpi(s.incidents_unassigned, 'Open & unassigned'),
    kpi(minutes(report.mtta_minutes), 'Mean time to acknowledge'),
    kpi(minutes(report.mttr_minutes), 'Mean time to resolve'),
  ]));

  box.appendChild(el('div', { class: 'report-section report-grid' }, [
    countTable('Events by priority', bySeverity(report.events_by_priority), 'Priority', priorityPill),
    countTable('Events by type', report.events_by_type.map((r) => [r.event_type, r.count]), 'Event type'),
    countTable('Incidents by priority', bySeverity(report.totals_by_priority), 'Priority', priorityPill),
    countTable('Incidents by state', Object.entries(report.totals_by_state).filter(([, n]) => n > 0), 'State'),
  ]));

  box.appendChild(el('div', { class: 'report-section report-grid' }, [
    el('div', { class: 'card' }, [
      el('h3', { class: 'section-title' }, 'Top attacker IPs'),
      report.top_source_ips.length
        ? el('table', {}, [
          el('thead', {}, el('tr', {}, ['IP', 'Events', 'Highest score', 'Last seen'].map((h) => el('th', {}, h)))),
          el('tbody', {}, report.top_source_ips.map((r) => el('tr', {}, [
            el('td', {}, el('a', { href: `/alerts?src_ip=${encodeURIComponent(r.src_ip)}` }, r.src_ip)),
            el('td', {}, String(r.count)), el('td', {}, String(r.max_score)), el('td', {}, formatTime(r.last_seen)),
          ]))),
        ])
        : el('div', { class: 'empty' }, 'No attacker IPs in this period.'),
    ]),
    countTable('Detection rules triggered', report.top_rules.map((r) => [r.rule_name, r.trigger_count]), 'Rule'),
    countTable('Critical assets targeted', report.critical_asset_hits.map((r) => [r.asset, r.count]), 'Asset'),
    el('div', { class: 'card' }, [
      el('h3', { class: 'section-title' }, 'Team workload'),
      report.workload.length
        ? el('table', {}, [
          el('thead', {}, el('tr', {}, ['Assignee', 'Assigned', 'Open', 'Resolved / closed'].map((h) => el('th', {}, h)))),
          el('tbody', {}, report.workload.map((r) => el('tr', {}, [
            el('td', {}, r.assignee), el('td', {}, String(r.assigned)), el('td', {}, String(r.open)), el('td', {}, String(r.resolved)),
          ]))),
        ])
        : el('div', { class: 'empty' }, 'No incidents in this period.'),
    ]),
  ]));

  box.appendChild(el('div', { class: 'card report-section', style: 'overflow-x:auto;' }, [
    el('h3', { class: 'section-title' }, `Incidents (${report.incidents.length})`),
    report.incidents.length
      ? el('table', {}, [
        el('thead', {}, el('tr', {}, ['Reference', 'Title', 'Priority', 'State', 'Assignee', 'Created', 'Time to ack', 'Time to resolve', 'Resolution'].map((h) => el('th', {}, h)))),
        el('tbody', {}, report.incidents.map((i) => el('tr', { class: 'clickable', onclick: () => (window.location.href = `/incidents/${i.reference}`) }, [
          el('td', { style: 'white-space:nowrap;' }, i.reference),
          el('td', {}, i.title),
          el('td', {}, priorityPill(i.priority_level)),
          el('td', {}, i.state),
          el('td', {}, i.assignee || 'Unassigned'),
          el('td', { style: 'white-space:nowrap;' }, formatTime(i.created_at)),
          el('td', {}, minutes(i.minutes_to_acknowledge)),
          el('td', {}, minutes(i.minutes_to_resolve)),
          el('td', { class: 'wrap-anywhere' }, i.resolution_summary || ''),
        ]))),
      ])
      : el('div', { class: 'empty' }, 'No incidents were opened in this period.'),
  ]));
}

async function download(from, to, format, button) {
  button.disabled = true;
  try {
    const params = rangeParams(from, to);
    const blob = await api.get(`/reports/incidents${qs({ ...params, format })}`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentrylite_report_${from}_to_${to}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('Report downloaded', `${format.toUpperCase()} for ${from} to ${to}`, null, 'ok');
  } catch (err) {
    window.alert(`Could not build the report: ${err.message}`);
  } finally {
    button.disabled = false;
  }
}

function init() {
  const [, defFrom, defTo] = presets()[2];
  const fromInput = el('input', { type: 'date', value: defFrom });
  const toInput = el('input', { type: 'date', value: defTo });

  async function generate() {
    if (fromInput.value > toInput.value) {
      window.alert('The "From" date must be on or before the "To" date.');
      return;
    }
    const box = document.getElementById('report-body');
    clear(box);
    box.appendChild(el('div', { class: 'empty' }, 'Building report…'));
    try {
      renderReport(await api.get(`/reports/incidents${qs({ ...rangeParams(fromInput.value, toInput.value), format: 'json' })}`));
    } catch (err) {
      clear(box);
      box.appendChild(el('div', { class: 'flash flash-error' }, err.message));
    }
  }

  const csvBtn = el('button', { onclick: () => download(fromInput.value, toInput.value, 'csv', csvBtn) }, '⬇ Download CSV (Excel)');
  const pdfBtn = el('button', { onclick: () => download(fromInput.value, toInput.value, 'pdf', pdfBtn) }, '⬇ Download PDF');

  root.appendChild(el('p', { class: 'page-intro' },
    'A summary of everything SentryLite saw and did in a period: events analysed, attackers, rules triggered, incidents opened and how fast the team handled them. The downloads contain exactly what is shown here.'));
  root.appendChild(el('div', { class: 'filter-bar' }, [
    el('div', {}, [el('label', {}, 'Quick range'), el('div', { class: 'btn-row' }, presets().map(([label, f, t]) =>
      el('button', { class: 'small', onclick: () => { fromInput.value = f; toInput.value = t; generate(); } }, label)))]),
    el('div', {}, [el('label', {}, 'From'), fromInput]),
    el('div', {}, [el('label', {}, 'To'), toInput]),
    el('div', {}, [el('label', {}, ' '), el('button', { class: 'primary', onclick: generate }, 'Generate report')]),
    el('div', {}, [el('label', {}, ' '), el('div', { class: 'btn-row' }, [csvBtn, pdfBtn])]),
  ]));
  root.appendChild(el('div', { id: 'report-body' }));
  generate();
}

init();

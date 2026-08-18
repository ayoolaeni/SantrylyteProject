import { api, qs } from './api.js';
import { el, clear } from './ui.js';

const root = document.getElementById('reports-root');

function defaultRange() {
  const to = new Date();
  const from = new Date(to.getTime() - 30 * 24 * 3600 * 1000);
  return { from: from.toISOString().slice(0, 10), to: to.toISOString().slice(0, 10) };
}

async function loadSummary(from, to) {
  const report = await api.get(`/reports/incidents${qs({ from, to, format: 'json' })}`);
  const summaryBox = document.getElementById('report-summary');
  clear(summaryBox);
  summaryBox.appendChild(
    el('div', { class: 'grid kpi-row' }, [
      el('div', { class: 'card' }, [el('div', { class: 'kpi-value' }, String(report.mtta_minutes ?? '-')), el('div', { class: 'kpi-label' }, 'MTTA (min)')]),
      el('div', { class: 'card' }, [el('div', { class: 'kpi-value' }, String(report.mttr_minutes ?? '-')), el('div', { class: 'kpi-label' }, 'MTTR (min)')]),
      el('div', { class: 'card' }, [el('div', { class: 'kpi-value' }, String(report.incidents.length)), el('div', { class: 'kpi-label' }, 'Incidents in range')]),
    ])
  );

  const table = el('table', {}, [
    el('thead', {}, el('tr', {}, ['Reference', 'Title', 'Priority', 'State', 'Assignee', 'Created', 'Closed'].map((h) => el('th', {}, h)))),
    el(
      'tbody',
      {},
      report.incidents.map((i) =>
        el('tr', {}, [
          el('td', {}, i.reference),
          el('td', {}, i.title),
          el('td', {}, i.priority_level),
          el('td', {}, i.state),
          el('td', {}, i.assignee || '-'),
          el('td', {}, i.created_at ? new Date(i.created_at).toLocaleString() : '-'),
          el('td', {}, i.closed_at ? new Date(i.closed_at).toLocaleString() : '-'),
        ])
      )
    ),
  ]);

  const tableBox = document.getElementById('report-table');
  clear(tableBox);
  tableBox.appendChild(table);
}

function init() {
  const { from, to } = defaultRange();
  const fromInput = el('input', { type: 'date', value: from });
  const toInput = el('input', { type: 'date', value: to });

  const bar = el('div', { class: 'filter-bar' }, [
    el('div', {}, [el('label', {}, 'From'), fromInput]),
    el('div', {}, [el('label', {}, 'To'), toInput]),
    el('div', {}, [
      el('label', {}, ' '),
      el('button', { class: 'primary', onclick: () => loadSummary(fromInput.value, toInput.value) }, 'Refresh'),
    ]),
    el('div', {}, [
      el('label', {}, ' '),
      el('button', { onclick: () => downloadReport(fromInput.value, toInput.value, 'csv') }, 'Download CSV'),
    ]),
    el('div', {}, [
      el('label', {}, ' '),
      el('button', { onclick: () => downloadReport(fromInput.value, toInput.value, 'pdf') }, 'Download PDF'),
    ]),
  ]);

  root.appendChild(bar);
  root.appendChild(el('div', { id: 'report-summary' }));
  root.appendChild(el('div', { class: 'card mt-2', style: 'overflow-x:auto;', id: 'report-table' }));

  loadSummary(from, to);
}

async function downloadReport(from, to, format) {
  const blob = await api.get(`/reports/incidents${qs({ from, to, format })}`);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sentrylite_incident_report.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

init();

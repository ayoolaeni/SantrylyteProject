import { api } from './api.js';
import { el, clear, formatTime } from './ui.js';

const SOURCE_TYPES = ['SYSLOG', 'AUTH_LOG', 'NGINX_ACCESS', 'APACHE_ACCESS', 'JSON_GENERIC', 'WINDOWS_JSON'];
const ROLES = ['ADMIN', 'ANALYST', 'VIEWER'];

function field(label, input) {
  return el('div', { class: 'mt-1' }, [el('label', {}, label), input]);
}

// ---------- Sources ----------
async function initSources() {
  const root = document.getElementById('admin-sources-root');
  const form = el('div', { class: 'card' }, [
    el('h2', { style: 'margin-top:0; font-size:1rem;' }, 'Add log source'),
  ]);
  const nameInput = el('input', { type: 'text', placeholder: 'e.g. web-01 nginx' });
  const hostInput = el('input', { type: 'text', placeholder: 'IP or hostname' });
  const typeSelect = el('select', {}, SOURCE_TYPES.map((t) => el('option', { value: t }, t)));
  form.appendChild(field('Name', nameInput));
  form.appendChild(field('Host identifier', hostInput));
  form.appendChild(field('Source type', typeSelect));
  const tokenBox = el('div', { class: 'mt-1' });
  form.appendChild(tokenBox);
  form.appendChild(
    el(
      'button',
      {
        class: 'primary mt-2',
        onclick: async () => {
          const source = await api.post('/sources', {
            name: nameInput.value,
            host_identifier: hostInput.value,
            source_type: typeSelect.value,
          });
          clear(tokenBox);
          tokenBox.appendChild(
            el('div', { class: 'flash flash-success' }, `Ingest token (shown once): ${source.ingest_token}`)
          );
          nameInput.value = '';
          hostInput.value = '';
          await loadTable();
        },
      },
      'Create source'
    )
  );

  const tableWrap = el('div', { class: 'card mt-2', style: 'overflow-x:auto;' });
  const tbody = el('tbody');
  tableWrap.appendChild(
    el('table', {}, [
      el('thead', {}, el('tr', {}, ['Name', 'Host', 'Type', 'Enabled', 'Last seen', 'Actions'].map((h) => el('th', {}, h)))),
      tbody,
    ])
  );

  async function loadTable() {
    const res = await api.get('/sources?per_page=200');
    clear(tbody);
    res.data.forEach((source) => {
      tbody.appendChild(
        el('tr', {}, [
          el('td', {}, source.name),
          el('td', {}, source.host_identifier),
          el('td', {}, source.source_type),
          el('td', {}, source.is_enabled ? 'yes' : 'no'),
          el('td', {}, formatTime(source.last_seen_at)),
          el('td', {}, [
            el(
              'button',
              {
                onclick: async () => {
                  await api.patch(`/sources/${source.source_id}`, { is_enabled: !source.is_enabled });
                  await loadTable();
                },
              },
              source.is_enabled ? 'Disable' : 'Enable'
            ),
            ' ',
            el(
              'button',
              {
                onclick: async () => {
                  const rotated = await api.post(`/sources/${source.source_id}/rotate-token`);
                  window.alert(`New token (shown once): ${rotated.ingest_token}`);
                },
              },
              'Rotate token'
            ),
          ]),
        ])
      );
    });
  }

  clear(root);
  root.appendChild(form);
  root.appendChild(tableWrap);
  await loadTable();
}

// ---------- Rules ----------
async function initRules() {
  const root = document.getElementById('admin-rules-root');
  const tableWrap = el('div', { class: 'card', style: 'overflow-x:auto;' });
  const tbody = el('tbody');
  tableWrap.appendChild(
    el('table', {}, [
      el('thead', {}, el('tr', {}, ['Name', 'Category', 'Weight', 'Enabled', 'Actions'].map((h) => el('th', {}, h)))),
      tbody,
    ])
  );

  async function loadTable() {
    const res = await api.get('/rules?per_page=200');
    clear(tbody);
    res.data.forEach((rule) => {
      tbody.appendChild(
        el('tr', {}, [
          el('td', {}, rule.name),
          el('td', {}, rule.category),
          el(
            'td',
            {},
            el('input', {
              type: 'text',
              value: String(rule.weight),
              style: 'width:70px;',
              onchange: async (e) => {
                await api.patch(`/rules/${rule.rule_id}`, { weight: parseFloat(e.target.value) });
              },
            })
          ),
          el('td', {}, [
            el('input', {
              type: 'checkbox',
              checked: rule.is_enabled ? 'checked' : undefined,
              onchange: async (e) => {
                await api.patch(`/rules/${rule.rule_id}`, { is_enabled: e.target.checked });
              },
            }),
          ]),
          el('td', {}, [
            el(
              'button',
              {
                onclick: async () => {
                  const sample = window.prompt('Sample event JSON to test against this rule:', '{"event_type": "AUTH_FAILURE"}');
                  if (!sample) return;
                  try {
                    const result = await api.post(`/rules/${rule.rule_id}/test`, { sample_event: JSON.parse(sample) });
                    window.alert(`matched=${result.matched} weight=${result.weight}`);
                  } catch (err) {
                    window.alert(err.message);
                  }
                },
              },
              'Test'
            ),
          ]),
        ])
      );
    });
  }

  clear(root);
  root.appendChild(tableWrap);
  await loadTable();
}

// ---------- Users ----------
async function initUsers() {
  const root = document.getElementById('admin-users-root');
  const form = el('div', { class: 'card' }, [el('h2', { style: 'margin-top:0; font-size:1rem;' }, 'Add user')]);
  const usernameInput = el('input', { type: 'text' });
  const emailInput = el('input', { type: 'text' });
  const fullNameInput = el('input', { type: 'text' });
  const roleSelect = el('select', {}, ROLES.map((r) => el('option', { value: r }, r)));
  form.appendChild(field('Username', usernameInput));
  form.appendChild(field('Email', emailInput));
  form.appendChild(field('Full name', fullNameInput));
  form.appendChild(field('Role', roleSelect));
  const resultBox = el('div', { class: 'mt-1' });
  form.appendChild(resultBox);
  form.appendChild(
    el(
      'button',
      {
        class: 'primary mt-2',
        onclick: async () => {
          const user = await api.post('/users', {
            username: usernameInput.value,
            email: emailInput.value,
            full_name: fullNameInput.value,
            role: roleSelect.value,
          });
          clear(resultBox);
          if (user.temporary_password) {
            resultBox.appendChild(
              el('div', { class: 'flash flash-success' }, `Temporary password (shown once): ${user.temporary_password}`)
            );
          }
          await loadTable();
        },
      },
      'Create user'
    )
  );

  const tableWrap = el('div', { class: 'card mt-2', style: 'overflow-x:auto;' });
  const tbody = el('tbody');
  tableWrap.appendChild(
    el('table', {}, [
      el('thead', {}, el('tr', {}, ['Username', 'Full name', 'Role', 'Active', 'Actions'].map((h) => el('th', {}, h)))),
      tbody,
    ])
  );

  async function loadTable() {
    const res = await api.get('/users?per_page=200');
    clear(tbody);
    res.data.forEach((user) => {
      tbody.appendChild(
        el('tr', {}, [
          el('td', {}, user.username),
          el('td', {}, user.full_name),
          el(
            'td',
            {},
            el(
              'select',
              {
                onchange: async (e) => {
                  await api.patch(`/users/${user.user_id}`, { role: e.target.value });
                },
              },
              ROLES.map((r) => el('option', { value: r, selected: user.role === r ? 'selected' : undefined }, r))
            )
          ),
          el('td', {}, user.is_active ? 'yes' : 'no'),
          el('td', {}, [
            el(
              'button',
              {
                onclick: async () => {
                  await api.del(`/users/${user.user_id}`);
                  await loadTable();
                },
              },
              'Deactivate'
            ),
          ]),
        ])
      );
    });
  }

  clear(root);
  root.appendChild(form);
  root.appendChild(tableWrap);
  await loadTable();
}

// ---------- Critical assets ----------
async function initAssets() {
  const root = document.getElementById('admin-assets-root');
  const form = el('div', { class: 'card' }, [el('h2', { style: 'margin-top:0; font-size:1rem;' }, 'Add critical asset')]);
  const idInput = el('input', { type: 'text', placeholder: 'IP, CIDR or hostname' });
  const labelInput = el('input', { type: 'text', placeholder: 'Label' });
  const multInput = el('input', { type: 'text', value: '1.5' });
  form.appendChild(field('Identifier', idInput));
  form.appendChild(field('Label', labelInput));
  form.appendChild(field('Criticality multiplier', multInput));
  form.appendChild(
    el(
      'button',
      {
        class: 'primary mt-2',
        onclick: async () => {
          await api.post('/assets', {
            identifier: idInput.value,
            label: labelInput.value,
            criticality_multiplier: parseFloat(multInput.value),
          });
          idInput.value = '';
          labelInput.value = '';
          await loadTable();
        },
      },
      'Create asset'
    )
  );

  const tableWrap = el('div', { class: 'card mt-2', style: 'overflow-x:auto;' });
  const tbody = el('tbody');
  tableWrap.appendChild(
    el('table', {}, [
      el('thead', {}, el('tr', {}, ['Identifier', 'Label', 'Multiplier', 'Enabled', 'Actions'].map((h) => el('th', {}, h)))),
      tbody,
    ])
  );

  async function loadTable() {
    const res = await api.get('/assets?per_page=200');
    clear(tbody);
    res.data.forEach((asset) => {
      tbody.appendChild(
        el('tr', {}, [
          el('td', {}, asset.identifier),
          el('td', {}, asset.label),
          el('td', {}, String(asset.criticality_multiplier)),
          el('td', {}, asset.is_enabled ? 'yes' : 'no'),
          el('td', {}, [
            el(
              'button',
              {
                onclick: async () => {
                  await api.del(`/assets/${asset.asset_id}`);
                  await loadTable();
                },
              },
              'Delete'
            ),
          ]),
        ])
      );
    });
  }

  clear(root);
  root.appendChild(form);
  root.appendChild(tableWrap);
  await loadTable();
}

if (document.getElementById('admin-sources-root')) initSources();
if (document.getElementById('admin-rules-root')) initRules();
if (document.getElementById('admin-users-root')) initUsers();
if (document.getElementById('admin-assets-root')) initAssets();

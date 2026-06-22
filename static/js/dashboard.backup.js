/* ==========================================================
   SIEM Dashboard — Client-Side Logic
   ========================================================== */

'use strict';

// ---- State ----
let eventsChart   = null;
let logTypesChart = null;
let geoChart      = null;
let worldFeatures = null;
let currentPage   = 'overview';
let currentRawLog = '';
let feedRowCache  = {};   // id → row, avoids embedding JSON in onclick attrs

const PAGE_LABELS = {
  overview:  'Overview',
  alerts:    'Alerts',
  agents:    'Agents',
  rules:     'Rules',
  assistant: 'AI Assistant',
  users:     'Users',
};

// Level number → human label
const LEVEL_NAMES = {
  0: 'Audit',
  1: 'Critical',
  2: 'Error',
  3: 'Warning',
  4: 'Info',
  5: 'Verbose',
};

// ---- Helpers ----
async function apiFetch(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (res.status === 401) { location.href = '/login'; return null; }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function fmtNum(n) {
  return (n ?? 0).toLocaleString();
}

function fmtTime(ts) {
  if (!ts) return '—';
  return ts.slice(0, 19).replace('T', ' ');
}

function sevBadge(sev) {
  return `<span class="sev sev-${(sev || 'info').toLowerCase()}">${(sev || 'info').toUpperCase()}</span>`;
}

function dispBadge(d) {
  return `<span class="disp disp-${d || 'open'}">${(d || 'open').replace('_', ' ')}</span>`;
}

function levelBadge(lvl) {
  const name = LEVEL_NAMES[lvl] ?? `L${lvl}`;
  const cls  = lvl === 1 ? 'lvl-critical'
             : lvl === 2 ? 'lvl-error'
             : lvl === 3 ? 'lvl-warning'
             : lvl === 0 ? 'lvl-audit'
             : 'lvl-info';
  return `<span class="lvl-badge ${cls}">${name}</span>`;
}

function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.)/.test(ip);
}

// ---- Page navigation ----
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));

  const page = document.getElementById(`page-${id}`);
  const nav  = document.getElementById(`nav-${id}`);
  if (page) page.classList.add('active');
  if (nav)  nav.classList.add('active');

  const bcEl = document.getElementById('bc-current');
  if (bcEl) bcEl.textContent = PAGE_LABELS[id] || id;

  currentPage = id;

  if (id === 'overview')  refreshAll();
  if (id === 'alerts')    loadAlertsPage();
  if (id === 'agents')    loadAgentsPage();
  if (id === 'rules')     loadRulesPage();
  if (id === 'assistant') loadAssistantPage();
  if (id === 'users')     loadUsersPage();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
}

function onTimeRangeChange() {
  if (currentPage === 'overview') loadEventsChart();
}

// ========================================================
// OVERVIEW PAGE — KPIs
// ========================================================
async function loadKPIs() {
  const data = await apiFetch('/api/stats');
  if (!data) return;

  document.getElementById('kpi-access').textContent   = fmtNum(data.access);
  document.getElementById('kpi-threat').textContent   = fmtNum(data.threat);
  document.getElementById('kpi-audit').textContent    = fmtNum(data.audit);
  document.getElementById('kpi-endpoint').textContent = fmtNum(data.endpoint);
  document.getElementById('kpi-total').textContent    = fmtNum(data.total_events);

  document.getElementById('sb-events').textContent = fmtNum(data.total_events);
  document.getElementById('sb-alerts').textContent = fmtNum(data.total_alerts);
  document.getElementById('sb-agents').textContent = data.active_agents;

  const badge = document.getElementById('badge-alerts');
  if (badge) {
    if (data.threat > 0) {
      badge.textContent = data.threat > 99 ? '99+' : data.threat;
      badge.classList.add('show');
    } else {
      badge.classList.remove('show');
    }
  }
}

// ---- Events over time chart ----
async function loadEventsChart() {
  const hours = document.getElementById('timeRange')?.value || 24;
  const data  = await apiFetch(`/api/events_over_time?hours=${hours}`);
  if (!data) return;

  const labels = data.map(d => (d.time || '').slice(11, 16));
  const counts = data.map(d => d.count);

  const meta = document.getElementById('chart-meta');
  if (meta) meta.textContent = `${data.length} buckets`;

  const cfg = {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data: counts,
        borderColor: '#0ea5e9',
        backgroundColor: 'rgba(14,165,233,0.08)',
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#0ea5e9',
        tension: 0.35,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: true, position: 'top', labels: { boxWidth: 12, font: { size: 12 } } },
        tooltip: { callbacks: { title: items => items[0].label + ':00' } }
      },
      scales: {
        x: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 11 }, maxTicksLimit: 12 } },
        y: { beginAtZero: true, grid: { color: '#f1f5f9' }, ticks: { font: { size: 11 }, precision: 0 } }
      }
    }
  };

  if (eventsChart) {
    eventsChart.data.labels = labels;
    eventsChart.data.datasets[0].data = counts;
    eventsChart.update('none');
  } else {
    const ctx = document.getElementById('eventsChart');
    if (ctx) eventsChart = new Chart(ctx, cfg);
  }
}

// ---- Alert summary table ----
async function loadSummaryTable() {
  const data = await apiFetch('/api/summary');
  if (!data) return;

  const tbody = document.getElementById('summaryBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#94a3b8;padding:24px">No alerts yet</td></tr>';
    return;
  }

  data.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="col-rule" title="${row.rule}">${row.rule}</td>
      <td class="col-sev">${sevBadge(row.severity)}</td>
      <td class="col-cnt">${fmtNum(row.events)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ---- Log types donut chart ----
async function loadLogTypesChart() {
  const data = await apiFetch('/api/log_types');
  if (!data) return;

  const labels  = data.map(d => d.type);
  const counts  = data.map(d => d.count);
  const palette = [
    '#22c55e','#3b82f6','#a855f7','#ec4899','#f97316',
    '#84cc16','#06b6d4','#eab308','#ef4444','#14b8a6',
    '#8b5cf6','#f59e0b',
  ];

  const cfg = {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: counts,
        backgroundColor: palette.slice(0, counts.length),
        borderWidth: 2, borderColor: '#fff', hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 }, padding: 10 } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${fmtNum(ctx.parsed)}` } }
      }
    }
  };

  if (logTypesChart) {
    logTypesChart.data.labels = labels;
    logTypesChart.data.datasets[0].data   = counts;
    logTypesChart.data.datasets[0].backgroundColor = palette.slice(0, counts.length);
    logTypesChart.update('none');
  } else {
    const ctx = document.getElementById('logTypesChart');
    if (ctx) logTypesChart = new Chart(ctx, cfg);
  }
}

// ========================================================
// ATTACKER ORIGIN MAP — chartjs-chart-geo (no image tiles)
// Uses topojson world topology + ip-api.com geolocation API
// ========================================================
async function loadWorldTopology() {
  if (worldFeatures) return worldFeatures;
  try {
    const res  = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    const topo = await res.json();
    worldFeatures = topojson.feature(topo, topo.objects.countries);
    return worldFeatures;
  } catch (e) {
    console.warn('World topology load failed:', e);
    return null;
  }
}

async function loadMap() {
  const canvas = document.getElementById('attackerMap');
  const noData = document.getElementById('mapNoData');
  const meta   = document.getElementById('map-meta');
  if (!canvas) return;

  const [ipData, topology] = await Promise.all([
    apiFetch('/api/top_ips'),
    loadWorldTopology(),
  ]);

  if (!topology) {
    if (meta) meta.textContent = 'topology unavailable';
    return;
  }

  // Always hide the overlay — map renders regardless of data
  if (noData) noData.style.display = 'none';

  const ipList    = ipData || [];
  const publicIPs = ipList.filter(d => !isPrivateIP(d.ip));

  let geoPoints = [];

  if (publicIPs.length > 0) {
    try {
      const res     = await fetch('http://ip-api.com/batch?fields=status,lat,lon,country,city,query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(publicIPs.slice(0, 15).map(d => ({ query: d.ip }))),
      });
      const geoData = await res.json();
      const maxCount = Math.max(...publicIPs.map(d => d.count), 1);
      geoData.forEach((geo, i) => {
        if (geo.status !== 'success') return;
        const entry = publicIPs[i];
        const ratio = entry.count / maxCount;
        geoPoints.push({
          lat:    geo.lat,
          lon:    geo.lon,
          label:  `${entry.ip}  —  ${geo.city ? geo.city + ', ' : ''}${geo.country}  (${entry.count} events)`,
          r:      5 + ratio * 16,
          color:  ratio > 0.7 ? 'rgba(239,68,68,0.75)'
                : ratio > 0.35 ? 'rgba(249,115,22,0.75)'
                : 'rgba(234,179,8,0.75)',
        });
      });
    } catch (_) {}
  }

  if (meta) {
    meta.textContent = geoPoints.length > 0
      ? `${geoPoints.length} location${geoPoints.length > 1 ? 's' : ''}`
      : ipList.length > 0 ? 'private network — no public IPs' : 'no agent IPs yet';
  }

  // Destroy previous chart if it exists
  if (geoChart) {
    geoChart.destroy();
    geoChart = null;
  }

  const cfg = {
    type: 'bubbleMap',
    data: {
      labels:   geoPoints.map(p => p.label),
      datasets: [{
        label:       'Agent Origin',
        outline:     topology.features,
        showOutline: true,
        showGraticule: false,
        backgroundColor: geoPoints.map(p => p.color),
        data: geoPoints.map(p => ({ latitude: p.lat, longitude: p.lon, r: p.r })),
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ctx.chart.data.labels[ctx.dataIndex] || '',
          }
        }
      },
      scales: {
        xy: {
          projection: 'equalEarth',
        }
      }
    }
  };

  try {
    geoChart = new Chart(canvas, cfg);
  } catch (e) {
    console.error('Geo chart error:', e);
  }
}

// ========================================================
// LIVE LOG FEED — includes agent_id + raw_log
// ========================================================
async function loadRecentLogs() {
  const data = await apiFetch('/api/recent_logs?limit=50');
  if (!data) return;

  const tbody = document.getElementById('logFeedBody');
  if (!tbody) return;

  const meta = document.getElementById('log-feed-meta');
  if (meta) meta.textContent = `${data.length} latest events`;

  tbody.innerHTML = '';

  if (!data.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center;color:#94a3b8;padding:28px">
          <i class="fas fa-satellite-dish" style="margin-right:8px"></i>
          Waiting for Windows Agent data — start SIEMAgent.exe on the endpoint
        </td>
      </tr>`;
    return;
  }

  feedRowCache = {};

  data.forEach(row => {
    // Cache row by ID so onclick can look it up without embedding JSON in HTML
    feedRowCache[row.id] = row;

    const st      = (row.source_type || 'unknown').toLowerCase();
    const stClass = 'lt-' + st.replace(/[^a-z0-9]/g, '-');
    const rowBg   = row.has_alert ? '#fff5f5' : '';
    const eidStr  = row.event_id != null ? row.event_id : '—';
    const lvlHtml = row.level != null ? levelBadge(row.level) : '<span style="color:#94a3b8">—</span>';

    const raw    = row.raw_log || '';
    const hasRaw = raw.length > 0;

    // Build JSON envelope matching the Windows Agent send format
    const rawSnip = raw.length > 80 ? raw.slice(0, 80) + '…' : raw;
    const logObj  = {
      agent_id:    row.agent_id    || '',
      hostname:    row.hostname    || '',
      os_type:     'windows',
      source_type: row.source_type || '',
      IP_AGENT:    row.ip_agent    || '',
      timestamp:   row.time        || '',
      raw_log:     rawSnip,
    };
    const logJson = JSON.stringify(logObj, null, 2);

    // Alert tags
    const alertCell = row.has_alert
      ? `<span class="alert-dot" title="${escHtml((row.rule_tags || []).join(', '))}">●</span>`
      : '<span style="color:#94a3b8">—</span>';

    const tr = document.createElement('tr');
    if (rowBg) tr.style.background = rowBg;
    tr.innerHTML = `
      <td class="cell-time">${fmtTime(row.time)}</td>
      <td><code class="agent-id-code">${escHtml(row.agent_id || '—')}</code></td>
      <td><span class="log-type-badge ${stClass}">${escHtml(st)}</span></td>
      <td class="cell-eid">${eidStr}</td>
      <td>${lvlHtml}</td>
      <td class="cell-host">${escHtml(row.hostname || '—')}</td>
      <td class="cell-raw">
        <pre class="log-json-snippet">${escHtml(logJson)}</pre>
        ${hasRaw ? `<button class="btn-view-raw" onclick="showRawLog(feedRowCache[${row.id}])">View</button>` : ''}
      </td>
      <td style="text-align:center">${alertCell}</td>
    `;
    tbody.appendChild(tr);
  });
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---- Raw Log Modal ----
function showRawLog(row) {
  currentRawLog = row.raw_log || '';
  const modal   = document.getElementById('rawLogModal');
  const content = document.getElementById('rawLogContent');
  const metaEl  = document.getElementById('rawLogMeta');

  if (metaEl) {
    metaEl.innerHTML = `
      <span class="rl-meta-item"><strong>Agent:</strong> ${escHtml(row.agent_id || '—')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Host:</strong> ${escHtml(row.hostname || '—')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Source:</strong> ${escHtml(row.source_type || '—')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Event ID:</strong> ${row.event_id != null ? row.event_id : '—'}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Time:</strong> ${escHtml(fmtTime(row.time))}</span>
    `;
  }

  if (content) {
    content.textContent = formatXML(currentRawLog);
  }

  if (modal) modal.style.display = 'flex';
}

function closeRawLogModal(e) {
  if (e.target === e.currentTarget)
    document.getElementById('rawLogModal').style.display = 'none';
}

function copyRawLog() {
  if (!currentRawLog) return;
  navigator.clipboard.writeText(currentRawLog).then(() => {
    const btn = document.querySelector('.btn-copy-raw');
    if (btn) {
      btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
      setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i> Copy'; }, 1500);
    }
  });
}

function formatXML(xml) {
  if (!xml) return '';
  try {
    let indent = 0;
    const lines = [];
    xml.replace(/>\s*</g, '>\n<').split('\n').forEach(line => {
      line = line.trim();
      if (!line) return;
      if (line.startsWith('</')) indent = Math.max(0, indent - 1);
      lines.push('  '.repeat(indent) + line);
      if (!line.startsWith('</') && !line.endsWith('/>') && line.includes('<') && !line.includes('</'))
        indent++;
    });
    return lines.join('\n');
  } catch (_) {
    return xml;
  }
}

// ========================================================
// ALERTS PAGE
// ========================================================
async function loadAlertsPage() {
  const data = await apiFetch('/api/alerts?limit=100');
  if (!data) return;

  const tbody = document.getElementById('alertsBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:#94a3b8;padding:32px">No alerts found</td></tr>';
    return;
  }

  data.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${a.id}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(a.threat)}">${escHtml(a.threat)}</td>
      <td>${sevBadge(a.severity)}</td>
      <td style="font-weight:600;color:#1d4ed8">${a.event_id != null ? a.event_id : '—'}</td>
      <td style="white-space:nowrap;color:#64748b;font-size:12px">${fmtTime(a.time)}</td>
      <td><code style="font-size:12px;color:#475569">${a.ip_agent || '—'}</code></td>
      <td><code style="font-size:12px;color:#475569">${escHtml(a.agent_id || '—')}</code></td>
      <td>${escHtml(a.hostname || '—')}</td>
      <td><span class="log-type-badge lt-${(a.source_type || '').replace(/[^a-z0-9]/g, '-')}">${a.source_type || '—'}</span></td>
      <td>${dispBadge(a.disposition)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ========================================================
// AGENTS PAGE
// ========================================================
async function loadAgentsPage() {
  const data = await apiFetch('/api/agents');
  if (!data) return;

  const tbody = document.getElementById('agentsBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:32px">No agents registered yet</td></tr>';
    return;
  }

  data.forEach(a => {
    const statusCls  = a.active ? 'agent-active' : 'agent-inactive';
    const statusText = a.active ? '● Active' : '○ Inactive';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${a.id}</td>
      <td><code style="font-size:12px;color:#1d4ed8;font-weight:600">${escHtml(a.agent_id)}</code></td>
      <td style="font-weight:500">${escHtml(a.hostname)}</td>
      <td><code style="font-size:12px;color:#475569">${a.ip || '—'}</code></td>
      <td>${a.os || '—'}</td>
      <td class="${statusCls}">${statusText}</td>
      <td style="color:#64748b;font-size:12px">${fmtTime(a.first_seen)}</td>
      <td style="color:#64748b;font-size:12px">${fmtTime(a.last_seen)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ========================================================
// RULES PAGE
// ========================================================
async function loadRulesPage() {
  const data = await apiFetch('/api/rules');
  if (!data) return;

  const tbody = document.getElementById('rulesBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  data.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${r.id}</td>
      <td style="max-width:400px" title="${escHtml(r.name)}">${escHtml(r.name)}</td>
      <td><code style="font-size:12px;color:#475569">${r.type}</code></td>
      <td>${sevBadge(r.severity)}</td>
      <td class="${r.active ? 'rule-on' : 'rule-off'}">${r.active ? '✓ Active' : '✗ Disabled'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ========================================================
// USERS PAGE
// ========================================================
async function loadUsersPage() {
  const data = await apiFetch('/api/users');
  if (!data) return;

  const tbody = document.getElementById('usersBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  data.forEach(u => {
    const roleColor = { admin: '#ef4444', analyst: '#0ea5e9', viewer: '#94a3b8' }[u.role] || '#94a3b8';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${u.id}</td>
      <td style="font-weight:500">${escHtml(u.username)}</td>
      <td style="color:#64748b">${u.email || '—'}</td>
      <td><span style="color:${roleColor};font-weight:600;text-transform:capitalize">${u.role}</span></td>
      <td class="${u.active ? 'agent-active' : 'agent-inactive'}">${u.active ? '● Active' : '○ Inactive'}</td>
      <td style="color:#64748b;font-size:12px">${fmtTime(u.created_at)}</td>
      <td style="color:#64748b;font-size:12px">${fmtTime(u.last_login)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function submitNewUser(e) {
  e.preventDefault();
  const form = e.target;
  const msg  = document.getElementById('modalMsg');
  const fd   = new FormData(form);
  const body = {
    username: fd.get('username'),
    password: fd.get('password'),
    email:    fd.get('email'),
    role:     fd.get('role'),
  };

  try {
    const res  = await fetch('/api/users', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (res.ok) {
      msg.textContent = `User "${body.username}" created!`;
      msg.className   = 'modal-msg ok';
      form.reset();
      setTimeout(() => {
        document.getElementById('addUserModal').style.display = 'none';
        msg.textContent = '';
        loadUsersPage();
      }, 1200);
    } else {
      msg.textContent = data.error || 'Failed to create user';
      msg.className   = 'modal-msg err';
    }
  } catch (err) {
    msg.textContent = 'Network error';
    msg.className   = 'modal-msg err';
  }
}

function closeModal(e) {
  if (e.target === e.currentTarget)
    document.getElementById('addUserModal').style.display = 'none';
}

// ========================================================
// AI ASSISTANT (LM Studio — local, no cloud)
// ========================================================
const AI_OFFLINE_MSG =
  'Local AI is offline. Open LM Studio, load qwen3-4b-instruct-2507, then start the Local Server on port 1234.';

function loadAssistantPage() {
  loadAIStatus();
  loadAIContext();
}

async function loadAIStatus() {
  const dot  = document.getElementById('aiStatusDot');
  const txt  = document.getElementById('aiStatusText');
  const meta = document.getElementById('aiStatusMeta');
  if (!dot || !txt) return;

  dot.className = 'ai-dot ai-dot-pending';
  txt.textContent = 'Checking local AI…';
  if (meta) meta.innerHTML = '';

  try {
    const res = await fetch('/api/ai/status', { credentials: 'same-origin' });
    if (res.status === 401) { location.href = '/login'; return; }
    const d = await res.json();

    if (d.online) {
      dot.className  = 'ai-dot ai-dot-online';
      txt.textContent = 'Local AI Online';
    } else {
      dot.className  = 'ai-dot ai-dot-offline';
      txt.textContent = 'Local AI Offline';
    }

    if (meta) {
      meta.innerHTML = `
        <div><strong>Provider:</strong> ${escHtml(d.provider || 'LM Studio')}</div>
        <div><strong>Model:</strong> <code>${escHtml(d.model || '—')}</code></div>
        <div><strong>Endpoint:</strong> <code>${escHtml(d.base_url || '—')}</code></div>
        <div><strong>Privacy:</strong> Local only — no cloud API</div>
        <div class="ai-status-msg">${escHtml(d.message || '')}</div>
      `;
    }
  } catch (e) {
    dot.className  = 'ai-dot ai-dot-offline';
    txt.textContent = 'Local AI Offline';
    if (meta) meta.innerHTML = `<div class="ai-status-msg">${escHtml(AI_OFFLINE_MSG)}</div>`;
  }
}

async function loadAIContext() {
  const box = document.getElementById('aiContextBody');
  if (!box) return;
  box.innerHTML = '<div class="ai-context-loading">Loading context…</div>';
  try {
    const data = await apiFetch('/api/ai/context');
    if (!data) return;

    const alerts = data.alerts || [];
    const logs   = data.logs   || [];

    const alertRows = alerts.length
      ? alerts.map(a => `
          <tr>
            <td>${sevBadge(a.severity)}</td>
            <td title="${escHtml(a.rule_name || '')}">${escHtml(a.rule_name || '—')}</td>
            <td>${a.event_id != null ? a.event_id : '—'}</td>
            <td>${escHtml(a.hostname || '—')}</td>
            <td><code>${escHtml(a.ip_agent || '—')}</code></td>
            <td style="color:#64748b;font-size:12px">${fmtTime(a.triggered_at)}</td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:12px">No alerts yet</td></tr>';

    const logRows = logs.length
      ? logs.map(l => `
          <tr>
            <td>${l.event_id != null ? l.event_id : '—'}</td>
            <td>${l.level != null ? levelBadge(l.level) : '—'}</td>
            <td>${escHtml(l.hostname || '—')}</td>
            <td><span class="log-type-badge">${escHtml(l.source_type || '—')}</span></td>
            <td style="color:#64748b;font-size:12px">${fmtTime(l.event_timestamp)}</td>
            <td>${(l.rule_tags || []).map(t => `<span class="ai-tag">${escHtml(t)}</span>`).join(' ') || '—'}</td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:12px">No logs yet</td></tr>';

    box.innerHTML = `
      <div class="ai-ctx-section">
        <div class="ai-ctx-title">Last ${alerts.length} alerts</div>
        <div class="table-wrap">
          <table class="siem-table">
            <thead><tr>
              <th>Severity</th><th>Rule</th><th>Event</th><th>Host</th><th>IP</th><th>Time</th>
            </tr></thead>
            <tbody>${alertRows}</tbody>
          </table>
        </div>
      </div>
      <div class="ai-ctx-section">
        <div class="ai-ctx-title">Last ${logs.length} logs</div>
        <div class="table-wrap">
          <table class="siem-table">
            <thead><tr>
              <th>Event</th><th>Level</th><th>Host</th><th>Source</th><th>Time</th><th>Rule Tags</th>
            </tr></thead>
            <tbody>${logRows}</tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    box.innerHTML = '<div class="ai-context-loading">Failed to load context.</div>';
  }
}

function setAssistantQuestion(text) {
  const ta = document.getElementById('aiQuestion');
  if (ta) {
    ta.value = text;
    ta.focus();
  }
}

function renderAIAnswer(text) {
  // Highlight the four section headings produced by the system prompt.
  const headers = ['Summary', 'Risk Level', 'Evidence From SIEM', 'Recommended Next Steps'];
  let html = escHtml(text);
  headers.forEach(h => {
    const re = new RegExp(`(^|\\n)\\s*(${h})\\s*:?`, 'g');
    html = html.replace(re, `$1<div class="ai-section-h">$2</div>`);
  });
  return html.replace(/\n/g, '<br>');
}

async function askAI() {
  const ta   = document.getElementById('aiQuestion');
  const btn  = document.getElementById('aiAskBtn');
  const out  = document.getElementById('aiResponse');
  if (!ta || !btn || !out) return;

  const question = (ta.value || '').trim();
  if (!question) {
    out.innerHTML = '<div class="ai-response-err">Please type a question first.</div>';
    return;
  }

  btn.disabled    = true;
  const oldHtml   = btn.innerHTML;
  btn.innerHTML   = '<i class="fas fa-spinner fa-spin"></i> Thinking…';
  out.innerHTML   = '<div class="ai-response-loading"><i class="fas fa-spinner fa-spin"></i> Local AI is analyzing SIEM context…</div>';

  try {
    const res = await fetch('/api/ai/ask', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, mode: 'general' }),
    });

    if (res.status === 401) { location.href = '/login'; return; }

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const msg = data.error || AI_OFFLINE_MSG;
      out.innerHTML = `<div class="ai-response-err"><i class="fas fa-triangle-exclamation"></i> ${escHtml(msg)}</div>`;
      return;
    }

    out.innerHTML = `
      <div class="ai-response-meta">
        <span><i class="fas fa-microchip"></i> ${escHtml(data.provider || 'LM Studio')}</span>
        <span><i class="fas fa-cube"></i> <code>${escHtml(data.model || '')}</code></span>
        <span><i class="fas fa-lock"></i> Local · no cloud</span>
      </div>
      <div class="ai-response-text">${renderAIAnswer(data.answer || '')}</div>
    `;
  } catch (err) {
    out.innerHTML = `<div class="ai-response-err"><i class="fas fa-triangle-exclamation"></i> ${escHtml(AI_OFFLINE_MSG)}</div>`;
  } finally {
    btn.disabled  = false;
    btn.innerHTML = oldHtml;
  }
}

// ========================================================
// GLOBAL REFRESH
// ========================================================
async function refreshAll() {
  const icon = document.getElementById('refreshIcon');
  if (icon) icon.classList.add('spin');

  try {
    if (currentPage === 'overview') {
      await Promise.all([
        loadKPIs(),
        loadEventsChart(),
        loadSummaryTable(),
        loadLogTypesChart(),
        loadMap(),
        loadRecentLogs(),
      ]);
    } else if (currentPage === 'alerts') {
      await Promise.all([loadKPIs(), loadAlertsPage()]);
    } else if (currentPage === 'agents') {
      await Promise.all([loadKPIs(), loadAgentsPage()]);
    } else if (currentPage === 'rules') {
      await loadRulesPage();
    } else if (currentPage === 'assistant') {
      // do not auto-refresh the assistant page to avoid disrupting input/response
    } else if (currentPage === 'users') {
      await loadUsersPage();
    }

    const ts = document.getElementById('sb-last-update');
    if (ts) ts.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    console.error('Refresh error:', err);
  } finally {
    if (icon) icon.classList.remove('spin');
  }
}

// ========================================================
// INIT
// ========================================================
document.addEventListener('DOMContentLoaded', () => {
  showPage('overview');

  // Auto-refresh every 5 s
  setInterval(() => {
    if (document.visibilityState === 'visible') refreshAll();
  }, 5000);

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshAll();
  });
});

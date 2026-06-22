/* ==========================================================
   SIEM Dashboard â€” Client-Side Logic
   ========================================================== */

'use strict';

// ---- State ----
let eventsChart   = null;
let logTypesChart = null;
let geoChart      = null;
let worldFeatures = null;
let currentPage   = 'overview';
let currentRawLog = '';
let playbookCache = [];
let selectedPlaybookId = null;
let activeRunId = null;
let activeRunCache = null;
let feedRowCache  = {};   // id â†’ row, avoids embedding JSON in onclick attrs

const PAGE_LABELS = {
  overview:  'Overview',
  alerts:    'Alerts',
  agents:    'Agents',
  rules:     'Rules',
  playbooks: 'Playbooks',
  runbooks:  'Runbooks',
  assistant: 'AI Assistant',
  users:     'Users',
};

// Level number â†’ human label
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
  if (!ts) return 'â€”';
  return ts.slice(0, 19).replace('T', ' ');
}

function sevBadge(sev) {
  return `<span class="sev sev-${(sev || 'info').toLowerCase()}">${(sev || 'info').toUpperCase()}</span>`;
}

function dispBadge(d) {
  return `<span class="disp disp-${d || 'open'}">${(d || 'open').replace('_', ' ')}</span>`;
}

function runStatusLabel(status) {
  return (status || 'in_progress').replace(/_/g, ' ');
}

function runTriggerLabel(run) {
  return run?.alert_id ? `Alert #${run.alert_id}` : 'Manual';
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
  if (id === 'playbooks') loadPlaybooksPage();
  if (id === 'runbooks')  loadRunbooksPage();
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
// OVERVIEW PAGE â€” KPIs
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
  const range = document.getElementById('timeRange')?.value || '3m';
  const data  = await apiFetch(`/api/events_over_time?range=${encodeURIComponent(range)}`);
  if (!data) return;

  const buckets = Array.isArray(data) ? data : (data.buckets || []);
  const labels  = buckets.map(d => d.label || d.time || '');
  const counts  = buckets.map(d => d.count);
  const grain   = Array.isArray(data) ? 'time' : (data.grain || 'bucket');

  const meta = document.getElementById('chart-meta');
  if (meta) meta.textContent = `${buckets.length} ${grain} buckets`;

  const pointRadius = buckets.length > 120 ? 0 : buckets.length > 60 ? 2 : 3;

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
        pointRadius,
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
        tooltip: { callbacks: { title: items => items[0].label } }
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
    eventsChart.data.datasets[0].pointRadius = pointRadius;
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
// ATTACKER ORIGIN MAP â€” chartjs-chart-geo (no image tiles)
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

  // Always hide the overlay â€” map renders regardless of data
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
          label:  `${entry.ip}  â€”  ${geo.city ? geo.city + ', ' : ''}${geo.country}  (${entry.count} events)`,
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
      : ipList.length > 0 ? 'private network â€” no public IPs' : 'no agent IPs yet';
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
// LIVE LOG FEED â€” includes agent_id + raw_log
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
          Waiting for Windows Agent data â€” start SIEMAgent.exe on the endpoint
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
    const eidStr  = row.event_id != null ? row.event_id : 'â€”';
    const lvlHtml = row.level != null ? levelBadge(row.level) : '<span style="color:#94a3b8">â€”</span>';

    const raw    = row.raw_log || '';
    const hasRaw = raw.length > 0;

    // Build JSON envelope matching the Windows Agent send format
    const rawSnip = raw.length > 80 ? raw.slice(0, 80) + 'â€¦' : raw;
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
      ? `<span class="alert-dot" title="${escHtml((row.rule_tags || []).join(', '))}">â—</span>`
      : '<span style="color:#94a3b8">â€”</span>';

    const tr = document.createElement('tr');
    if (rowBg) tr.style.background = rowBg;
    tr.innerHTML = `
      <td class="cell-time">${fmtTime(row.time)}</td>
      <td><code class="agent-id-code">${escHtml(row.agent_id || 'â€”')}</code></td>
      <td><span class="log-type-badge ${stClass}">${escHtml(st)}</span></td>
      <td class="cell-eid">${eidStr}</td>
      <td>${lvlHtml}</td>
      <td class="cell-host">${escHtml(row.hostname || 'â€”')}</td>
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
      <span class="rl-meta-item"><strong>Agent:</strong> ${escHtml(row.agent_id || 'â€”')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Host:</strong> ${escHtml(row.hostname || 'â€”')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Source:</strong> ${escHtml(row.source_type || 'â€”')}</span>
      <span class="rl-meta-sep">|</span>
      <span class="rl-meta-item"><strong>Event ID:</strong> ${row.event_id != null ? row.event_id : 'â€”'}</span>
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
    tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:#94a3b8;padding:32px">No alerts found</td></tr>';
    return;
  }

  data.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${a.id}</td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(a.threat)}">${escHtml(a.threat)}</td>
      <td>${sevBadge(a.severity)}</td>
      <td style="font-weight:600;color:#1d4ed8">${a.event_id != null ? a.event_id : 'â€”'}</td>
      <td style="white-space:nowrap;color:#64748b;font-size:12px">${fmtTime(a.time)}</td>
      <td><code style="font-size:12px;color:#475569">${a.ip_agent || 'â€”'}</code></td>
      <td><code style="font-size:12px;color:#475569">${escHtml(a.agent_id || 'â€”')}</code></td>
      <td>${escHtml(a.hostname || 'â€”')}</td>
      <td><span class="log-type-badge lt-${(a.source_type || '').replace(/[^a-z0-9]/g, '-')}">${a.source_type || 'â€”'}</span></td>
      <td>${dispBadge(a.disposition)}</td>
      <td>
        <button class="btn-playbook-mini" onclick="openAlertPlaybook(${a.id})" title="Open matched playbook">
          <i class="fas fa-clipboard-list"></i> Open
        </button>
      </td>
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
    const statusText = a.active ? 'â— Active' : 'â—‹ Inactive';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:#94a3b8;font-size:12px">${a.id}</td>
      <td><code style="font-size:12px;color:#1d4ed8;font-weight:600">${escHtml(a.agent_id)}</code></td>
      <td style="font-weight:500">${escHtml(a.hostname)}</td>
      <td><code style="font-size:12px;color:#475569">${a.ip || 'â€”'}</code></td>
      <td>${a.os || 'â€”'}</td>
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
      <td class="${r.active ? 'rule-on' : 'rule-off'}">${r.active ? 'âœ“ Active' : 'âœ— Disabled'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ========================================================
// USERS PAGE
// ========================================================
// ========================================================
// PLAYBOOKS PAGE
// ========================================================
async function loadPlaybooksPage() {
  const box = document.getElementById('playbookList');
  if (box) box.innerHTML = '<div class="pb-empty">Loading playbooks...</div>';

  const data = await apiFetch('/api/playbooks');
  if (!data) return;

  playbookCache = data.playbooks || [];
  updatePlaybookCoverage(data.coverage);
  populatePlaybookCategoryFilter(playbookCache);
  renderPlaybookList();

  if (!selectedPlaybookId && playbookCache.length) {
    selectPlaybook(playbookCache[0].id);
  } else if (selectedPlaybookId) {
    selectPlaybook(selectedPlaybookId);
  }
}

function updatePlaybookCoverage(coverage) {
  if (!coverage) return;
  const pct = Number(coverage.coverage_percent || 0);
  const pctEl = document.getElementById('pbCoveragePct');
  const barEl = document.getElementById('pbCoverageBar');
  const coveredEl = document.getElementById('pbCoverageCovered');
  const missingEl = document.getElementById('pbCoverageMissing');
  if (pctEl) pctEl.textContent = `${pct}%`;
  if (barEl) barEl.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  if (coveredEl) coveredEl.textContent = `${coverage.covered_rules || 0}/${coverage.total_rules || 0} rules covered`;
  if (missingEl) {
    const missing = coverage.missing_rules || 0;
    missingEl.textContent = `${missing} missing`;
    missingEl.classList.toggle('pb-coverage-ok', missing === 0);
    missingEl.classList.toggle('pb-coverage-warn', missing > 0);
  }
}

function populatePlaybookCategoryFilter(playbooks) {
  const sel = document.getElementById('playbookCategoryFilter');
  if (!sel) return;
  const current = sel.value;
  const cats = [...new Set(playbooks.map(p => p.category).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">All categories</option>' +
    cats.map(c => `<option value="${escHtml(c)}">${escHtml(c)}</option>`).join('');
  if (cats.includes(current)) sel.value = current;
}

function playbookSearchText(p) {
  return [
    p.name,
    p.summary,
    p.category,
    p.severity,
    ...(p.event_ids || []),
    ...(p.rule_names || []),
    ...(p.mitre_tactics || []),
    ...(p.mitre_techniques || []),
  ].filter(v => v != null).join(' ').toLowerCase();
}

function filteredPlaybooks() {
  const q = (document.getElementById('playbookSearch')?.value || '').trim().toLowerCase();
  const sev = document.getElementById('playbookSeverityFilter')?.value || '';
  const cat = document.getElementById('playbookCategoryFilter')?.value || '';
  return playbookCache.filter(p => {
    if (sev && p.severity !== sev) return false;
    if (cat && p.category !== cat) return false;
    return !q || playbookSearchText(p).includes(q);
  });
}

function renderPlaybookList() {
  const list = document.getElementById('playbookList');
  const count = document.getElementById('playbookCount');
  if (!list) return;

  const rows = filteredPlaybooks();
  if (count) count.textContent = `${rows.length} playbook${rows.length === 1 ? '' : 's'}`;

  if (!rows.length) {
    list.innerHTML = '<div class="pb-empty">No playbooks match the current filters.</div>';
    return;
  }

  list.innerHTML = rows.map(p => {
    const active = p.id === selectedPlaybookId ? ' active' : '';
    const events = (p.event_ids || []).slice(0, 4).map(id => `<span>EID ${escHtml(id)}</span>`).join('');
    return `
      <button type="button" class="playbook-item${active}" onclick="selectPlaybook(${p.id})">
        <span class="pb-item-top">
          ${sevBadge(p.severity)}
          <span class="pb-category">${escHtml(p.category)}</span>
        </span>
        <span class="pb-item-name">${escHtml(p.name)}</span>
        <span class="pb-item-summary">${escHtml(p.summary)}</span>
        <span class="pb-event-tags">${events}</span>
      </button>`;
  }).join('');
}

async function selectPlaybook(id) {
  selectedPlaybookId = id;
  renderPlaybookList();

  const detail = document.getElementById('playbookDetail');
  if (detail) detail.innerHTML = '<div class="pb-empty">Loading playbook...</div>';

  const p = await apiFetch(`/api/playbooks/${id}`);
  if (!p || !detail) return;

  const eventTags = (p.event_ids || []).map(e => `<span class="pb-tag">EID ${escHtml(e)}</span>`).join('');
  const rules = (p.rule_names || []).map(r => `<li>${escHtml(r)}</li>`).join('');
  const evidence = (p.evidence_items || []).map(item => `<li><i class="fas fa-square-check"></i>${escHtml(item)}</li>`).join('');
  const mitre = [...(p.mitre_tactics || []), ...(p.mitre_techniques || [])]
    .map(m => `<span class="pb-tag pb-tag-mitre">${escHtml(m)}</span>`).join('');
  const steps = (p.steps || []).map(step => renderPlaybookStep(step)).join('');

  detail.innerHTML = `
    <div class="pb-detail-head">
      <div>
        <div class="pb-detail-meta">${sevBadge(p.severity)} <span>${escHtml(p.category)}</span></div>
        <h3>${escHtml(p.name)}</h3>
        <p>${escHtml(p.summary)}</p>
      </div>
      <button class="btn-primary" onclick="startPlaybookRun(${p.id})">
        <i class="fas fa-play"></i> Create Runbook
      </button>
    </div>

    <div class="pb-tag-row">${eventTags}${mitre}</div>

    <div class="pb-detail-grid">
      <div class="pb-panel">
        <h4><i class="fas fa-fingerprint"></i> Evidence Checklist</h4>
        <ul class="pb-check-list">${evidence}</ul>
      </div>
      <div class="pb-panel">
        <h4><i class="fas fa-triangle-exclamation"></i> Escalation</h4>
        <p>${escHtml(p.escalation || 'No escalation guidance defined.')}</p>
        <h4><i class="fas fa-shield-halved"></i> Containment</h4>
        <p>${escHtml(p.containment || 'No containment guidance defined.')}</p>
      </div>
    </div>

    <div class="pb-panel">
      <h4><i class="fas fa-bullseye"></i> Linked Detection Rules</h4>
      <ul class="pb-rule-list">${rules || '<li>No linked rules.</li>'}</ul>
    </div>

    <div class="pb-steps">
      <h4><i class="fas fa-route"></i> Runbook Template</h4>
      ${steps}
    </div>
  `;
}

function renderPlaybookStep(step, runMode = false) {
  const runLocked = runMode && activeRunCache?.status === 'cancelled';
  const command = step.command
    ? `<div class="pb-command">
         <button class="btn-copy-cmd" onclick="copyPlaybookCommand(this)" title="Copy command">
           <i class="fas fa-copy"></i>
         </button>
         <pre>${escHtml(step.command)}</pre>
       </div>`
    : '';
  const checkbox = runMode
    ? `<input type="checkbox" ${step.done ? 'checked' : ''} ${runLocked ? 'disabled' : ''} onchange="toggleRunStep(${step.step_id}, this.checked)">`
    : `<span class="pb-step-num">${step.order}</span>`;
  return `
    <div class="pb-step ${step.done ? 'done' : ''}" ${runMode ? `id="run-step-${step.step_id}"` : ''}>
      <div class="pb-step-marker">${checkbox}</div>
      <div class="pb-step-body">
        <div class="pb-step-top">
          <span class="pb-phase">${escHtml(step.phase)}</span>
          <span class="pb-step-type">${escHtml(step.type || 'manual')}</span>
        </div>
        <h5>${escHtml(step.title)}</h5>
        <p>${escHtml(step.detail)}</p>
        ${command}
      </div>
    </div>`;
}

async function startPlaybookRun(playbookId, alertId = null) {
  const res = await fetch('/api/playbook-runs', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ playbook_id: playbookId, alert_id: alertId }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    showPlaybookError(data.error || 'Failed to start playbook run.');
    return;
  }
  showPage('runbooks');
  await openPlaybookRun(data.run_id);
}

async function openPlaybookRun(runId) {
  const detail = document.getElementById('runbookDetail') || document.getElementById('playbookDetail');
  if (detail) detail.innerHTML = '<div class="pb-empty">Loading run...</div>';

  const run = await apiFetch(`/api/playbook-runs/${runId}`);
  if (!run || !detail) return;
  activeRunId = run.id;
  activeRunCache = run;

  const done = run.steps.filter(s => s.done).length;
  const total = run.steps.length;
  const pct = total ? Math.round((done / total) * 100) : 0;
  const isClosed = ['completed', 'cancelled'].includes(run.status);
  const statusCls = `run-status-${(run.status || 'in_progress').replace(/_/g, '-')}`;
  const firstTodo = run.steps.find(s => !s.done);
  detail.innerHTML = `
    <div class="pb-detail-head">
      <div>
        <div class="pb-detail-meta">${sevBadge(run.severity)} <span>${escHtml(run.category)}</span> <span class="run-status-pill ${statusCls}">${escHtml(runStatusLabel(run.status))}</span></div>
        <h3>${escHtml(run.playbook_name)}</h3>
        <p>${escHtml(run.summary || '')}</p>
      </div>
      <div class="runbook-detail-actions">
        <button class="btn-primary" onclick="resumePlaybookRun()" ${firstTodo && !isClosed ? '' : 'disabled'}>
          <i class="fas fa-play"></i> Resume
        </button>
        <button class="btn-playbook-mini" onclick="showRunReport()">
          <i class="fas fa-file-lines"></i> View Report
        </button>
        <button class="btn-playbook-mini btn-run-cancel" onclick="cancelPlaybookRun(${run.id})" ${isClosed ? 'disabled' : ''}>
          <i class="fas fa-ban"></i> Cancel
        </button>
        <button class="btn-refresh" onclick="openPlaybookLibrary(${run.playbook_id})">
          <i class="fas fa-book-open"></i> Library View
        </button>
      </div>
    </div>
    <div class="runbook-facts">
      <span><i class="fas fa-hashtag"></i> Run #${run.id}</span>
      <span><i class="fas fa-bolt"></i> ${escHtml(runTriggerLabel(run))}</span>
      <span><i class="fas fa-user-shield"></i> ${escHtml(run.started_by || 'Unknown analyst')}</span>
      <span><i class="fas fa-clock"></i> Started ${escHtml(fmtTime(run.started_at))}</span>
      ${run.completed_at ? `<span><i class="fas fa-flag-checkered"></i> Closed ${escHtml(fmtTime(run.completed_at))}</span>` : ''}
    </div>
    <div class="pb-run-progress">
      <div>
        <strong>Run #${run.id}</strong>
        <span>${escHtml(runStatusLabel(run.status))}</span>
      </div>
      <div class="pb-progress-bar"><span style="width:${pct}%"></span></div>
      <span>${done}/${total} steps complete</span>
    </div>
    <div class="pb-steps pb-run-steps">
      ${run.steps.map(step => renderPlaybookStep(step, true)).join('')}
    </div>
  `;
  await loadRunbookRuns();
}

async function toggleRunStep(stepId, done) {
  if (!activeRunId) return;
  const res = await fetch(`/api/playbook-runs/${activeRunId}/steps/${stepId}`, {
    method: 'PATCH',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ done }),
  });
  if (!res.ok) {
    showPlaybookError('Failed to update run step.');
    return;
  }
  await openPlaybookRun(activeRunId);
  await loadRunbookRuns();
}

function resumePlaybookRun() {
  const todo = activeRunCache?.steps?.find(s => !s.done);
  if (!todo) return;
  const el = document.getElementById(`run-step-${todo.step_id}`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('pb-step-focus');
    setTimeout(() => el.classList.remove('pb-step-focus'), 1600);
  }
}

async function cancelPlaybookRun(runId) {
  const run = activeRunCache?.id === runId ? activeRunCache : null;
  if (run && ['completed', 'cancelled'].includes(run.status)) return;
  if (!confirm(`Cancel response run #${runId}?`)) return;

  const res = await fetch(`/api/playbook-runs/${runId}/cancel`, {
    method: 'PATCH',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    showPlaybookError(data.error || 'Failed to cancel response run.');
    return;
  }
  await openPlaybookRun(runId);
  await loadRunbookRuns();
}

function showRunReport() {
  const run = activeRunCache;
  const modal = document.getElementById('runReportModal');
  const content = document.getElementById('runReportContent');
  if (!run || !modal || !content) return;

  const done = run.steps.filter(s => s.done).length;
  const total = run.steps.length;
  const stepRows = run.steps.map(step => `
    <tr>
      <td>${step.done ? '<i class="fas fa-check-circle report-ok"></i>' : '<i class="far fa-circle report-pending"></i>'}</td>
      <td>${step.order}</td>
      <td>${escHtml(step.phase)}</td>
      <td>${escHtml(step.title)}</td>
      <td>${escHtml(step.completed_at ? fmtTime(step.completed_at) : 'Pending')}</td>
    </tr>
  `).join('');

  content.innerHTML = `
    <div class="run-report-summary">
      <div><span>Run</span><strong>#${run.id}</strong></div>
      <div><span>Status</span><strong>${escHtml(runStatusLabel(run.status))}</strong></div>
      <div><span>Trigger</span><strong>${escHtml(runTriggerLabel(run))}</strong></div>
      <div><span>Progress</span><strong>${done}/${total}</strong></div>
    </div>
    <div class="run-report-meta">
      <h4>${escHtml(run.playbook_name)}</h4>
      <p>${escHtml(run.summary || '')}</p>
      <span>Started ${escHtml(fmtTime(run.started_at))}</span>
      ${run.completed_at ? `<span>Closed ${escHtml(fmtTime(run.completed_at))}</span>` : ''}
    </div>
    <table class="run-report-table">
      <thead><tr><th></th><th>#</th><th>Phase</th><th>Step</th><th>Completed</th></tr></thead>
      <tbody>${stepRows}</tbody>
    </table>
  `;
  modal.style.display = 'flex';
}

function closeRunReportModal(e) {
  if (e.target === e.currentTarget)
    document.getElementById('runReportModal').style.display = 'none';
}

async function loadRunbooksPage() {
  await loadRunbookRuns();
  if (activeRunId) {
    await openPlaybookRun(activeRunId);
  }
}

async function loadRunbookRuns() {
  const box = document.getElementById('runbookRuns');
  if (!box) return;
  const runs = await apiFetch('/api/playbook-runs');
  if (!runs) return;

  if (!runs.length) {
    box.innerHTML = '<div class="pb-empty">No playbook runs yet.</div>';
    return;
  }
  if (activeRunId && !runs.some(r => r.id === activeRunId)) {
    activeRunId = null;
    activeRunCache = null;
  }

  box.innerHTML = runs.map(r => {
    const pct = r.total_steps ? Math.round((r.done_steps / r.total_steps) * 100) : 0;
    const isActive = r.id === activeRunId;
    const active = isActive ? ' active' : '';
    const statusCls = `run-status-${(r.status || 'in_progress').replace(/_/g, '-')}`;
    return `
      <button type="button" class="pb-run-item${active}" onclick="openPlaybookRun(${r.id})" ${isActive ? 'aria-current="true"' : ''}>
        <span class="pb-item-top">
          <span class="run-status-pill ${statusCls}">${escHtml(runStatusLabel(r.status))}</span>
          <span class="pb-category">${isActive ? 'Selected' : escHtml(runTriggerLabel(r))}</span>
        </span>
        <span class="pb-run-title">${escHtml(r.playbook_name)}</span>
        <span class="pb-run-meta">#${r.id} - ${escHtml(r.started_by || 'Unknown analyst')} - ${escHtml(fmtTime(r.started_at))}</span>
        <span class="pb-run-status">${r.done_steps}/${r.total_steps} steps complete</span>
        <span class="pb-run-bar"><span style="width:${pct}%"></span></span>
      </button>`;
  }).join('');
}

async function loadPlaybookRuns() {
  return loadRunbookRuns();
}

async function openPlaybookLibrary(playbookId) {
  showPage('playbooks');
  if (!playbookCache.length) {
    const data = await apiFetch('/api/playbooks');
    playbookCache = data?.playbooks || [];
    populatePlaybookCategoryFilter(playbookCache);
  }
  await selectPlaybook(playbookId);
}

async function openAlertPlaybook(alertId) {
  showPage('playbooks');
  const detail = document.getElementById('playbookDetail');
  if (detail) detail.innerHTML = '<div class="pb-empty">Matching alert to a playbook...</div>';

  const match = await apiFetch(`/api/playbooks/match?alert_id=${alertId}`);
  if (!match) return;
  if (!match.playbook) {
    showPlaybookError('No matching playbook found for this alert.');
    return;
  }

  selectedPlaybookId = match.playbook.id;
  if (!playbookCache.length) {
    const data = await apiFetch('/api/playbooks');
    playbookCache = data?.playbooks || [];
    populatePlaybookCategoryFilter(playbookCache);
  }
  renderPlaybookList();
  await selectPlaybook(match.playbook.id);

  const head = document.querySelector('#playbookDetail .pb-detail-head');
  if (head) {
    head.insertAdjacentHTML('afterend', `
      <div class="pb-alert-match">
        <i class="fas fa-bell"></i>
        Matched Alert #${match.alert.id}: ${escHtml(match.alert.threat)} / EID ${match.alert.event_id ?? 'unknown'}
        <button class="btn-primary" onclick="startPlaybookRun(${match.playbook.id}, ${alertId})">
          <i class="fas fa-play"></i> Start for Alert
        </button>
      </div>`);
  }
}

function copyPlaybookCommand(btn) {
  const pre = btn?.parentElement?.querySelector('pre');
  const text = pre?.textContent || '';
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    btn.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i>'; }, 1200);
  });
}

function showPlaybookError(msg) {
  const detail = document.getElementById('playbookDetail');
  if (detail) {
    detail.innerHTML = `<div class="ai-response-err"><i class="fas fa-triangle-exclamation"></i> ${escHtml(msg)}</div>`;
  }
}

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
      <td style="color:#64748b">${u.email || 'â€”'}</td>
      <td><span style="color:${roleColor};font-weight:600;text-transform:capitalize">${u.role}</span></td>
      <td class="${u.active ? 'agent-active' : 'agent-inactive'}">${u.active ? 'â— Active' : 'â—‹ Inactive'}</td>
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
// AI ASSISTANT (LM Studio â€” local, no cloud)
// ========================================================
const AI_OFFLINE_MSG =
  'Ollama is offline. Start Ollama and make sure the selected model is installed.';
const AI_MODEL_KEY = 'siem_ai_model_profile';
const AI_MODEL_PROFILES = {
  fast: {
    label: 'Fast',
    model: 'llama3.2:3b',
    hint: 'Fast is recommended for live demos.',
    meta: 'Ollama - llama3.2:3b - Fast - Local'
  },
  deep: {
    label: 'Deep',
    model: 'qwen3:8b',
    hint: 'Deep gives richer analysis but may respond slower.',
    meta: 'Ollama - qwen3:8b - Deep - Local'
  }
};

// Cache the most recently loaded SIEM context so analyze buttons work
// without a second round trip.
let aiContextCache = { events: [] };
let aiBusy = false;
let eventPickerState = { selectedIndex: null, filter: 'all' };
let aiProgressTimer = null;
let aiSelectedModelProfile = localStorage.getItem(AI_MODEL_KEY) || 'fast';

function loadAssistantPage() {
  initAIModelSelector();
  loadAIStatus();
  loadAIContext();
}

function getAIModelProfile() {
  return AI_MODEL_PROFILES[aiSelectedModelProfile] ? aiSelectedModelProfile : 'fast';
}

function initAIModelSelector() {
  selectAIModel(getAIModelProfile(), false);
}

function selectAIModel(profile, persist = true) {
  aiSelectedModelProfile = AI_MODEL_PROFILES[profile] ? profile : 'fast';
  if (persist) localStorage.setItem(AI_MODEL_KEY, aiSelectedModelProfile);

  document.querySelectorAll('.ai-model-option').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.profile === aiSelectedModelProfile);
  });

  const hint = document.getElementById('aiModelHint');
  const selected = AI_MODEL_PROFILES[aiSelectedModelProfile];
  if (hint && selected) hint.textContent = selected.hint;

  const sub = document.getElementById('aiStatusSub');
  if (sub && selected) sub.textContent = selected.meta;
}

function applyAIModelAvailability(profiles) {
  (profiles || []).forEach(p => {
    const btn = document.querySelector(`.ai-model-option[data-profile="${p.id}"]`);
    if (!btn) return;
    btn.classList.toggle('missing', p.installed === false);
    const badge = btn.querySelector('.ai-model-badge');
    if (badge && p.installed === false) {
      badge.textContent = 'Not installed';
    } else if (badge && p.id === 'fast') {
      badge.textContent = 'Recommended';
    } else if (badge && p.id === 'deep') {
      badge.textContent = 'Higher quality';
    }
  });
}

// ---- Status (simple Online/Offline) ----
async function loadAIStatus() {
  const dot  = document.getElementById('aiStatusDot');
  const txt  = document.getElementById('aiStatusText');
  const hint = document.getElementById('aiStatusHint');
  const sub  = document.getElementById('aiStatusSub');
  if (!dot || !txt) return;

  dot.className = 'ai-dot ai-dot-pending';
  txt.textContent = 'Checkingâ€¦';
  if (hint) hint.textContent = '';

  try {
    const res = await fetch('/api/ai/status', { credentials: 'same-origin' });
    if (res.status === 401) { location.href = '/login'; return; }
    const d = await res.json();
    applyAIModelAvailability(d.profiles || []);
    const selected = AI_MODEL_PROFILES[getAIModelProfile()];

    if (d.online) {
      dot.className  = 'ai-dot ai-dot-online';
      txt.textContent = 'Online';
      if (sub) sub.textContent = selected ? selected.meta : `${d.provider || 'Ollama'} - Local`;
      if (hint) hint.textContent = '';
    } else {
      dot.className  = 'ai-dot ai-dot-offline';
      txt.textContent = 'Offline';
      if (sub) sub.textContent = selected ? selected.meta : `${d.provider || 'Ollama'} - Local`;
      if (hint) hint.textContent = d.message || AI_OFFLINE_MSG;
    }
  } catch (_) {
    dot.className  = 'ai-dot ai-dot-offline';
    txt.textContent = 'Offline';
    const selected = AI_MODEL_PROFILES[getAIModelProfile()];
    if (sub) sub.textContent = selected ? selected.meta : 'Ollama - Local';
    if (hint) hint.textContent = AI_OFFLINE_MSG;
  }
}

// ---- Context: compact cards + populates dropdowns ----
async function loadAIContext() {
  if (aiBusy) return; // don't disturb an in-flight analysis
  const eventsBox = document.getElementById('aiCtxEvents');
  const eventSel  = document.getElementById('aiEventSelect');

  // Preserve current dropdown selections across reloads
  const prevEventIdx = eventSel ? eventSel.value : '';

  if (eventsBox) eventsBox.innerHTML = '<div class="ai-ctx-loading">Loading...</div>';

  try {
    const data = await apiFetch('/api/ai/context');
    if (!data) return;

    const events = data.events || [];
    aiContextCache = { events };

    if (eventsBox) {
      eventsBox.innerHTML = events.length
        ? events.map((e, i) => {
            const badge = e.is_alert
              ? `<span class="ai-type-badge ai-type-alert">ALERT</span>`
              : `<span class="ai-type-badge ai-type-log">LOG</span>`;
            const title = e.is_alert && e.alert_rule ? e.alert_rule : `Event ${e.event_id != null ? e.event_id : 'unknown'}`;
            return `
              <div class="ai-ctx-item" onclick="selectEventFromList(${i})" title="Click to select for analysis">
                <div class="ai-ctx-row1">
                  ${badge}
                  <span class="ai-ctx-eid">EID ${e.event_id != null ? e.event_id : 'â€”'}</span>
                  ${e.level != null ? levelBadge(e.level) : ''}
                  <span class="ai-ctx-rule" title="${escHtml(title)}">${escHtml(title)}</span>
                </div>
                <div class="ai-ctx-row2">
                  <span><i class="fas fa-desktop"></i> ${escHtml(e.hostname || 'â€”')}</span>
                  <span><i class="fas fa-network-wired"></i> <code>${escHtml(e.ip_agent || 'â€”')}</code></span>
                  <span><i class="fas fa-clock"></i> ${fmtTime(e.event_timestamp)}</span>
                </div>
              </div>`;
          }).join('')
        : '<div class="ai-ctx-empty">No events yet</div>';
    }

    if (eventSel) {
      if (events.length) {
        eventSel.innerHTML = events.map((e, i) => {
          const kind  = e.is_alert ? 'ALERT' : 'LOG';
          const name  = e.is_alert && e.alert_rule ? e.alert_rule : `Event ${e.event_id != null ? e.event_id : 'unknown'}`;
          const host  = e.hostname || 'â€”';
          const src   = (e.source_type || 'unknown').toUpperCase();
          const ts    = fmtTime(e.event_timestamp);
          const label = `[${kind}] ${name} â€” ${host} â€” ${src} â€” ${ts}`;
          return `<option value="${i}">${escHtml(label)}</option>`;
        }).join('');
      } else {
        eventSel.innerHTML = '<option value="">No events loaded</option>';
      }
    }

    if (eventSel && prevEventIdx !== '' && eventSel.querySelector(`option[value="${prevEventIdx}"]`)) {
      eventSel.value = prevEventIdx;
    }
    if (!eventSel || eventSel.value === '') {
      eventPickerState.selectedIndex = events.length ? 0 : null;
      if (eventSel && events.length) eventSel.value = '0';
    } else {
      eventPickerState.selectedIndex = parseInt(eventSel.value, 10);
    }
    updateEventPickerSelected();
    renderEventPickerList();
  } catch (_) {
    if (eventsBox) eventsBox.innerHTML = '<div class="ai-ctx-empty">Failed to load.</div>';
    const selected = document.getElementById('eventPickerSelected');
    if (selected) selected.textContent = 'Failed to load events';
  }
}

function switchCtxTab(name) {
  document.querySelectorAll('.ai-ctx-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === name);
  });
  const a = document.getElementById('aiCtxAlerts');
  const l = document.getElementById('aiCtxLogs');
  if (a) a.style.display = name === 'alerts' ? '' : 'none';
  if (l) l.style.display = name === 'logs'   ? '' : 'none';
}

function selectAlertFromList(i) {
  const sel = document.getElementById('aiAlertSelect');
  if (sel && sel.options[i]) {
    sel.value = String(i);
    sel.focus();
  }
}

function eventTitle(e) {
  return e?.is_alert && e.alert_rule
    ? e.alert_rule
    : `Event ${e?.event_id != null ? e.event_id : 'unknown'}`;
}

function eventSearchText(e) {
  return [
    e?.is_alert ? 'alert' : 'log',
    eventTitle(e),
    e?.event_id,
    e?.hostname,
    e?.ip_agent,
    e?.source_type,
    e?.alert_severity,
    e?.event_timestamp,
  ].filter(v => v != null).join(' ').toLowerCase();
}

function eventShortLabel(e) {
  if (!e) return 'No event selected';
  const kind = e.is_alert ? 'ALERT' : 'LOG';
  const host = e.hostname || 'unknown host';
  return `${kind} Â· ${eventTitle(e)} Â· ${host}`;
}

function toggleEventPicker(forceOpen) {
  const picker = document.getElementById('eventPicker');
  if (!picker) return;
  const isOpen = picker.classList.contains('open');
  picker.classList.toggle('open', forceOpen ?? !isOpen);
  if (picker.classList.contains('open')) {
    renderEventPickerList();
    document.getElementById('eventPickerSearch')?.focus();
  }
}

function closeEventPicker() {
  document.getElementById('eventPicker')?.classList.remove('open');
}

function setEventPickerFilter(filter) {
  eventPickerState.filter = filter;
  document.querySelectorAll('.event-filter').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });
  renderEventPickerList();
}

function updateEventPickerSelected() {
  const selected = document.getElementById('eventPickerSelected');
  const e = aiContextCache.events[eventPickerState.selectedIndex];
  if (selected) selected.textContent = e ? eventShortLabel(e) : 'No events loaded';
}

function renderEventPickerList() {
  const list = document.getElementById('eventPickerList');
  if (!list) return;

  const q = (document.getElementById('eventPickerSearch')?.value || '').trim().toLowerCase();
  const filter = eventPickerState.filter;
  const rows = aiContextCache.events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => {
      if (filter === 'alerts' && !event.is_alert) return false;
      if (filter === 'logs' && event.is_alert) return false;
      return !q || eventSearchText(event).includes(q);
    });

  if (!rows.length) {
    list.innerHTML = '<div class="event-picker-empty">No matching events</div>';
    return;
  }

  list.innerHTML = rows.map(({ event: e, index }) => {
    const kind = e.is_alert ? 'ALERT' : 'LOG';
    const typeClass = e.is_alert ? 'ai-type-alert' : 'ai-type-log';
    const selected = index === eventPickerState.selectedIndex ? ' selected' : '';
    const severity = e.is_alert && e.alert_severity ? sevBadge(e.alert_severity) : '';
    const source = (e.source_type || 'unknown').toUpperCase();
    return `
      <button type="button" class="event-picker-item${selected}" onclick="selectEventFromList(${index})">
        <span class="event-picker-main">
          <span class="ai-type-badge ${typeClass}">${kind}</span>
          ${severity}
          <span class="event-picker-title">${escHtml(eventTitle(e))}</span>
        </span>
        <span class="event-picker-meta">
          <span>EID ${e.event_id != null ? escHtml(String(e.event_id)) : 'unknown'}</span>
          <span>${escHtml(e.hostname || 'unknown host')}</span>
          <span>${escHtml(source)}</span>
          <span>${escHtml(fmtTime(e.event_timestamp))}</span>
        </span>
      </button>`;
  }).join('');
}

function selectEventFromList(i) {
  const sel = document.getElementById('aiEventSelect');
  if (!aiContextCache.events[i]) return;
  eventPickerState.selectedIndex = i;
  if (sel && sel.options[i]) sel.value = String(i);
  updateEventPickerSelected();
  renderEventPickerList();
  closeEventPicker();
}

// ---- Custom question helpers ----
function setAssistantQuestion(text) {
  const ta = document.getElementById('aiQuestion');
  if (ta) {
    ta.value = text;
    ta.focus();
  }
}

function onChipExplainSelectedEvent() {
  const sel = document.getElementById('aiEventSelect');
  const idx = sel ? parseInt(sel.value, 10) : NaN;
  if (isNaN(idx) || !aiContextCache.events[idx]) {
    showInlineHint('Please select an event first.');
    return;
  }
  analyzeSelectedEvent();
}

function showInlineHint(msg) {
  const out = document.getElementById('aiResponse');
  if (!out) return;
  out.innerHTML = `<div class="ai-response-hint"><i class="fas fa-circle-info"></i> ${escHtml(msg)}</div>`;
}

// ---- Analyze actions ----
function analyzeSelectedAlert() {
  analyzeSelectedEvent();
}

function analyzeSelectedEvent() {
  const sel = document.getElementById('aiEventSelect');
  const idx = sel ? parseInt(sel.value, 10) : NaN;
  const e   = aiContextCache.events[idx];
  if (!e) {
    showInlineHint('Please select a recent event first.');
    return;
  }

  const tags = (e.rule_tags || []).join(', ') || 'none';
  const snippet = (e.raw_snippet || '').slice(0, 260);
  const kind = e.is_alert ? 'ALERT-triggered event' : 'regular log event';

  const facts = [
    `Type: ${kind}`,
    e.is_alert ? `Alert Rule: ${e.alert_rule || 'unknown'}` : '',
    e.is_alert ? `Alert Severity: ${e.alert_severity || 'unknown'}` : '',
    e.is_alert ? `Alert Disposition: ${e.alert_disposition || 'open'}` : '',
    `Event ID: ${e.event_id != null ? e.event_id : 'unknown'}`,
    `Level: ${e.level != null ? e.level : 'unknown'}`,
    `Hostname: ${e.hostname || 'unknown'}`,
    `Agent IP: ${e.ip_agent || 'unknown'}`,
    `Source Type: ${e.source_type || 'unknown'}`,
    `Timestamp: ${e.event_timestamp || 'unknown'}`,
    `Matched Rule Tags: ${tags}`,
    snippet ? `Raw Snippet (truncated):\n${snippet}` : ''
  ].filter(Boolean).join('\n');

  const q =
    `Analyze the following selected SIEM event in detail. ` +
    `Only use the SIEM context provided in this conversation. ` +
    `Do not invent additional events, IPs, or usernames.\n\n` +
    `Selected Event:\n${facts}\n\n` +
    `Please cover: what this event means, the risk level, the supporting ` +
    `evidence visible in the SIEM context, and clear recommended response steps.`;

  setAssistantQuestion(q);
  askAI();
}

// ---- Render + Ask ----
function renderAIAnswer(text) {
  const headers = ['Summary', 'Risk Level', 'Evidence From SIEM', 'Recommended Next Steps'];
  let html = escHtml(text);
  headers.forEach(h => {
    const re = new RegExp(`(^|\\n)\\s*(${h})\\s*:?`, 'g');
    html = html.replace(re, `$1<div class="ai-section-h">$2</div>`);
  });
  return html.replace(/\n/g, '<br>');
}

function setAIBusy(busy) {
  aiBusy = busy;
  ['aiAskBtn', 'aiAnalyzeAlertBtn', 'aiAnalyzeEventBtn'].forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = busy;
  });
  const askBtn = document.getElementById('aiAskBtn');
  if (askBtn) {
    askBtn.innerHTML = busy
      ? '<i class="fas fa-spinner fa-spin"></i> Analyzing...'
      : '<i class="fas fa-paper-plane"></i> Ask';
  }
}

function setAIThinkingStatus(text) {
  const meta = document.getElementById('aiResponseMeta');
  if (meta) meta.innerHTML = `<i class="fas fa-circle-notch fa-spin"></i> ${escHtml(text)}`;
}

function startAIProgress() {
  const selected = AI_MODEL_PROFILES[getAIModelProfile()];
  const steps = [
    'Preparing local context...',
    `Contacting ${selected?.model || 'Ollama'}...`,
    'Model is generating...',
    'Still generating locally...'
  ];
  let i = 0;
  setAIThinkingStatus(steps[i]);
  clearInterval(aiProgressTimer);
  aiProgressTimer = setInterval(() => {
    i = Math.min(i + 1, steps.length - 1);
    setAIThinkingStatus(steps[i]);
  }, 3500);
}

function stopAIProgress() {
  clearInterval(aiProgressTimer);
  aiProgressTimer = null;
}

function renderAIStreamingShell() {
  const selected = AI_MODEL_PROFILES[getAIModelProfile()];
  return `
    <div class="ai-generating">
      <span class="ai-generate-dot"></span>
      <div>
        <strong>Generating with ${escHtml(selected?.label || 'AI')} mode</strong>
        <span>${escHtml(selected?.model || 'Ollama')} is working locally. The answer will appear as soon as tokens arrive.</span>
      </div>
    </div>
    <div class="ai-response-text ai-streaming-text" id="aiStreamingText"></div>
  `;
}

function appendAIStreamText(text, chunk) {
  const next = text + chunk;
  const box = document.getElementById('aiStreamingText');
  if (box) {
    box.innerHTML = renderAIAnswer(next);
    box.scrollIntoView({ block: 'end' });
  }
  return next;
}

async function askAIStream(question, mode = 'general') {
  const out = document.getElementById('aiResponse');
  if (!out) return null;

  const res = await fetch('/api/ai/ask_stream', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question, mode, model_profile: getAIModelProfile() }),
  });

  if (res.status === 401) { location.href = '/login'; return null; }
  if (!res.ok || !res.body) {
    const data = await res.json().catch(() => ({}));
    const msg = data.error || (res.status === 404
      ? 'AI streaming endpoint is not loaded yet. Restart the SIEM server to apply the latest AI update.'
      : `AI request failed with HTTP ${res.status}.`);
    throw new Error(msg);
  }

  out.innerHTML = renderAIStreamingShell();

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let answer = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const parts = buffer.split('\n\n');
    buffer = parts.pop() || '';

    for (const part of parts) {
      const eventLine = part.split('\n').find(line => line.startsWith('event:'));
      const dataLine = part.split('\n').find(line => line.startsWith('data:'));
      if (!eventLine || !dataLine) continue;

      const eventName = eventLine.replace('event:', '').trim();
      const payload = JSON.parse(dataLine.replace('data:', '').trim() || '{}');

      if (eventName === 'token') {
        answer = appendAIStreamText(answer, payload.token || '');
        setAIThinkingStatus('Generating response...');
      } else if (eventName === 'error') {
        throw new Error(payload.message || AI_OFFLINE_MSG);
      } else if (eventName === 'done') {
        return answer;
      }
    }
  }

  return answer;
}

async function askAI() {
  const ta   = document.getElementById('aiQuestion');
  const out  = document.getElementById('aiResponse');
  const meta = document.getElementById('aiResponseMeta');
  if (!ta || !out) return;

  const question = (ta.value || '').trim();
  if (!question) {
    showInlineHint('Please type a question or select an alert/event first.');
    return;
  }

  setAIBusy(true);
  startAIProgress();
  out.innerHTML = renderAIStreamingShell();

  try {
    const answer = await askAIStream(question, 'general');
    if (answer !== null) {
      const selected = AI_MODEL_PROFILES[getAIModelProfile()];
      if (meta) meta.innerHTML = `<i class="fas fa-lock"></i> ${escHtml(selected?.meta || 'Ollama - Local')}`;
      if (!answer.trim()) {
        out.innerHTML = '<div class="ai-response-err"><i class="fas fa-triangle-exclamation"></i> Ollama returned an empty response.</div>';
      }
    }
  } catch (err) {
    out.innerHTML = `<div class="ai-response-err"><i class="fas fa-triangle-exclamation"></i> ${escHtml(err.message || AI_OFFLINE_MSG)}</div>`;
  } finally {
    stopAIProgress();
    setAIBusy(false);
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
    } else if (currentPage === 'playbooks') {
      await loadPlaybooksPage();
    } else if (currentPage === 'runbooks') {
      await loadRunbooksPage();
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

function shouldAutoRefresh() {
  return ['overview', 'alerts', 'agents'].includes(currentPage);
}

// ========================================================
// INIT
// ========================================================
document.addEventListener('DOMContentLoaded', () => {
  showPage('overview');

  // Auto-refresh every 5 s
  setInterval(() => {
    if (document.visibilityState === 'visible' && shouldAutoRefresh()) refreshAll();
  }, 5000);

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && shouldAutoRefresh()) refreshAll();
  });

  document.addEventListener('click', (e) => {
    const picker = document.getElementById('eventPicker');
    if (picker && !picker.contains(e.target)) closeEventPicker();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeEventPicker();
  });
});

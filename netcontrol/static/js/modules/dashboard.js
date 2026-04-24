/**
 * Dashboard Module — Main dashboard, custom dashboards, and list page controls
 * Lazy-loaded when user navigates to #dashboard
 */
import * as api from '../api.js';
import {
    navigateToPage, listViewState, escapeHtml, showError, showSuccess, showToast,
    formatDate, showModal, closeAllModals, showConfirm, showFormModal,
    PlexusChart, getTimeRangeParams, onTimeRangeChange, offTimeRangeChange,
    emptyStateHTML, debounce, skeletonCards, initCopyableBlocks,
    activateFocusTrap, deactivateFocusTrap, closeModal, invalidatePageCache,
    rangeToMs,
    textMatch, byNameAsc, byNameDesc
} from '../app.js';
import { applyInventoryFilters } from './inventory.js';
import { applyPlaybookFilters, applyJobFilters, applyTemplateFilters, applyCredentialFilters } from './jobs.js';
import { applyDriftFilters } from './configuration.js';


// =============================================================================
// Module-scope state
// =============================================================================

let _dashboardTimeListener = null;
let dashboardData = null;


// =============================================================================
// Dashboard (main)
// =============================================================================

async function loadDashboard(_options = {}) {
    const container = document.getElementById('page-dashboard');
    container.querySelector('.loading')?.remove();

    try {
        const data = await api.getDashboard();
        dashboardData = data;

        const hosts = data.stats?.total_hosts || 0;
        const playbooks = data.stats?.total_playbooks || 0;
        const jobs = data.stats?.total_jobs || 0;

        // Animate stats
        animateCounter('stat-hosts', hosts);
        animateCounter('stat-playbooks', playbooks);
        animateCounter('stat-jobs', jobs);

        // Animate ring charts — use a sensible max so partial rings look meaningful
        const ringMax = Math.max(hosts, playbooks, jobs, 1);
        animateRing('ring-hosts', hosts, ringMax);
        animateRing('ring-playbooks', playbooks, ringMax);
        animateRing('ring-jobs', jobs, ringMax);

        // Render network health overview
        populateGroupFilter(data.groups || []);
        renderHealthSummary(data.monitoring || {}, data.device_health || []);
        renderDeviceHealthTable(data.device_health || []);
        renderDashboardAlerts(data.open_alerts || []);
    } catch (error) {
        showError('Failed to load dashboard', container);
    }

    // Also load custom dashboards section
    await loadCustomDashboards(_options);
}

function isReducedMotion() {
    return document.body.classList.contains('reduced-motion');
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const num = parseInt(target, 10) || 0;
    if (num === 0) { el.textContent = '0'; return; }
    if (isReducedMotion()) { el.textContent = num; return; }
    const duration = 600;
    const start = performance.now();
    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(eased * num);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function animateRing(elementId, value, maxValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const circumference = 2 * Math.PI * 34; // r=34
    const clamped = Math.min(value, maxValue);
    const ratio = maxValue > 0 ? clamped / maxValue : 0;
    const offset = circumference * (1 - ratio);
    // Start fully hidden, then animate
    el.style.strokeDasharray = circumference;
    el.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
        el.style.strokeDashoffset = offset;
    });
}

window.goToInventory = function() {
    navigateToPage('inventory');
};


// =============================================================================
// Network Health Overview (SolarWinds-style)
// =============================================================================

/**
 * Classify a device's overall health based on its latest poll data.
 * Returns: 'healthy' | 'warning' | 'critical' | 'down' | 'unknown'
 */
function classifyDeviceHealth(poll) {
    if (!poll) return 'unknown';
    if (poll.poll_status === 'error') return 'down';
    const cpu = poll.cpu_percent;
    const mem = poll.memory_percent;
    const pktLoss = poll.packet_loss_pct;
    // Critical: CPU > 90%, memory > 95%, or packet loss > 50%
    if ((cpu != null && cpu >= 90) ||
        (mem != null && mem >= 95) ||
        (pktLoss != null && pktLoss >= 50)) return 'critical';
    // Warning: CPU > 75%, memory > 80%, packet loss > 10%, or interfaces down
    if ((cpu != null && cpu >= 75) ||
        (mem != null && mem >= 80) ||
        (pktLoss != null && pktLoss >= 10) ||
        (poll.if_down_count > 0)) return 'warning';
    // If we have data and nothing is bad, it's healthy
    if (cpu != null || mem != null) return 'healthy';
    return 'unknown';
}

function populateGroupFilter(groups) {
    const sel = document.getElementById('health-group-filter');
    if (!sel || sel.dataset.populated === '1') return;
    sel.dataset.populated = '1';
    groups.forEach(g => {
        const opt = document.createElement('option');
        opt.value = g.id;
        opt.textContent = g.name;
        sel.appendChild(opt);
    });
    sel.addEventListener('change', () => filterAndRenderDevices());
    const sortSel = document.getElementById('health-sort');
    if (sortSel && sortSel.dataset.populated !== '1') {
        sortSel.dataset.populated = '1';
        sortSel.addEventListener('change', () => filterAndRenderDevices());
    }
}

function filterAndRenderDevices() {
    if (!dashboardData) return;
    const devices = dashboardData.device_health || [];
    const groupId = document.getElementById('health-group-filter')?.value;
    const sortBy = document.getElementById('health-sort')?.value || 'severity';
    let filtered = devices;
    if (groupId) {
        filtered = devices.filter(d => String(d.group_id) === groupId);
    }
    const sorted = sortDevices(filtered, sortBy);
    renderHealthSummary(dashboardData.monitoring || {}, sorted);
    renderDeviceHealthTable(sorted);
}

function sortDevices(devices, sortBy) {
    const copy = [...devices];
    const severityOrder = { down: 0, critical: 1, warning: 2, unknown: 3, healthy: 4 };
    switch (sortBy) {
        case 'severity':
            return copy.sort((a, b) => {
                const sa = severityOrder[classifyDeviceHealth(a)] ?? 3;
                const sb = severityOrder[classifyDeviceHealth(b)] ?? 3;
                return sa - sb;
            });
        case 'name':
            return copy.sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''));
        case 'cpu':
            return copy.sort((a, b) => (b.cpu_percent ?? -1) - (a.cpu_percent ?? -1));
        case 'memory':
            return copy.sort((a, b) => (b.memory_percent ?? -1) - (a.memory_percent ?? -1));
        default:
            return copy;
    }
}

function renderHealthSummary(monitoring, devices) {
    const container = document.getElementById('health-summary-tiles');
    if (!container) return;

    // Count devices by health status
    let healthy = 0, warning = 0, critical = 0, down = 0, unknown = 0;
    devices.forEach(d => {
        const status = classifyDeviceHealth(d);
        if (status === 'healthy') healthy++;
        else if (status === 'warning') warning++;
        else if (status === 'critical') critical++;
        else if (status === 'down') down++;
        else unknown++;
    });

    const total = devices.length;
    const openAlerts = monitoring.open_alerts || 0;

    container.innerHTML = `
        <div class="health-tile">
            <div class="health-tile-icon healthy">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            </div>
            <div class="health-tile-value" style="color:#4caf50;">${healthy}</div>
            <div class="health-tile-label">Healthy</div>
        </div>
        <div class="health-tile">
            <div class="health-tile-icon warning">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <div class="health-tile-value" style="color:#ff9800;">${warning}</div>
            <div class="health-tile-label">Warning</div>
        </div>
        <div class="health-tile">
            <div class="health-tile-icon critical">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            </div>
            <div class="health-tile-value" style="color:#f44336;">${critical + down}</div>
            <div class="health-tile-label">Critical / Down</div>
        </div>
        <div class="health-tile">
            <div class="health-tile-icon unknown">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <div class="health-tile-value" style="color:#9e9e9e;">${unknown}</div>
            <div class="health-tile-label">Unknown</div>
        </div>
        <div class="health-tile">
            <div class="health-tile-icon info">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            </div>
            <div class="health-tile-value">${total}</div>
            <div class="health-tile-label">Total Monitored</div>
        </div>
        <div class="health-tile">
            <div class="health-tile-icon ${openAlerts > 0 ? 'critical' : 'healthy'}">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
            </div>
            <div class="health-tile-value" style="color:${openAlerts > 0 ? '#f44336' : '#4caf50'};">${openAlerts}</div>
            <div class="health-tile-label">Open Alerts</div>
        </div>`;
}

function renderUsageBar(pct) {
    if (pct == null) return '<span class="text-muted">N/A</span>';
    const clamped = Math.min(Math.max(pct, 0), 100);
    const level = clamped >= 90 ? 'high' : clamped >= 70 ? 'medium' : 'low';
    return `<div class="usage-bar-wrap">
        <div class="usage-bar"><div class="usage-bar-fill ${level}" style="width:${clamped}%"></div></div>
        <span class="usage-bar-pct">${Math.round(clamped)}%</span>
    </div>`;
}

function renderDeviceHealthTable(devices) {
    const container = document.getElementById('device-health-table-wrap');
    if (!container) return;

    if (!devices.length) {
        container.innerHTML = emptyStateHTML('No monitored devices yet', 'monitoring');
        return;
    }

    const rows = devices.map(d => {
        const health = classifyDeviceHealth(d);
        const statusLabel = health === 'healthy' ? 'Up' :
                            health === 'warning' ? 'Warning' :
                            health === 'critical' ? 'Critical' :
                            health === 'down' ? 'Down' : 'Unknown';
        const dotClass = health === 'healthy' ? 'up' : health;
        const statusClass = health === 'healthy' ? 'up' : health;
        const uptimeStr = d.uptime_seconds != null ? formatUptime(d.uptime_seconds) : '-';
        const ifStr = d.if_up_count != null
            ? `<span style="color:#4caf50">${d.if_up_count}&#x25B2;</span> / <span style="color:#f44336">${d.if_down_count || 0}&#x25BC;</span>`
            : '-';
        const responseStr = d.response_time_ms != null ? `${Math.round(d.response_time_ms)}ms` : '-';
        const polledAgo = d.polled_at ? timeAgo(d.polled_at) : '-';
        return `<tr>
            <td><div class="device-health-status status-${statusClass}"><span class="status-dot ${dotClass}"></span>${statusLabel}</div></td>
            <td><strong>${escapeHtml(d.hostname || '-')}</strong></td>
            <td>${escapeHtml(d.ip_address || '-')}</td>
            <td>${escapeHtml(d.group_name || '-')}</td>
            <td>${escapeHtml(d.model || d.device_type || '-')}</td>
            <td>${renderUsageBar(d.cpu_percent)}</td>
            <td>${renderUsageBar(d.memory_percent)}</td>
            <td>${ifStr}</td>
            <td>${responseStr}</td>
            <td>${uptimeStr}</td>
            <td title="${d.polled_at || ''}">${polledAgo}</td>
        </tr>`;
    }).join('');

    container.innerHTML = `
        <table class="device-health-table">
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Group</th>
                    <th>Model</th>
                    <th>CPU</th>
                    <th>Memory</th>
                    <th>Interfaces</th>
                    <th>Response</th>
                    <th>Uptime</th>
                    <th>Last Poll</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;
}

function renderDashboardAlerts(alerts) {
    const container = document.getElementById('dashboard-alerts-list');
    if (!container) return;

    if (!alerts.length) {
        container.innerHTML = `<div style="padding:1rem; text-align:center; color:var(--text-muted);">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4; margin-bottom:0.5rem;"><polyline points="20 6 9 17 4 12"/></svg>
            <p style="margin:0;">No active alerts &mdash; all systems nominal</p>
        </div>`;
        return;
    }

    container.innerHTML = alerts.slice(0, 20).map(a => {
        const sev = (a.severity || 'info').toLowerCase();
        return `<div class="dashboard-alert-item">
            <span class="alert-severity-badge ${sev}">${escapeHtml(sev)}</span>
            <span class="dashboard-alert-host">${escapeHtml(a.hostname || '-')}</span>
            <span class="dashboard-alert-msg">${escapeHtml(a.message || a.metric || '-')}</span>
            <span class="dashboard-alert-time">${a.created_at ? timeAgo(a.created_at) : ''}</span>
        </div>`;
    }).join('');
}

function formatUptime(seconds) {
    if (seconds == null) return '-';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    if (days > 0) return `${days}d ${hours}h`;
    const mins = Math.floor((seconds % 3600) / 60);
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

function timeAgo(isoStr) {
    try {
        const date = new Date(isoStr.endsWith('Z') ? isoStr : isoStr + 'Z');
        const diff = (Date.now() - date.getTime()) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch { return isoStr; }
}


// =============================================================================
// Custom Dashboards Page
// =============================================================================

function setDashboardDefaultContentVisible(visible) {
    // Hide/show the default dashboard sections (stats, jobs, timeline, groups) when viewing a custom dashboard
    const container = document.getElementById('page-dashboard');
    if (!container) return;
    const marker = document.getElementById('dashboard-default-content-end');
    if (!marker) return;
    let el = container.firstElementChild;
    while (el && el !== marker) {
        el.style.display = visible ? '' : 'none';
        el = el.nextElementSibling;
    }
    if (marker) marker.style.display = 'none'; // always hide the marker itself
}

async function loadCustomDashboards({ preserveContent } = {}) {
    const listView = document.getElementById('dashboards-list-view');
    const viewer = document.getElementById('dashboard-viewer');
    // If we have a current dashboard, show viewer
    if (listViewState.customDashboards.currentId) {
        setDashboardDefaultContentVisible(false);
        if (listView) listView.style.display = 'none';
        if (viewer) viewer.style.display = '';
        await viewDashboard(listViewState.customDashboards.currentId);
        return;
    }
    // Show default dashboard content + dashboards list
    setDashboardDefaultContentVisible(true);
    if (listView) listView.style.display = '';
    if (viewer) viewer.style.display = 'none';
    try {
        const data = await api.getCustomDashboards();
        const dashboards = data?.dashboards || data || [];
        listViewState.customDashboards.items = dashboards;
        renderDashboardsList(dashboards);
    } catch (e) {
        showError('Failed to load dashboards: ' + e.message);
    }
}

function renderDashboardsList(dashboards) {
    const list = document.getElementById('dashboards-list');
    const empty = document.getElementById('dashboards-empty');
    if (!list) return;
    if (!dashboards.length) {
        list.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';
    list.innerHTML = dashboards.map(d => `
        <div class="card dashboard-card" onclick="openDashboard(${d.id})">
            <div class="card-title">${escapeHtml(d.name)}</div>
            <p class="text-muted" style="font-size:0.85rem; margin:0.25rem 0;">${escapeHtml(d.description || 'No description')}</p>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.5rem;">
                <span class="text-muted" style="font-size:0.75rem;">${d.updated_at ? new Date(d.updated_at).toLocaleDateString() : ''}</span>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); confirmDeleteDashboardById(${d.id})" title="Delete">&times;</button>
            </div>
        </div>`).join('');
}

function openDashboard(id) {
    listViewState.customDashboards.currentId = id;
    loadCustomDashboards({});
}
window.openDashboard = openDashboard;

function backToDashboardsList() {
    listViewState.customDashboards.currentId = null;
    listViewState.customDashboards.editMode = false;
    destroyDashboard();
    loadCustomDashboards({});
}
window.backToDashboardsList = backToDashboardsList;

async function viewDashboard(id) {
    try {
        const data = await api.getCustomDashboard(id);
        const dashboard = data?.dashboard || data;
        const panels = dashboard?.panels || data?.panels || [];

        document.getElementById('dashboard-viewer-title').textContent = dashboard.name || 'Dashboard';

        // Register time-range listener — remove old one first to avoid stale closure
        if (_dashboardTimeListener) { offTimeRangeChange(_dashboardTimeListener); _dashboardTimeListener = null; }
        _dashboardTimeListener = () => renderAllDashboardPanels(panels);
        onTimeRangeChange(_dashboardTimeListener);

        // Render variable dropdowns
        renderDashboardVariables(dashboard.variables_json ? JSON.parse(dashboard.variables_json) : []);

        // Render panels
        renderDashboardGrid(panels);
        await renderAllDashboardPanels(panels);

        // Edit mode controls
        updateDashboardEditControls();
    } catch (e) {
        showError('Failed to load dashboard: ' + e.message);
    }
}

function renderDashboardGrid(panels) {
    const grid = document.getElementById('dashboard-grid');
    if (!grid) return;
    if (!panels.length) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1; padding:3rem 1rem;"><svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.3;"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg><h3>No Panels Yet</h3><p style="color:var(--text-muted); margin-bottom:1rem;">Click <strong>Edit</strong> then <strong>+ Add Panel</strong> to get started.</p></div>';
        return;
    }
    grid.innerHTML = panels.map(p => `
        <div class="dashboard-panel" style="grid-column: span ${p.grid_w || 6}; grid-row: span ${p.grid_h || 4};" data-panel-id="${p.id}">
            <div class="panel-header">
                <span class="panel-title">${escapeHtml(p.title || 'Untitled')}</span>
                <div class="panel-actions" style="display:none;">
                    <button class="btn btn-sm btn-secondary" onclick="editPanelModal(${p.id})" title="Edit">&#9998;</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeletePanel(${p.id})" title="Remove">&times;</button>
                </div>
            </div>
            <div id="panel-chart-${p.id}" class="panel-chart-container"></div>
        </div>`).join('');
}

async function renderAllDashboardPanels(panels) {
    const variables = getCurrentDashboardVariables();
    const trp = getTimeRangeParams();
    const range = trp.range === 'custom' ? '24h' : trp.range;

    await Promise.allSettled(panels.map(async (panel) => {
        const query = panel.metric_query_json ? JSON.parse(panel.metric_query_json) : {};
        const resolvedQuery = resolveVariables(query, variables);
        const chartId = `panel-chart-${panel.id}`;
        const chartType = panel.chart_type || 'line';

        try {
            const host = resolvedQuery.host || '*';
            const metric = resolvedQuery.metric || 'cpu_percent';
            const data = await api.queryMetrics(metric, host, range, 'auto', resolvedQuery.group || null);
            const items = data?.data || [];

            if (chartType === 'gauge') {
                const avg = items.length ? items.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0) / items.length : 0;
                PlexusChart.gauge(chartId, avg, { title: metric });
            } else if (chartType === 'bar') {
                const byHost = groupByHost(items);
                const labels = Object.keys(byHost);
                const values = labels.map(h => {
                    const arr = byHost[h];
                    return arr.length ? arr.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0) / arr.length : 0;
                });
                PlexusChart.bar(chartId, labels, values.map(v => Math.round(v * 10) / 10));
            } else if (chartType === 'heatmap') {
                renderHeatmapPanel(chartId, items);
            } else if (chartType === 'table') {
                renderTablePanel(chartId, items, metric);
            } else {
                // Default: line chart
                const byHost = groupByHost(items);
                const series = Object.entries(byHost).map(([hostname, pts]) => ({
                    name: hostname,
                    data: pts.map(d => ({ time: d.sampled_at || d.period_start, value: d.val_avg ?? d.value ?? 0 })),
                }));
                PlexusChart.timeSeries(chartId, series.length ? series : [{ name: metric, data: [] }], { area: true });

                // Overlay annotations on line charts
                try {
                    const endISO = new Date().toISOString();
                    const startISO = new Date(Date.now() - rangeToMs(range)).toISOString();
                    const hostParam = host !== '*' ? host : undefined;
                    const annRes = await api.getAnnotations({ hostId: hostParam, start: startISO, end: endISO, categories: 'deployment,config,alert' });
                    const events = annRes?.annotations || [];
                    if (events.length) PlexusChart.addAnnotations(chartId, events);
                } catch { /* annotations are non-critical */ }
            }
        } catch (e) {
            const container = document.getElementById(chartId);
            if (container) container.innerHTML = `<p class="text-muted" style="padding:1rem;">Error: ${escapeHtml(e.message)}</p>`;
        }
    }));
}

function groupByHost(items) {
    const map = {};
    items.forEach(d => {
        const key = d.hostname || `host-${d.host_id}`;
        if (!map[key]) map[key] = [];
        map[key].push(d);
    });
    return map;
}

function renderHeatmapPanel(chartId, items) {
    if (!items.length) { PlexusChart.timeSeries(chartId, [{ name: 'No data', data: [] }]); return; }
    const byHost = groupByHost(items);
    const hostNames = Object.keys(byHost);
    const timeSet = new Set();
    items.forEach(d => timeSet.add(d.sampled_at || d.period_start));
    const times = [...timeSet].sort();
    const data = [];
    times.forEach((t, ti) => {
        hostNames.forEach((h, hi) => {
            const pt = byHost[h].find(d => (d.sampled_at || d.period_start) === t);
            data.push([ti, hi, pt ? Math.round((pt.val_avg ?? pt.value ?? 0) * 10) / 10 : 0]);
        });
    });
    PlexusChart.heatmap(chartId, times.map(t => new Date(t).toLocaleTimeString()), hostNames, data);
}

function renderTablePanel(chartId, items, metric) {
    const columns = [
        { key: 'hostname', label: 'Host' },
        { key: 'time', label: 'Time' },
        { key: 'value', label: metric },
    ];
    const rows = items.map(d => ({
        hostname: d.hostname || `host-${d.host_id}`,
        time: new Date(d.sampled_at || d.period_start).toLocaleString(),
        value: (d.val_avg ?? d.value ?? 0).toFixed(2),
    }));
    PlexusChart.table(chartId, columns, rows);
}

function refreshDashboardPanels() {
    const id = listViewState.customDashboards.currentId;
    if (id) viewDashboard(id);
}
window.refreshDashboardPanels = refreshDashboardPanels;

// Dashboard variables
function renderDashboardVariables(variables) {
    const container = document.getElementById('dashboard-variables');
    if (!container) return;
    if (!variables?.length) { container.innerHTML = ''; return; }
    container.innerHTML = variables.map(v => {
        if (v.type === 'group') {
            return `<select id="dashvar-${v.name}" class="form-select form-select-sm" onchange="onDashboardVariableChange()">
                <option value="*">All Groups</option>
            </select>`;
        }
        if (v.type === 'host') {
            return `<select id="dashvar-${v.name}" class="form-select form-select-sm" onchange="onDashboardVariableChange()">
                <option value="*">All Hosts</option>
            </select>`;
        }
        return '';
    }).join('');
    // Populate selects
    populateDashboardVariableOptions(variables);
}

async function populateDashboardVariableOptions(variables) {
    try {
        const groups = await api.getInventoryGroups(true);
        const allGroups = groups?.groups || groups || [];
        variables.forEach(v => {
            const sel = document.getElementById(`dashvar-${v.name}`);
            if (!sel) return;
            if (v.type === 'group') {
                allGroups.forEach(g => {
                    const opt = document.createElement('option');
                    opt.value = g.id;
                    opt.textContent = g.name;
                    sel.appendChild(opt);
                });
            } else if (v.type === 'host') {
                allGroups.forEach(g => {
                    (g.hosts || []).forEach(h => {
                        const opt = document.createElement('option');
                        opt.value = h.id;
                        opt.textContent = `${h.hostname} (${g.name})`;
                        sel.appendChild(opt);
                    });
                });
            }
        });
    } catch (e) {
        console.error('Error populating dashboard variables:', e);
    }
}

function getCurrentDashboardVariables() {
    const vars = {};
    document.querySelectorAll('#dashboard-variables select').forEach(sel => {
        const name = sel.id.replace('dashvar-', '');
        vars[name] = sel.value;
    });
    return vars;
}

function onDashboardVariableChange() {
    refreshDashboardPanels();
}
window.onDashboardVariableChange = onDashboardVariableChange;

function resolveVariables(queryObj, variables) {
    let queryStr = JSON.stringify(queryObj);
    for (const [name, value] of Object.entries(variables)) {
        queryStr = queryStr.replace(new RegExp(`\\$${name}`, 'g'), value);
    }
    return JSON.parse(queryStr);
}

// Dashboard CRUD
function showCreateDashboardModal() {
    const html = `
        <div class="form-group"><label class="form-label">Name</label><input type="text" class="form-input" id="new-dash-name" required></div>
        <div class="form-group"><label class="form-label">Description</label><input type="text" class="form-input" id="new-dash-desc"></div>
        <div class="form-group">
            <label class="form-label">Template Variables</label>
            <div style="display:flex; gap:0.5rem;">
                <label><input type="checkbox" id="new-dash-var-group"> $group</label>
                <label><input type="checkbox" id="new-dash-var-host"> $host</label>
            </div>
        </div>`;
    showFormModal('Create Dashboard', html, async () => {
        const name = document.getElementById('new-dash-name').value.trim();
        if (!name) { showError('Name is required'); return; }
        const vars = [];
        if (document.getElementById('new-dash-var-group')?.checked) vars.push({ name: 'group', type: 'group', default: '*' });
        if (document.getElementById('new-dash-var-host')?.checked) vars.push({ name: 'host', type: 'host', default: '*' });
        try {
            await api.createCustomDashboard({
                name,
                description: document.getElementById('new-dash-desc').value.trim(),
                variables_json: JSON.stringify(vars),
            });
            showSuccess('Dashboard created');
            loadCustomDashboards({ preserveContent: false });
        } catch (e) { showError('Failed to create dashboard: ' + e.message); }
    });
}
window.showCreateDashboardModal = showCreateDashboardModal;

function showAddPanelModal() {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    const html = `
        <div class="form-group"><label class="form-label">Panel Title</label><input type="text" class="form-input" id="new-panel-title"></div>
        <div class="form-group">
            <label class="form-label">Chart Type</label>
            <select class="form-select" id="new-panel-type">
                <option value="line">Line</option>
                <option value="bar">Bar</option>
                <option value="gauge">Gauge</option>
                <option value="heatmap">Heatmap</option>
                <option value="table">Table</option>
            </select>
        </div>
        <div class="form-group"><label class="form-label">Metric</label><input type="text" class="form-input" id="new-panel-metric" value="cpu_percent" placeholder="e.g. cpu_percent"></div>
        <div class="form-group"><label class="form-label">Host (ID, "*", or "$host")</label><input type="text" class="form-input" id="new-panel-host" value="*"></div>
        <div class="form-group" style="display:flex; gap:1rem;">
            <div><label class="form-label">Width (1-12)</label><input type="number" class="form-input" id="new-panel-w" value="6" min="1" max="12"></div>
            <div><label class="form-label">Height (rows)</label><input type="number" class="form-input" id="new-panel-h" value="4" min="1" max="12"></div>
        </div>`;
    showFormModal('Add Panel', html, async () => {
        const title = document.getElementById('new-panel-title')?.value.trim() || 'Untitled';
        const chartType = document.getElementById('new-panel-type')?.value || 'line';
        const metric = document.getElementById('new-panel-metric')?.value.trim() || 'cpu_percent';
        const host = document.getElementById('new-panel-host')?.value.trim() || '*';
        const gridW = parseInt(document.getElementById('new-panel-w')?.value) || 6;
        const gridH = parseInt(document.getElementById('new-panel-h')?.value) || 4;
        try {
            await api.createDashboardPanel(dashId, {
                title, chart_type: chartType,
                metric_query_json: JSON.stringify({ metric, host }),
                grid_w: gridW, grid_h: gridH, grid_x: 0, grid_y: 0,
            });
            showSuccess('Panel added');
            viewDashboard(dashId);
        } catch (e) { showError('Failed to add panel: ' + e.message); }
    });
}
window.showAddPanelModal = showAddPanelModal;

function editPanelModal(panelId) {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    // Find panel in current DOM
    const panelEl = document.querySelector(`[data-panel-id="${panelId}"]`);
    const titleEl = panelEl?.querySelector('.panel-title');
    const currentTitle = titleEl?.textContent || '';
    const html = `
        <div class="form-group"><label class="form-label">Panel Title</label><input type="text" class="form-input" id="edit-panel-title" value="${escapeHtml(currentTitle)}"></div>
        <div class="form-group">
            <label class="form-label">Chart Type</label>
            <select class="form-select" id="edit-panel-type">
                <option value="line">Line</option><option value="bar">Bar</option><option value="gauge">Gauge</option><option value="heatmap">Heatmap</option><option value="table">Table</option>
            </select>
        </div>
        <div class="form-group"><label class="form-label">Metric</label><input type="text" class="form-input" id="edit-panel-metric" placeholder="cpu_percent"></div>
        <div class="form-group"><label class="form-label">Host</label><input type="text" class="form-input" id="edit-panel-host" value="*"></div>
        <div class="form-group" style="display:flex; gap:1rem;">
            <div><label class="form-label">Width (1-12)</label><input type="number" class="form-input" id="edit-panel-w" value="6" min="1" max="12"></div>
            <div><label class="form-label">Height (rows)</label><input type="number" class="form-input" id="edit-panel-h" value="4" min="1" max="12"></div>
        </div>`;
    showFormModal('Edit Panel', html, async () => {
        const title = document.getElementById('edit-panel-title')?.value.trim() || 'Untitled';
        const chartType = document.getElementById('edit-panel-type')?.value || 'line';
        const metric = document.getElementById('edit-panel-metric')?.value.trim() || 'cpu_percent';
        const host = document.getElementById('edit-panel-host')?.value.trim() || '*';
        const gridW = parseInt(document.getElementById('edit-panel-w')?.value) || 6;
        const gridH = parseInt(document.getElementById('edit-panel-h')?.value) || 4;
        try {
            await api.updateDashboardPanel(dashId, panelId, {
                title, chart_type: chartType,
                metric_query_json: JSON.stringify({ metric, host }),
                grid_w: gridW, grid_h: gridH,
            });
            showSuccess('Panel updated');
            viewDashboard(dashId);
        } catch (e) { showError('Failed to update panel: ' + e.message); }
    });
}
window.editPanelModal = editPanelModal;

async function confirmDeletePanel(panelId) {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    const ok = await showConfirm('Delete this panel?', 'This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteDashboardPanel(dashId, panelId);
        showSuccess('Panel deleted');
        viewDashboard(dashId);
    } catch (e) { showError('Failed to delete panel: ' + e.message); }
}
window.confirmDeletePanel = confirmDeletePanel;

function toggleDashboardEditMode() {
    listViewState.customDashboards.editMode = !listViewState.customDashboards.editMode;
    updateDashboardEditControls();
}
window.toggleDashboardEditMode = toggleDashboardEditMode;

function updateDashboardEditControls() {
    const editing = listViewState.customDashboards.editMode;
    const editBtn = document.getElementById('dashboard-edit-toggle');
    const addBtn = document.getElementById('dashboard-add-panel-btn');
    const delBtn = document.getElementById('dashboard-delete-btn');
    if (editBtn) { editBtn.textContent = editing ? 'Done' : 'Edit'; editBtn.classList.toggle('btn-primary', editing); editBtn.classList.toggle('btn-secondary', !editing); }
    if (addBtn) addBtn.style.display = editing ? '' : 'none';
    if (delBtn) delBtn.style.display = editing ? '' : 'none';
    document.querySelectorAll('.panel-actions').forEach(el => el.style.display = editing ? 'flex' : 'none');
    document.querySelectorAll('.dashboard-panel').forEach(el => el.classList.toggle('editing', editing));
}

async function confirmDeleteDashboard() {
    const id = listViewState.customDashboards.currentId;
    if (!id) return;
    const ok = await showConfirm('Delete this dashboard?', 'All panels will be removed. This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteCustomDashboard(id);
        showSuccess('Dashboard deleted');
        backToDashboardsList();
    } catch (e) { showError('Failed to delete dashboard: ' + e.message); }
}
window.confirmDeleteDashboard = confirmDeleteDashboard;

async function confirmDeleteDashboardById(id) {
    const ok = await showConfirm('Delete this dashboard?', 'All panels will be removed. This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteCustomDashboard(id);
        showSuccess('Dashboard deleted');
        loadCustomDashboards({});
    } catch (e) { showError('Failed to delete dashboard: ' + e.message); }
}
window.confirmDeleteDashboardById = confirmDeleteDashboardById;


// =============================================================================
// List Page Controls
// =============================================================================

function bindListControl(id, handler) {
    const el = document.getElementById(id);
    if (!el || el.dataset.bound === '1') return;
    el.dataset.bound = '1';
    el.addEventListener('input', handler);
    el.addEventListener('change', handler);
}

function initListPageControls() {
    // Search inputs: debounced to avoid re-rendering on every keystroke
    bindListControl('inventory-search', debounce((e) => {
        listViewState.inventory.query = e.target.value;
        window.renderInventoryGroups(applyInventoryFilters());
    }, 300));
    // Sort/filter dropdowns: instant response
    bindListControl('inventory-sort', (e) => {
        listViewState.inventory.sort = e.target.value;
        window.renderInventoryGroups(applyInventoryFilters());
    });
    bindListControl('playbooks-search', debounce((e) => {
        listViewState.playbooks.query = e.target.value;
        window.renderPlaybooksList(applyPlaybookFilters());
    }, 300));
    bindListControl('playbooks-sort', (e) => {
        listViewState.playbooks.sort = e.target.value;
        window.renderPlaybooksList(applyPlaybookFilters());
    });
    bindListControl('jobs-search', debounce((e) => {
        listViewState.jobs.query = e.target.value;
        window.renderJobsList(applyJobFilters());
    }, 300));
    bindListControl('jobs-sort', (e) => {
        listViewState.jobs.sort = e.target.value;
        window.renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-status-filter', (e) => {
        listViewState.jobs.status = e.target.value;
        window.renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-dryrun-filter', (e) => {
        listViewState.jobs.dryRun = e.target.value;
        window.renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-date-filter', (e) => {
        listViewState.jobs.dateRange = e.target.value;
        window.renderJobsList(applyJobFilters());
    });
    bindListControl('templates-search', debounce((e) => {
        listViewState.templates.query = e.target.value;
        window.renderTemplatesList(applyTemplateFilters());
    }, 300));
    bindListControl('templates-sort', (e) => {
        listViewState.templates.sort = e.target.value;
        window.renderTemplatesList(applyTemplateFilters());
    });
    bindListControl('credentials-search', debounce((e) => {
        listViewState.credentials.query = e.target.value;
        window.renderCredentialsList(applyCredentialFilters());
    }, 300));
    bindListControl('credentials-sort', (e) => {
        listViewState.credentials.sort = e.target.value;
        window.renderCredentialsList(applyCredentialFilters());
    });
    bindListControl('drift-search', debounce((e) => {
        listViewState.configDrift.query = e.target.value;
        window.renderDriftEventsList(applyDriftFilters());
    }, 300));
    bindListControl('drift-status-filter', (e) => {
        listViewState.configDrift.status = e.target.value;
        window.renderDriftEventsList(applyDriftFilters());
    });
    bindListControl('drift-sort', (e) => {
        listViewState.configDrift.sort = e.target.value;
        window.renderDriftEventsList(applyDriftFilters());
    });
}


// =============================================================================
// Cleanup
// =============================================================================

function destroyDashboard() {
    if (_dashboardTimeListener) {
        offTimeRangeChange(_dashboardTimeListener);
        _dashboardTimeListener = null;
    }
    PlexusChart.destroyAll();
    listViewState.customDashboards.items = [];
    listViewState.customDashboards.currentId = null;
    listViewState.customDashboards.editMode = false;
    // Invalidate page cache so returning to this page always reloads data.
    // Without this, the 30-second page cache would skip loadDashboard() on
    // return, leaving the DOM stale (no charts, no dashboard list populated).
    invalidatePageCache('dashboard');
}


// =============================================================================
// Exports
// =============================================================================

export {
    loadDashboard,
    loadCustomDashboards,
    destroyDashboard,
    initListPageControls,
    animateCounter,
    animateRing,
};

/**
 * Reports & Graph Templates Module
 * Reports / Export, Syslog, Capacity Planning, Availability, Graph Templates / Host Templates / Graph Trees
 * Lazy-loaded when user navigates to #reports or #graph-templates
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    showModal, closeAllModals, showConfirm, formatDate, formatRelativeTime,
    skeletonCards, emptyStateHTML, navigateToPage, PlexusChart,
    getTimeRangeParams, copyableCodeBlock, initCopyableBlocks, debounce,
    formatDuration
} from '../app.js';
import { ensureModalDOM, templateOidProfileModal } from '../page-templates.js';

const closeModal = closeAllModals;

// =============================================================================
// Capacity Planning
// =============================================================================

async function loadCapacityPlanning() {
    const metric = document.getElementById('cap-plan-metric')?.value || 'cpu_percent';
    const range = document.getElementById('cap-plan-range')?.value || '90d';
    const groupFilter = document.getElementById('cap-plan-group')?.value || '';
    const chartEl = document.getElementById('cap-plan-chart-main');
    const thresholdEl = document.getElementById('cap-plan-thresholds');
    const emptyEl = document.getElementById('cap-plan-empty');

    // Populate group filter on first load
    const groupSelect = document.getElementById('cap-plan-group');
    if (groupSelect && groupSelect.options.length <= 1) {
        try {
            const inv = await api.getInventoryGroups(false);
            const groups = inv?.groups || inv || [];
            groups.forEach(g => {
                const opt = document.createElement('option');
                opt.value = g.id;
                opt.textContent = g.name;
                groupSelect.appendChild(opt);
            });
        } catch { /* ignore */ }
    }

    try {
        const data = await api.getCapacityPlanning({
            metric, range, group: groupFilter || undefined, projectionDays: 30,
        });

        if (!data.count) {
            if (chartEl) chartEl.style.display = 'none';
            if (thresholdEl) thresholdEl.innerHTML = '';
            if (emptyEl) emptyEl.style.display = '';
            return;
        }
        if (emptyEl) emptyEl.style.display = 'none';
        if (chartEl) chartEl.style.display = '';

        // Build chart series: historical data per host + projection
        const byHost = {};
        for (const d of (data.data || [])) {
            const key = d.hostname || `host-${d.host_id}`;
            if (!byHost[key]) byHost[key] = [];
            byHost[key].push(d);
        }

        const series = [];
        for (const [hostname, pts] of Object.entries(byHost)) {
            series.push({
                name: hostname,
                data: pts.map(d => ({
                    time: d.period_start,
                    value: d.val_avg ?? d.value ?? 0,
                })),
            });
        }

        // Add projection lines (dashed) for each host
        for (const hostResult of (data.per_host || [])) {
            if (hostResult.projection && hostResult.projection.length) {
                series.push({
                    name: `${hostResult.hostname} (proj.)`,
                    data: hostResult.projection.map(p => ({ time: p.date, value: p.value })),
                    lineStyle: { type: 'dashed', width: 1.5 },
                    itemStyle: { opacity: 0 },
                });
            }
        }

        const isPercent = metric.endsWith('_percent') || metric.endsWith('_pct');
        const yOpts = isPercent ? { yAxisName: '%', yMin: 0, yMax: 100 } : { yAxisName: '' };
        PlexusChart.timeSeries('cap-plan-chart-main', series.length ? series : [{ name: metric, data: [] }], { area: false, ...yOpts });

        // Add threshold markLine
        const threshold = data.threshold || 90;
        if (isPercent) {
            const chart = PlexusChart.instances.get('cap-plan-chart-main');
            if (chart) {
                const opt = chart.getOption();
                if (opt.series?.length) {
                    opt.series[0].markLine = opt.series[0].markLine || { silent: true, symbol: 'none', data: [] };
                    opt.series[0].markLine.data.push({
                        yAxis: threshold,
                        label: { formatter: `Threshold ${threshold}%`, position: 'insideEndTop', fontSize: 10, color: '#ef4444' },
                        lineStyle: { color: '#ef4444', type: 'dashed', width: 1.5 },
                    });
                    chart.setOption(opt);
                }
            }
        }

        // Render threshold ETA table
        if (thresholdEl) {
            const hostResults = data.per_host || [];
            const hasETA = hostResults.some(h => h.threshold_eta);
            if (!hostResults.length) {
                thresholdEl.innerHTML = '<p class="text-muted">No per-host data available.</p>';
            } else {
                thresholdEl.innerHTML = `
                    <table class="chart-table">
                        <thead><tr>
                            <th>Host</th>
                            <th>Current (avg)</th>
                            <th>Trend (per day)</th>
                            <th>Threshold (${threshold}${isPercent ? '%' : ''})</th>
                            <th>Days Until</th>
                        </tr></thead>
                        <tbody>${hostResults.map(h => {
                            const current = h.threshold_eta?.current_value ?? (h.trend ? (h.trend.slope * (data.data?.length || 90) + h.trend.intercept).toFixed(1) : 'N/A');
                            const slopeStr = h.trend ? (h.trend.slope >= 0 ? '+' : '') + h.trend.slope.toFixed(4) : 'N/A';
                            const etaStr = h.threshold_eta ? `${h.threshold_eta.days_until}d (${h.threshold_eta.date})` : h.trend && h.trend.slope <= 0 ? 'Never (declining)' : 'N/A';
                            const etaColor = h.threshold_eta && h.threshold_eta.days_until < 30 ? 'var(--danger)' :
                                             h.threshold_eta && h.threshold_eta.days_until < 90 ? 'var(--warning)' : 'var(--success)';
                            return `<tr>
                                <td>${escapeHtml(h.hostname)}</td>
                                <td>${typeof current === 'number' ? current.toFixed(1) : current}</td>
                                <td>${slopeStr}</td>
                                <td>${threshold}${isPercent ? '%' : ''}</td>
                                <td style="color:${etaColor}; font-weight:600;">${etaStr}</td>
                            </tr>`;
                        }).join('')}</tbody>
                    </table>`;
            }
        }
    } catch (e) {
        showError('Failed to load capacity planning: ' + e.message);
    }
}
window.loadCapacityPlanning = loadCapacityPlanning;


// =============================================================================
// Availability Tracking Page
// =============================================================================

async function loadAvailability(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('availability-hosts-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const groupId = document.getElementById('availability-group-filter')?.value || '';
        const days = parseInt(document.getElementById('availability-period')?.value || '7', 10);

        // Populate group filter on first load
        const groupSelect = document.getElementById('availability-group-filter');
        if (groupSelect && groupSelect.options.length <= 1) {
            try {
                const inv = await api.getInventoryGroups(false);
                const groups = inv?.groups || inv || [];
                groups.forEach(g => {
                    const opt = document.createElement('option');
                    opt.value = g.id;
                    opt.textContent = g.name;
                    groupSelect.appendChild(opt);
                });
            } catch (_) { /* ignore */ }
        }

        const [summary, outages, transitions] = await Promise.all([
            api.getAvailabilitySummary(groupId || null, days),
            api.getAvailabilityOutages({ groupId: groupId || null, days, limit: 200 }),
            api.getAvailabilityTransitions({ entityType: 'host', limit: 200 }),
        ]);

        // Summary cards
        const cardsEl = document.getElementById('availability-summary-cards');
        if (cardsEl) {
            const hosts = summary?.hosts || [];
            const totalHosts = hosts.length;
            const upHosts = hosts.filter(h => h.current_state === 'up').length;
            const avgUptime = totalHosts > 0 ? (hosts.reduce((s, h) => s + (h.uptime_pct || 0), 0) / totalHosts) : 0;
            const totalOutages = (outages?.outages || outages || []).length;
            cardsEl.innerHTML = `
                <div class="drift-summary-card"><div class="drift-summary-value">${upHosts}/${totalHosts}</div><div class="drift-summary-label">Hosts Up</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value">${avgUptime.toFixed(2)}%</div><div class="drift-summary-label">Avg Uptime</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value">${totalOutages}</div><div class="drift-summary-label">Outages (${days}d)</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value">${(transitions?.transitions || []).length}</div><div class="drift-summary-label">Transitions</div></div>
            `;
        }

        // Hosts tab
        const hosts = summary?.hosts || [];
        if (container) {
            if (!hosts.length) {
                container.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No availability data yet. Enable monitoring to start tracking.</p></div>';
            } else {
                container.innerHTML = `<table class="chart-table">
                    <thead><tr><th>Host</th><th>State</th><th>Uptime %</th><th>Total Up</th><th>Total Down</th><th>Transitions</th></tr></thead>
                    <tbody>${hosts.map(h => `<tr>
                        <td>${escapeHtml(h.hostname || `Host #${h.host_id}`)}</td>
                        <td><span class="badge badge-${h.current_state === 'up' ? 'success' : h.current_state === 'down' ? 'danger' : 'warning'}">${escapeHtml(h.current_state || 'unknown')}</span></td>
                        <td>${h.uptime_pct != null ? h.uptime_pct.toFixed(2) + '%' : 'N/A'}</td>
                        <td>${h.total_up_seconds != null ? formatDuration(h.total_up_seconds) : '-'}</td>
                        <td>${h.total_down_seconds != null ? formatDuration(h.total_down_seconds) : '-'}</td>
                        <td>${h.transition_count ?? '-'}</td>
                    </tr>`).join('')}</tbody>
                </table>`;
            }
        }

        // Outages tab
        const outageList = outages?.outages || outages || [];
        const outagesEl = document.getElementById('availability-outages-list');
        if (outagesEl) {
            if (!outageList.length) {
                outagesEl.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No outages recorded.</p></div>';
            } else {
                outagesEl.innerHTML = `<table class="chart-table">
                    <thead><tr><th>Host</th><th>Started</th><th>Ended</th><th>Duration</th></tr></thead>
                    <tbody>${outageList.map(o => `<tr>
                        <td>${escapeHtml(o.hostname || `Host #${o.host_id}`)}</td>
                        <td>${o.down_at ? new Date(o.down_at).toLocaleString() : '-'}</td>
                        <td>${o.up_at ? new Date(o.up_at).toLocaleString() : 'Ongoing'}</td>
                        <td>${o.duration_seconds != null ? formatDuration(o.duration_seconds) : 'Ongoing'}</td>
                    </tr>`).join('')}</tbody>
                </table>`;
            }
        }

        // Transitions tab
        const transList = transitions?.transitions || transitions || [];
        const transEl = document.getElementById('availability-transitions-list');
        if (transEl) {
            if (!transList.length) {
                transEl.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No state transitions recorded.</p></div>';
            } else {
                transEl.innerHTML = `<table class="chart-table">
                    <thead><tr><th>Host</th><th>Entity</th><th>From</th><th>To</th><th>Time</th></tr></thead>
                    <tbody>${transList.map(t => `<tr>
                        <td>${escapeHtml(t.hostname || `Host #${t.host_id}`)}</td>
                        <td>${escapeHtml(t.entity_type || '')}${t.entity_id ? ' ' + escapeHtml(t.entity_id) : ''}</td>
                        <td><span class="badge badge-${t.old_state === 'up' ? 'success' : t.old_state === 'down' ? 'danger' : 'warning'}">${escapeHtml(t.old_state)}</span></td>
                        <td><span class="badge badge-${t.new_state === 'up' ? 'success' : t.new_state === 'down' ? 'danger' : 'warning'}">${escapeHtml(t.new_state)}</span></td>
                        <td>${t.transition_at ? new Date(t.transition_at).toLocaleString() : '-'}</td>
                    </tr>`).join('')}</tbody>
                </table>`;
            }
        }
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading availability: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadAvailability = loadAvailability;

function switchAvailTab(tab) {
    document.querySelectorAll('.avail-tab').forEach(t => t.style.display = 'none');
    document.querySelectorAll('.avail-tab-btn').forEach(b => b.classList.remove('active'));
    const tabEl = document.getElementById(`avail-tab-${tab}`);
    if (tabEl) tabEl.style.display = '';
    const btn = document.querySelector(`.avail-tab-btn[data-avail-tab="${tab}"]`);
    if (btn) btn.classList.add('active');
}
window.switchAvailTab = switchAvailTab;

// =============================================================================
// Syslog Events Page
// =============================================================================

async function loadSyslog(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('syslog-events-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const severity = document.getElementById('syslog-severity-filter')?.value || '';
        const eventType = document.getElementById('syslog-type-filter')?.value || '';
        const events = await api.getSyslogEvents({
            severity: severity || undefined,
            eventType: eventType || undefined,
            limit: 500,
        });
        const items = events?.events || events || [];

        // Summary cards
        const cardsEl = document.getElementById('syslog-summary-cards');
        if (cardsEl) {
            const total = items.length;
            const critCount = items.filter(e => ['emergency', 'alert', 'critical'].includes(e.severity)).length;
            const errCount = items.filter(e => e.severity === 'error').length;
            const warnCount = items.filter(e => e.severity === 'warning').length;
            cardsEl.innerHTML = `
                <div class="drift-summary-card"><div class="drift-summary-value">${total}</div><div class="drift-summary-label">Total Events</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value" style="color:var(--danger)">${critCount}</div><div class="drift-summary-label">Critical+</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value" style="color:var(--danger)">${errCount}</div><div class="drift-summary-label">Errors</div></div>
                <div class="drift-summary-card"><div class="drift-summary-value" style="color:var(--warning)">${warnCount}</div><div class="drift-summary-label">Warnings</div></div>
            `;
        }

        if (container) {
            if (!items.length) {
                container.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No syslog events found.</p></div>';
            } else {
                container.innerHTML = `<table class="chart-table">
                    <thead><tr><th>Time</th><th>Host</th><th>Severity</th><th>Type</th><th>Message</th></tr></thead>
                    <tbody>${items.map(e => {
                        const sevClass = ['emergency', 'alert', 'critical'].includes(e.severity) ? 'danger' : e.severity === 'error' ? 'danger' : e.severity === 'warning' ? 'warning' : 'info';
                        return `<tr>
                            <td style="white-space:nowrap;">${e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}</td>
                            <td>${escapeHtml(e.hostname || e.host_id || '-')}</td>
                            <td><span class="badge badge-${sevClass}">${escapeHtml(e.severity || '-')}</span></td>
                            <td>${escapeHtml(e.event_type || '-')}</td>
                            <td style="max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(e.message || e.event_data || '-')}</td>
                        </tr>`;
                    }).join('')}</tbody>
                </table>`;
            }
        }

        // Wire up search filter
        const searchInput = document.getElementById('syslog-search');
        if (searchInput) {
            searchInput.oninput = debounce(() => {
                const q = searchInput.value.toLowerCase();
                const rows = container?.querySelectorAll('tbody tr') || [];
                rows.forEach(row => {
                    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            }, 200);
        }
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading syslog: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadSyslog = loadSyslog;

// =============================================================================
// Reports & Export Page
// =============================================================================

async function loadReports(options = {}) {
    const { preserveContent = false } = options;

    // Populate group filter
    const groupSelect = document.getElementById('report-group');
    if (groupSelect && groupSelect.options.length <= 1) {
        try {
            const inv = await api.getInventoryGroups(false);
            const groups = inv?.groups || inv || [];
            groups.forEach(g => {
                const opt = document.createElement('option');
                opt.value = g.id;
                opt.textContent = g.name;
                groupSelect.appendChild(opt);
            });
        } catch (_) { /* ignore */ }
    }

    // Load report history
    const histContainer = document.getElementById('report-runs-list');
    if (!preserveContent && histContainer) histContainer.innerHTML = skeletonCards(2);
    try {
        const result = await api.getReportRuns();
        const runs = result?.runs || result || [];
        if (histContainer) {
            if (!runs.length) {
                histContainer.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No reports generated yet.</p></div>';
            } else {
                histContainer.innerHTML = `<table class="chart-table">
                    <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Rows</th><th>Started</th><th>Actions</th></tr></thead>
                    <tbody>${runs.map(r => `<tr>
                        <td>#${r.id}</td>
                        <td>${escapeHtml(r.report_type || '')}</td>
                        <td><span class="badge badge-${r.status === 'completed' ? 'success' : r.status === 'error' ? 'danger' : 'warning'}">${escapeHtml(r.status || '')}</span></td>
                        <td>${r.row_count ?? '-'}</td>
                        <td>${r.started_at ? new Date(r.started_at).toLocaleString() : '-'}</td>
                        <td>
                            ${r.status === 'completed' ? `<a class="btn btn-sm btn-secondary" href="/api/reports/runs/${r.id}/csv" download>CSV</a>` : ''}
                        </td>
                    </tr>`).join('')}</tbody>
                </table>`;
            }
        }
    } catch (error) {
        if (histContainer) histContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error loading reports: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadReports = loadReports;

function switchReportTab(tab) {
    document.querySelectorAll('.report-tab').forEach(t => t.style.display = 'none');
    document.querySelectorAll('.report-tab-btn').forEach(b => b.classList.remove('active'));
    const tabEl = document.getElementById(`report-tab-${tab}`);
    if (tabEl) tabEl.style.display = '';
    const btn = document.querySelector(`.report-tab-btn[data-report-tab="${tab}"]`);
    if (btn) btn.classList.add('active');
    // Lazy load syslog and OID profiles when their tabs are selected
    if (tab === 'events') loadSyslog();
    if (tab === 'oid-profiles' && typeof window.loadOidProfiles === 'function') window.loadOidProfiles();
}
window.switchReportTab = switchReportTab;

function showGenerateReport() {
    switchReportTab('generate');
    document.getElementById('report-result').innerHTML = '';
}
window.showGenerateReport = showGenerateReport;

function updateReportParams() {
    const type = document.getElementById('report-type')?.value;
    const daysGroup = document.getElementById('report-days-group');
    // Compliance doesn't use days
    if (daysGroup) daysGroup.style.display = type === 'compliance' ? 'none' : '';
}
window.updateReportParams = updateReportParams;

async function generateAndShowReport() {
    const resultEl = document.getElementById('report-result');
    if (!resultEl) return;
    resultEl.innerHTML = '<div class="card" style="padding:1.5rem;">Generating report...</div>';

    const reportType = document.getElementById('report-type')?.value || 'availability';
    const groupId = document.getElementById('report-group')?.value || '';
    const days = parseInt(document.getElementById('report-days')?.value || '30', 10);

    const params = {};
    if (groupId) params.group_id = parseInt(groupId, 10);
    if (reportType !== 'compliance') params.days = days;

    try {
        const result = await api.generateReport({ report_type: reportType, parameters: params });
        const rows = result?.rows || [];
        if (!rows.length) {
            resultEl.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">Report generated with 0 rows. No data found for the selected criteria.</p></div>';
            return;
        }
        const cols = Object.keys(rows[0]);
        resultEl.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                <span>${rows.length} row${rows.length !== 1 ? 's' : ''} &middot; Run #${result.run_id || '-'}</span>
                ${result.run_id ? `<a class="btn btn-sm btn-secondary" href="/api/reports/runs/${result.run_id}/csv" download>Export CSV</a>` : ''}
            </div>
            <div style="overflow-x:auto;">
                <table class="chart-table">
                    <thead><tr>${cols.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr></thead>
                    <tbody>${rows.slice(0, 200).map(r => `<tr>${cols.map(c => `<td>${escapeHtml(String(r[c] ?? ''))}</td>`).join('')}</tr>`).join('')}</tbody>
                </table>
            </div>
            ${rows.length > 200 ? `<p class="text-muted">Showing first 200 of ${rows.length} rows. Export CSV for full data.</p>` : ''}
        `;
        // Refresh history tab
        loadReports({ preserveContent: true });
    } catch (error) {
        resultEl.innerHTML = `<div class="card" style="color:var(--danger); padding:1.5rem;">Error: ${escapeHtml(error.message)}</div>`;
    }
}
window.generateAndShowReport = generateAndShowReport;

// =============================================================================
// Device Syslog Tab
// =============================================================================

async function renderDeviceSyslogTab(hostId) {
    const container = document.getElementById('device-syslog-events');
    if (!container) return;
    try {
        const events = await api.getSyslogEvents({ hostId, limit: 100 });
        const items = events?.events || events || [];
        if (!items.length) {
            container.innerHTML = '<p class="text-muted">No syslog events for this device</p>';
            return;
        }
        container.innerHTML = `<table class="chart-table">
            <thead><tr><th>Time</th><th>Severity</th><th>Message</th></tr></thead>
            <tbody>${items.map(e => {
                const sevClass = ['emergency', 'alert', 'critical'].includes(e.severity) ? 'danger' : e.severity === 'error' ? 'danger' : e.severity === 'warning' ? 'warning' : 'info';
                return `<tr>
                    <td style="white-space:nowrap;">${e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}</td>
                    <td><span class="badge badge-${sevClass}">${escapeHtml(e.severity || '-')}</span></td>
                    <td>${escapeHtml(e.message || e.event_data || '-')}</td>
                </tr>`;
            }).join('')}</tbody>
        </table>`;
    } catch (e) {
        container.innerHTML = '<p class="text-muted">Could not load syslog events</p>';
    }
}

// =============================================================================
// Graph Templates Page (Cacti-parity)
// =============================================================================

async function loadGraphTemplates(options = {}) {
    const state = listViewState.graphTemplates;
    try {
        const [gtRes, htRes, treeRes] = await Promise.all([
            api.getGraphTemplates(),
            api.getHostTemplates(),
            api.getGraphTrees(),
        ]);
        state.items = gtRes.graph_templates || [];
        state.hostTemplates = htRes.host_templates || [];
        state.graphTrees = treeRes.graph_trees || [];
        renderGraphTemplatesTab(state.tab);
    } catch (e) {
        console.error('Failed to load graph templates:', e);
        showError('Failed to load graph templates: ' + e.message);
    }
}

function renderGraphTemplatesTab(tab) {
    const state = listViewState.graphTemplates;
    state.tab = tab;
    const tabSelect = document.getElementById('graph-templates-tab');
    if (tabSelect) tabSelect.value = tab;
    const catFilter = document.getElementById('graph-templates-category');

    document.getElementById('graph-templates-list-view').style.display = tab === 'graph-templates' ? '' : 'none';
    document.getElementById('host-templates-list-view').style.display = tab === 'host-templates' ? '' : 'none';
    document.getElementById('graph-trees-list-view').style.display = tab === 'graph-trees' ? '' : 'none';
    if (catFilter) catFilter.style.display = tab === 'graph-templates' ? '' : 'none';

    const addBtn = document.querySelector('#page-graph-templates .page-header .btn-primary');
    if (addBtn) {
        if (tab === 'graph-templates') { addBtn.textContent = '+ New Template'; addBtn.onclick = showCreateGraphTemplateModal; }
        else if (tab === 'host-templates') { addBtn.textContent = '+ New Host Template'; addBtn.onclick = showCreateHostTemplateModal; }
        else { addBtn.textContent = '+ New Tree'; addBtn.onclick = showCreateGraphTreeModal; }
    }

    if (tab === 'graph-templates') renderGraphTemplatesList();
    else if (tab === 'host-templates') renderHostTemplatesList();
    else renderGraphTreesList();
}
window.switchGraphTemplatesTab = function(v) { renderGraphTemplatesTab(v); };
window.filterGraphTemplatesCategory = function(v) { listViewState.graphTemplates.category = v; renderGraphTemplatesList(); };

function renderGraphTemplatesList() {
    const state = listViewState.graphTemplates;
    const container = document.getElementById('graph-templates-list');
    const emptyEl = document.getElementById('graph-templates-empty');
    let items = state.items;

    if (state.category) items = items.filter(t => t.category === state.category);
    if (state.query) {
        const q = state.query.toLowerCase();
        items = items.filter(t => (t.name || '').toLowerCase().includes(q) || (t.category || '').toLowerCase().includes(q));
    }

    if (!items.length) {
        container.innerHTML = '';
        if (emptyEl) emptyEl.style.display = '';
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    const scopeIcon = (scope) => scope === 'interface'
        ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v16H4z"></path><path d="M4 12h16"></path></svg>'
        : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>';

    container.innerHTML = `<div class="card-grid" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem;">
        ${items.map(t => `
            <div class="card" style="cursor:pointer;" onclick="showGraphTemplateDetail(${t.id})">
                <div class="card-body">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                        <h4 style="margin:0;">${escapeHtml(t.name)}</h4>
                        ${t.built_in ? '<span class="badge badge-info" style="font-size:0.7rem;">Built-in</span>' : ''}
                    </div>
                    <p class="text-muted" style="margin:0 0 0.5rem; font-size:0.85rem;">${escapeHtml(t.description || 'No description')}</p>
                    <div style="display:flex; gap:0.75rem; font-size:0.8rem; color:var(--text-secondary);">
                        <span>${scopeIcon(t.scope)} ${escapeHtml(t.scope)}</span>
                        <span class="badge badge-secondary">${escapeHtml(t.category)}</span>
                        <span>${escapeHtml(t.graph_type)}</span>
                    </div>
                </div>
            </div>
        `).join('')}
    </div>`;
}

function renderHostTemplatesList() {
    const state = listViewState.graphTemplates;
    const container = document.getElementById('host-templates-list');
    const items = state.hostTemplates;

    if (!items.length) {
        container.innerHTML = '<p class="text-muted" style="padding:1rem;">No host templates configured.</p>';
        return;
    }

    container.innerHTML = `<div class="card-grid" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem;">
        ${items.map(ht => {
            let dtypes = [];
            try { dtypes = JSON.parse(ht.device_types || '[]'); } catch(e) {}
            const dtLabel = dtypes.length ? dtypes.join(', ') : 'All devices';
            const gtCount = (ht.graph_templates || []).length;
            return `<div class="card">
                <div class="card-body">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                        <h4 style="margin:0;">${escapeHtml(ht.name)}</h4>
                        <span class="badge ${ht.auto_apply ? 'badge-success' : 'badge-secondary'}">${ht.auto_apply ? 'Auto-apply' : 'Manual'}</span>
                    </div>
                    <p class="text-muted" style="margin:0 0 0.5rem; font-size:0.85rem;">${escapeHtml(ht.description || '')}</p>
                    <div style="display:flex; gap:0.75rem; font-size:0.8rem; color:var(--text-secondary);">
                        <span>Devices: ${escapeHtml(dtLabel)}</span>
                        <span>${gtCount} graph template${gtCount !== 1 ? 's' : ''}</span>
                    </div>
                    ${gtCount > 0 ? `<div style="margin-top:0.5rem; font-size:0.8rem;">${ht.graph_templates.map(g => `<span class="badge badge-secondary" style="margin:0.1rem;">${escapeHtml(g.name)}</span>`).join('')}</div>` : ''}
                </div>
                <div class="card-actions" style="display:flex; gap:0.5rem; padding:0.5rem 1rem; border-top:1px solid var(--border-color);">
                    <button class="btn btn-sm btn-secondary" onclick="editHostTemplate(${ht.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteHostTemplateConfirm(${ht.id})">Delete</button>
                </div>
            </div>`;
        }).join('')}
    </div>`;
}

function renderGraphTreesList() {
    const state = listViewState.graphTemplates;
    const container = document.getElementById('graph-trees-list');
    const items = state.graphTrees;

    if (!items.length) {
        container.innerHTML = '<p class="text-muted" style="padding:1rem;">No graph trees configured. Create a tree to organize graphs hierarchically.</p>';
        return;
    }

    container.innerHTML = `<div class="card-grid" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem;">
        ${items.map(tree => `
            <div class="card" style="cursor:pointer;" onclick="showGraphTreeDetail(${tree.id})">
                <div class="card-body">
                    <h4 style="margin:0 0 0.5rem;">${escapeHtml(tree.name)}</h4>
                    <p class="text-muted" style="margin:0; font-size:0.85rem;">${escapeHtml(tree.description || 'No description')}</p>
                </div>
                <div class="card-actions" style="display:flex; gap:0.5rem; padding:0.5rem 1rem; border-top:1px solid var(--border-color);">
                    <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); editGraphTree(${tree.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteGraphTreeConfirm(${tree.id})">Delete</button>
                </div>
            </div>
        `).join('')}
    </div>`;
}

// -- Graph Template Detail Modal ----------------------------------------------

window.showGraphTemplateDetail = async function(id) {
    try {
        const tpl = await api.getGraphTemplate(id);
        const items = tpl.items || [];
        const html = `
            <div class="modal-header"><h3>${escapeHtml(tpl.name)}</h3></div>
            <div class="modal-body">
                <p>${escapeHtml(tpl.description || '')}</p>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; margin-bottom:1rem; font-size:0.85rem;">
                    <div><strong>Type:</strong> ${escapeHtml(tpl.graph_type)}</div>
                    <div><strong>Scope:</strong> ${escapeHtml(tpl.scope)}</div>
                    <div><strong>Category:</strong> ${escapeHtml(tpl.category)}</div>
                    <div><strong>Y-Axis:</strong> ${escapeHtml(tpl.y_axis_label || '-')}</div>
                    <div><strong>Stacked:</strong> ${tpl.stacked ? 'Yes' : 'No'}</div>
                    <div><strong>Area Fill:</strong> ${tpl.area_fill ? 'Yes' : 'No'}</div>
                    <div><strong>Grid Size:</strong> ${tpl.grid_w}x${tpl.grid_h}</div>
                    <div><strong>Built-in:</strong> ${tpl.built_in ? 'Yes' : 'No'}</div>
                </div>
                <h4>Data Series (${items.length})</h4>
                ${items.length ? `<table class="table"><thead><tr><th>Label</th><th>Metric</th><th>Type</th><th>Color</th><th>Consolidation</th></tr></thead><tbody>
                    ${items.map(i => `<tr>
                        <td>${escapeHtml(i.label)}</td>
                        <td><code>${escapeHtml(i.metric_name)}</code></td>
                        <td>${escapeHtml(i.line_type)}</td>
                        <td><span style="display:inline-block;width:16px;height:16px;border-radius:3px;background:${escapeHtml(i.color)};vertical-align:middle;"></span> ${escapeHtml(i.color)}</td>
                        <td>${escapeHtml(i.consolidation)}</td>
                    </tr>`).join('')}
                </tbody></table>` : '<p class="text-muted">No data series defined.</p>'}
            </div>
            <div class="modal-footer">
                ${!tpl.built_in ? `<button class="btn btn-danger" onclick="deleteGraphTemplateConfirm(${tpl.id})">Delete</button>` : ''}
                <button class="btn btn-secondary" onclick="closeModal()">Close</button>
            </div>`;
        showModal(html);
    } catch (e) {
        showError('Failed to load template: ' + e.message);
    }
};

// -- Create Graph Template Modal ----------------------------------------------

function showCreateGraphTemplateModal() {
    const html = `
        <div class="modal-header"><h3>New Graph Template</h3></div>
        <div class="modal-body">
            <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="gt-name" placeholder="e.g. CPU Usage"></div>
            <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="gt-desc" placeholder="Optional description"></div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                <div class="form-group"><label class="form-label">Graph Type</label>
                    <select class="form-select" id="gt-type"><option value="line">Line</option><option value="bar">Bar</option><option value="gauge">Gauge</option><option value="heatmap">Heatmap</option></select></div>
                <div class="form-group"><label class="form-label">Scope</label>
                    <select class="form-select" id="gt-scope"><option value="device">Device</option><option value="interface">Interface</option></select></div>
                <div class="form-group"><label class="form-label">Category</label>
                    <select class="form-select" id="gt-category"><option value="system">System</option><option value="traffic">Traffic</option><option value="availability">Availability</option><option value="custom">Custom</option></select></div>
                <div class="form-group"><label class="form-label">Title Format</label><input class="form-input" id="gt-title-format" placeholder="$interface Traffic"></div>
                <div class="form-group"><label class="form-label">Y-Axis Label</label><input class="form-input" id="gt-y-label" placeholder="e.g. Bits/sec"></div>
                <div class="form-group" style="display:flex; gap:1rem; align-items:center; padding-top:1.5rem;">
                    <label><input type="checkbox" id="gt-stacked"> Stacked</label>
                    <label><input type="checkbox" id="gt-area" checked> Area Fill</label>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="submitCreateGraphTemplate()">Create</button>
        </div>`;
    showModal(html);
}
window.showCreateGraphTemplateModal = showCreateGraphTemplateModal;

window.submitCreateGraphTemplate = async function() {
    const name = document.getElementById('gt-name').value.trim();
    if (!name) { showError('Name is required'); return; }
    try {
        await api.createGraphTemplate({
            name,
            description: document.getElementById('gt-desc').value.trim(),
            graph_type: document.getElementById('gt-type').value,
            scope: document.getElementById('gt-scope').value,
            category: document.getElementById('gt-category').value,
            title_format: document.getElementById('gt-title-format').value.trim(),
            y_axis_label: document.getElementById('gt-y-label').value.trim(),
            stacked: document.getElementById('gt-stacked').checked,
            area_fill: document.getElementById('gt-area').checked,
        });
        closeModal();
        showSuccess('Graph template created');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to create template: ' + e.message);
    }
};

window.deleteGraphTemplateConfirm = async function(id) {
    if (!confirm('Delete this graph template? This will also remove all host graph instances using it.')) return;
    try {
        await api.deleteGraphTemplate(id);
        closeModal();
        showSuccess('Graph template deleted');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to delete: ' + e.message);
    }
};

// -- Host Template CRUD -------------------------------------------------------

function showCreateHostTemplateModal() {
    const html = `
        <div class="modal-header"><h3>New Host Template</h3></div>
        <div class="modal-body">
            <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="ht-name" placeholder="e.g. Cisco IOS Switches"></div>
            <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="ht-desc" placeholder="Optional description"></div>
            <div class="form-group"><label class="form-label">Device Types (comma-separated, leave empty for all)</label><input class="form-input" id="ht-dtypes" placeholder="e.g. cisco_ios, cisco_nxos"></div>
            <div class="form-group"><label><input type="checkbox" id="ht-auto" checked> Auto-apply to matching devices</label></div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="submitCreateHostTemplate()">Create</button>
        </div>`;
    showModal(html);
}
window.showCreateHostTemplateModal = showCreateHostTemplateModal;

window.submitCreateHostTemplate = async function() {
    const name = document.getElementById('ht-name').value.trim();
    if (!name) { showError('Name is required'); return; }
    const dtypes = document.getElementById('ht-dtypes').value.trim();
    const dtArr = dtypes ? dtypes.split(',').map(s => s.trim()).filter(Boolean) : [];
    try {
        await api.createHostTemplate({
            name,
            description: document.getElementById('ht-desc').value.trim(),
            device_types: JSON.stringify(dtArr),
            auto_apply: document.getElementById('ht-auto').checked,
        });
        closeModal();
        showSuccess('Host template created');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to create host template: ' + e.message);
    }
};

window.editHostTemplate = async function(id) {
    try {
        const ht = await api.getHostTemplate(id);
        let dtypes = [];
        try { dtypes = JSON.parse(ht.device_types || '[]'); } catch(e) {}
        const html = `
            <div class="modal-header"><h3>Edit Host Template</h3></div>
            <div class="modal-body">
                <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="ht-edit-name" value="${escapeHtml(ht.name)}"></div>
                <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="ht-edit-desc" value="${escapeHtml(ht.description || '')}"></div>
                <div class="form-group"><label class="form-label">Device Types (comma-separated)</label><input class="form-input" id="ht-edit-dtypes" value="${escapeHtml(dtypes.join(', '))}"></div>
                <div class="form-group"><label><input type="checkbox" id="ht-edit-auto" ${ht.auto_apply ? 'checked' : ''}> Auto-apply</label></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="submitEditHostTemplate(${id})">Save</button>
            </div>`;
        showModal(html);
    } catch (e) {
        showError('Failed to load host template: ' + e.message);
    }
};

window.submitEditHostTemplate = async function(id) {
    const dtypes = document.getElementById('ht-edit-dtypes').value.trim();
    const dtArr = dtypes ? dtypes.split(',').map(s => s.trim()).filter(Boolean) : [];
    try {
        await api.updateHostTemplate(id, {
            name: document.getElementById('ht-edit-name').value.trim(),
            description: document.getElementById('ht-edit-desc').value.trim(),
            device_types: JSON.stringify(dtArr),
            auto_apply: document.getElementById('ht-edit-auto').checked,
        });
        closeModal();
        showSuccess('Host template updated');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to update: ' + e.message);
    }
};

window.deleteHostTemplateConfirm = async function(id) {
    if (!confirm('Delete this host template?')) return;
    try {
        await api.deleteHostTemplate(id);
        showSuccess('Host template deleted');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to delete: ' + e.message);
    }
};

// -- Graph Tree CRUD ----------------------------------------------------------

function showCreateGraphTreeModal() {
    const html = `
        <div class="modal-header"><h3>New Graph Tree</h3></div>
        <div class="modal-body">
            <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="tree-name" placeholder="e.g. All Devices"></div>
            <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="tree-desc"></div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="submitCreateGraphTree()">Create</button>
        </div>`;
    showModal(html);
}
window.showCreateGraphTreeModal = showCreateGraphTreeModal;

window.submitCreateGraphTree = async function() {
    const name = document.getElementById('tree-name').value.trim();
    if (!name) { showError('Name is required'); return; }
    try {
        await api.createGraphTree({
            name,
            description: document.getElementById('tree-desc').value.trim(),
        });
        closeModal();
        showSuccess('Graph tree created');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to create tree: ' + e.message);
    }
};

window.showGraphTreeDetail = async function(id) {
    try {
        const tree = await api.getGraphTree(id);
        const nodes = tree.nodes || [];
        const html = `
            <div class="modal-header"><h3>${escapeHtml(tree.name)}</h3></div>
            <div class="modal-body">
                <p>${escapeHtml(tree.description || '')}</p>
                <h4>Nodes (${nodes.length})</h4>
                ${nodes.length ? `<table class="table"><thead><tr><th>Title</th><th>Type</th><th>Sort</th></tr></thead><tbody>
                    ${nodes.map(n => `<tr>
                        <td>${escapeHtml(n.title || '-')}</td>
                        <td><span class="badge badge-secondary">${escapeHtml(n.node_type)}</span></td>
                        <td>${n.sort_order}</td>
                    </tr>`).join('')}
                </tbody></table>` : '<p class="text-muted">No nodes yet. Add nodes to organize your graph hierarchy.</p>'}
                <button class="btn btn-sm btn-primary" onclick="showAddTreeNodeModal(${id})" style="margin-top:0.5rem;">+ Add Node</button>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Close</button>
            </div>`;
        showModal(html);
    } catch (e) {
        showError('Failed to load tree: ' + e.message);
    }
};

window.showAddTreeNodeModal = function(treeId) {
    const html = `
        <div class="modal-header"><h3>Add Tree Node</h3></div>
        <div class="modal-body">
            <div class="form-group"><label class="form-label">Title</label><input class="form-input" id="tnode-title" placeholder="e.g. Core Switches"></div>
            <div class="form-group"><label class="form-label">Type</label>
                <select class="form-select" id="tnode-type"><option value="header">Header</option><option value="device">Device</option><option value="graph">Graph</option></select></div>
            <div class="form-group"><label class="form-label">Sort Order</label><input class="form-input" id="tnode-sort" type="number" value="0"></div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" onclick="submitAddTreeNode(${treeId})">Add</button>
        </div>`;
    showModal(html);
};

window.submitAddTreeNode = async function(treeId) {
    const title = document.getElementById('tnode-title').value.trim();
    if (!title) { showError('Title is required'); return; }
    try {
        await api.createGraphTreeNode(treeId, {
            title,
            node_type: document.getElementById('tnode-type').value,
            sort_order: parseInt(document.getElementById('tnode-sort').value) || 0,
        });
        closeModal();
        showSuccess('Node added');
        showGraphTreeDetail(treeId);
    } catch (e) {
        showError('Failed to add node: ' + e.message);
    }
};

window.editGraphTree = async function(id) {
    try {
        const tree = await api.getGraphTree(id);
        const html = `
            <div class="modal-header"><h3>Edit Graph Tree</h3></div>
            <div class="modal-body">
                <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="tree-edit-name" value="${escapeHtml(tree.name)}"></div>
                <div class="form-group"><label class="form-label">Description</label><input class="form-input" id="tree-edit-desc" value="${escapeHtml(tree.description || '')}"></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="submitEditGraphTree(${id})">Save</button>
            </div>`;
        showModal(html);
    } catch (e) {
        showError('Failed to load tree: ' + e.message);
    }
};

window.submitEditGraphTree = async function(id) {
    try {
        await api.updateGraphTree(id, {
            name: document.getElementById('tree-edit-name').value.trim(),
            description: document.getElementById('tree-edit-desc').value.trim(),
        });
        closeModal();
        showSuccess('Graph tree updated');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to update: ' + e.message);
    }
};

window.deleteGraphTreeConfirm = async function(id) {
    if (!confirm('Delete this graph tree and all its nodes?')) return;
    try {
        await api.deleteGraphTree(id);
        showSuccess('Graph tree deleted');
        await loadGraphTemplates({ force: true });
    } catch (e) {
        showError('Failed to delete: ' + e.message);
    }
};

// -- Graph Templates Search ---------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    const searchEl = document.getElementById('graph-templates-search');
    if (searchEl) {
        searchEl.addEventListener('input', debounce(() => {
            listViewState.graphTemplates.query = searchEl.value;
            renderGraphTemplatesList();
        }, 200));
    }
});

// =============================================================================
// Destroy / Cleanup
// =============================================================================

function destroyReports() {
    PlexusChart.destroyAll();
    listViewState.graphTemplates.items = [];
    listViewState.graphTemplates.hostTemplates = [];
    listViewState.graphTemplates.graphTrees = [];
    listViewState.graphTemplates.query = '';
}

// =============================================================================
// Custom OID Profiles
// =============================================================================

async function loadOidProfiles(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('oid-profiles-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const vendor = document.getElementById('oid-vendor-filter')?.value || '';
        const result = await api.getOidProfiles(vendor || null);
        const profiles = result?.profiles || result || [];

        // Populate vendor filter
        const vendorSelect = document.getElementById('oid-vendor-filter');
        if (vendorSelect && vendorSelect.options.length <= 1) {
            const vendors = [...new Set(profiles.map(p => p.vendor).filter(Boolean))];
            vendors.forEach(v => {
                const opt = document.createElement('option');
                opt.value = v;
                opt.textContent = v;
                vendorSelect.appendChild(opt);
            });
        }

        if (container) {
            if (!profiles.length) {
                container.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No custom OID profiles. Click "+ New Profile" to create one.</p></div>';
            } else {
                container.innerHTML = profiles.map(p => {
                    let oidCount = 0;
                    try { oidCount = JSON.parse(p.oids_json || '[]').length; } catch (_) {}
                    return `<div class="card" style="padding:1rem; margin-bottom:0.75rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <strong>${escapeHtml(p.name)}</strong>
                                ${p.vendor ? `<span class="badge badge-info" style="margin-left:0.5rem;">${escapeHtml(p.vendor)}</span>` : ''}
                                ${p.device_type ? `<span class="text-muted" style="margin-left:0.5rem;">${escapeHtml(p.device_type)}</span>` : ''}
                                ${p.is_default ? '<span class="badge badge-success" style="margin-left:0.5rem;">Default</span>' : ''}
                            </div>
                            <div style="display:flex; gap:0.5rem;">
                                <button class="btn btn-sm btn-secondary" onclick="editOidProfile(${p.id})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteOidProfile(${p.id})">Delete</button>
                            </div>
                        </div>
                        <div class="text-muted" style="font-size:0.85em; margin-top:0.25rem;">
                            ${escapeHtml(p.description || '')} &middot; ${oidCount} OID mapping${oidCount !== 1 ? 's' : ''}
                        </div>
                    </div>`;
                }).join('');
            }
        }

        // Built-in vendor defaults (informational)
        const defaultsEl = document.getElementById('vendor-oid-defaults-list');
        if (defaultsEl) {
            defaultsEl.innerHTML = `<div class="card" style="padding:1rem;">
                <p class="text-muted" style="margin-bottom:0.75rem;">These OIDs are polled automatically based on device type detection.</p>
                <table class="chart-table">
                    <thead><tr><th>Vendor</th><th>Metric</th><th>OID</th></tr></thead>
                    <tbody>
                        <tr><td>Cisco IOS</td><td>CPU 5min</td><td>1.3.6.1.4.1.9.9.109.1.1.1.1.8</td></tr>
                        <tr><td>Cisco IOS</td><td>Memory Used</td><td>1.3.6.1.4.1.9.9.48.1.1.1.5</td></tr>
                        <tr><td>Juniper</td><td>CPU</td><td>1.3.6.1.4.1.2636.3.1.13.1.8</td></tr>
                        <tr><td>Juniper</td><td>Memory</td><td>1.3.6.1.4.1.2636.3.1.13.1.11</td></tr>
                        <tr><td>Arista</td><td>CPU</td><td>1.3.6.1.2.1.25.3.3.1.2</td></tr>
                        <tr><td>Generic</td><td>sysUpTime</td><td>1.3.6.1.2.1.1.3.0</td></tr>
                        <tr><td>Generic</td><td>ifHCInOctets</td><td>1.3.6.1.2.1.31.1.1.1.6</td></tr>
                        <tr><td>Generic</td><td>ifHCOutOctets</td><td>1.3.6.1.2.1.31.1.1.1.10</td></tr>
                    </tbody>
                </table>
            </div>`;
        }
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading OID profiles: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadOidProfiles = loadOidProfiles;

function showCreateOidProfile() {
    ensureModalDOM('oid-profile-modal', templateOidProfileModal);
    document.getElementById('oid-profile-edit-id').value = '';
    document.getElementById('oid-profile-modal-title').textContent = 'New OID Profile';
    document.getElementById('oid-profile-name').value = '';
    document.getElementById('oid-profile-vendor').value = '';
    document.getElementById('oid-profile-device-type').value = '';
    document.getElementById('oid-profile-description').value = '';
    document.getElementById('oid-profile-oids').value = '[\n  {"oid": "", "metric_name": "", "label": "", "type": "gauge"}\n]';
    document.getElementById('oid-profile-modal').style.display = '';
}
window.showCreateOidProfile = showCreateOidProfile;

async function editOidProfile(profileId) {
    ensureModalDOM('oid-profile-modal', templateOidProfileModal);
    try {
        const profile = await api.getOidProfile(profileId);
        document.getElementById('oid-profile-edit-id').value = profile.id;
        document.getElementById('oid-profile-modal-title').textContent = 'Edit OID Profile';
        document.getElementById('oid-profile-name').value = profile.name || '';
        document.getElementById('oid-profile-vendor').value = profile.vendor || '';
        document.getElementById('oid-profile-device-type').value = profile.device_type || '';
        document.getElementById('oid-profile-description').value = profile.description || '';
        document.getElementById('oid-profile-oids').value = profile.oids_json || '[]';
        document.getElementById('oid-profile-modal').style.display = '';
    } catch (e) { showError(e.message); }
}
window.editOidProfile = editOidProfile;

async function saveOidProfile() {
    const editId = document.getElementById('oid-profile-edit-id').value;
    const data = {
        name: document.getElementById('oid-profile-name').value.trim(),
        vendor: document.getElementById('oid-profile-vendor').value.trim(),
        device_type: document.getElementById('oid-profile-device-type').value.trim(),
        description: document.getElementById('oid-profile-description').value.trim(),
        oids_json: document.getElementById('oid-profile-oids').value.trim(),
    };
    if (!data.name) { showError('Profile name is required'); return; }
    // Validate JSON
    try { JSON.parse(data.oids_json); } catch (_) { showError('Invalid OID JSON'); return; }
    try {
        if (editId) {
            await api.updateOidProfile(editId, data);
            showSuccess('OID profile updated');
        } else {
            await api.createOidProfile(data);
            showSuccess('OID profile created');
        }
        closeOidProfileModal();
        loadOidProfiles();
    } catch (e) { showError(e.message); }
}
window.saveOidProfile = saveOidProfile;

function closeOidProfileModal() {
    document.getElementById('oid-profile-modal').style.display = 'none';
}
window.closeOidProfileModal = closeOidProfileModal;

async function deleteOidProfile(profileId) {
    if (!await showConfirm({ title: 'Delete OID Profile', message: 'Delete this OID profile?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteOidProfile(profileId);
        showSuccess('OID profile deleted');
        loadOidProfiles();
    } catch (e) { showError(e.message); }
}
window.deleteOidProfile = deleteOidProfile;

// =============================================================================
// Exports
// =============================================================================

export {
    loadReports,
    loadGraphTemplates,
    destroyReports,
    loadCapacityPlanning,
    loadAvailability,
    loadSyslog,
    renderDeviceSyslogTab,
    switchReportTab,
    switchAvailTab,
    showGenerateReport,
    updateReportParams,
    generateAndShowReport,
    formatDuration,
    loadOidProfiles,
};

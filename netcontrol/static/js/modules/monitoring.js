/**
 * Monitoring & SLA Module — Device polling, alerts, SLA tracking
 * Lazy-loaded when user navigates to #monitoring
 */
import * as api from '../api.js';
import {
    escapeHtml, showToast, showError, showModal, showConfirm, showSuccess,
    PlexusChart, listViewState, emptyStateHTML, formatDate,
    closeAllModals, invalidatePageCache, navigateToDeviceDetail, debounce,
    getTimeRangeParams, onTimeRangeChange, offTimeRangeChange, copyableCodeBlock,
    initCopyableBlocks, showFormModal, skeletonCards,
    formatMinutes, getHostSlaCompliance, formatUptime
} from '../app.js';
import { ensureModalDOM, templateSlaHostDetailModal, templateSlaTargetModal } from '../page-templates.js';

const closeModal = closeAllModals;

// =============================================================================
// Real-Time Monitoring
// =============================================================================

async function loadMonitoring(options = {}) {
    const { preserveContent = false } = options;
    const devContainer = document.getElementById('monitoring-devices-list');
    if (!preserveContent && devContainer) devContainer.innerHTML = skeletonCards(2);
    try {
        const [summary, polls, alerts] = await Promise.all([
            api.getMonitoringSummary(),
            api.getMonitoringPolls(),
            api.getMonitoringAlerts({ acknowledged: false, limit: 200 }),
        ]);
        renderMonitoringSummary(summary);
        listViewState.monitoring.polls = polls || [];
        listViewState.monitoring.alerts = alerts || [];
        renderMonitoringDevices(polls || []);
        renderMonitoringAlerts(alerts || []);
    } catch (error) {
        if (devContainer) devContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error loading monitoring: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadMonitoring = loadMonitoring;

function renderMonitoringSummary(s) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('mon-stat-hosts', s.monitored_hosts ?? '-');
    set('mon-stat-cpu', s.avg_cpu != null ? s.avg_cpu + '%' : '-');
    set('mon-stat-mem', s.avg_memory != null ? s.avg_memory + '%' : '-');
    set('mon-stat-if-up', s.interfaces_up ?? '-');
    set('mon-stat-if-down', s.interfaces_down ?? '-');
    set('mon-stat-vpn-up', s.vpn_tunnels_up ?? '-');
    set('mon-stat-vpn-down', s.vpn_tunnels_down ?? '-');
    set('mon-stat-routes', s.total_routes ?? '-');
    set('mon-stat-alerts', s.open_alerts ?? '-');

    // Highlight problem stats
    const cpuEl = document.getElementById('mon-stat-cpu');
    if (cpuEl) cpuEl.style.color = (s.avg_cpu != null && s.avg_cpu >= 80) ? 'var(--danger)' : '';
    const memEl = document.getElementById('mon-stat-mem');
    if (memEl) memEl.style.color = (s.avg_memory != null && s.avg_memory >= 80) ? 'var(--danger)' : '';
    const ifDownEl = document.getElementById('mon-stat-if-down');
    if (ifDownEl) ifDownEl.style.color = (s.interfaces_down > 0) ? 'var(--warning)' : '';
    const vpnDownEl = document.getElementById('mon-stat-vpn-down');
    if (vpnDownEl) vpnDownEl.style.color = (s.vpn_tunnels_down > 0) ? 'var(--warning)' : '';
    const alertsEl = document.getElementById('mon-stat-alerts');
    if (alertsEl) alertsEl.style.color = (s.open_alerts > 0) ? 'var(--danger)' : '';
}

function renderMonitoringDevices(polls) {
    const container = document.getElementById('monitoring-devices-list');
    if (!container) return;
    const query = (listViewState.monitoring.query || '').toLowerCase();
    const filtered = polls.filter(p => {
        if (query && !(p.hostname || '').toLowerCase().includes(query)
            && !(p.ip_address || '').toLowerCase().includes(query)) return false;
        return true;
    });
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No monitoring data', 'monitoring',
            '<button class="btn btn-primary btn-sm" onclick="runMonitoringPollNow()">Run First Poll</button>');
        return;
    }
    container.innerHTML = filtered.map(p => {
        const cpuColor = p.cpu_percent == null ? 'text-muted' : (p.cpu_percent >= 90 ? 'danger' : (p.cpu_percent >= 70 ? 'warning' : 'success'));
        const memColor = p.memory_percent == null ? 'text-muted' : (p.memory_percent >= 90 ? 'danger' : (p.memory_percent >= 70 ? 'warning' : 'success'));
        const cpuVal = p.cpu_percent != null ? p.cpu_percent + '%' : 'N/A';
        const memVal = p.memory_percent != null ? p.memory_percent + '%' : 'N/A';
        const polled = p.polled_at ? new Date(p.polled_at + 'Z').toLocaleString() : '-';
        const statusDot = p.poll_status === 'error' ? 'danger' : 'success';
        const uptime = p.uptime_seconds != null ? formatUptime(p.uptime_seconds) : 'N/A';

        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div style="display:flex; align-items:center; gap:0.5rem;">
                    <span style="width:8px; height:8px; border-radius:50%; background:var(--${statusDot}); display:inline-block;"></span>
                    <strong>${escapeHtml(p.hostname || 'Unknown')}</strong>
                    <span style="color:var(--text-muted); font-size:0.85em;">${escapeHtml(p.ip_address || '')}</span>
                    <span style="color:var(--text-muted); font-size:0.8em;">${escapeHtml(p.device_type || '')}</span>
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-secondary" onclick="navigateToDeviceDetail(${p.host_id})">Details</button>
                    <button class="btn btn-sm btn-secondary" onclick="showMonitoringHostHistory(${p.host_id}, '${escapeHtml(p.hostname || '')}')">History</button>
                </div>
            </div>
            <div style="display:flex; gap:1.5rem; margin-top:0.75rem; flex-wrap:wrap; font-size:0.9em;">
                <div><span style="color:var(--text-muted);">CPU:</span> <span style="color:var(--${cpuColor}); font-weight:600;">${cpuVal}</span></div>
                <div><span style="color:var(--text-muted);">Memory:</span> <span style="color:var(--${memColor}); font-weight:600;">${memVal}</span>${p.memory_used_mb != null && p.memory_total_mb != null ? ` <span style="font-size:0.8em; color:var(--text-muted);">(${p.memory_used_mb}/${p.memory_total_mb} MB)</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">Interfaces:</span> <span style="color:var(--success);">${p.if_up_count} up</span>${p.if_down_count > 0 ? ` / <span style="color:var(--danger);">${p.if_down_count} down</span>` : ''}${p.if_admin_down > 0 ? ` / <span style="color:var(--text-muted);">${p.if_admin_down} admin-down</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">VPN:</span> <span style="color:var(--success);">${p.vpn_tunnels_up} up</span>${p.vpn_tunnels_down > 0 ? ` / <span style="color:var(--danger);">${p.vpn_tunnels_down} down</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">Routes:</span> ${p.route_count}</div>
                <div><span style="color:var(--text-muted);">Uptime:</span> ${uptime}</div>
            </div>
            ${p.cpu_percent != null ? `<div style="display:flex; gap:0.5rem; margin-top:0.5rem; align-items:center;">
                <span style="font-size:0.75em; color:var(--text-muted); width:28px; text-align:right;">CPU</span>
                <div style="flex:1; background:var(--bg-secondary); border-radius:4px; height:6px; overflow:hidden;" title="CPU ${cpuVal}">
                    <div style="width:${Math.min(p.cpu_percent, 100)}%; height:100%; background:var(--${cpuColor}); border-radius:4px; transition:width 0.3s;"></div>
                </div>
                <span style="font-size:0.75em; color:var(--text-muted); width:28px; text-align:right;">MEM</span>
                <div style="flex:1; background:var(--bg-secondary); border-radius:4px; height:6px; overflow:hidden;" title="Memory ${memVal}">
                    <div style="width:${Math.min(p.memory_percent || 0, 100)}%; height:100%; background:var(--${memColor}); border-radius:4px; transition:width 0.3s;"></div>
                </div>
            </div>` : ''}
            <div style="margin-top:0.4rem; font-size:0.8em; color:var(--text-muted);">Last poll: ${polled}</div>
        </div>`;
    }).join('');
}

function renderMonitoringAlerts(alerts) {
    const container = document.getElementById('monitoring-alerts-list');
    if (!container) return;
    const query = (listViewState.monitoring.query || '').toLowerCase();
    const sevFilter = document.getElementById('mon-alert-filter-severity')?.value || '';
    const ackFilter = document.getElementById('mon-alert-filter-ack')?.value;

    let filtered = alerts;
    if (sevFilter) filtered = filtered.filter(a => a.severity === sevFilter);
    if (ackFilter === 'true') filtered = filtered.filter(a => a.acknowledged);
    else if (ackFilter === 'false') filtered = filtered.filter(a => !a.acknowledged);
    if (query) filtered = filtered.filter(a =>
        (a.hostname || '').toLowerCase().includes(query) ||
        (a.message || '').toLowerCase().includes(query) ||
        (a.metric || '').toLowerCase().includes(query));

    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No alerts', 'monitoring', '');
        return;
    }

    // Bulk acknowledge button for unacknowledged alerts
    const unackedIds = filtered.filter(a => !a.acknowledged).map(a => a.id);
    const bulkBtn = unackedIds.length > 1
        ? `<div style="margin-bottom:0.5rem;"><button class="btn btn-sm btn-secondary" onclick="bulkAcknowledgeAlerts([${unackedIds.join(',')}])">Acknowledge All (${unackedIds.length})</button></div>`
        : '';

    container.innerHTML = bulkBtn + filtered.map(a => {
        const sevColors = { critical: 'danger', warning: 'warning', info: 'primary' };
        const sevColor = sevColors[a.severity] || 'text-muted';
        const created = a.created_at ? new Date(a.created_at + 'Z').toLocaleString() : '-';
        const lastSeen = a.last_seen_at ? new Date(a.last_seen_at + 'Z').toLocaleString() : created;
        const ackBadge = a.acknowledged
            ? `<span style="color:var(--success); font-size:0.8em;">Acknowledged${a.acknowledged_by ? ` by ${escapeHtml(a.acknowledged_by)}` : ''}</span>`
            : `<button class="btn btn-sm btn-secondary" onclick="acknowledgeMonitoringAlert(${a.id})">Acknowledge</button>`;

        // Dedup badge
        const occurrences = (a.occurrence_count || 1);
        const dedupBadge = occurrences > 1
            ? `<span style="background:var(--bg-secondary); color:var(--text-muted); font-size:0.75em; padding:2px 6px; border-radius:3px; margin-left:0.3rem;" title="Deduplicated: seen ${occurrences} times">${occurrences}x</span>`
            : '';

        // Escalation badge
        const escalationBadge = a.escalated
            ? `<span style="background:var(--danger); color:white; font-size:0.7em; padding:2px 6px; border-radius:3px; margin-left:0.3rem;" title="Escalated from ${escapeHtml(a.original_severity || '')}">ESCALATED</span>`
            : '';

        return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; border-left:3px solid var(--${sevColor});">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                <div>
                    <span class="badge" style="background:var(--${sevColor}); color:white; font-size:0.75em; padding:2px 8px; border-radius:3px; text-transform:uppercase;">${escapeHtml(a.severity)}</span>
                    ${escalationBadge}${dedupBadge}
                    <strong style="margin-left:0.4rem;">${escapeHtml(a.hostname || '')}</strong>
                    <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.4rem;">${escapeHtml(a.metric || '')}</span>
                </div>
                <div style="display:flex; gap:0.4rem; align-items:center;">
                    ${ackBadge}
                </div>
            </div>
            <div style="margin-top:0.3rem; font-size:0.9em;">${escapeHtml(a.message)}</div>
            <div style="margin-top:0.2rem; font-size:0.8em; color:var(--text-muted);">
                Created: ${created}${occurrences > 1 ? ` · Last seen: ${lastSeen}` : ''}${a.rule_id ? ` · Rule #${a.rule_id}` : ''}
            </div>
        </div>`;
    }).join('');
}

window.bulkAcknowledgeAlerts = async function(alertIds) {
    try {
        const result = await api.bulkAcknowledgeAlerts(alertIds);
        showSuccess(`${result.acknowledged} alert(s) acknowledged`);
        loadMonitoring();
    } catch (e) {
        showError(e.message);
    }
};

window.switchMonitoringTab = function(tab) {
    listViewState.monitoring.tab = tab;
    document.querySelectorAll('.mon-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-mon-tab') === tab));
    document.querySelectorAll('.monitoring-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`monitoring-tab-${tab}`);
    if (target) target.style.display = '';

    if (tab === 'routes' && !document.getElementById('monitoring-routes-list')?.dataset.loaded) {
        loadMonitoringRouteChurn();
    }
    if (tab === 'rules') loadMonitoringRules();
    if (tab === 'suppressions') loadMonitoringSuppressions();
    if (tab === 'sla') { loadSla(); loadAvailability(); }
    if (tab === 'capacity') loadCapacityPlanning();
};

async function loadMonitoringRouteChurn() {
    const container = document.getElementById('monitoring-routes-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        // Get latest polls that have route data
        const polls = listViewState.monitoring.polls.filter(p => p.route_count > 0);
        if (!polls.length) {
            container.innerHTML = emptyStateHTML('No route data collected', 'monitoring', '');
            container.dataset.loaded = '1';
            return;
        }
        // For each host with routes, get the last 2 route snapshots
        const routeAlerts = (listViewState.monitoring.alerts || []).filter(a => a.metric === 'route_churn');
        if (!routeAlerts.length) {
            container.innerHTML = `<div class="card" style="padding:1rem;">
                <p style="color:var(--text-muted);">No route churn events detected. Routes are stable across ${polls.length} monitored device(s).</p>
                <p style="color:var(--text-muted); font-size:0.85em;">Route churn alerts are generated when the route table changes between polling cycles.</p>
            </div>`;
        } else {
            container.innerHTML = routeAlerts.map(a => {
                const created = a.created_at ? new Date(a.created_at + 'Z').toLocaleString() : '-';
                return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; border-left:3px solid var(--warning);">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <strong>${escapeHtml(a.hostname || '')}</strong>
                            <span style="color:var(--text-muted); margin-left:0.5rem; font-size:0.85em;">${escapeHtml(a.ip_address || '')}</span>
                        </div>
                        <button class="btn btn-sm btn-secondary" onclick="showRouteSnapshotHistory(${a.host_id}, '${escapeHtml(a.hostname || '')}')">View History</button>
                    </div>
                    <div style="margin-top:0.3rem; font-size:0.9em;">${escapeHtml(a.message)}</div>
                    <div style="margin-top:0.2rem; font-size:0.8em; color:var(--text-muted);">${created}</div>
                </div>`;
            }).join('');
        }
        container.dataset.loaded = '1';
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.acknowledgeMonitoringAlert = async function(alertId) {
    try {
        await api.acknowledgeMonitoringAlert(alertId);
        showSuccess('Alert acknowledged');
        loadMonitoring();
    } catch (e) {
        showError(e.message);
    }
};

window.runMonitoringPollNow = async function() {
    const btn = document.getElementById('poll-now-btn');
    const progressEl = document.getElementById('poll-progress');
    const progressBar = document.getElementById('poll-progress-bar');
    const progressCount = document.getElementById('poll-progress-count');
    const progressTitle = document.getElementById('poll-progress-title');
    const progressLog = document.getElementById('poll-progress-log');

    if (btn) { btn.disabled = true; btn.textContent = 'Polling...'; }
    if (progressEl) progressEl.style.display = '';
    if (progressBar) progressBar.style.width = '0%';
    if (progressCount) progressCount.textContent = '';
    if (progressTitle) progressTitle.textContent = 'Starting poll...';
    if (progressLog) progressLog.innerHTML = '';

    try {
        await api.runMonitoringPollStream(function(event) {
            if (event.type === 'start') {
                const total = event.total_hosts;
                if (progressTitle) progressTitle.textContent = `Polling ${total} device${total !== 1 ? 's' : ''}...`;
                if (progressCount) progressCount.textContent = `0 / ${total}`;
            } else if (event.type === 'host_done') {
                const pct = Math.round((event.completed / event.total_hosts) * 100);
                if (progressBar) progressBar.style.width = pct + '%';
                if (progressCount) progressCount.textContent = `${event.completed} / ${event.total_hosts}`;
                const statusIcon = event.status === 'ok' ? '&#10003;' : '&#9888;';
                const statusColor = event.status === 'ok' ? 'var(--success)' : 'var(--warning)';
                const details = [];
                if (event.cpu != null) details.push(`CPU ${event.cpu}%`);
                if (event.memory != null) details.push(`Mem ${event.memory}%`);
                if (event.alerts > 0) details.push(`<span style="color:var(--danger);">${event.alerts} alert${event.alerts !== 1 ? 's' : ''}</span>`);
                const detailStr = details.length ? ` — ${details.join(', ')}` : '';
                if (progressLog) {
                    progressLog.innerHTML += `<div><span style="color:${statusColor};">${statusIcon}</span> ${escapeHtml(event.hostname)}${detailStr}</div>`;
                    progressLog.scrollTop = progressLog.scrollHeight;
                }
            } else if (event.type === 'host_error') {
                const pct = Math.round((event.completed / event.total_hosts) * 100);
                if (progressBar) progressBar.style.width = pct + '%';
                if (progressCount) progressCount.textContent = `${event.completed} / ${event.total_hosts}`;
                if (progressLog) {
                    progressLog.innerHTML += `<div><span style="color:var(--danger);">&#10007;</span> ${escapeHtml(event.hostname)} — <span style="color:var(--danger);">error</span></div>`;
                    progressLog.scrollTop = progressLog.scrollHeight;
                }
            } else if (event.type === 'done') {
                if (progressBar) progressBar.style.width = '100%';
                if (progressTitle) progressTitle.textContent = 'Poll complete';
                showSuccess(`Poll complete: ${event.hosts_polled} hosts polled, ${event.alerts_created} alerts, ${event.errors} errors`);
                loadMonitoring();
                // Auto-hide progress after a delay
                setTimeout(() => { if (progressEl) progressEl.style.display = 'none'; }, 8000);
            }
        });
    } catch (e) {
        if (e.name === 'AbortError') return; // navigated away — silently cancel
        showError(e.message);
        if (progressTitle) progressTitle.textContent = 'Poll failed';
        if (progressBar) progressBar.style.background = 'var(--danger)';
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Poll Now'; }
    }
};

window.refreshMonitoring = function() { loadMonitoring(); };

window.filterMonitoringAlerts = function() {
    renderMonitoringAlerts(listViewState.monitoring.alerts);
};

window.showMonitoringHostDetail = async function(hostId) {
    try {
        const polls = listViewState.monitoring.polls;
        const poll = polls.find(p => p.host_id === hostId);
        if (!poll) { showError('No poll data for this host'); return; }

        let ifDetails = [];
        try { ifDetails = JSON.parse(poll.if_details || '[]'); } catch (e) { /* ignore */ }
        let vpnDetails = [];
        try { vpnDetails = JSON.parse(poll.vpn_details || '[]'); } catch (e) { /* ignore */ }

        const ifTable = ifDetails.length ? `
            <h4 style="margin-top:1rem;">Interfaces (${ifDetails.length})</h4>
            <div style="max-height:300px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Name</th>
                    <th style="text-align:left; padding:4px 8px;">Status</th>
                    <th style="text-align:right; padding:4px 8px;">Speed</th>
                    <th style="text-align:right; padding:4px 8px;">In Octets</th>
                    <th style="text-align:right; padding:4px 8px;">Out Octets</th>
                </tr>
                ${ifDetails.map(i => {
                    const sColor = i.status === 'up' ? 'success' : (i.status === 'admin_down' ? 'text-muted' : 'danger');
                    return `<tr style="border-bottom:1px solid var(--border-color);">
                        <td style="padding:4px 8px;">${escapeHtml(i.name)}</td>
                        <td style="padding:4px 8px; color:var(--${sColor});">${i.status}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.speed_mbps ? i.speed_mbps + ' Mbps' : '-'}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.in_octets?.toLocaleString() || '0'}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.out_octets?.toLocaleString() || '0'}</td>
                    </tr>`;
                }).join('')}
            </table>
            </div>` : '<p style="color:var(--text-muted);">No interface data available.</p>';

        const vpnTable = vpnDetails.length ? `
            <h4 style="margin-top:1rem;">VPN Tunnels (${vpnDetails.length})</h4>
            <div style="max-height:200px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Peer</th>
                    <th style="text-align:left; padding:4px 8px;">Status</th>
                </tr>
                ${vpnDetails.map(v => {
                    const vColor = v.status === 'up' ? 'success' : 'danger';
                    return `<tr style="border-bottom:1px solid var(--border-color);">
                        <td style="padding:4px 8px;">${escapeHtml(v.peer || '')}</td>
                        <td style="padding:4px 8px; color:var(--${vColor});">${v.status}</td>
                    </tr>`;
                }).join('')}
            </table>
            </div>` : '<p style="color:var(--text-muted);">No VPN data available.</p>';

        const uptime = poll.uptime_seconds != null ? formatUptime(poll.uptime_seconds) : 'N/A';
        const polled = poll.polled_at ? new Date(poll.polled_at + 'Z').toLocaleString() : '-';

        showModal(`${escapeHtml(poll.hostname || 'Device')} - Monitoring Detail`, `
            <div style="display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1rem;">
                <div><strong>CPU:</strong> ${poll.cpu_percent != null ? poll.cpu_percent + '%' : 'N/A'}</div>
                <div><strong>Memory:</strong> ${poll.memory_percent != null ? poll.memory_percent + '%' : 'N/A'}${poll.memory_used_mb != null ? ` (${poll.memory_used_mb}/${poll.memory_total_mb} MB)` : ''}</div>
                <div><strong>Uptime:</strong> ${uptime}</div>
                <div><strong>Routes:</strong> ${poll.route_count}</div>
                <div><strong>Last Poll:</strong> ${polled}</div>
            </div>
            ${poll.poll_status === 'error' ? `<div style="color:var(--danger); margin-bottom:0.5rem;">Poll Error: ${escapeHtml(poll.poll_error || '')}</div>` : ''}
            ${ifTable}
            ${vpnTable}
        `);
    } catch (e) {
        showError(e.message);
    }
};

window.showMonitoringHostHistory = async function(hostId, hostname) {
    try {
        const history = await api.getMonitoringPollHistory(hostId, 50);
        if (!history.length) { showError('No history available'); return; }

        const rows = history.map(p => {
            const ts = p.polled_at ? new Date(p.polled_at + 'Z').toLocaleString() : '-';
            return `<tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:4px 8px; font-size:0.85em;">${ts}</td>
                <td style="padding:4px 8px; text-align:right;">${p.cpu_percent != null ? p.cpu_percent + '%' : '-'}</td>
                <td style="padding:4px 8px; text-align:right;">${p.memory_percent != null ? p.memory_percent + '%' : '-'}</td>
                <td style="padding:4px 8px; text-align:center;">${p.if_up_count}/${p.if_down_count}</td>
                <td style="padding:4px 8px; text-align:center;">${p.vpn_tunnels_up}/${p.vpn_tunnels_down}</td>
                <td style="padding:4px 8px; text-align:right;">${p.route_count}</td>
                <td style="padding:4px 8px; text-align:center;">${p.poll_status === 'error' ? '<span style="color:var(--danger);">err</span>' : '<span style="color:var(--success);">ok</span>'}</td>
            </tr>`;
        }).join('');

        showModal(`${escapeHtml(hostname)} - Poll History`, `
            <div style="max-height:400px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:2px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Time</th>
                    <th style="text-align:right; padding:4px 8px;">CPU</th>
                    <th style="text-align:right; padding:4px 8px;">Memory</th>
                    <th style="text-align:center; padding:4px 8px;">IF Up/Down</th>
                    <th style="text-align:center; padding:4px 8px;">VPN Up/Down</th>
                    <th style="text-align:right; padding:4px 8px;">Routes</th>
                    <th style="text-align:center; padding:4px 8px;">Status</th>
                </tr>
                ${rows}
            </table>
            </div>
        `);
    } catch (e) {
        showError(e.message);
    }
};

window.showRouteSnapshotHistory = async function(hostId, hostname) {
    try {
        const snapshots = await api.getMonitoringRouteSnapshots(hostId, 10);
        if (!snapshots.length) { showError('No route snapshots available'); return; }

        const items = snapshots.map((s, i) => {
            const ts = s.captured_at ? new Date(s.captured_at + 'Z').toLocaleString() : '-';
            const prev = snapshots[i + 1];
            const delta = prev ? s.route_count - prev.route_count : 0;
            const deltaStr = delta > 0 ? `<span style="color:var(--success);">+${delta}</span>` : (delta < 0 ? `<span style="color:var(--danger);">${delta}</span>` : '<span style="color:var(--text-muted);">0</span>');
            return `<div class="card" style="margin-bottom:0.5rem; padding:0.5rem 0.75rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span style="font-size:0.85em; color:var(--text-muted);">${ts}</span>
                        <span style="margin-left:0.75rem;">Routes: <strong>${s.route_count}</strong></span>
                        <span style="margin-left:0.5rem; font-size:0.85em;">Delta: ${deltaStr}</span>
                    </div>
                    <button class="btn btn-sm btn-secondary" data-routes="${btoa(encodeURIComponent(s.routes_text || ''))}" onclick="showRouteSnapshotDetail(decodeURIComponent(atob(this.dataset.routes)), '${ts}')">View</button>
                </div>
            </div>`;
        }).join('');

        showModal(`${escapeHtml(hostname)} - Route Snapshots`, `<div style="max-height:400px; overflow:auto;">${items}</div>`);
    } catch (e) {
        showError(e.message);
    }
};

window.showRouteSnapshotDetail = function(routesText, timestamp) {
    showModal(`Route Table - ${timestamp}`, copyableCodeBlock(routesText));
    initCopyableBlocks();
};

// -- Alert Rules Management ---------------------------------------------------

async function loadMonitoringRules() {
    const container = document.getElementById('monitoring-rules-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        const rules = await api.getAlertRules();
        if (!rules.length) {
            container.innerHTML = emptyStateHTML('No alert rules defined', 'monitoring',
                '<button class="btn btn-primary btn-sm" onclick="showCreateAlertRuleModal()">Create First Rule</button>');
            return;
        }
        container.innerHTML = rules.map(r => {
            const sevColors = { critical: 'danger', warning: 'warning', info: 'primary' };
            const sevColor = sevColors[r.severity] || 'text-muted';
            const scope = r.hostname ? `Host: ${escapeHtml(r.hostname)}` : (r.group_name ? `Group: ${escapeHtml(r.group_name)}` : 'All hosts');
            const escalation = r.escalate_after_minutes > 0
                ? `<span style="font-size:0.8em; color:var(--text-muted);">Escalate to ${escapeHtml(r.escalate_to)} after ${r.escalate_after_minutes}m</span>`
                : '';
            return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; opacity:${r.enabled ? 1 : 0.5};">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                    <div>
                        <span class="badge" style="background:var(--${sevColor}); color:white; font-size:0.75em; padding:2px 8px; border-radius:3px; text-transform:uppercase;">${escapeHtml(r.severity)}</span>
                        <strong style="margin-left:0.4rem;">${escapeHtml(r.name || 'Unnamed')}</strong>
                        <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.5rem;">${escapeHtml(r.metric)} ${escapeHtml(r.operator)} ${r.value}</span>
                        ${!r.enabled ? '<span style="color:var(--text-muted); font-size:0.75em; margin-left:0.3rem;">(disabled)</span>' : ''}
                    </div>
                    <div style="display:flex; gap:0.4rem;">
                        <button class="btn btn-sm btn-secondary" onclick="toggleAlertRule(${r.id}, ${r.enabled ? 0 : 1})">${r.enabled ? 'Disable' : 'Enable'}</button>
                        <button class="btn btn-sm" style="color:var(--danger);" onclick="confirmDeleteAlertRule(${r.id}, '${escapeHtml(r.name || '')}')">Delete</button>
                    </div>
                </div>
                <div style="margin-top:0.3rem; font-size:0.85em; color:var(--text-muted);">
                    ${scope} · Cooldown: ${r.cooldown_minutes}m ${escalation ? '· ' + escalation : ''}
                    ${r.description ? `<br>${escapeHtml(r.description)}` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.showCreateAlertRuleModal = async function() {
    let groups = [], hosts = [];
    try {
        const inv = await api.getInventoryGroups(true);
        groups = inv || [];
        hosts = groups.flatMap(g => (g.hosts || []).map(h => ({ ...h, group_name: g.name })));
    } catch (e) { /* ignore */ }

    const groupOpts = `<option value="">All Groups</option>` + groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const hostOpts = `<option value="">All Hosts</option>` + hosts.map(h => `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`).join('');

    showModal('Create Alert Rule', `
        <label class="form-label">Rule Name</label>
        <input type="text" class="form-input" id="ar-name" placeholder="e.g. High CPU Warning" required>
        <label class="form-label" style="margin-top:0.75rem;">Metric</label>
        <select id="ar-metric" class="form-select">
            <option value="cpu">CPU %</option>
            <option value="memory">Memory %</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Tunnels Down</option>
            <option value="route_count">Route Count</option>
            <option value="uptime">Uptime (seconds)</option>
        </select>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Operator</label>
                <select id="ar-operator" class="form-select">
                    <option value=">=">>= (greater or equal)</option>
                    <option value=">">  > (greater)</option>
                    <option value="<="><= (less or equal)</option>
                    <option value="<">  < (less)</option>
                </select>
            </div>
            <div style="flex:1;">
                <label class="form-label">Value</label>
                <input type="number" class="form-input" id="ar-value" value="90" step="0.1">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Severity</label>
        <select id="ar-severity" class="form-select">
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
        </select>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Cooldown (minutes)</label>
                <input type="number" class="form-input" id="ar-cooldown" value="15" min="1" max="1440">
            </div>
            <div style="flex:1;">
                <label class="form-label">Escalate After (min, 0=off)</label>
                <input type="number" class="form-input" id="ar-escalate-after" value="0" min="0" max="1440">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Scope: Group</label>
        <select id="ar-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.5rem;">Scope: Host (overrides group)</label>
        <select id="ar-host" class="form-select">${hostOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Description</label>
        <textarea class="form-input" id="ar-description" rows="2" placeholder="Optional description..."></textarea>
        <button class="btn btn-primary" style="margin-top:1rem; width:100%;" onclick="submitCreateAlertRule()">Create Rule</button>
    `);
};

window.submitCreateAlertRule = async function() {
    try {
        const data = {
            name: document.getElementById('ar-name').value,
            metric: document.getElementById('ar-metric').value,
            operator: document.getElementById('ar-operator').value,
            value: parseFloat(document.getElementById('ar-value').value) || 0,
            severity: document.getElementById('ar-severity').value,
            cooldown_minutes: parseInt(document.getElementById('ar-cooldown').value) || 15,
            escalate_after_minutes: parseInt(document.getElementById('ar-escalate-after').value) || 0,
            escalate_to: 'critical',
            description: document.getElementById('ar-description').value,
        };
        const hostId = document.getElementById('ar-host').value;
        const groupId = document.getElementById('ar-group').value;
        if (hostId) data.host_id = parseInt(hostId);
        else if (groupId) data.group_id = parseInt(groupId);

        await api.createAlertRule(data);
        closeModal();
        showSuccess('Alert rule created');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

window.toggleAlertRule = async function(ruleId, enabled) {
    try {
        await api.updateAlertRule(ruleId, { enabled });
        showSuccess(enabled ? 'Rule enabled' : 'Rule disabled');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

window.confirmDeleteAlertRule = function(ruleId, name) {
    showModal('Delete Rule', `
        <p>Delete rule <strong>${escapeHtml(name)}</strong>?</p>
        <div style="display:flex; gap:0.5rem; margin-top:1rem;">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn" style="background:var(--danger); color:white;" onclick="deleteAlertRuleConfirmed(${ruleId})">Delete</button>
        </div>
    `);
};

window.deleteAlertRuleConfirmed = async function(ruleId) {
    try {
        await api.deleteAlertRule(ruleId);
        closeModal();
        showSuccess('Rule deleted');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

// -- Alert Suppressions Management --------------------------------------------

async function loadMonitoringSuppressions() {
    const container = document.getElementById('monitoring-suppressions-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        const suppressions = await api.getAlertSuppressions();
        if (!suppressions.length) {
            container.innerHTML = emptyStateHTML('No suppressions', 'monitoring',
                '<button class="btn btn-primary btn-sm" onclick="showCreateSuppressionModal()">Create Suppression</button>');
            return;
        }
        const now = new Date();
        container.innerHTML = suppressions.map(s => {
            const ends = new Date(s.ends_at + 'Z');
            const isActive = ends > now && new Date(s.starts_at + 'Z') <= now;
            const statusColor = isActive ? 'success' : 'text-muted';
            const statusLabel = isActive ? 'Active' : (ends <= now ? 'Expired' : 'Scheduled');
            const scope = s.hostname ? `Host: ${escapeHtml(s.hostname)}` : (s.group_name ? `Group: ${escapeHtml(s.group_name)}` : 'Global');
            const metricLabel = s.metric ? `Metric: ${escapeHtml(s.metric)}` : 'All metrics';
            const startsStr = s.starts_at ? new Date(s.starts_at + 'Z').toLocaleString() : '-';
            const endsStr = s.ends_at ? new Date(s.ends_at + 'Z').toLocaleString() : '-';

            return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; opacity:${isActive ? 1 : 0.5};">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                    <div>
                        <span style="color:var(--${statusColor}); font-size:0.8em; font-weight:600; text-transform:uppercase;">${statusLabel}</span>
                        <strong style="margin-left:0.4rem;">${escapeHtml(s.name || 'Unnamed')}</strong>
                        <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.5rem;">${scope} · ${metricLabel}</span>
                    </div>
                    <button class="btn btn-sm" style="color:var(--danger);" onclick="confirmDeleteSuppression(${s.id}, '${escapeHtml(s.name || '')}')">Delete</button>
                </div>
                <div style="margin-top:0.3rem; font-size:0.85em; color:var(--text-muted);">
                    ${startsStr} — ${endsStr}${s.reason ? ` · Reason: ${escapeHtml(s.reason)}` : ''}${s.created_by ? ` · By ${escapeHtml(s.created_by)}` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.showCreateSuppressionModal = async function() {
    let groups = [], hosts = [];
    try {
        const inv = await api.getInventoryGroups(true);
        groups = inv || [];
        hosts = groups.flatMap(g => (g.hosts || []).map(h => ({ ...h, group_name: g.name })));
    } catch (e) { /* ignore */ }

    const groupOpts = `<option value="">All Groups</option>` + groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const hostOpts = `<option value="">All Hosts</option>` + hosts.map(h => `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`).join('');

    // Default: 2 hours from now
    const now = new Date();
    const endsDefault = new Date(now.getTime() + 2 * 3600000);
    const toLocal = d => d.toISOString().slice(0, 16);

    showModal('Create Alert Suppression', `
        <label class="form-label">Name</label>
        <input type="text" class="form-input" id="sup-name" placeholder="e.g. Maintenance Window - Switch Upgrade" required>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Starts At</label>
                <input type="datetime-local" class="form-input" id="sup-starts" value="${toLocal(now)}">
            </div>
            <div style="flex:1;">
                <label class="form-label">Ends At</label>
                <input type="datetime-local" class="form-input" id="sup-ends" value="${toLocal(endsDefault)}">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Scope: Group</label>
        <select id="sup-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.5rem;">Scope: Host (overrides group)</label>
        <select id="sup-host" class="form-select">${hostOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Metric (blank = all metrics)</label>
        <select id="sup-metric" class="form-select">
            <option value="">All Metrics</option>
            <option value="cpu">CPU</option>
            <option value="memory">Memory</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Down</option>
            <option value="route_churn">Route Churn</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Reason</label>
        <textarea class="form-input" id="sup-reason" rows="2" placeholder="Optional reason..."></textarea>
        <button class="btn btn-primary" style="margin-top:1rem; width:100%;" onclick="submitCreateSuppression()">Create Suppression</button>
    `);
};

window.submitCreateSuppression = async function() {
    try {
        const startsVal = document.getElementById('sup-starts').value;
        const endsVal = document.getElementById('sup-ends').value;
        if (!endsVal) { showError('End time is required'); return; }

        const data = {
            name: document.getElementById('sup-name').value,
            starts_at: startsVal ? new Date(startsVal).toISOString().replace('T', ' ').slice(0, 19) : '',
            ends_at: new Date(endsVal).toISOString().replace('T', ' ').slice(0, 19),
            metric: document.getElementById('sup-metric').value,
            reason: document.getElementById('sup-reason').value,
        };
        const hostId = document.getElementById('sup-host').value;
        const groupId = document.getElementById('sup-group').value;
        if (hostId) data.host_id = parseInt(hostId);
        else if (groupId) data.group_id = parseInt(groupId);

        await api.createAlertSuppression(data);
        closeModal();
        showSuccess('Suppression created');
        loadMonitoringSuppressions();
    } catch (e) {
        showError(e.message);
    }
};

window.confirmDeleteSuppression = function(supId, name) {
    showModal('Delete Suppression', `
        <p>Delete suppression <strong>${escapeHtml(name)}</strong>?</p>
        <div style="display:flex; gap:0.5rem; margin-top:1rem;">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn" style="background:var(--danger); color:white;" onclick="deleteSuppressionConfirmed(${supId})">Delete</button>
        </div>
    `);
};

window.deleteSuppressionConfirmed = async function(supId) {
    try {
        await api.deleteAlertSuppression(supId);
        closeModal();
        showSuccess('Suppression deleted');
        loadMonitoringSuppressions();
    } catch (e) {
        showError(e.message);
    }
};

// Wire up monitoring search
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('monitoring-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            listViewState.monitoring.query = searchInput.value;
            const tab = listViewState.monitoring.tab;
            if (tab === 'devices') renderMonitoringDevices(listViewState.monitoring.polls);
            else if (tab === 'alerts') renderMonitoringAlerts(listViewState.monitoring.alerts);
        }, 200));
    }
});


// =============================================================================
// SLA Dashboards
// =============================================================================

async function loadSla(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('sla-hosts-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const [summary, targets] = await Promise.all([
            api.getSlaSummary(null, days),
            api.getSlaTargets(),
        ]);
        listViewState.sla.summary = summary;
        listViewState.sla.targets = targets || [];
        renderSlaSummary(summary);
        renderSlaHosts(summary.hosts || [], targets || []);
        renderSlaIncidents(summary);
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading SLA data: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadSla = loadSla;

function renderSlaSummary(s) {
    const CIRC = 2 * Math.PI * 52; // ~326.73

    // Uptime gauge
    const uptimeVal = s.avg_uptime_pct != null ? s.avg_uptime_pct : 0;
    const uptimeFill = document.getElementById('sla-gauge-uptime-fill');
    if (uptimeFill) {
        const pct = Math.min(uptimeVal, 100) / 100;
        uptimeFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
        uptimeFill.classList.remove('sla-gauge-warn', 'sla-gauge-danger');
        if (uptimeVal < 99) uptimeFill.classList.add('sla-gauge-danger');
        else if (uptimeVal < 99.9) uptimeFill.classList.add('sla-gauge-warn');
    }
    const uptimeEl = document.getElementById('sla-val-uptime');
    if (uptimeEl) uptimeEl.textContent = s.avg_uptime_pct != null ? s.avg_uptime_pct.toFixed(2) + '%' : '-';

    // Latency gauge (scale: 0-500ms maps to full circle)
    const latVal = s.avg_latency_ms != null ? s.avg_latency_ms : 0;
    const latFill = document.getElementById('sla-gauge-latency-fill');
    if (latFill) {
        const pct = Math.min(latVal / 500, 1);
        latFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const latEl = document.getElementById('sla-val-latency');
    if (latEl) latEl.textContent = s.avg_latency_ms != null ? s.avg_latency_ms.toFixed(1) + 'ms' : '-';

    // Jitter gauge (scale: 0-100ms)
    const jitVal = s.avg_jitter_ms != null ? s.avg_jitter_ms : 0;
    const jitFill = document.getElementById('sla-gauge-jitter-fill');
    if (jitFill) {
        const pct = Math.min(jitVal / 100, 1);
        jitFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const jitEl = document.getElementById('sla-val-jitter');
    if (jitEl) jitEl.textContent = s.avg_jitter_ms != null ? s.avg_jitter_ms.toFixed(1) + 'ms' : '-';

    // Packet loss gauge (scale: 0-100%)
    const pktVal = s.avg_packet_loss_pct != null ? s.avg_packet_loss_pct : 0;
    const pktFill = document.getElementById('sla-gauge-pktloss-fill');
    if (pktFill) {
        const pct = Math.min(pktVal / 100, 1);
        pktFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const pktEl = document.getElementById('sla-val-pktloss');
    if (pktEl) pktEl.textContent = s.avg_packet_loss_pct != null ? s.avg_packet_loss_pct.toFixed(2) + '%' : '-';

    // MTTR / MTTD
    const mttrEl = document.getElementById('sla-val-mttr');
    if (mttrEl) mttrEl.textContent = s.mttr_minutes != null ? formatMinutes(s.mttr_minutes) : '-';
    const mttdEl = document.getElementById('sla-val-mttd');
    if (mttdEl) mttdEl.textContent = s.mttd_minutes != null ? formatMinutes(s.mttd_minutes) : '-';
}

function renderSlaHosts(hosts, targets) {
    const container = document.getElementById('sla-hosts-list');
    if (!container) return;
    const query = (listViewState.sla.query || '').toLowerCase();
    const filtered = hosts.filter(h => {
        if (query && !(h.hostname || '').toLowerCase().includes(query)
            && !(h.ip_address || '').toLowerCase().includes(query)) return false;
        return true;
    });

    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No SLA data available', 'sla',
            '<p style="color:var(--text-muted); font-size:0.9em;">SLA metrics are computed from monitoring polls. Enable monitoring and run polls to see data.</p>');
        return;
    }

    const header = `<div class="card" style="padding:0; overflow:hidden;">
        <div class="sla-host-row sla-host-header">
            <div>Host</div>
            <div>Uptime</div>
            <div>Latency</div>
            <div>Jitter</div>
            <div>Pkt Loss</div>
            <div>Status</div>
        </div>`;

    const rows = filtered.map(h => {
        const compliance = getHostSlaCompliance(h, targets);
        const uptimeColor = h.uptime_pct >= 99.9 ? 'success' : h.uptime_pct >= 99 ? 'warning' : 'danger';
        const badgeClass = compliance.status === 'met' ? 'met' : compliance.status === 'warn' ? 'warn' : compliance.status === 'breach' ? 'breach' : 'met';
        const badgeLabel = compliance.status === 'none' ? 'No Target' : compliance.status === 'met' ? 'Met' : compliance.status === 'warn' ? 'Warning' : 'Breach';

        return `<div class="sla-host-row" onclick="showSlaHostDetail(${h.host_id})">
            <div>
                <strong>${escapeHtml(h.hostname || 'Unknown')}</strong>
                <span style="color:var(--text-muted); font-size:0.8em; margin-left:0.4rem;">${escapeHtml(h.ip_address || '')}</span>
            </div>
            <div style="color:var(--${uptimeColor}); font-weight:600;">${h.uptime_pct != null ? h.uptime_pct.toFixed(2) + '%' : '-'}</div>
            <div>${h.avg_latency_ms != null ? h.avg_latency_ms.toFixed(1) + 'ms' : '-'}</div>
            <div>${h.jitter_ms != null ? h.jitter_ms.toFixed(1) + 'ms' : '-'}</div>
            <div>${h.avg_packet_loss_pct != null ? h.avg_packet_loss_pct.toFixed(2) + '%' : '-'}</div>
            <div><span class="sla-compliance-badge ${badgeClass}">${badgeLabel}</span></div>
        </div>`;
    }).join('');

    container.innerHTML = header + rows + '</div>';
}

function renderSlaIncidents(summary) {
    const container = document.getElementById('sla-incidents-list');
    if (!container) return;

    const alerts_info = {
        total: summary.total_alerts || 0,
        resolved: summary.resolved_alerts || 0,
        mttr: summary.mttr_minutes,
        mttd: summary.mttd_minutes,
    };

    // Show incident stats
    const open = alerts_info.total - alerts_info.resolved;
    container.innerHTML = `<div class="card" style="padding:1rem;">
        <div style="display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1rem;">
            <div><span style="color:var(--text-muted);">Total Alerts:</span> <strong>${alerts_info.total}</strong></div>
            <div><span style="color:var(--text-muted);">Resolved:</span> <strong style="color:var(--success);">${alerts_info.resolved}</strong></div>
            <div><span style="color:var(--text-muted);">Open:</span> <strong style="color:${open > 0 ? 'var(--danger)' : 'var(--success)'};">${open}</strong></div>
            <div><span style="color:var(--text-muted);">Avg MTTR:</span> <strong>${alerts_info.mttr != null ? formatMinutes(alerts_info.mttr) : '-'}</strong></div>
            <div><span style="color:var(--text-muted);">Avg MTTD:</span> <strong>${alerts_info.mttd != null ? formatMinutes(alerts_info.mttd) : '-'}</strong></div>
        </div>
        <div style="font-size:0.85em; color:var(--text-muted);">
            <p><strong>MTTR</strong> (Mean Time To Repair): Average time from alert creation to acknowledgement.</p>
            <p><strong>MTTD</strong> (Mean Time To Detect): Average time from first failure to alert creation.</p>
        </div>
    </div>`;
}

function switchSlaTab(tab) {
    listViewState.sla.tab = tab;
    document.querySelectorAll('.sla-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-sla-tab') === tab));
    document.querySelectorAll('.sla-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`sla-tab-${tab}`);
    if (target) target.style.display = '';

    if (tab === 'trends') loadSlaTrends();
    if (tab === 'targets') loadSlaTargets();
    if (tab === 'availability') loadAvailability();
}
window.switchSlaTab = switchSlaTab;

// -- SLA Trends (SVG charts) --------------------------------------------------

async function loadSlaTrends() {
    const container = document.getElementById('sla-trends-container');
    if (!container) return;
    container.innerHTML = '<div class="skeleton skeleton-card" style="height:300px;"></div>';

    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const summary = listViewState.sla.summary;
        if (!summary || !summary.hosts || !summary.hosts.length) {
            container.innerHTML = '<div class="card" style="padding:1rem; color:var(--text-muted);">No trend data available. Run monitoring polls to collect SLA metrics.</div>';
            return;
        }

        // Get detailed daily data for first host (or aggregate)
        // Use first host with data for detailed trend
        const hostId = summary.hosts[0].host_id;
        const detail = await api.getSlaHostDetail(hostId, days);

        let html = '';
        if (detail.daily && detail.daily.length) {
            html += renderSlaChart(detail.daily, 'uptime_pct', 'Uptime %', 'var(--success)', 95, 100);
            html += renderSlaChart(detail.daily, 'avg_latency_ms', 'Latency (ms)', 'var(--primary)', 0, null);
            html += renderSlaChart(detail.daily, 'jitter_ms', 'Jitter (ms)', 'var(--warning)', 0, null);
            html += renderSlaChart(detail.daily, 'avg_packet_loss_pct', 'Packet Loss %', 'var(--danger)', 0, null);
        }
        html += `<div style="font-size:0.8em; color:var(--text-muted); margin-top:0.5rem;">
            Showing trends for <strong>${escapeHtml(detail.hostname || 'Host #' + hostId)}</strong>.
            Click a host in the Host SLAs tab to view its specific trends.
        </div>`;
        container.innerHTML = html;
    } catch (error) {
        container.innerHTML = `<div class="card" style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}

function renderSlaChart(daily, field, label, color, minY, maxY) {
    if (!daily || !daily.length) return '';

    const values = daily.map(d => d[field]).filter(v => v != null);
    if (!values.length) return `<div class="card" style="padding:1rem;"><div class="sla-chart-label">${escapeHtml(label)}</div><div style="color:var(--text-muted); font-size:0.9em;">No data</div></div>`;

    const W = 700, H = 200, PAD_L = 55, PAD_R = 20, PAD_T = 30, PAD_B = 35;
    const chartW = W - PAD_L - PAD_R;
    const chartH = H - PAD_T - PAD_B;

    const dataMin = Math.min(...values);
    const dataMax = Math.max(...values);
    const yMin = minY != null ? Math.min(minY, dataMin) : dataMin - (dataMax - dataMin) * 0.1;
    const yMax = maxY != null ? Math.max(maxY, dataMax) : dataMax + (dataMax - dataMin) * 0.1 || 1;
    const yRange = yMax - yMin || 1;

    const points = daily.map((d, i) => {
        const v = d[field];
        if (v == null) return null;
        const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
        const y = PAD_T + chartH - ((v - yMin) / yRange) * chartH;
        return { x, y, v, day: d.day };
    }).filter(Boolean);

    if (!points.length) return '';

    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaPath = linePath + ` L${points[points.length - 1].x.toFixed(1)},${PAD_T + chartH} L${points[0].x.toFixed(1)},${PAD_T + chartH} Z`;

    // Grid lines (4 horizontal)
    let gridLines = '';
    for (let i = 0; i <= 4; i++) {
        const y = PAD_T + (i / 4) * chartH;
        const val = yMax - (i / 4) * yRange;
        gridLines += `<line x1="${PAD_L}" y1="${y}" x2="${W - PAD_R}" y2="${y}" class="sla-chart-grid-line"/>`;
        gridLines += `<text x="${PAD_L - 8}" y="${y + 3}" text-anchor="end" class="sla-chart-axis-label">${val.toFixed(val < 10 ? 1 : 0)}</text>`;
    }

    // X-axis labels (show ~5 labels)
    let xLabels = '';
    const step = Math.max(1, Math.floor(daily.length / 5));
    for (let i = 0; i < daily.length; i += step) {
        const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
        const d = daily[i].day || '';
        const short = d.slice(5); // MM-DD
        xLabels += `<text x="${x}" y="${H - 5}" text-anchor="middle" class="sla-chart-axis-label">${short}</text>`;
    }

    const dots = points.map(p =>
        `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" class="sla-chart-dot" stroke="${color}">
            <title>${p.day}: ${p.v.toFixed(2)}</title>
        </circle>`
    ).join('');

    return `<div class="card" style="padding:1rem; margin-bottom:1rem;">
        <div class="sla-chart-label">${escapeHtml(label)}</div>
        <div class="sla-chart-container">
            <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
                ${gridLines}
                ${xLabels}
                <path d="${areaPath}" class="sla-chart-area" fill="${color}"/>
                <path d="${linePath}" class="sla-chart-line" stroke="${color}"/>
                ${dots}
            </svg>
        </div>
    </div>`;
}

// -- SLA Host Detail Modal ----------------------------------------------------

async function showSlaHostDetail(hostId) {
    ensureModalDOM('sla-host-detail-modal', templateSlaHostDetailModal);
    const modal = document.getElementById('sla-host-detail-modal');
    const body = document.getElementById('sla-host-detail-body');
    const title = document.getElementById('sla-host-detail-title');
    if (!modal || !body) return;
    modal.style.display = 'block';
    body.innerHTML = '<div class="skeleton skeleton-card" style="height:200px;"></div>';

    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const detail = await api.getSlaHostDetail(hostId, days);
        if (title) title.textContent = `SLA Detail: ${detail.hostname || 'Host #' + hostId}`;

        let html = `<div style="display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1rem; font-size:0.9em;">
            <div><span style="color:var(--text-muted);">Host:</span> <strong>${escapeHtml(detail.hostname)}</strong></div>
            <div><span style="color:var(--text-muted);">IP:</span> ${escapeHtml(detail.ip_address)}</div>
            <div><span style="color:var(--text-muted);">Type:</span> ${escapeHtml(detail.device_type || '-')}</div>
            <div><span style="color:var(--text-muted);">Period:</span> ${detail.period_days} days</div>
            <div><span style="color:var(--text-muted);">Alerts:</span> ${detail.total_alerts} (${detail.resolved_alerts} resolved)</div>
            <div><span style="color:var(--text-muted);">MTTR:</span> ${detail.mttr_minutes != null ? formatMinutes(detail.mttr_minutes) : '-'}</div>
        </div>`;

        if (detail.daily && detail.daily.length) {
            html += renderSlaChart(detail.daily, 'uptime_pct', 'Daily Uptime %', 'var(--success)', 95, 100);
            html += renderSlaChart(detail.daily, 'avg_latency_ms', 'Daily Latency (ms)', 'var(--primary)', 0, null);
            html += renderSlaChart(detail.daily, 'jitter_ms', 'Daily Jitter (ms)', 'var(--warning)', 0, null);
            html += renderSlaChart(detail.daily, 'avg_packet_loss_pct', 'Daily Packet Loss %', 'var(--danger)', 0, null);
        } else {
            html += '<div style="color:var(--text-muted);">No daily trend data available.</div>';
        }

        body.innerHTML = html;
    } catch (error) {
        body.innerHTML = `<div style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}
window.showSlaHostDetail = showSlaHostDetail;

function closeSlaHostDetailModal() {
    const modal = document.getElementById('sla-host-detail-modal');
    if (modal) modal.style.display = 'none';
}
window.closeSlaHostDetailModal = closeSlaHostDetailModal;

// -- SLA Targets CRUD ---------------------------------------------------------

async function loadSlaTargets() {
    const container = document.getElementById('sla-targets-list');
    if (!container) return;
    container.innerHTML = skeletonCards(1);
    try {
        const targets = await api.getSlaTargets();
        listViewState.sla.targets = targets || [];
        renderSlaTargets(targets || []);
    } catch (error) {
        container.innerHTML = `<div class="card" style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}

function renderSlaTargets(targets) {
    const container = document.getElementById('sla-targets-list');
    if (!container) return;
    if (!targets.length) {
        container.innerHTML = emptyStateHTML('No SLA targets defined', 'sla',
            '<button class="btn btn-primary btn-sm" onclick="showCreateSlaTargetModal()">Create First Target</button>');
        return;
    }

    const metricLabels = { uptime: 'Uptime %', latency: 'Latency (ms)', jitter: 'Jitter (ms)', packet_loss: 'Packet Loss %' };

    container.innerHTML = targets.map(t => {
        const scope = t.host_name ? `Host: ${escapeHtml(t.host_name)}` :
                       t.group_name ? `Group: ${escapeHtml(t.group_name)}` : 'Global';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(t.name)}</strong>
                    ${!t.enabled ? '<span style="color:var(--text-muted); font-size:0.8em; margin-left:0.5rem;">(disabled)</span>' : ''}
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-secondary" onclick="editSlaTarget(${t.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSlaTarget(${t.id})">Delete</button>
                </div>
            </div>
            <div style="display:flex; gap:1.5rem; margin-top:0.5rem; font-size:0.9em; flex-wrap:wrap;">
                <div><span style="color:var(--text-muted);">Metric:</span> ${metricLabels[t.metric] || t.metric}</div>
                <div><span style="color:var(--text-muted);">Target:</span> <strong style="color:var(--success);">${t.target_value}</strong></div>
                <div><span style="color:var(--text-muted);">Warning:</span> <strong style="color:var(--warning);">${t.warning_value}</strong></div>
                <div><span style="color:var(--text-muted);">Scope:</span> ${scope}</div>
            </div>
        </div>`;
    }).join('');
}

async function showCreateSlaTargetModal(editTarget = null) {
    ensureModalDOM('sla-target-modal', templateSlaTargetModal);
    const modal = document.getElementById('sla-target-modal');
    const titleEl = document.getElementById('sla-target-modal-title');
    if (!modal) return;

    // Reset form
    document.getElementById('sla-target-edit-id').value = editTarget ? editTarget.id : '';
    document.getElementById('sla-target-name').value = editTarget ? editTarget.name : '';
    document.getElementById('sla-target-metric').value = editTarget ? editTarget.metric : 'uptime';
    document.getElementById('sla-target-value').value = editTarget ? editTarget.target_value : 99.9;
    document.getElementById('sla-target-warning').value = editTarget ? editTarget.warning_value : 99.0;

    // Scope
    const scopeSelect = document.getElementById('sla-target-scope');
    if (editTarget?.host_id) scopeSelect.value = 'host';
    else if (editTarget?.group_id) scopeSelect.value = 'group';
    else scopeSelect.value = 'global';
    toggleSlaTargetScope();

    // Populate group/host selects
    try {
        const groups = await api.getGroups();
        const groupSelect = document.getElementById('sla-target-group-id');
        groupSelect.innerHTML = groups.map(g => `<option value="${g.id}" ${editTarget?.group_id === g.id ? 'selected' : ''}>${escapeHtml(g.name)}</option>`).join('');

        // For hosts, flatten from groups
        const hostSelect = document.getElementById('sla-target-host-id');
        let hostOptions = '';
        for (const g of groups) {
            const hosts = g.hosts || [];
            for (const h of hosts) {
                hostOptions += `<option value="${h.id}" ${editTarget?.host_id === h.id ? 'selected' : ''}>${escapeHtml(h.hostname || h.ip_address)} (${escapeHtml(g.name)})</option>`;
            }
        }
        hostSelect.innerHTML = hostOptions || '<option value="">No hosts</option>';
    } catch { /* ignore populate errors */ }

    if (titleEl) titleEl.textContent = editTarget ? 'Edit SLA Target' : 'New SLA Target';
    modal.style.display = 'block';
}
window.showCreateSlaTargetModal = showCreateSlaTargetModal;

function toggleSlaTargetScope() {
    const scope = document.getElementById('sla-target-scope')?.value || 'global';
    document.getElementById('sla-target-scope-group').style.display = scope === 'group' ? '' : 'none';
    document.getElementById('sla-target-scope-host').style.display = scope === 'host' ? '' : 'none';
}
window.toggleSlaTargetScope = toggleSlaTargetScope;

function closeSlaTargetModal() {
    const modal = document.getElementById('sla-target-modal');
    if (modal) modal.style.display = 'none';
}
window.closeSlaTargetModal = closeSlaTargetModal;

async function saveSlaTarget() {
    const editId = document.getElementById('sla-target-edit-id')?.value;
    const name = document.getElementById('sla-target-name')?.value?.trim();
    const metric = document.getElementById('sla-target-metric')?.value;
    const targetValue = parseFloat(document.getElementById('sla-target-value')?.value);
    const warningValue = parseFloat(document.getElementById('sla-target-warning')?.value);
    const scope = document.getElementById('sla-target-scope')?.value || 'global';

    if (!name) { showError('Name is required'); return; }

    const data = {
        name,
        metric,
        target_value: targetValue,
        warning_value: warningValue,
        host_id: scope === 'host' ? parseInt(document.getElementById('sla-target-host-id')?.value) || null : null,
        group_id: scope === 'group' ? parseInt(document.getElementById('sla-target-group-id')?.value) || null : null,
    };

    try {
        if (editId) {
            await api.updateSlaTarget(parseInt(editId), data);
            showSuccess('SLA target updated');
        } else {
            await api.createSlaTarget(data);
            showSuccess('SLA target created');
        }
        closeSlaTargetModal();
        loadSlaTargets();
    } catch (error) {
        showError('Failed to save target: ' + error.message);
    }
}
window.saveSlaTarget = saveSlaTarget;

async function editSlaTarget(id) {
    const targets = listViewState.sla.targets || [];
    const target = targets.find(t => t.id === id);
    if (target) {
        showCreateSlaTargetModal(target);
    }
}
window.editSlaTarget = editSlaTarget;

async function deleteSlaTarget(id) {
    if (!await showConfirm({ title: 'Delete SLA Target', message: 'Delete this SLA target?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteSlaTarget(id);
        showSuccess('SLA target deleted');
        loadSlaTargets();
    } catch (error) {
        showError('Failed to delete: ' + error.message);
    }
}
window.deleteSlaTarget = deleteSlaTarget;

// Wire up SLA search
document.addEventListener('DOMContentLoaded', () => {
    const slaSearch = document.getElementById('sla-search');
    if (slaSearch) {
        slaSearch.addEventListener('input', debounce(() => {
            listViewState.sla.query = slaSearch.value;
            const summary = listViewState.sla.summary;
            if (summary && summary.hosts) {
                renderSlaHosts(summary.hosts, listViewState.sla.targets || []);
            }
        }, 200));
    }
});


// =============================================================================
// Availability Tracking
// =============================================================================

async function loadAvailability() {
    const summaryContainer = document.getElementById('availability-summary-cards');
    const hostsContainer = document.getElementById('availability-hosts-list');
    const outagesContainer = document.getElementById('availability-outages-list');
    const transitionsContainer = document.getElementById('availability-transitions-list');

    const groupId = document.getElementById('availability-group-filter')?.value || null;
    const days = parseInt(document.getElementById('availability-period')?.value || '7', 10);

    // Populate group filter on first load
    const groupFilter = document.getElementById('availability-group-filter');
    if (groupFilter && groupFilter.options.length <= 1) {
        try {
            const groups = await api.getInventoryGroups();
            (groups || []).forEach(g => {
                const opt = document.createElement('option');
                opt.value = g.id;
                opt.textContent = g.name;
                groupFilter.appendChild(opt);
            });
        } catch { /* ignore */ }
    }

    try {
        const [summary, outages, transitions] = await Promise.all([
            api.getAvailabilitySummary(groupId, days),
            api.getAvailabilityOutages({ groupId, days, limit: 200 }),
            api.getAvailabilityTransitions({ limit: 500 }),
        ]);

        // Summary cards
        if (summaryContainer) {
            const s = summary || {};
            summaryContainer.innerHTML = `
                <div class="stat-card"><div class="stat-ring-value">${s.total_hosts ?? '-'}</div><div class="stat-label">Hosts Tracked</div></div>
                <div class="stat-card"><div class="stat-ring-value" style="color:var(--success);">${s.hosts_up ?? '-'}</div><div class="stat-label">Currently Up</div></div>
                <div class="stat-card"><div class="stat-ring-value" style="color:var(--danger);">${s.hosts_down ?? '-'}</div><div class="stat-label">Currently Down</div></div>
                <div class="stat-card"><div class="stat-ring-value">${s.avg_uptime_pct != null ? s.avg_uptime_pct.toFixed(2) + '%' : '-'}</div><div class="stat-label">Avg Uptime</div></div>
                <div class="stat-card"><div class="stat-ring-value">${s.total_outages ?? '-'}</div><div class="stat-label">Outages (${days}d)</div></div>
            `;
        }

        // Host availability list
        if (hostsContainer) {
            const hosts = summary?.hosts || [];
            if (!hosts.length) {
                hostsContainer.innerHTML = emptyStateHTML('No availability data', 'monitoring', 'Run monitoring polls to begin tracking availability.');
            } else {
                hostsContainer.innerHTML = hosts.map(h => {
                    const uptimeColor = (h.uptime_pct ?? 100) >= 99.9 ? 'success' : (h.uptime_pct ?? 100) >= 99 ? 'warning' : 'danger';
                    const state = h.current_state || 'unknown';
                    const stateColor = state === 'up' ? 'success' : state === 'down' ? 'danger' : 'text-muted';
                    return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <span style="width:8px; height:8px; border-radius:50%; background:var(--${stateColor}); display:inline-block;"></span>
                                <strong style="margin-left:0.4rem;">${escapeHtml(h.hostname || 'Unknown')}</strong>
                                <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.4rem;">${escapeHtml(h.ip_address || '')}</span>
                            </div>
                            <span style="color:var(--${uptimeColor}); font-weight:600;">${h.uptime_pct != null ? h.uptime_pct.toFixed(2) + '%' : '-'}</span>
                        </div>
                    </div>`;
                }).join('');
            }
        }

        // Outages list
        const outageList = outages?.outages || [];
        if (outagesContainer) {
            if (!outageList.length) {
                outagesContainer.innerHTML = `<div class="card" style="padding:1rem; color:var(--text-muted);">No outages recorded in the last ${days} days.</div>`;
            } else {
                outagesContainer.innerHTML = outageList.map(o => {
                    const start = o.started_at ? new Date(o.started_at + 'Z').toLocaleString() : '-';
                    const end = o.ended_at ? new Date(o.ended_at + 'Z').toLocaleString() : '<span style="color:var(--danger);">Ongoing</span>';
                    const dur = o.duration_seconds ? formatUptime(o.duration_seconds) : '-';
                    return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; border-left:3px solid var(--danger);">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <strong>${escapeHtml(o.hostname || 'Unknown')}</strong>
                                <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.4rem;">${escapeHtml(o.entity_type || 'host')}${o.entity_id ? ' ' + escapeHtml(o.entity_id) : ''}</span>
                            </div>
                            <span style="font-size:0.85em; color:var(--text-muted);">Duration: <strong>${dur}</strong></span>
                        </div>
                        <div style="margin-top:0.3rem; font-size:0.85em; color:var(--text-muted);">${start} — ${end}</div>
                    </div>`;
                }).join('');
            }
        }

        // State transitions
        const transList = transitions?.transitions || [];
        if (transitionsContainer) {
            if (!transList.length) {
                transitionsContainer.innerHTML = `<div class="card" style="padding:1rem; color:var(--text-muted);">No state transitions recorded.</div>`;
            } else {
                transitionsContainer.innerHTML = `<div style="max-height:400px; overflow:auto;">
                    <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                        <tr style="border-bottom:2px solid var(--border-color);">
                            <th style="text-align:left; padding:4px 8px;">Time</th>
                            <th style="text-align:left; padding:4px 8px;">Host</th>
                            <th style="text-align:left; padding:4px 8px;">Entity</th>
                            <th style="text-align:center; padding:4px 8px;">From</th>
                            <th style="text-align:center; padding:4px 8px;">To</th>
                        </tr>
                        ${transList.slice(0, 200).map(t => {
                            const ts = t.changed_at ? new Date(t.changed_at + 'Z').toLocaleString() : '-';
                            const toColor = t.new_state === 'up' ? 'success' : t.new_state === 'down' ? 'danger' : 'text-muted';
                            const fromColor = t.old_state === 'up' ? 'success' : t.old_state === 'down' ? 'danger' : 'text-muted';
                            return `<tr style="border-bottom:1px solid var(--border-color);">
                                <td style="padding:4px 8px;">${ts}</td>
                                <td style="padding:4px 8px;">${escapeHtml(t.hostname || '')}</td>
                                <td style="padding:4px 8px;">${escapeHtml(t.entity_type || 'host')}${t.entity_id ? ' ' + escapeHtml(t.entity_id) : ''}</td>
                                <td style="padding:4px 8px; text-align:center; color:var(--${fromColor});">${escapeHtml(t.old_state || '?')}</td>
                                <td style="padding:4px 8px; text-align:center; color:var(--${toColor});">${escapeHtml(t.new_state || '?')}</td>
                            </tr>`;
                        }).join('')}
                    </table>
                </div>`;
            }
        }
    } catch (error) {
        if (hostsContainer) hostsContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadAvailability = loadAvailability;

window.switchAvailTab = function(tab) {
    document.querySelectorAll('.avail-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-avail-tab') === tab));
    document.querySelectorAll('.avail-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`avail-tab-${tab}`);
    if (target) target.style.display = '';
};

// =============================================================================
// Capacity Planning
// =============================================================================

async function loadCapacityPlanning() {
    const chartContainer = document.getElementById('cap-plan-chart-main');
    const thresholdsContainer = document.getElementById('cap-plan-thresholds');
    const emptyEl = document.getElementById('cap-plan-empty');

    const metric = document.getElementById('cap-plan-metric')?.value || 'cpu_percent';
    const range = document.getElementById('cap-plan-range')?.value || '90d';
    const groupId = document.getElementById('cap-plan-group')?.value || null;

    // Populate group filter on first load
    const groupFilter = document.getElementById('cap-plan-group');
    if (groupFilter && groupFilter.options.length <= 1) {
        try {
            const groups = await api.getInventoryGroups();
            (groups || []).forEach(g => {
                const opt = document.createElement('option');
                opt.value = g.id;
                opt.textContent = g.name;
                groupFilter.appendChild(opt);
            });
        } catch { /* ignore */ }
    }

    if (chartContainer) chartContainer.innerHTML = '<div class="skeleton skeleton-card" style="height:300px;"></div>';
    if (thresholdsContainer) thresholdsContainer.innerHTML = '';
    if (emptyEl) emptyEl.style.display = 'none';

    try {
        const data = await api.getCapacityPlanning({
            metric,
            range,
            group: groupId,
            projectionDays: 90,
            threshold: 80,
        });

        if (!data || !data.data_points || !data.data_points.length) {
            if (chartContainer) chartContainer.innerHTML = '';
            if (emptyEl) emptyEl.style.display = '';
            return;
        }

        // Render trend chart using PlexusChart
        const points = data.data_points || [];
        const projection = data.projection || [];

        if (chartContainer) {
            chartContainer.innerHTML = '';
            const metricLabels = {
                cpu_percent: 'CPU %', memory_percent: 'Memory %',
                route_count: 'Route Count', if_up_count: 'Interfaces Up',
                vpn_tunnels_up: 'VPN Tunnels Up',
            };
            const label = metricLabels[metric] || metric;

            // Combine actual + projected data
            const allLabels = points.map(p => p.timestamp || p.day || '').concat(
                projection.map(p => p.timestamp || p.day || '')
            );
            const actualValues = points.map(p => p.value);
            const projectedValues = new Array(points.length).fill(null).concat(
                projection.map(p => p.value)
            );

            const chart = new PlexusChart(chartContainer, {
                type: 'line',
                labels: allLabels,
                datasets: [
                    { label: `${label} (Actual)`, data: actualValues, color: 'var(--primary)' },
                    { label: `${label} (Projected)`, data: projectedValues, color: 'var(--warning)', dashed: true },
                ],
                options: { height: 320 },
            });
            chart.render();
        }

        // Threshold estimates
        if (thresholdsContainer && data.threshold_estimates) {
            const estimates = data.threshold_estimates;
            const rows = Object.entries(estimates).map(([thresh, info]) => {
                const daysUntil = info.days_until != null ? `${info.days_until} days` : 'N/A';
                const date = info.estimated_date || 'N/A';
                const color = (info.days_until != null && info.days_until <= 30) ? 'danger' :
                              (info.days_until != null && info.days_until <= 90) ? 'warning' : 'success';
                return `<tr style="border-bottom:1px solid var(--border-color);">
                    <td style="padding:6px 12px;">${thresh}%</td>
                    <td style="padding:6px 12px; color:var(--${color}); font-weight:600;">${daysUntil}</td>
                    <td style="padding:6px 12px;">${date}</td>
                </tr>`;
            }).join('');
            thresholdsContainer.innerHTML = `
                <table style="width:100%; font-size:0.9em; border-collapse:collapse;">
                    <tr style="border-bottom:2px solid var(--border-color);">
                        <th style="text-align:left; padding:6px 12px;">Threshold</th>
                        <th style="text-align:left; padding:6px 12px;">Days Until</th>
                        <th style="text-align:left; padding:6px 12px;">Est. Date</th>
                    </tr>
                    ${rows}
                </table>`;
        }
    } catch (error) {
        if (chartContainer) chartContainer.innerHTML = `<div style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadCapacityPlanning = loadCapacityPlanning;


// =============================================================================
// Exports
// =============================================================================

export { loadMonitoring, loadSla };

export function destroyMonitoring() {
    listViewState.monitoring.polls = [];
    listViewState.monitoring.alerts = [];
    listViewState.monitoring.query = '';
    listViewState.sla.summary = null;
    listViewState.sla.hosts = [];
    listViewState.sla.query = '';
}

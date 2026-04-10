/**
 * Device Detail Module — Device detail page with metrics, interfaces, alerts, compliance, syslog
 * Lazy-loaded when user navigates to #device-detail
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, navigateToPage,
    PlexusChart, getTimeRangeParams, onTimeRangeChange, offTimeRangeChange,
    formatUptime, showToast
} from '../app.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Device Detail Page
// ═══════════════════════════════════════════════════════════════════════════════

let _deviceDetailTimeListener = null;

function navigateToDeviceDetail(hostId) {
    listViewState.deviceDetail.hostId = hostId;
    listViewState.deviceDetail.tab = 'overview';
    navigateToPage('device-detail');
}
window.navigateToDeviceDetail = navigateToDeviceDetail;

function switchDeviceTab(tab) {
    listViewState.deviceDetail.tab = tab;
    document.querySelectorAll('.dev-tab-btn').forEach(b => b.classList.toggle('active', b.dataset.devTab === tab));
    document.querySelectorAll('.device-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`device-tab-${tab}`);
    if (target) target.style.display = '';
}
window.switchDeviceTab = switchDeviceTab;

async function loadDeviceDetail({ preserveContent, force } = {}) {
    const hostId = listViewState.deviceDetail.hostId;
    if (!hostId) { navigateToPage('monitoring'); return; }

    // Register time-range listener once (not on every load/reload)
    if (!_deviceDetailTimeListener) {
        _deviceDetailTimeListener = () => loadDeviceDetail({ force: true });
        onTimeRangeChange(_deviceDetailTimeListener);
    }

    const trp = getTimeRangeParams();
    const range = trp.range === 'custom' ? '24h' : trp.range;

    try {
        // Fetch data in parallel
        const [cpuData, memData, rtData, plData, ifData, alertsRes, pollHistory] = await Promise.allSettled([
            api.queryMetrics('cpu_percent', String(hostId), range),
            api.queryMetrics('memory_percent', String(hostId), range),
            api.queryMetrics('response_time_ms', String(hostId), range),
            api.queryMetrics('packet_loss_pct', String(hostId), range),
            api.getInterfaceTimeSeries(hostId, range),
            api.getMonitoringAlerts({ hostId, limit: 50 }),
            api.getMonitoringPollHistory(hostId, 1),
        ]);

        // Info bar
        const latestPoll = pollHistory.status === 'fulfilled' ? (pollHistory.value?.polls || pollHistory.value || [])[0] : null;
        renderDeviceInfoBar(hostId, latestPoll);

        // Title
        const title = document.getElementById('device-detail-title');
        if (title) title.textContent = latestPoll?.hostname || `Device #${hostId}`;

        // Batch all metric chart creation into a single animation frame
        // to avoid layout thrashing (each PlexusChart.timeSeries reads element dimensions)
        const cpuSeries = extractMetricSeries(cpuData, 'CPU %');
        const memSeries = extractMetricSeries(memData, 'Memory %');
        const rtSeries = extractMetricSeries(rtData, 'Response Time');
        const plSeries = extractMetricSeries(plData, 'Packet Loss');
        requestAnimationFrame(() => {
            PlexusChart.timeSeries('device-chart-cpu', cpuSeries, { area: true, yAxisName: '%', yMin: 0, yMax: 100 });
            PlexusChart.timeSeries('device-chart-memory', memSeries, { area: true, yAxisName: '%', yMin: 0, yMax: 100 });
            PlexusChart.timeSeries('device-chart-response', rtSeries, { area: true, yAxisName: 'ms' });
            PlexusChart.timeSeries('device-chart-pktloss', plSeries, { area: true, yAxisName: '%', yMin: 0 });
        });

        // Interface summary bar chart + detail table
        if (ifData.status === 'fulfilled') {
            renderInterfaceSummaryChart(ifData.value);
            renderInterfaceDetailCharts(ifData.value, latestPoll);
        } else {
            // Even without time-series, render interface table from poll data
            renderInterfaceDetailCharts(null, latestPoll);
        }

        // Alert history
        if (alertsRes.status === 'fulfilled') {
            renderDeviceAlertHistory(alertsRes.value?.alerts || alertsRes.value || []);
        }

        // Compliance tab
        renderDeviceComplianceTab(hostId);

        // Syslog tab
        renderDeviceSyslogTab(hostId);

        // Overlay deployment/config/alert annotations on metric charts
        try {
            const endISO = new Date().toISOString();
            const startISO = new Date(Date.now() - _rangeToMs(range)).toISOString();
            const annRes = await api.getAnnotations({ hostId, start: startISO, end: endISO, categories: 'deployment,config,alert' });
            const events = annRes?.annotations || [];
            if (events.length) {
                for (const chartId of ['device-chart-cpu', 'device-chart-memory', 'device-chart-response', 'device-chart-pktloss']) {
                    PlexusChart.addAnnotations(chartId, events);
                }
            }
        } catch { /* annotations are non-critical */ }
    } catch (e) {
        console.error('Device detail load error:', e);
        showError(`Failed to load device detail: ${e.message}`);
    }
}

function refreshDeviceDetail() {
    loadDeviceDetail({ force: true });
}
window.refreshDeviceDetail = refreshDeviceDetail;

function _rangeToMs(range) {
    const units = { h: 3600000, d: 86400000 };
    const m = /^(\d+)([hd])$/.exec(range);
    return m ? parseInt(m[1]) * units[m[2]] : 86400000;
}

function extractMetricSeries(result, name) {
    if (result.status !== 'fulfilled') return [{ name, data: [] }];
    const raw = result.value?.data || [];
    return [{
        name,
        data: raw.map(d => ({
            time: d.sampled_at || d.period_start || d.timestamp,
            value: d.val_avg ?? d.value ?? 0,
        })),
    }];
}

function renderDeviceInfoBar(hostId, poll) {
    const el = document.getElementById('device-detail-info');
    if (!el) return;
    if (!poll) { el.innerHTML = '<span class="text-muted">No poll data available</span>'; return; }
    const uptimeStr = poll.uptime_seconds ? formatUptime(poll.uptime_seconds) : 'N/A';
    const polledAt = poll.polled_at ? new Date(poll.polled_at).toLocaleString() : 'N/A';
    const ifTotal = (poll.if_up_count || 0) + (poll.if_down_count || 0) + (poll.if_admin_down || 0);
    const ifSummary = ifTotal > 0
        ? `<span class="badge badge-success">${poll.if_up_count || 0}</span>/<span class="badge badge-danger">${poll.if_down_count || 0}</span>/<span class="badge badge-secondary">${poll.if_admin_down || 0}</span>`
        : 'N/A';
    el.innerHTML = `
        <div class="device-info-item"><span class="device-info-label">Hostname</span><span>${escapeHtml(poll.hostname || 'Unknown')}</span></div>
        <div class="device-info-item"><span class="device-info-label">IP</span><span>${escapeHtml(poll.ip_address || 'N/A')}</span></div>
        <div class="device-info-item"><span class="device-info-label">Type</span><span>${escapeHtml(poll.device_type || 'N/A')}</span></div>
        <div class="device-info-item"><span class="device-info-label">CPU</span><span>${poll.cpu_percent != null ? poll.cpu_percent.toFixed(1) + '%' : 'N/A'}</span></div>
        <div class="device-info-item"><span class="device-info-label">Memory</span><span>${poll.memory_percent != null ? poll.memory_percent.toFixed(1) + '%' : 'N/A'}</span></div>
        <div class="device-info-item"><span class="device-info-label">Interfaces</span><span>${ifSummary}</span></div>
        <div class="device-info-item"><span class="device-info-label">Uptime</span><span>${uptimeStr}</span></div>
        <div class="device-info-item"><span class="device-info-label">Last Poll</span><span>${polledAt}</span></div>`;
}

function renderInterfaceSummaryChart(ifData) {
    const interfaces = ifData?.data || ifData?.interfaces || ifData || [];
    if (!interfaces.length) return;
    // Group by interface name, take latest utilization
    const ifMap = new Map();
    interfaces.forEach(d => {
        const key = d.if_name || `idx-${d.if_index}`;
        if (!ifMap.has(key) || new Date(d.sampled_at) > new Date(ifMap.get(key).sampled_at)) {
            ifMap.set(key, d);
        }
    });
    const sorted = [...ifMap.values()].sort((a, b) => (b.utilization_pct || 0) - (a.utilization_pct || 0)).slice(0, 20);
    PlexusChart.bar('device-chart-if-summary', sorted.map(d => d.if_name || `idx-${d.if_index}`), sorted.map(d => Math.round((d.utilization_pct || 0) * 10) / 10), { rotateLabels: 45 });
}

function renderInterfaceDetailCharts(ifData, latestPoll) {
    const container = document.getElementById('device-interface-charts');
    if (!container) return;

    // -- Interface Status Table from latest poll --
    let pollInterfaces = [];
    if (latestPoll) {
        try {
            const raw = typeof latestPoll.if_details === 'string'
                ? JSON.parse(latestPoll.if_details || '[]')
                : (latestPoll.if_details || []);
            pollInterfaces = raw;
        } catch { pollInterfaces = []; }
    }

    // -- Time-series data for traffic charts --
    const tsInterfaces = ifData?.data || ifData?.interfaces || ifData || [];

    // Build a merged map: keyed by if_index, combining poll status + latest TS rates
    const ifMap = new Map();
    pollInterfaces.forEach(iface => {
        const idx = String(iface.if_index);
        ifMap.set(idx, {
            if_index: iface.if_index,
            name: iface.name || `ifIndex-${iface.if_index}`,
            status: iface.status || 'unknown',
            speed_mbps: iface.speed_mbps || 0,
            in_octets: iface.in_octets || 0,
            out_octets: iface.out_octets || 0,
            in_rate_bps: null,
            out_rate_bps: null,
            utilization_pct: null,
        });
    });

    // Overlay latest TS rate data
    const latestByIf = {};
    tsInterfaces.forEach(d => {
        const idx = String(d.if_index);
        if (!latestByIf[idx] || new Date(d.sampled_at) > new Date(latestByIf[idx].sampled_at)) {
            latestByIf[idx] = d;
        }
    });
    Object.entries(latestByIf).forEach(([idx, d]) => {
        const existing = ifMap.get(idx) || { if_index: parseInt(idx), name: d.if_name || `ifIndex-${idx}`, status: 'unknown', speed_mbps: d.if_speed_mbps || 0 };
        existing.in_rate_bps = d.in_rate_bps;
        existing.out_rate_bps = d.out_rate_bps;
        existing.utilization_pct = d.utilization_pct;
        if (d.if_name) existing.name = d.if_name;
        ifMap.set(idx, existing);
    });

    const allIfaces = [...ifMap.values()].sort((a, b) => a.if_index - b.if_index);

    if (!allIfaces.length && !tsInterfaces.length) {
        container.innerHTML = '<p class="text-muted">No interface data available. Ensure SNMP is configured and at least one poll has completed.</p>';
        return;
    }

    // -- Classify interfaces: Physical/Logical vs VLANs vs Loopback/Management --
    const isVlan = (n) => /^(Vl|Vlan|vlan|BDI|irb\.|vlan\.)\s*[\d]/i.test(n) || /vlan/i.test(n);
    const isLoopback = (n) => /^(Lo|Loopback|lo[\d])/i.test(n);
    const isMgmt = (n) => /^(Mgmt|Management|mgmt|ma[\d]|FastEthernet0$|GigabitEthernet0$)/i.test(n) || /^(Null|Embedded-Service|NV|Async|Voice|Cellular)/i.test(n);
    const isPortChannel = (n) => /^(Po|Port-channel|port-channel|ae[\d]|Bundle-Ether)/i.test(n);
    const isTunnel = (n) => /^(Tu|Tunnel|tunnel[\d])/i.test(n);

    const physicals = [];
    const vlans = [];
    const portChannels = [];
    const tunnels = [];
    const other = []; // loopbacks, mgmt, virtual, etc.

    allIfaces.forEach(i => {
        const n = i.name;
        if (isVlan(n)) vlans.push(i);
        else if (isPortChannel(n)) portChannels.push(i);
        else if (isTunnel(n)) tunnels.push(i);
        else if (isLoopback(n) || isMgmt(n)) other.push(i);
        else physicals.push(i);
    });

    // Format helpers
    const fmtRate = (bps) => {
        if (bps == null) return '<span class="text-muted">-</span>';
        if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
        if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
        if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
        return Math.round(bps) + ' bps';
    };
    const statusBadge = (s) => {
        if (s === 'up') return '<span class="badge badge-success">Up</span>';
        if (s === 'admin_down') return '<span class="badge badge-secondary">Admin Down</span>';
        return '<span class="badge badge-danger">Down</span>';
    };
    const utilBar = (pct) => {
        if (pct == null) return '<span class="text-muted">-</span>';
        const color = pct > 80 ? 'var(--danger)' : pct > 50 ? 'var(--warning)' : 'var(--success)';
        return `<div style="display:flex;align-items:center;gap:0.5rem;"><div style="flex:1;max-width:80px;height:6px;background:var(--border-color);border-radius:3px;overflow:hidden;"><div style="width:${Math.min(pct, 100)}%;height:100%;background:${color};border-radius:3px;"></div></div><span>${pct.toFixed(1)}%</span></div>`;
    };
    const fmtSpeed = (mbps) => {
        if (!mbps) return '<span class="text-muted">-</span>';
        return mbps >= 1000 ? (mbps / 1000) + ' Gbps' : mbps + ' Mbps';
    };

    // Count stats across all
    const upCount = allIfaces.filter(i => i.status === 'up').length;
    const downCount = allIfaces.filter(i => i.status === 'down').length;
    const adminDownCount = allIfaces.filter(i => i.status === 'admin_down').length;

    // -- Build a full-detail table for a set of interfaces --
    const buildFullTable = (ifaces) => {
        if (!ifaces.length) return '<p class="text-muted" style="padding:0.5rem;">None</p>';
        return `<div style="overflow-x:auto;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>Name</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th><th>Util</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td>${fmtSpeed(i.speed_mbps)}</td>
                <td>${fmtRate(i.in_rate_bps)}</td>
                <td>${fmtRate(i.out_rate_bps)}</td>
                <td>${utilBar(i.utilization_pct)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // -- Build a compact table for VLANs (status + name, no traffic columns) --
    const buildVlanTable = (ifaces) => {
        if (!ifaces.length) return '<p class="text-muted" style="padding:0.5rem;">No VLANs detected</p>';
        const vlanUp = ifaces.filter(i => i.status === 'up').length;
        const vlanDown = ifaces.filter(i => i.status !== 'up').length;
        return `<div style="margin-bottom:0.5rem; font-size:0.8rem; display:flex; gap:0.5rem;">
                <span class="badge badge-success">${vlanUp} up</span>
                ${vlanDown > 0 ? `<span class="badge badge-danger">${vlanDown} down</span>` : ''}
            </div>
            <div style="overflow-y:auto; max-height:400px;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>VLAN</th><th>Status</th><th>In</th><th>Out</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td style="font-size:0.78rem;">${fmtRate(i.in_rate_bps)}</td>
                <td style="font-size:0.78rem;">${fmtRate(i.out_rate_bps)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // -- Build a compact table for Port-Channels / Tunnels / Other --
    const buildCompactTable = (ifaces) => {
        if (!ifaces.length) return '';
        return `<div style="overflow-x:auto;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>Name</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td>${fmtSpeed(i.speed_mbps)}</td>
                <td>${fmtRate(i.in_rate_bps)}</td>
                <td>${fmtRate(i.out_rate_bps)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // -- Summary bar --
    let html = `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap; gap:0.5rem;">
        <h4 style="margin:0;">${allIfaces.length} Interfaces</h4>
        <div style="display:flex; gap:0.5rem; font-size:0.85rem; flex-wrap:wrap;">
            <span class="badge badge-success">${upCount} Up</span>
            ${downCount > 0 ? `<span class="badge badge-danger">${downCount} Down</span>` : ''}
            ${adminDownCount > 0 ? `<span class="badge badge-secondary">${adminDownCount} Admin Down</span>` : ''}
            <span style="color:var(--text-secondary);">|</span>
            <span style="color:var(--text-secondary);">${physicals.length} Physical</span>
            ${portChannels.length ? `<span style="color:var(--text-secondary);">${portChannels.length} Port-Channel</span>` : ''}
            <span style="color:var(--text-secondary);">${vlans.length} VLAN</span>
            ${tunnels.length ? `<span style="color:var(--text-secondary);">${tunnels.length} Tunnel</span>` : ''}
            ${other.length ? `<span style="color:var(--text-secondary);">${other.length} Other</span>` : ''}
        </div>
    </div>`;

    // -- Two-column layout: Physical interfaces (left) + VLANs (right) --
    html += `<div class="if-split-grid">`;

    // Left column: Physical interfaces
    html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
        <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">Physical Interfaces (${physicals.length})</h4>
        ${buildFullTable(physicals)}
    </div></div>`;

    // Right column: VLANs
    html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
        <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">VLANs (${vlans.length})</h4>
        ${buildVlanTable(vlans)}
    </div></div>`;

    html += `</div>`; // close grid

    // -- Port-Channels, Tunnels, Other in a row below --
    const extraSections = [];
    if (portChannels.length) extraSections.push({ title: `Port-Channels (${portChannels.length})`, items: portChannels });
    if (tunnels.length) extraSections.push({ title: `Tunnels (${tunnels.length})`, items: tunnels });
    if (other.length) extraSections.push({ title: `Loopback / Management / Other (${other.length})`, items: other });

    if (extraSections.length) {
        const cols = Math.min(extraSections.length, 3);
        html += `<div class="if-extra-grid" style="grid-template-columns:repeat(${cols}, 1fr);">`;
        extraSections.forEach(sec => {
            html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
                <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">${escapeHtml(sec.title)}</h4>
                ${buildCompactTable(sec.items)}
            </div></div>`;
        });
        html += `</div>`;
    }

    // -- Per-interface traffic charts (from time-series data) --
    if (tsInterfaces.length) {
        const grouped = {};
        tsInterfaces.forEach(d => {
            const key = d.if_name || `idx-${d.if_index}`;
            if (!grouped[key]) grouped[key] = [];
            grouped[key].push(d);
        });
        // Sort by most traffic, show up to 12, skip VLANs/loopbacks (focus on physical + port-channels)
        const ifNames = Object.keys(grouped).sort((a, b) => {
            const aMax = Math.max(...grouped[a].map(d => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
            const bMax = Math.max(...grouped[b].map(d => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
            return bMax - aMax;
        }).slice(0, 12);

        if (ifNames.length) {
            html += '<h4 style="margin:1.25rem 0 0.5rem;">Traffic Charts (Top 12 by Activity)</h4>';
            html += '<div class="if-chart-grid">';
            html += ifNames.map(name => `
                <div class="card" style="margin-bottom:0;">
                    <div class="card-title" style="font-size:0.85rem; padding:0.5rem 0.75rem;">${escapeHtml(name)}</div>
                    <div id="if-chart-${name.replace(/[^a-zA-Z0-9]/g, '_')}" class="chart-container" style="height:180px;"></div>
                </div>`).join('');
            html += '</div>';
        }

        container.innerHTML = html;

        // Defer chart creation to next frame — let the browser complete layout
        // from the innerHTML assignment before ECharts queries element dimensions
        requestAnimationFrame(() => {
            ifNames.forEach(name => {
                const data = grouped[name].sort((a, b) => new Date(a.sampled_at) - new Date(b.sampled_at));
                const chartId = `if-chart-${name.replace(/[^a-zA-Z0-9]/g, '_')}`;
                PlexusChart.timeSeries(chartId, [
                    { name: 'In (bps)', data: data.map(d => ({ time: d.sampled_at, value: d.in_rate_bps || 0 })), color: '#3b82f6' },
                    { name: 'Out (bps)', data: data.map(d => ({ time: d.sampled_at, value: d.out_rate_bps || 0 })), color: '#f59e0b' },
                ], { area: true, yAxisName: 'bps' });
            });
        });
    } else {
        html += '<p class="text-muted" style="margin-top:1rem;">Traffic charts will appear after two or more polling cycles collect rate data.</p>';
        container.innerHTML = html;
    }
}

function renderDeviceAlertHistory(alerts) {
    const container = document.getElementById('device-alert-history');
    if (!container) return;
    if (!alerts.length) { container.innerHTML = '<p class="text-muted">No alerts for this device</p>'; return; }
    const sevClass = s => s === 'critical' ? 'danger' : s === 'warning' ? 'warning' : 'info';
    container.innerHTML = `
        <table class="chart-table">
            <thead><tr><th>Time</th><th>Severity</th><th>Metric</th><th>Message</th><th>Status</th><th></th></tr></thead>
            <tbody>${alerts.map(a => `<tr>
                <td>${new Date(a.created_at).toLocaleString()}</td>
                <td><span class="badge badge-${sevClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td>${escapeHtml(a.metric || '')}</td>
                <td>${escapeHtml(a.message || '')}</td>
                <td>${a.acknowledged ? 'Ack' : 'Open'}</td>
                <td><button class="btn btn-sm btn-secondary" onclick="showAlertCorrelation(${a.id})" title="View correlated events" style="padding:2px 6px; font-size:0.75em;">Correlate</button></td>
            </tr>`).join('')}</tbody>
        </table>`;
}

async function renderDeviceComplianceTab(hostId) {
    const container = document.getElementById('device-compliance-status');
    if (!container) return;
    try {
        const results = await api.getComplianceScanResults({ hostId, limit: 20 });
        const items = results?.results || results || [];
        if (!items.length) { container.innerHTML = '<p class="text-muted">No compliance data for this device</p>'; return; }
        container.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Profile</th><th>Status</th><th>Score</th><th>Scanned</th></tr></thead>
                <tbody>${items.map(r => `<tr>
                    <td>${escapeHtml(r.profile_name || '')}</td>
                    <td><span class="badge badge-${r.status === 'pass' ? 'success' : r.status === 'fail' ? 'danger' : 'warning'}">${escapeHtml(r.status || '')}</span></td>
                    <td>${r.score != null ? r.score + '%' : 'N/A'}</td>
                    <td>${r.scanned_at ? new Date(r.scanned_at).toLocaleString() : 'N/A'}</td>
                </tr>`).join('')}</tbody>
            </table>`;
    } catch (e) {
        container.innerHTML = '<p class="text-muted">Could not load compliance data</p>';
    }
}

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

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

function destroyDeviceDetail() {
    if (_deviceDetailTimeListener) {
        offTimeRangeChange(_deviceDetailTimeListener);
        _deviceDetailTimeListener = null;
    }
    PlexusChart.destroyAll();
    listViewState.deviceDetail.hostId = null;
    listViewState.deviceDetail.tab = 'overview';
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════════════════════

export { loadDeviceDetail, destroyDeviceDetail, navigateToDeviceDetail };

/**
 * Network Tools Module — MAC Tracking + Traffic Analysis
 * Lazy-loaded when user navigates to #mac-tracking or #traffic-analysis
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    formatDate, formatRelativeTime, skeletonCards, emptyStateHTML,
    navigateToPage, PlexusChart, debounce, showModal
} from '../app.js';

// =============================================================================
// MAC Tracking
// =============================================================================

async function loadMacTrackingPage({ preserveContent } = {}) {
    const resultsEl = document.getElementById('mac-tracking-results');
    const emptyEl = document.getElementById('mac-tracking-empty');
    if (!preserveContent && resultsEl) resultsEl.innerHTML = '';
    if (emptyEl) emptyEl.style.display = (!resultsEl || !resultsEl.innerHTML) ? '' : 'none';
}

async function searchMacTrackingUI() {
    const query = document.getElementById('mac-tracking-search')?.value?.trim();
    if (!query) return;
    const resultsEl = document.getElementById('mac-tracking-results');
    const emptyEl = document.getElementById('mac-tracking-empty');
    if (!resultsEl) return;

    resultsEl.innerHTML = '<div class="skeleton-loader" style="height:200px;"></div>';
    if (emptyEl) emptyEl.style.display = 'none';

    try {
        const results = await api.searchMacTracking(query);
        if (!results || results.length === 0) {
            resultsEl.innerHTML = '<div class="glass-card card" style="text-align:center; padding:2rem; opacity:0.7;">No results found for "' + escapeHtml(query) + '"</div>';
            return;
        }
        const fmtTime = (t) => t ? new Date(t).toLocaleString() : '-';
        resultsEl.innerHTML = `
            <div class="glass-card card" style="overflow-x:auto;">
                <table class="data-table" style="width:100%;">
                    <thead><tr>
                        <th>MAC Address</th><th>IP Address</th><th>Switch</th><th>Port</th>
                        <th>VLAN</th><th>Type</th><th>First Seen</th><th>Last Seen</th><th></th>
                    </tr></thead>
                    <tbody>
                    ${results.map(r => `<tr>
                        <td><code style="font-size:0.85em;">${escapeHtml(r.mac_address || '-')}</code></td>
                        <td>${escapeHtml(r.ip_address || '-')}</td>
                        <td>${escapeHtml(r.hostname || 'host-' + r.host_id)}</td>
                        <td>${escapeHtml(r.port_name || '-')}</td>
                        <td>${escapeHtml(String(r.vlan || '-'))}</td>
                        <td><span class="badge badge-sm">${escapeHtml(r.entry_type || 'dynamic')}</span></td>
                        <td style="font-size:0.85em;">${fmtTime(r.first_seen)}</td>
                        <td style="font-size:0.85em;">${fmtTime(r.last_seen)}</td>
                        <td><button class="btn btn-sm" onclick="showMacHistory('${escapeHtml(r.mac_address)}')">History</button></td>
                    </tr>`).join('')}
                    </tbody>
                </table>
                <div style="margin-top:0.5rem; font-size:0.85em; opacity:0.6;">${results.length} result(s)</div>
            </div>`;
    } catch (err) {
        resultsEl.innerHTML = '<div class="glass-card card" style="color:var(--danger);">Search error: ' + escapeHtml(err.message) + '</div>';
    }
}

async function showMacHistory(macAddress) {
    try {
        const history = await api.getMacHistory(macAddress);
        if (!history || history.length === 0) {
            showToast('No movement history found for ' + macAddress, 'info');
            return;
        }
        const fmtTime = (t) => t ? new Date(t).toLocaleString() : '-';
        const content = `
            <div style="max-height:400px; overflow-y:auto;">
                <h4>Movement History: <code>${escapeHtml(macAddress)}</code></h4>
                <table class="data-table" style="width:100%;">
                    <thead><tr><th>Time</th><th>Switch</th><th>Port</th><th>VLAN</th><th>IP</th></tr></thead>
                    <tbody>
                    ${history.map(h => `<tr>
                        <td style="font-size:0.85em;">${fmtTime(h.seen_at)}</td>
                        <td>${escapeHtml(h.hostname || 'host-' + h.host_id)}</td>
                        <td>${escapeHtml(h.port_name || '-')}</td>
                        <td>${escapeHtml(String(h.vlan || '-'))}</td>
                        <td>${escapeHtml(h.ip_address || '-')}</td>
                    </tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
        showModal('MAC History', content);
    } catch (err) {
        showToast('Failed to load history: ' + err.message, 'error');
    }
}

async function triggerMacCollectionUI() {
    showToast('Starting MAC/ARP collection...', 'info');
    try {
        const result = await api.triggerMacCollection();
        showToast(`Collected ${result.macs_found || 0} MACs, ${result.arps_found || 0} ARPs from ${result.hosts_collected || 1} host(s)`, 'success');
    } catch (err) {
        showToast('Collection failed: ' + err.message, 'error');
    }
}

// =============================================================================
// Traffic Analysis (NetFlow / sFlow / IPFIX)
// =============================================================================

async function loadTrafficAnalysis({ preserveContent } = {}) {
    const hours = parseInt(document.getElementById('traffic-time-range')?.value || '6');

    // Load flow status
    try {
        const status = await api.getFlowStatus();
        const badge = document.getElementById('flow-collector-status');
        if (badge) {
            badge.textContent = status.running ? 'Collector Running' : 'Collector Stopped';
            badge.className = 'badge ' + (status.running ? 'badge-success' : 'badge-warning');
        }
    } catch (e) { /* ignore */ }

    // Load data in parallel
    const [topSrc, topDst, topApps, topConvos, timeline] = await Promise.allSettled([
        api.getFlowTopTalkers({ hours, direction: 'src', limit: 15 }),
        api.getFlowTopTalkers({ hours, direction: 'dst', limit: 15 }),
        api.getFlowTopApplications({ hours, limit: 15 }),
        api.getFlowTopConversations({ hours, limit: 15 }),
        api.getFlowTimeline({ hours, bucketMinutes: hours <= 1 ? 1 : hours <= 6 ? 5 : 15 }),
    ]);

    const emptyEl = document.getElementById('traffic-analysis-empty');
    const contentEl = document.getElementById('traffic-analysis-content');

    const hasData = [topSrc, topDst, topApps, topConvos].some(
        r => r.status === 'fulfilled' && r.value && r.value.length > 0
    );

    if (!hasData) {
        if (emptyEl) emptyEl.style.display = '';
        if (contentEl) contentEl.style.display = 'none';
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    if (contentEl) contentEl.style.display = '';

    const fmtBytes = (b) => {
        if (!b || b === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(b) / Math.log(1024));
        return (b / Math.pow(1024, i)).toFixed(1) + ' ' + units[Math.min(i, units.length - 1)];
    };

    // Render top sources
    const srcEl = document.getElementById('traffic-top-src');
    if (srcEl && topSrc.status === 'fulfilled' && topSrc.value?.length) {
        srcEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>IP</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topSrc.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (srcEl) { srcEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top destinations
    const dstEl = document.getElementById('traffic-top-dst');
    if (dstEl && topDst.status === 'fulfilled' && topDst.value?.length) {
        dstEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>IP</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topDst.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (dstEl) { dstEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top applications
    const appsEl = document.getElementById('traffic-top-apps');
    if (appsEl && topApps.status === 'fulfilled' && topApps.value?.length) {
        appsEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>Service</th><th>Port</th><th>Proto</th><th>Traffic</th></tr></thead>
            <tbody>${topApps.value.slice(0, 10).map(r => `<tr>
                <td>${escapeHtml(r.service_name || '-')}</td><td>${r.port}</td><td>${escapeHtml(r.protocol_name || String(r.protocol))}</td><td>${fmtBytes(r.total_bytes)}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (appsEl) { appsEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top conversations
    const convosEl = document.getElementById('traffic-top-convos');
    if (convosEl && topConvos.status === 'fulfilled' && topConvos.value?.length) {
        convosEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>Source</th><th>Destination</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topConvos.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.src_ip)}</code></td><td><code>${escapeHtml(r.dst_ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (convosEl) { convosEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render traffic timeline chart
    const chartEl = document.getElementById('traffic-timeline-chart');
    if (chartEl && timeline.status === 'fulfilled' && timeline.value?.length) {
        const data = timeline.value;
        PlexusChart.bar(
            'traffic-timeline-chart',
            data.map(d => d.bucket?.substring(11, 16) || ''),
            data.map(d => d.total_bytes || 0),
            { rotateLabels: 45 }
        );
    }
}

// =============================================================================
// Cleanup
// =============================================================================

function destroyNetworkTools() {
    // Minimal teardown — clear any DOM references or intervals if needed
}

// =============================================================================
// Window registrations (onclick handlers used from HTML templates)
// =============================================================================

window.searchMacTrackingUI = searchMacTrackingUI;
window.triggerMacCollectionUI = triggerMacCollectionUI;
window.showMacHistory = showMacHistory;
window.loadTrafficAnalysis = loadTrafficAnalysis;

// =============================================================================
// Exports
// =============================================================================

export { loadMacTrackingPage, loadTrafficAnalysis, destroyNetworkTools };

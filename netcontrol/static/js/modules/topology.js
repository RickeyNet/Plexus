/**
 * Topology Module — Network graph visualization
 * Lazy-loaded when user navigates to #topology
 */
import * as api from '../api.js';
import {
    escapeHtml, showToast, showError, showModal, showConfirm, showSuccess,
    PlexusChart, isReducedMotion, navigateToPage, navigateToDeviceDetail,
    listViewState, emptyStateHTML, formatDate, invalidatePageCache,
    closeAllModals, getTimeRangeParams, createStreamHandler
} from '../app.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Topology
// ═══════════════════════════════════════════════════════════════════════════════

let _topologyNetwork = null;
let _topologyData = null;
let _topoNodesDS = null;         // vis.DataSet for nodes (persistent)
let _topoEdgesDS = null;         // vis.DataSet for edges (persistent)
let _topoSavedPositions = {};    // { nodeId: {x, y} } loaded from server
let _topoPathMode = false;
let _topoPathSource = null;
let _topoOriginalColors = null;  // stashed node/edge colors for restore
let _topoUtilOverlay = false;    // utilization overlay toggle state
let _topoStpOverlay = false;     // STP overlay toggle state
let _topoStpStateByPort = new Map(); // key: "<host_id>|<norm_ifname>" -> stp row
let _topoThemeColors = null;     // cached theme-aware colors for vis-network

function _getTopoThemeColors() {
    const style = getComputedStyle(document.documentElement);
    const theme = document.documentElement.getAttribute('data-theme') || 'forest';
    const isDark = !['light', 'sandstone'].includes(theme);
    const hasLightTopoNodes = ['light', 'sandstone'].includes(theme);
    const v = (prop, fallback) => style.getPropertyValue(prop).trim() || fallback;
    _topoThemeColors = {
        nodeFont: hasLightTopoNodes ? '#2a1818' : v('--text', '#c8d4c8'),
        nodeFontStroke: hasLightTopoNodes ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.6)',
        edgeFont: hasLightTopoNodes ? '#4a3030' : v('--text-muted', '#7a8a7a'),
        edgeFontStroke: hasLightTopoNodes ? 'rgba(255,255,255,0.6)' : 'rgba(0,0,0,0.5)',
        externalBg: isDark ? '#263238' : v('--bg-secondary', '#edf2ea'),
        externalBorder: isDark ? '#546e7a' : v('--border', '#d1d9d1'),
        externalHighlightBg: isDark ? '#37474f' : v('--card-bg-hover', '#f2f5ef'),
        externalHighlightBorder: isDark ? '#90a4ae' : v('--border-light', '#c1c9c1'),
        // Vendor node colors
        cisco:     { background: v('--topo-cisco-bg', '#0d47a1'), border: v('--topo-cisco-border', '#42a5f5'), highlight: { background: v('--topo-cisco-hi-bg', '#1565c0'), border: v('--topo-cisco-hi-border', '#90caf9') }, hover: { background: v('--topo-cisco-hi-bg', '#1565c0'), border: v('--topo-cisco-hi-border', '#90caf9') } },
        juniper:   { background: v('--topo-juniper-bg', '#1b5e20'), border: v('--topo-juniper-border', '#66bb6a'), highlight: { background: v('--topo-juniper-hi-bg', '#2e7d32'), border: v('--topo-juniper-hi-border', '#a5d6a7') }, hover: { background: v('--topo-juniper-hi-bg', '#2e7d32'), border: v('--topo-juniper-hi-border', '#a5d6a7') } },
        arista:    { background: v('--topo-arista-bg', '#e65100'), border: v('--topo-arista-border', '#ffa726'), highlight: { background: v('--topo-arista-hi-bg', '#f57c00'), border: v('--topo-arista-hi-border', '#ffcc80') }, hover: { background: v('--topo-arista-hi-bg', '#f57c00'), border: v('--topo-arista-hi-border', '#ffcc80') } },
        fortinet:  { background: v('--topo-fortinet-bg', '#b71c1c'), border: v('--topo-fortinet-border', '#ef5350'), highlight: { background: v('--topo-fortinet-hi-bg', '#c62828'), border: v('--topo-fortinet-hi-border', '#ef9a9a') }, hover: { background: v('--topo-fortinet-hi-bg', '#c62828'), border: v('--topo-fortinet-hi-border', '#ef9a9a') } },
        unknown:   { background: v('--topo-unknown-bg', '#37474f'), border: v('--topo-unknown-border', '#78909c'), highlight: { background: v('--topo-unknown-hi-bg', '#455a64'), border: v('--topo-unknown-hi-border', '#b0bec5') }, hover: { background: v('--topo-unknown-hi-bg', '#455a64'), border: v('--topo-unknown-hi-border', '#b0bec5') } },
        // Edge protocol colors
        edgeCdp:   { color: v('--topo-edge-cdp', '#00b0ff'), highlight: v('--topo-edge-cdp-hi', '#40c4ff'), hover: v('--topo-edge-cdp-hi', '#40c4ff'), opacity: 0.8 },
        edgeLldp:  { color: v('--topo-edge-lldp', '#00e676'), highlight: v('--topo-edge-lldp-hi', '#69f0ae'), hover: v('--topo-edge-lldp-hi', '#69f0ae'), opacity: 0.8 },
        edgeOspf:  { color: v('--topo-edge-ospf', '#ffab40'), highlight: v('--topo-edge-ospf-hi', '#ffd180'), hover: v('--topo-edge-ospf-hi', '#ffd180'), opacity: 0.8 },
        edgeBgp:   { color: v('--topo-edge-bgp', '#e040fb'), highlight: v('--topo-edge-bgp-hi', '#ea80fc'), hover: v('--topo-edge-bgp-hi', '#ea80fc'), opacity: 0.8 },
        // Path highlighting
        pathGlow:  v('--topo-path-glow', 'rgba(255,255,255,0.6)'),
        dimColor:  { background: v('--topo-dim-bg', 'rgba(40,50,60,0.4)'), border: v('--topo-dim-border', 'rgba(60,70,80,0.4)') },
        dimEdge:   { color: v('--topo-dim-edge', 'rgba(80,90,100,0.2)'), highlight: v('--topo-dim-edge-hi', 'rgba(80,90,100,0.3)'), hover: v('--topo-dim-edge-hi', 'rgba(80,90,100,0.3)') },
    };
    return _topoThemeColors;
}

function _topoNodeShape(deviceType) {
    if (deviceType === 'fortinet') return 'triangle';
    if (['cisco_ios', 'juniper_junos', 'arista_eos'].includes(deviceType)) return 'diamond';
    return 'dot';
}

function _topoNodeColor(node) {
    const tc = _topoThemeColors || _getTopoThemeColors();
    if (!node.in_inventory) {
        return { background: tc.externalBg, border: tc.externalBorder, highlight: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder }, hover: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder } };
    }
    const vendorMap = { cisco_ios: tc.cisco, juniper_junos: tc.juniper, arista_eos: tc.arista, fortinet: tc.fortinet };
    return vendorMap[node.device_type] || tc.unknown;
}

function _topoEdgeColor(protocol) {
    const tc = _topoThemeColors || _getTopoThemeColors();
    if (protocol === 'lldp') return tc.edgeLldp;
    if (protocol === 'ospf') return tc.edgeOspf;
    if (protocol === 'bgp')  return tc.edgeBgp;
    return tc.edgeCdp;
}

// Utilization overlay color: green (0%) → yellow (50%) → red (100%)
function _utilColor(pct) {
    let r, g, b;
    if (pct <= 50) {
        // green → yellow
        const t = pct / 50;
        r = Math.round(76 + (255 - 76) * t);
        g = Math.round(175 + (235 - 175) * t);
        b = Math.round(80 + (59 - 80) * t);
    } else {
        // yellow → red
        const t = (pct - 50) / 50;
        r = Math.round(255 + (244 - 255) * t);
        g = Math.round(235 - 235 * t * 0.85);
        b = Math.round(59 + (67 - 59) * t);
    }
    const hex = `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
    return { color: hex, highlight: hex, hover: hex, opacity: 0.9 };
}

function _formatBps(bps) {
    if (!bps || bps < 0) return '0 bps';
    if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
    return bps + ' bps';
}

function _utilShadow(pct) {
    if (pct > 75) return 'rgba(244,67,54,0.4)';
    if (pct > 50) return 'rgba(255,235,59,0.3)';
    return 'rgba(76,175,80,0.3)';
}

function _normalizeIfaceName(name) {
    let n = String(name || '').trim().toLowerCase();
    if (!n) return '';
    n = n.replace(/\s+/g, '');
    n = n
        .replace(/tengigabitethernet/g, 'te')
        .replace(/gigabitethernet/g, 'gi')
        .replace(/fastethernet/g, 'fa')
        .replace(/port-channel/g, 'po')
        .replace(/ethernet/g, 'eth');
    return n;
}

function _stpPortKey(hostId, iface) {
    return `${String(hostId)}|${_normalizeIfaceName(iface)}`;
}

function _stpLegendVisible(visible) {
    const ids = [
        'topology-legend-stp-forwarding',
        'topology-legend-stp-learning',
        'topology-legend-stp-blocked',
    ];
    for (const id of ids) {
        const el = document.getElementById(id);
        if (el) el.style.display = visible ? 'inline-flex' : 'none';
    }
}

function _stpStyle(state) {
    const s = String(state || '').toLowerCase();
    if (s === 'forwarding') {
        return {
            color: { color: '#43a047', highlight: '#66bb6a', hover: '#66bb6a', opacity: 0.9 },
            width: 4,
            dashes: false,
            shadow: 'rgba(67,160,71,0.35)',
        };
    }
    if (s === 'learning' || s === 'listening') {
        return {
            color: { color: '#f9a825', highlight: '#fbc02d', hover: '#fbc02d', opacity: 0.95 },
            width: 4,
            dashes: [6, 4],
            shadow: 'rgba(249,168,37,0.35)',
        };
    }
    if (s === 'blocking' || s === 'discarding' || s === 'disabled' || s === 'broken') {
        return {
            color: { color: '#e53935', highlight: '#ef5350', hover: '#ef5350', opacity: 0.95 },
            width: 6,
            dashes: [4, 3],
            shadow: 'rgba(229,57,53,0.45)',
        };
    }
    return null;
}

function _lookupStpForEdge(edge) {
    if (!_topoStpOverlay) return null;
    const fromHostId = edge.from_host_id || edge.from;
    if (!fromHostId || typeof fromHostId !== 'number') return null;
    const iface = edge.source_interface || '';
    if (!iface) return null;
    return _topoStpStateByPort.get(_stpPortKey(fromHostId, iface)) || null;
}

function _edgeOverlayProps(edge) {
    const util = edge.utilization;
    const hasUtil = _topoUtilOverlay && util && util.utilization_pct != null;
    const utilPct = hasUtil ? util.utilization_pct : 0;
    const utilWidth = hasUtil ? (util.width || (2 + (utilPct / 100) * 6)) : 2;
    const utilColor = hasUtil ? (util.color || _utilColor(utilPct)) : null;

    const stp = _lookupStpForEdge(edge);
    const stpStyle = stp ? _stpStyle(stp.port_state) : null;

    let label = edge.label || '';
    if (hasUtil) label = `${label ? label + ' ' : ''}(${utilPct}%)`;
    if (stpStyle) {
        const role = stp.port_role ? `/${stp.port_role}` : '';
        label = `${label ? label + ' ' : ''}[STP:${stp.port_state}${role}]`;
    }

    const baseProtocolShadow = ({ lldp: 'rgba(0,230,118,0.3)', ospf: 'rgba(255,171,64,0.3)', bgp: 'rgba(224,64,251,0.3)' }[edge.protocol] || 'rgba(0,176,255,0.3)');

    return {
        label,
        color: stpStyle ? stpStyle.color : (utilColor || _topoEdgeColor(edge.protocol)),
        width: stpStyle ? Math.max(utilWidth, stpStyle.width) : utilWidth,
        dashes: stpStyle ? stpStyle.dashes : (edge.protocol === 'lldp' ? [8, 5] : edge.protocol === 'ospf' ? [12, 4, 4, 4] : edge.protocol === 'bgp' ? [4, 4] : false),
        shadowColor: stpStyle ? stpStyle.shadow : (hasUtil ? _utilShadow(utilPct) : baseProtocolShadow),
    };
}

let _utilEventSource = null;
let _utilReconnectTimer = null;

function toggleUtilizationOverlay() {
    _topoUtilOverlay = !_topoUtilOverlay;
    const btn = document.getElementById('topology-util-btn');
    if (btn) btn.classList.toggle('active', _topoUtilOverlay);
    const utilLegend = document.getElementById('topology-legend-util');
    if (utilLegend) utilLegend.style.display = _topoUtilOverlay ? 'inline-flex' : 'none';

    // Start/stop live utilization SSE stream
    if (_topoUtilOverlay) {
        _startUtilizationStream();
    } else {
        _stopUtilizationStream();
    }

    // Update edges in-place without rebuilding the graph
    _refreshTopologyEdgeStyles();
}

function _refreshTopologyEdgeStyles() {
    if (_topologyNetwork && _topologyData) {
        const edgesDS = _topologyNetwork.body.data.edges;
        const updates = _topologyData.edges.map(e => {
            const overlay = _edgeOverlayProps(e);
            return {
                id: e.id,
                label: overlay.label,
                color: overlay.color,
                width: overlay.width,
                dashes: overlay.dashes,
                shadow: {
                    enabled: true,
                    color: overlay.shadowColor,
                    size: 6, x: 0, y: 0,
                },
            };
        });
        edgesDS.update(updates);
    }
}

function _startUtilizationStream() {
    _stopUtilizationStream();
    try {
        _utilEventSource = new EventSource('/api/topology/utilization/stream?interval=30');
        _utilEventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.edges && _topologyData) {
                    // Update utilization data on matching edges
                    const utilMap = {};
                    for (const e of data.edges) {
                        const key = `${e.source_host_id}-${e.target_host_id}-${e.source_interface}`;
                        utilMap[key] = e.utilization;
                    }
                    for (const edge of _topologyData.edges) {
                        const key = `${edge.from_host_id || edge.from}-${edge.to_host_id || edge.to}-${edge.source_interface || ''}`;
                        if (utilMap[key]) {
                            edge.utilization = utilMap[key];
                        }
                    }
                    if (_topoUtilOverlay || _topoStpOverlay) _refreshTopologyEdgeStyles();
                }
            } catch (e) { /* parse error, skip */ }
        };
        _utilEventSource.onerror = () => {
            // Reconnect on error after a delay
            _stopUtilizationStream();
            if (_topoUtilOverlay) {
                _utilReconnectTimer = setTimeout(() => { if (_topoUtilOverlay) _startUtilizationStream(); }, 10000);
            }
        };
    } catch (e) { /* SSE not supported or error */ }
}

function _stopUtilizationStream() {
    clearTimeout(_utilReconnectTimer);
    _utilReconnectTimer = null;
    if (_utilEventSource) {
        _utilEventSource.close();
        _utilEventSource = null;
    }
}

function _currentStpVlan() {
    const el = document.getElementById('topology-stp-vlan');
    if (!el) return 1;
    const parsed = parseInt(el.value || '1', 10);
    if (!Number.isFinite(parsed)) return 1;
    return Math.max(1, Math.min(4094, parsed));
}

function _updateStpEventBadge(count) {
    const badge = document.getElementById('topology-stp-event-badge');
    const btn = document.getElementById('topology-stp-events-btn');
    if (!badge || !btn) return;
    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : String(count);
        badge.style.display = 'inline-flex';
        btn.classList.add('has-changes');
    } else {
        badge.style.display = 'none';
        btn.classList.remove('has-changes');
    }
}

function _hydrateStpOverlayState(rows) {
    _topoStpStateByPort = new Map();
    for (const row of (rows || [])) {
        const key = _stpPortKey(row.host_id, row.interface_name || '');
        if (!key.endsWith('|')) {
            _topoStpStateByPort.set(key, row);
        }
    }
}

async function _loadStpOverlayData() {
    const groupFilter = document.getElementById('topology-group-filter')?.value || '';
    const vlanId = _currentStpVlan();
    const resp = await api.getTopologyStpState(groupFilter || null, null, vlanId, 20000);
    _hydrateStpOverlayState(resp.states || []);
    _updateStpEventBadge(resp.unacknowledged_events || 0);
    return resp;
}

async function toggleStpOverlay() {
    _topoStpOverlay = !_topoStpOverlay;
    const btn = document.getElementById('topology-stp-btn');
    if (btn) btn.classList.toggle('active', _topoStpOverlay);
    _stpLegendVisible(_topoStpOverlay);

    if (!_topoStpOverlay) {
        _topoStpStateByPort = new Map();
        _refreshTopologyEdgeStyles();
        return;
    }

    try {
        const resp = await _loadStpOverlayData();
        if ((resp.count || 0) === 0) {
            showToast('No STP data yet. Click "Scan STP" to poll devices.', 'info');
        }
    } catch (err) {
        _topoStpOverlay = false;
        if (btn) btn.classList.remove('active');
        _stpLegendVisible(false);
        _topoStpStateByPort = new Map();
        showError('Failed to load STP overlay: ' + err.message);
    } finally {
        _refreshTopologyEdgeStyles();
    }
}

async function _onStpVlanChange() {
    if (!_topoStpOverlay) return;
    try {
        await _loadStpOverlayData();
        _refreshTopologyEdgeStyles();
    } catch (err) {
        showError('Failed to refresh STP overlay: ' + err.message);
    }
}

function _syncStpVlanControlState() {
    const allVlansEl = document.getElementById('topology-stp-all-vlans');
    const vlanEl = document.getElementById('topology-stp-vlan');
    if (!allVlansEl || !vlanEl) return;
    vlanEl.disabled = Boolean(allVlansEl.checked);
    vlanEl.title = allVlansEl.checked ? 'Disabled while scanning all VLANs' : 'STP instance/VLAN';
}

async function _onStpAllVlansToggle() {
    _syncStpVlanControlState();
    if (_topoStpOverlay) {
        try {
            await _loadStpOverlayData();
            _refreshTopologyEdgeStyles();
        } catch (err) {
            showError('Failed to refresh STP overlay: ' + err.message);
        }
    }
}

async function scanTopologyStp() {
    const btn = document.getElementById('topology-stp-scan-btn');
    const groupFilter = document.getElementById('topology-group-filter')?.value || '';
    const vlanId = _currentStpVlan();
    const allVlans = Boolean(document.getElementById('topology-stp-all-vlans')?.checked);

    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Scanning...';
    }

    try {
        const result = await api.discoverTopologyStp(groupFilter || null, vlanId, allVlans, 128);
        const vlanScope = result.all_vlans
            ? `${(result.vlans_scanned || []).length || 0} VLANs`
            : `VLAN ${vlanId}`;
        const msg = `STP scan complete (${vlanScope}): ${result.ports_collected} ports from ${result.hosts_updated}/${result.hosts_scanned} hosts` +
            (result.errors > 0 ? ` (${result.errors} errors)` : '');
        showToast(msg, result.errors > 0 ? 'warning' : 'success');
        _updateStpEventBadge(result.unacknowledged_events || 0);

        if (_topoStpOverlay) {
            await _loadStpOverlayData();
            _refreshTopologyEdgeStyles();
        }
    } catch (err) {
        showError('STP scan failed: ' + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Scan STP';
        }
    }
}

async function showStpTopologyEvents() {
    try {
        const resp = await api.getTopologyStpEvents(true, 300);
        const events = resp.events || [];
        if (events.length === 0) {
            showToast('No unacknowledged STP events', 'info');
            return;
        }

        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        title.textContent = 'STP Topology Events';

        let html = `<div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="color:var(--text-muted); font-size:0.85rem;">${events.length} unacknowledged event${events.length !== 1 ? 's' : ''}</span>
            <button class="btn btn-secondary btn-sm" onclick="acknowledgeStpTopologyEvents()">Acknowledge All</button>
        </div>`;
        html += '<div style="max-height:420px; overflow-y:auto;">';

        for (const ev of events) {
            const sev = String(ev.severity || 'warning').toLowerCase();
            const sevColor = sev === 'critical' ? '#ef5350' : '#ffb300';
            const iface = ev.interface_name ? `<span style="opacity:0.85;">${escapeHtml(ev.interface_name)}</span>` : '<span style="opacity:0.7;">host-level</span>';
            const details = escapeHtml(ev.details || ev.event_type || 'stp event');
            const oldVal = escapeHtml(ev.old_value || '');
            const newVal = escapeHtml(ev.new_value || '');
            const delta = oldVal || newVal ? `<div style="font-family:monospace; font-size:0.75rem; margin-top:0.25rem; color:var(--text-muted);">${oldVal} &rarr; ${newVal}</div>` : '';

            html += `<div style="padding:0.55rem 0.7rem; margin-bottom:0.45rem; border-radius:0.35rem; border-left:3px solid ${sevColor}; background:${sevColor}14;">
                <div style="display:flex; justify-content:space-between; align-items:baseline; gap:0.75rem;">
                    <strong style="font-size:0.86rem; color:${sevColor};">${escapeHtml((ev.event_type || 'event').replaceAll('_', ' ').toUpperCase())}</strong>
                    <span style="font-size:0.72rem; color:var(--text-muted);">${new Date((ev.created_at || '') + 'Z').toLocaleString()}</span>
                </div>
                <div style="font-size:0.8rem; margin-top:0.2rem;">
                    <strong>${escapeHtml(ev.hostname || ('Host #' + ev.host_id))}</strong> &middot; VLAN ${escapeHtml(ev.vlan_id || '')} &middot; ${iface}
                </div>
                <div style="font-size:0.8rem; margin-top:0.2rem;">${details}</div>
                ${delta}
            </div>`;
        }
        html += '</div>';

        body.innerHTML = html;
        document.getElementById('modal-overlay').classList.add('active');
    } catch (err) {
        showError('Failed to load STP events: ' + err.message);
    }
}

async function acknowledgeStpTopologyEvents() {
    try {
        const resp = await api.acknowledgeTopologyStpEvents();
        showToast(`Acknowledged ${resp.acknowledged} STP event${resp.acknowledged !== 1 ? 's' : ''}`, 'success');
        _updateStpEventBadge(0);
        closeAllModals();
    } catch (err) {
        showError('Failed to acknowledge STP events: ' + err.message);
    }
}

async function loadTopology(options = {}) {
    const { preserveContent = false } = options;
    // Attach listeners now that lazy DOM elements exist
    _initTopoListeners();
    const container = document.querySelector('.topology-container');
    const legend = document.getElementById('topology-legend');
    const emptyEl = document.getElementById('topology-empty');

    // Populate group filter
    try {
        const groups = await api.getInventoryGroups(false);
        const select = document.getElementById('topology-group-filter');
        const currentVal = select.value;
        select.innerHTML = '<option value="">All Groups</option>';
        (groups || []).forEach(g => {
            const opt = document.createElement('option');
            opt.value = g.id;
            opt.textContent = g.name;
            select.appendChild(opt);
        });
        if (currentVal) select.value = currentVal;
    } catch (e) { /* ignore */ }

    // Fetch topology data and saved positions in parallel
    const groupFilter = document.getElementById('topology-group-filter').value;
    try {
        const [data, positions] = await Promise.all([
            api.getTopology(groupFilter || null),
            api.getTopologyPositions().catch(() => ({})),
        ]);
        _topologyData = data;
        _topoSavedPositions = positions || {};
        if (!data.nodes || data.nodes.length === 0) {
            container.style.display = 'none';
            legend.style.display = 'none';
            emptyEl.style.display = 'flex';
            if (_topologyNetwork) { _topologyNetwork.destroy(); _topologyNetwork = null; }
            return;
        }
        container.style.display = 'flex';
        legend.style.display = 'flex';
        emptyEl.style.display = 'none';
        renderTopologyGraph(data);
        if (_topoStpOverlay) {
            try {
                await _loadStpOverlayData();
            } catch (e) {
                // keep graph usable even if STP overlay fetch fails
                _topoStpStateByPort = new Map();
            }
            _refreshTopologyEdgeStyles();
        } else {
            _refreshTopologyEdgeStyles();
        }
        // Update change badge
        _updateTopologyChangeBadge(data.unacknowledged_changes || 0);
        api.getTopologyStpEvents(true, 1)
            .then(resp => _updateStpEventBadge(resp.unacknowledged_count || 0))
            .catch(() => {});
    } catch (error) {
        container.style.display = 'none';
        legend.style.display = 'none';
        emptyEl.style.display = 'flex';
        showError('Failed to load topology: ' + error.message);
    }
}

function _buildVisNode(n, savedPos) {
    const colors = _topoNodeColor(n);
    const node = {
        id: n.id,
        label: n.label,
        title: `${n.label}\n${n.ip || ''}\nType: ${n.device_type}${n.group_name ? '\nGroup: ' + n.group_name : ''}${n.in_inventory ? '' : '\n(External)'}\nDrag to move · Right-click to unpin`,
        shape: _topoNodeShape(n.device_type),
        color: colors,
        size: n.in_inventory ? 25 : 18,
        borderWidth: n.in_inventory ? 2.5 : 1.5,
        borderWidthSelected: 4,
        shapeProperties: { borderDashes: n.in_inventory ? false : [5, 5] },
        shadow: { enabled: true, color: colors.border, size: n.in_inventory ? 18 : 8, x: 0, y: 0 },
        font: { color: (_topoThemeColors || _getTopoThemeColors()).nodeFont, size: 12, face: 'Inter, sans-serif', strokeWidth: 3, strokeColor: (_topoThemeColors || _getTopoThemeColors()).nodeFontStroke },
        _raw: n,
    };
    // Apply saved position — pin the node so physics won't move it
    const key = String(n.id);
    if (savedPos[key]) {
        node.x = savedPos[key].x;
        node.y = savedPos[key].y;
        node.fixed = { x: true, y: true };
        node.physics = false;
    } else if (n._circularX != null) {
        // Circular layout: set initial positions but leave draggable
        node.x = n._circularX;
        node.y = n._circularY;
    }
    return node;
}

function _buildVisEdge(e) {
    const overlay = _edgeOverlayProps(e);
    return {
        id: e.id,
        from: e.from,
        to: e.to,
        label: overlay.label,
        color: overlay.color,
        dashes: overlay.dashes,
        width: overlay.width,
        hoverWidth: 0.5,
        selectionWidth: 1,
        shadow: {
            enabled: true,
            color: overlay.shadowColor,
            size: 6, x: 0, y: 0,
        },
        font: { size: 9, color: (_topoThemeColors || _getTopoThemeColors()).edgeFont, strokeWidth: 2, strokeColor: (_topoThemeColors || _getTopoThemeColors()).edgeFontStroke, align: 'middle' },
        smooth: { type: 'continuous', roundness: 0.4 },
        _raw: e,
    };
}

function renderTopologyGraph(data) {
    _getTopoThemeColors();
    const container = document.getElementById('topology-canvas');
    const layoutMode = document.getElementById('topology-layout').value;

    _topoNodesDS = new vis.DataSet(data.nodes.map(n => _buildVisNode(n, _topoSavedPositions)));
    _topoEdgesDS = new vis.DataSet(data.edges.map(e => _buildVisEdge(e)));

    // Decide physics: if ALL nodes have saved positions, disable physics entirely
    const allPinned = data.nodes.length > 0 && data.nodes.every(n => _topoSavedPositions[String(n.id)]);
    const isHierarchical = layoutMode.startsWith('hierarchical-');
    const isCircular = layoutMode === 'circular';
    const usePhysics = layoutMode === 'physics' && !allPinned;

    // For circular layout, pre-compute positions in a circle
    if (isCircular) {
        const nodeCount = data.nodes.length;
        const radius = Math.max(200, nodeCount * 35);
        data.nodes.forEach((n, i) => {
            // Only assign circular positions if no saved position exists
            if (!_topoSavedPositions[String(n.id)]) {
                const angle = (2 * Math.PI * i) / nodeCount - Math.PI / 2;
                n._circularX = Math.round(radius * Math.cos(angle));
                n._circularY = Math.round(radius * Math.sin(angle));
            }
        });
    }

    // Build layout config
    let layoutConfig = {};
    if (isHierarchical) {
        const direction = layoutMode.split('-')[1]; // UD, DU, LR, RL
        layoutConfig = {
            hierarchical: { direction, sortMethod: 'hubsize', nodeSpacing: 180, levelSeparation: 140 },
        };
    }

    const graphOptions = {
        physics: {
            enabled: isCircular ? false : usePhysics,
            barnesHut: {
                gravitationalConstant: -4000,
                centralGravity: 0.25,
                springLength: 180,
                springConstant: 0.035,
                damping: 0.1,
                avoidOverlap: 0.3,
            },
            stabilization: { iterations: 250, updateInterval: 20 },
        },
        interaction: {
            hover: true,
            tooltipDelay: 150,
            navigationButtons: false,
            keyboard: { enabled: true },
            zoomSpeed: 0.6,
        },
        layout: layoutConfig,
        edges: {
            smooth: { type: 'continuous', roundness: 0.4 },
        },
    };

    if (_topologyNetwork) {
        _topologyNetwork.destroy();
    }
    _topologyNetwork = new vis.Network(container, { nodes: _topoNodesDS, edges: _topoEdgesDS }, graphOptions);

    _topologyNetwork.on('click', (params) => {
        if (_topoPathMode && params.nodes.length > 0) {
            _handlePathClick(params.nodes[0], _topoNodesDS, _topoEdgesDS, data);
            return;
        }
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = _topoNodesDS.get(nodeId);
            if (node && node._raw) showTopologyNodeDetails(node._raw, data.edges);
        } else {
            closeTopologyDetails();
        }
    });

    // Save position when a node is dragged
    _topologyNetwork.on('dragEnd', (params) => {
        if (!params.nodes.length) return;
        const positions = _topologyNetwork.getPositions(params.nodes);
        const updates = {};
        for (const nid of params.nodes) {
            const pos = positions[nid];
            if (!pos) continue;
            updates[String(nid)] = { x: Math.round(pos.x), y: Math.round(pos.y) };
            _topoSavedPositions[String(nid)] = updates[String(nid)];
            // Pin the node so it stays put
            _topoNodesDS.update({ id: nid, fixed: { x: true, y: true }, physics: false });
        }
        // Persist to server (fire-and-forget)
        _saveNodePositions(updates);
    });

    // Right-click on a node: unpin it (release back to physics)
    _topologyNetwork.on('oncontext', (params) => {
        params.event.preventDefault();
        if (!params.nodes || params.nodes.length === 0) return;
        const nid = params.nodes[0];
        const key = String(nid);
        if (_topoSavedPositions[key]) {
            delete _topoSavedPositions[key];
            _topoNodesDS.update({ id: nid, fixed: false, physics: true });
            // Delete just this node's position from server
            api.saveTopologyPositions({ [key]: null }).catch(() => {});
            showToast('Node unpinned', 'info');
        }
    });

    // Cursor: grab when hovering a node, grabbing while dragging
    _topologyNetwork.on('hoverNode', () => { container.style.cursor = 'grab'; });
    _topologyNetwork.on('blurNode', () => { container.style.cursor = 'default'; });
    _topologyNetwork.on('dragStart', (params) => {
        if (params.nodes.length) container.style.cursor = 'grabbing';
    });
    _topologyNetwork.on('dragEnd', () => { container.style.cursor = 'default'; });

    // For hierarchical layouts: once layout computes, capture positions
    // then switch to free mode so nodes can be dragged in any direction
    if (isHierarchical) {
        _topologyNetwork.once('stabilizationIterationsDone', () => {
            const computedPos = _topologyNetwork.getPositions();
            // Apply computed positions to nodes that don't have saved positions
            const nodeUpdates = [];
            for (const [nid, pos] of Object.entries(computedPos)) {
                if (!_topoSavedPositions[String(nid)]) {
                    nodeUpdates.push({ id: /^\d+$/.test(nid) ? Number(nid) : nid, x: pos.x, y: pos.y });
                }
            }
            if (nodeUpdates.length) _topoNodesDS.update(nodeUpdates);
            // Switch off hierarchical layout to allow free dragging
            _topologyNetwork.setOptions({
                layout: { hierarchical: { enabled: false } },
                physics: { enabled: false },
            });
            _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        });
    } else if (usePhysics) {
        _topologyNetwork.once('stabilizationIterationsDone', () => {
            _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        });
    } else if (allPinned || isCircular) {
        // All nodes positioned — just fit to view
        setTimeout(() => _topologyNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }), 50);
    }
}

let _savePositionTimer = null;
async function _saveNodePositions(positionsMap) {
    // Debounce: batch rapid drags into one API call
    clearTimeout(_savePositionTimer);
    _savePositionTimer = setTimeout(async () => {
        try {
            await api.saveTopologyPositions(positionsMap);
        } catch (e) {
            console.warn('Failed to save topology positions:', e.message);
        }
    }, 500);
}

async function resetTopologyPositions() {
    try {
        await api.deleteTopologyPositions();
        _topoSavedPositions = {};
        showToast('Node positions reset — physics re-enabled', 'success');
        // Unpin all nodes and re-enable physics in-place instead of rebuilding
        if (_topologyNetwork && _topoNodesDS) {
            const updates = _topoNodesDS.getIds().map(id => ({
                id,
                fixed: false,
                physics: true,
            }));
            _topoNodesDS.update(updates);
            // Re-enable physics and force a new stabilization cycle
            _topologyNetwork.setOptions({ physics: { enabled: true } });
            _topologyNetwork.once('stabilizationIterationsDone', () => {
                _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
            });
            _topologyNetwork.stabilize(250);
        }
    } catch (e) {
        showError('Failed to reset positions: ' + e.message);
    }
}

function showTopologyNodeDetails(node, allEdges) {
    const panel = document.getElementById('topology-details');
    const title = document.getElementById('topology-details-title');
    const content = document.getElementById('topology-details-content');

    title.textContent = node.label || 'Unknown';
    const connectedEdges = (allEdges || []).filter(e =>
        e.from === node.id || e.to === node.id
    );

    const esc = (s) => escapeHtml(String(s ?? ''));
    let html = `
        <div class="topology-detail-section">
            <div class="topology-detail-row"><span class="topology-detail-label">IP Address</span><span>${esc(node.ip || 'N/A')}</span></div>
            <div class="topology-detail-row"><span class="topology-detail-label">Device Type</span><span>${esc(node.device_type || 'unknown')}</span></div>
            <div class="topology-detail-row"><span class="topology-detail-label">Status</span><span class="status-badge status-${esc(node.status || 'unknown')}">${esc(node.status || 'unknown')}</span></div>
            ${node.group_name ? `<div class="topology-detail-row"><span class="topology-detail-label">Group</span><span>${esc(node.group_name)}</span></div>` : ''}
            <div class="topology-detail-row"><span class="topology-detail-label">In Inventory</span><span>${node.in_inventory ? 'Yes' : 'No'}</span></div>
            ${node.platform ? `<div class="topology-detail-row"><span class="topology-detail-label">Platform</span><span>${esc(node.platform)}</span></div>` : ''}
        </div>
    `;

    if (connectedEdges.length > 0) {
        html += `<h4 style="margin-top:1rem; margin-bottom:0.5rem; color:var(--text-color);">Connections (${connectedEdges.length})</h4>`;
        html += '<div class="topology-detail-section">';
        for (const edge of connectedEdges) {
            const isSource = edge.from === node.id;
            const peerLabel = isSource
                ? (_topologyData?.nodes?.find(n => n.id === edge.to)?.label || edge.to)
                : (_topologyData?.nodes?.find(n => n.id === edge.from)?.label || edge.from);
            const proto = { cdp: 'CDP', lldp: 'LLDP', ospf: 'OSPF', bgp: 'BGP' }[edge.protocol] || edge.protocol?.toUpperCase() || 'L2';
            const util = edge.utilization;
            const utilHtml = util ? `<span style="font-size:0.7rem; padding:0.1rem 0.35rem; border-radius:0.2rem; background:${util.utilization_pct > 75 ? 'rgba(244,67,54,0.2)' : util.utilization_pct > 50 ? 'rgba(255,235,59,0.15)' : 'rgba(76,175,80,0.15)'}; color:${util.utilization_pct > 75 ? '#ef5350' : util.utilization_pct > 50 ? '#fdd835' : '#66bb6a'};">${util.utilization_pct}% (${_formatBps(util.in_bps)} in / ${_formatBps(util.out_bps)} out)</span>` : '';
            const stp = _lookupStpForEdge(edge);
            const stpHtml = stp ? `<span style="font-size:0.7rem; padding:0.1rem 0.35rem; border-radius:0.2rem; background:rgba(67,160,71,0.14); color:#81c784;">STP ${escapeHtml(stp.port_state || 'unknown')}${stp.port_role ? '/' + escapeHtml(stp.port_role) : ''} VLAN ${escapeHtml(stp.vlan_id || '')}</span>` : '';
            html += `<div class="topology-detail-row" style="flex-direction:column; align-items:flex-start; gap:0.15rem;">
                <span style="font-weight:500; color:var(--text-color);">${esc(peerLabel)}</span>
                <span style="font-size:0.75rem; color:var(--text-muted);">${esc(edge.source_interface || '')} &harr; ${esc(edge.target_interface || '')} &middot; ${esc(proto)}</span>
                ${utilHtml}
                ${stpHtml}
            </div>`;
        }
        html += '</div>';
    }

    if (!node.in_inventory && node.ip) {
        html += `<button class="btn btn-primary btn-sm topology-add-inventory-btn" style="margin-top:1rem; width:100%;"
                         data-hostname="${esc(node.label)}" data-ip="${esc(node.ip)}">Add to Inventory</button>`;
    }

    content.innerHTML = html;
    const addBtn = content.querySelector('.topology-add-inventory-btn');
    if (addBtn) {
        addBtn.addEventListener('click', () => {
            addTopologyNodeToInventory(addBtn.dataset.hostname, addBtn.dataset.ip);
        });
    }
    panel.style.display = 'flex';
}

function closeTopologyDetails() {
    document.getElementById('topology-details').style.display = 'none';
}

async function addTopologyNodeToInventory(hostname, ip) {
    try {
        const groups = await api.getInventoryGroups(false);
        if (!groups || groups.length === 0) {
            showError('No inventory groups available. Create a group first.');
            return;
        }
        // Add to the first group by default
        await api.addHost(groups[0].id, hostname, ip, 'unknown');
        showToast(`Added ${hostname} (${ip}) to ${groups[0].name}`, 'success');
        invalidatePageCache('topology');
        invalidatePageCache('inventory');
        await loadTopology({ preserveContent: true });
    } catch (error) {
        showError('Failed to add host: ' + error.message);
    }
}

async function discoverTopology() {
    const btn = document.getElementById('topology-discover-btn');
    const groupFilter = document.getElementById('topology-group-filter').value;
    btn.disabled = true;
    btn.textContent = 'Discovering...';

    // Show live progress modal
    showModal('Neighbor Discovery', `
        <div style="padding: 1.5rem 1rem;">
            <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                <div class="discovery-spinner" id="disco-spinner"></div>
                <div>
                    <div style="font-size: 1rem; font-weight: 600;" id="disco-title">Initializing discovery...</div>
                    <div style="color: var(--text-muted); font-size: 0.85rem;" id="disco-subtitle">
                        Preparing to scan hosts via SNMP
                    </div>
                </div>
            </div>
            <div style="margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.35rem;">
                    <span><span id="disco-scanned">0</span> / <span id="disco-total">?</span> hosts scanned</span>
                    <span><span id="disco-links" style="color: var(--primary-light); font-weight: 600;">0</span> links found</span>
                </div>
                <div style="height: 6px; background: var(--bg-secondary); border-radius: 3px; overflow: hidden;">
                    <div id="disco-progress-bar" style="height: 100%; width: 0%; background: var(--primary); border-radius: 3px; transition: width 0.15s ease;"></div>
                </div>
            </div>
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.5rem;">
                Elapsed: <span id="disco-elapsed">0s</span> &middot; <span id="disco-step">Waiting for stream...</span>
            </div>
            <div id="disco-feed" style="max-height: 220px; overflow-y: auto; border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.4rem 0.6rem; font-size: 0.8rem; font-family: monospace; background: var(--bg-secondary);"></div>
        </div>
    `);

    // Elapsed timer
    const startTime = Date.now();
    const elapsedInterval = setInterval(() => {
        const el = document.getElementById('disco-elapsed');
        if (el) {
            const sec = Math.floor((Date.now() - startTime) / 1000);
            el.textContent = sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
        }
    }, 1000);

    let totalLinks = 0;
    let finalResult = null;

    function appendFeed(text, color) {
        const feedEl = document.getElementById('disco-feed');
        if (!feedEl) return;
        const entry = document.createElement('div');
        entry.style.cssText = `padding: 0.15rem 0; border-bottom: 1px solid var(--border); color: ${color || 'var(--text-primary)'};`;
        entry.textContent = text;
        feedEl.appendChild(entry);
        feedEl.scrollTop = feedEl.scrollHeight;
    }

    try {
        await api.discoverTopologyStream(groupFilter || null, (event) => {
            const titleEl = document.getElementById('disco-title');
            const subtitleEl = document.getElementById('disco-subtitle');
            const stepEl = document.getElementById('disco-step');
            const scannedEl = document.getElementById('disco-scanned');
            const totalEl = document.getElementById('disco-total');
            const barEl = document.getElementById('disco-progress-bar');
            const linksEl = document.getElementById('disco-links');

            if (event.type === 'start') {
                if (totalEl) totalEl.textContent = event.total_hosts;
                if (titleEl) titleEl.textContent = `Discovering neighbors across ${event.total_groups} group(s)...`;
                if (subtitleEl) subtitleEl.textContent = `${event.total_hosts} host(s) to scan`;
                appendFeed(`Starting discovery: ${event.total_hosts} hosts in ${event.total_groups} group(s)`, 'var(--text-muted)');

            } else if (event.type === 'group_start') {
                if (stepEl) stepEl.textContent = `Scanning group: ${event.group}`;
                appendFeed(`\u25B6 Group "${event.group}" \u2014 ${event.host_count} host(s)`, 'var(--primary-light)');

            } else if (event.type === 'host_walked') {
                if (scannedEl) scannedEl.textContent = event.scanned;
                if (barEl && event.total_hosts) barEl.style.width = `${Math.round((event.scanned / event.total_hosts) * 100)}%`;
                if (stepEl) stepEl.textContent = `Walked ${event.hostname}`;
                totalLinks += event.neighbors;
                if (linksEl) linksEl.textContent = totalLinks;

                if (event.ok) {
                    const color = event.neighbors > 0 ? 'var(--success-color, #22c55e)' : 'var(--text-muted)';
                    const icon = event.neighbors > 0 ? '\u2713' : '\u2013';
                    appendFeed(`  ${icon} ${event.hostname} (${event.ip}) \u2014 ${event.neighbors} neighbor(s)`, color);
                } else {
                    appendFeed(`  \u2717 ${event.hostname} (${event.ip}) \u2014 failed`, 'var(--danger-color, #ef4444)');
                }

            } else if (event.type === 'db_write_start') {
                if (stepEl) stepEl.textContent = `Saving results for ${event.group}...`;
                appendFeed(`  Saving topology data for "${event.group}"...`, 'var(--text-muted)');

            } else if (event.type === 'group_done') {
                appendFeed(`\u2714 Group "${event.group}" complete \u2014 ${event.links} link(s)`, 'var(--success-color, #22c55e)');

            } else if (event.type === 'resolving') {
                if (stepEl) stepEl.textContent = 'Resolving neighbor identities...';
                appendFeed('Resolving neighbor host IDs against inventory...', 'var(--text-muted)');

            } else if (event.type === 'done') {
                finalResult = event;

            } else if (event.type === 'error') {
                appendFeed(`Error: ${event.message}`, 'var(--danger-color, #ef4444)');
            }
        });

        // Update modal to show completion
        const spinnerEl = document.getElementById('disco-spinner');
        const titleEl = document.getElementById('disco-title');
        const stepEl = document.getElementById('disco-step');
        const barEl = document.getElementById('disco-progress-bar');

        if (spinnerEl) spinnerEl.style.display = 'none';
        if (barEl) barEl.style.width = '100%';

        if (finalResult) {
            if (titleEl) titleEl.textContent = 'Discovery Complete';
            if (stepEl) stepEl.textContent = `${finalResult.links_discovered} links from ${finalResult.hosts_scanned} hosts`;
            appendFeed(`\u2501\u2501 Done: ${finalResult.links_discovered} links, ${finalResult.hosts_scanned} hosts scanned, ${finalResult.errors} error(s)`, 'var(--primary-light)');

            const msg = `Discovered ${finalResult.links_discovered} links from ${finalResult.hosts_scanned} hosts` +
                (finalResult.errors > 0 ? ` (${finalResult.errors} errors)` : '');
            showToast(msg, finalResult.errors > 0 ? 'warning' : 'success');
        } else {
            if (titleEl) titleEl.textContent = 'Discovery Finished';
            if (stepEl) stepEl.textContent = 'No results received';
        }

        invalidatePageCache('topology');
        await loadTopology({ preserveContent: true });
    } catch (error) {
        if (error.name === 'AbortError') return; // navigated away — silently cancel
        const spinnerEl = document.getElementById('disco-spinner');
        if (spinnerEl) spinnerEl.style.display = 'none';
        appendFeed(`Error: ${error.message}`, 'var(--danger-color, #ef4444)');
        showError('Discovery failed: ' + error.message);
    } finally {
        clearInterval(elapsedInterval);
        btn.disabled = false;
        btn.textContent = 'Discover Neighbors';
    }
}

async function refreshTopology() {
    invalidatePageCache('topology');
    // If no network exists yet, do a full load
    if (!_topologyNetwork || !_topoNodesDS || !_topoEdgesDS) {
        loadTopology({ preserveContent: false });
        return;
    }
    // Fetch fresh data + positions without rebuilding the graph
    const groupFilter = document.getElementById('topology-group-filter').value;
    try {
        const [data, positions] = await Promise.all([
            api.getTopology(groupFilter || null),
            api.getTopologyPositions().catch(() => ({})),
        ]);
        _topologyData = data;
        _topoSavedPositions = positions || {};

        const container = document.querySelector('.topology-container');
        const legend = document.getElementById('topology-legend');
        const emptyEl = document.getElementById('topology-empty');

        if (!data.nodes || data.nodes.length === 0) {
            container.style.display = 'none';
            legend.style.display = 'none';
            emptyEl.style.display = 'flex';
            _topologyNetwork.destroy(); _topologyNetwork = null;
            _topoNodesDS = null; _topoEdgesDS = null;
            return;
        }
        container.style.display = 'flex';
        legend.style.display = 'flex';
        emptyEl.style.display = 'none';

        // Capture current positions from the live network for nodes without saved positions
        const currentPositions = _topologyNetwork.getPositions();
        const mergedPos = { ..._topoSavedPositions };
        for (const [nid, pos] of Object.entries(currentPositions)) {
            if (!mergedPos[String(nid)]) {
                mergedPos[String(nid)] = { x: Math.round(pos.x), y: Math.round(pos.y) };
            }
        }

        // Update nodes in-place: add new, update existing, remove stale
        const newNodeIds = new Set(data.nodes.map(n => n.id));
        const existingNodeIds = new Set(_topoNodesDS.getIds());

        // Remove nodes no longer in data
        const toRemove = [...existingNodeIds].filter(id => !newNodeIds.has(id));
        if (toRemove.length) _topoNodesDS.remove(toRemove);

        // Add or update nodes
        const nodeUpdates = data.nodes.map(n => _buildVisNode(n, mergedPos));
        _topoNodesDS.update(nodeUpdates);

        // Update edges in-place
        const newEdgeIds = new Set(data.edges.map(e => e.id));
        const existingEdgeIds = new Set(_topoEdgesDS.getIds());
        const edgesToRemove = [...existingEdgeIds].filter(id => !newEdgeIds.has(id));
        if (edgesToRemove.length) _topoEdgesDS.remove(edgesToRemove);
        const edgeUpdates = data.edges.map(e => _buildVisEdge(e));
        _topoEdgesDS.update(edgeUpdates);

        if (_topoStpOverlay) {
            try {
                await _loadStpOverlayData();
            } catch (e) {
                _topoStpStateByPort = new Map();
            }
            _refreshTopologyEdgeStyles();
        } else {
            _refreshTopologyEdgeStyles();
            api.getTopologyStpEvents(true, 1)
                .then(resp => _updateStpEventBadge(resp.unacknowledged_count || 0))
                .catch(() => {});
        }

        _updateTopologyChangeBadge(data.unacknowledged_changes || 0);
        showToast('Topology refreshed', 'success');
    } catch (error) {
        showError('Failed to refresh topology: ' + error.message);
    }
}

function fitTopology() {
    if (_topologyNetwork) {
        _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
    }
}

// ── Path View ──

function togglePathMode() {
    const btn = document.getElementById('topology-path-btn');
    const bar = document.getElementById('topology-path-bar');
    if (_topoPathMode) {
        clearPathMode();
        return;
    }
    if (!_topologyNetwork || !_topologyData || !_topologyData.nodes.length) return;
    _topoPathMode = true;
    _topoPathSource = null;
    btn.classList.add('btn-active');
    bar.style.display = 'flex';
    document.getElementById('topology-path-status').textContent = 'Click a source node...';
    closeTopologyDetails();
}

function clearPathMode() {
    _topoPathMode = false;
    _topoPathSource = null;
    const btn = document.getElementById('topology-path-btn');
    const bar = document.getElementById('topology-path-bar');
    btn.classList.remove('btn-active');
    bar.style.display = 'none';
    // Restore original colors
    if (_topoOriginalColors && _topoNodesDS && _topoEdgesDS) {
        for (const [id, color] of _topoOriginalColors.nodes) {
            _topoNodesDS.update({ id, color, opacity: 1 });
        }
        for (const [id, color] of _topoOriginalColors.edges) {
            _topoEdgesDS.update({ id, color, opacity: 1 });
        }
        _topoOriginalColors = null;
    }
}

function _handlePathClick(nodeId, nodesDS, edgesDS, data) {
    if (!_topoPathSource) {
        _topoPathSource = nodeId;
        const label = nodesDS.get(nodeId)?.label || nodeId;
        document.getElementById('topology-path-status').textContent = `Source: ${label}  —  click a destination node...`;
        // Highlight source
        nodesDS.update({ id: nodeId, borderWidth: 4 });
        return;
    }

    const targetId = nodeId;
    if (targetId === _topoPathSource) return;

    // BFS shortest path
    const path = _bfsShortestPath(_topoPathSource, targetId, data);
    if (!path) {
        showToast('No path found between these nodes.', 'warning');
        clearPathMode();
        return;
    }

    _highlightPath(path, nodesDS, edgesDS, data);

    const srcLabel = nodesDS.get(_topoPathSource)?.label || _topoPathSource;
    const tgtLabel = nodesDS.get(targetId)?.label || targetId;
    document.getElementById('topology-path-status').textContent =
        `Path: ${srcLabel} → ${tgtLabel}  (${path.length - 1} hop${path.length - 1 !== 1 ? 's' : ''})`;

    _topoPathMode = false;
    document.getElementById('topology-path-btn').classList.remove('btn-active');
}

function _bfsShortestPath(startId, endId, data) {
    // Build adjacency list from edges
    const adj = new Map();
    for (const edge of data.edges) {
        if (!adj.has(edge.from)) adj.set(edge.from, []);
        if (!adj.has(edge.to)) adj.set(edge.to, []);
        adj.get(edge.from).push(edge.to);
        adj.get(edge.to).push(edge.from);
    }

    const visited = new Set();
    const queue = [[startId]];
    visited.add(startId);

    while (queue.length > 0) {
        const path = queue.shift();
        const current = path[path.length - 1];
        if (current === endId) return path;

        for (const neighbor of (adj.get(current) || [])) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push([...path, neighbor]);
            }
        }
    }
    return null;  // No path found
}

function _highlightPath(path, nodesDS, edgesDS, data) {
    const pathSet = new Set(path);

    // Find edges on the path
    const pathEdgeIds = new Set();
    for (let i = 0; i < path.length - 1; i++) {
        const a = path[i], b = path[i + 1];
        const edge = data.edges.find(e =>
            (e.from === a && e.to === b) || (e.from === b && e.to === a)
        );
        if (edge) pathEdgeIds.add(edge.id);
    }

    // Stash original colors for restore
    _topoOriginalColors = { nodes: [], edges: [] };
    const tc = _topoThemeColors || _getTopoThemeColors();

    for (const node of nodesDS.get()) {
        _topoOriginalColors.nodes.push([node.id, node.color]);
        if (!pathSet.has(node.id)) {
            nodesDS.update({ id: node.id, color: tc.dimColor, opacity: 0.3 });
        } else {
            // Brighten path nodes
            nodesDS.update({
                id: node.id,
                borderWidth: 4,
                shadow: { enabled: true, color: tc.pathGlow, size: 20, x: 0, y: 0 },
            });
        }
    }

    for (const edge of edgesDS.get()) {
        _topoOriginalColors.edges.push([edge.id, edge.color]);
        if (!pathEdgeIds.has(edge.id)) {
            edgesDS.update({ id: edge.id, color: tc.dimEdge, opacity: 0.15 });
        } else {
            // Brighten path edges
            edgesDS.update({
                id: edge.id,
                width: 4,
                shadow: { enabled: true, color: tc.pathGlow, size: 12, x: 0, y: 0 },
            });
        }
    }
}

// ── Node Search ──

let _topoSearchDebounce = null;

function _onTopoSearchInput() {
    clearTimeout(_topoSearchDebounce);
    const input = document.getElementById('topology-search');
    const resultsEl = document.getElementById('topology-search-results');
    const query = (input?.value || '').trim().toLowerCase();
    if (!query || !_topologyData || !_topologyData.nodes.length) {
        resultsEl.style.display = 'none';
        return;
    }
    _topoSearchDebounce = setTimeout(() => {
        const matches = _topologyData.nodes.filter(n =>
            (n.label || '').toLowerCase().includes(query) ||
            (n.ip || '').includes(query)
        ).slice(0, 12);

        if (matches.length === 0) {
            resultsEl.innerHTML = '<div class="topology-search-item" style="color:rgba(180,210,240,0.4); cursor:default;">No matches</div>';
        } else {
            resultsEl.innerHTML = matches.map(n => {
                const qRe = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
                const label = escapeHtml(n.label || '').replace(qRe, '<mark>$1</mark>');
                const ip = escapeHtml(n.ip || '').replace(qRe, '<mark>$1</mark>');
                return `<div class="topology-search-item" data-node-id="${n.id}">${label}${n.ip ? `<span class="search-ip">${ip}</span>` : ''}</div>`;
            }).join('');
        }
        resultsEl.style.display = 'block';
    }, 150);
}

function _onTopoSearchResultClick(e) {
    const item = e.target.closest('.topology-search-item');
    if (!item || !item.dataset.nodeId) return;
    const nodeId = isNaN(item.dataset.nodeId) ? item.dataset.nodeId : Number(item.dataset.nodeId);
    _focusTopologyNode(nodeId);
    document.getElementById('topology-search').value = '';
    document.getElementById('topology-search-results').style.display = 'none';
}

function _focusTopologyNode(nodeId) {
    if (!_topologyNetwork) return;
    _topologyNetwork.focus(nodeId, {
        scale: 1.5,
        animation: { duration: 600, easingFunction: 'easeInOutQuad' },
    });
    _topologyNetwork.selectNodes([nodeId]);
    // Show details
    const node = (_topologyData?.nodes || []).find(n => n.id === nodeId);
    if (node) showTopologyNodeDetails(node, _topologyData.edges);
}

// ── Listener management (attached after lazy DOM is ready) ──

let _topoListenersBound = false;

function _onTopoSearchKeydown(e) {
    const resultsEl = document.getElementById('topology-search-results');
    const items = resultsEl?.querySelectorAll('.topology-search-item[data-node-id]') || [];
    if (!items.length) return;
    const activeItem = resultsEl.querySelector('.topology-search-item.active');
    let idx = Array.from(items).indexOf(activeItem);
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        idx = Math.min(idx + 1, items.length - 1);
        items.forEach(i => i.classList.remove('active'));
        items[idx].classList.add('active');
        items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        idx = Math.max(idx - 1, 0);
        items.forEach(i => i.classList.remove('active'));
        items[idx].classList.add('active');
        items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
        e.preventDefault();
        if (activeItem && activeItem.dataset.nodeId) {
            const nodeId = isNaN(activeItem.dataset.nodeId) ? activeItem.dataset.nodeId : Number(activeItem.dataset.nodeId);
            _focusTopologyNode(nodeId);
            document.getElementById('topology-search').value = '';
            resultsEl.style.display = 'none';
        }
    } else if (e.key === 'Escape') {
        resultsEl.style.display = 'none';
    }
}

function _onTopoDocClick(e) {
    if (!e.target.closest('.topology-search-wrap')) {
        const el = document.getElementById('topology-search-results');
        if (el) el.style.display = 'none';
    }
}

function _onTopoGroupFilterChange() {
    invalidatePageCache('topology');
    loadTopology({ preserveContent: false });
}

function _onTopoLayoutChange() {
    if (_topologyData) renderTopologyGraph(_topologyData);
}

function _initTopoListeners() {
    if (_topoListenersBound) return;
    _topoListenersBound = true;
    document.getElementById('topology-search')?.addEventListener('input', _onTopoSearchInput);
    document.getElementById('topology-search')?.addEventListener('keydown', _onTopoSearchKeydown);
    document.getElementById('topology-search-results')?.addEventListener('click', _onTopoSearchResultClick);
    document.addEventListener('click', _onTopoDocClick);
    document.getElementById('topology-group-filter')?.addEventListener('change', _onTopoGroupFilterChange);
    document.getElementById('topology-layout')?.addEventListener('change', _onTopoLayoutChange);
    document.getElementById('topology-stp-vlan')?.addEventListener('change', _onStpVlanChange);
    document.getElementById('topology-stp-all-vlans')?.addEventListener('change', _onStpAllVlansToggle);
    _syncStpVlanControlState();
}

function _removeTopoDocListeners() {
    if (!_topoListenersBound) return;
    _topoListenersBound = false;
    document.getElementById('topology-search')?.removeEventListener('input', _onTopoSearchInput);
    document.getElementById('topology-search')?.removeEventListener('keydown', _onTopoSearchKeydown);
    document.getElementById('topology-search-results')?.removeEventListener('click', _onTopoSearchResultClick);
    document.removeEventListener('click', _onTopoDocClick);
    document.getElementById('topology-group-filter')?.removeEventListener('change', _onTopoGroupFilterChange);
    document.getElementById('topology-layout')?.removeEventListener('change', _onTopoLayoutChange);
    document.getElementById('topology-stp-vlan')?.removeEventListener('change', _onStpVlanChange);
    document.getElementById('topology-stp-all-vlans')?.removeEventListener('change', _onStpAllVlansToggle);
}

// ── Layout Settings ──

function toggleTopologySettings() {
    const pop = document.getElementById('topology-settings-popover');
    if (!pop) return;
    pop.style.display = pop.style.display === 'none' ? 'block' : 'none';
}

function onTopologySettingChange() {
    const spacingEl = document.getElementById('topo-setting-spacing');
    const repulsionEl = document.getElementById('topo-setting-repulsion');
    const edgeLenEl = document.getElementById('topo-setting-edgelen');
    if (!spacingEl || !repulsionEl || !edgeLenEl) return;

    const spacing = parseInt(spacingEl.value, 10);
    const repulsion = parseInt(repulsionEl.value, 10);
    const edgeLen = parseInt(edgeLenEl.value, 10);

    // Update displayed values
    document.getElementById('topo-setting-spacing-val').textContent = spacing;
    document.getElementById('topo-setting-repulsion-val').textContent = repulsion;
    document.getElementById('topo-setting-edgelen-val').textContent = edgeLen;

    if (!_topologyNetwork) return;

    const layoutMode = document.getElementById('topology-layout').value;
    if (layoutMode.startsWith('hierarchical-')) {
        _topologyNetwork.setOptions({
            layout: {
                hierarchical: {
                    nodeSpacing: spacing,
                    levelSeparation: Math.round(edgeLen * 0.78),
                },
            },
        });
    } else if (layoutMode === 'physics') {
        _topologyNetwork.setOptions({
            physics: {
                enabled: true,
                barnesHut: {
                    gravitationalConstant: -repulsion,
                    springLength: edgeLen,
                    avoidOverlap: 0.3,
                },
            },
        });
        _topologyNetwork.stabilize(200);
    }
}

// ── Export ──

function exportTopologyPNG() {
    if (!_topologyNetwork) { showToast('No topology to export', 'warning'); return; }
    const canvas = document.getElementById('topology-canvas')?.querySelector('canvas');
    if (!canvas) { showToast('Canvas not found', 'warning'); return; }
    try {
        const headerHeight = 48;
        const out = document.createElement('canvas');
        out.width = canvas.width;
        out.height = canvas.height + headerHeight;
        const ctx = out.getContext('2d');

        // White background
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, out.width, out.height);

        // Title bar
        const groupFilter = document.getElementById('topology-group-filter');
        const groupName = groupFilter?.selectedOptions?.[0]?.textContent || 'All Groups';
        const dateStr = new Date().toLocaleDateString();
        ctx.fillStyle = '#f5f5f5';
        ctx.fillRect(0, 0, out.width, headerHeight);
        ctx.fillStyle = '#333';
        ctx.font = 'bold 16px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(`Network Topology — ${groupName}`, out.width / 2, 22);
        ctx.font = '11px Inter, sans-serif';
        ctx.fillStyle = '#888';
        ctx.fillText(dateStr, out.width / 2, 38);

        // Draw the topology canvas below the header
        ctx.drawImage(canvas, 0, headerHeight);

        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.png`;
        link.href = out.toDataURL('image/png');
        link.click();
        showToast('PNG exported', 'success');
    } catch (err) {
        showError('Failed to export PNG: ' + err.message);
    }
}

function exportTopologyJSON() {
    if (!_topologyData) { showToast('No topology to export', 'warning'); return; }
    try {
        const blob = new Blob([JSON.stringify(_topologyData, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.json`;
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        showToast('JSON exported', 'success');
    } catch (err) {
        showError('Failed to export JSON: ' + err.message);
    }
}

function printTopology() {
    if (!_topologyNetwork) { showToast('No topology to print', 'warning'); return; }
    window.print();
}

// ── SVG Export ──

function exportTopologySVG() {
    if (!_topologyNetwork || !_topologyData) { showToast('No topology to export', 'warning'); return; }
    try {
        const positions = _topologyNetwork.getPositions();
        const nodeMap = {};
        (_topologyData.nodes || []).forEach(n => { nodeMap[n.id] = n; });

        // Calculate bounds
        const posArray = Object.values(positions);
        if (posArray.length === 0) { showToast('No nodes to export', 'warning'); return; }
        const margin = 80;
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        posArray.forEach(p => {
            if (p.x < minX) minX = p.x;
            if (p.y < minY) minY = p.y;
            if (p.x > maxX) maxX = p.x;
            if (p.y > maxY) maxY = p.y;
        });
        const width = maxX - minX + margin * 2;
        const height = maxY - minY + margin * 2;
        const ox = -minX + margin;
        const oy = -minY + margin;

        const tc = _topoThemeColors || _getTopoThemeColors();
        let edgeSvg = '';
        let nodeSvg = '';

        // Draw edges
        (_topologyData.edges || []).forEach(e => {
            const fromPos = positions[e.from];
            const toPos = positions[e.to];
            if (!fromPos || !toPos) return;
            const proto = (e.protocol || 'cdp').toLowerCase();
            const color = tc.edgeColors?.[proto] || '#888';
            const dash = proto === 'lldp' ? ' stroke-dasharray="8 5"' : proto === 'ospf' ? ' stroke-dasharray="12 4 4 4"' : proto === 'bgp' ? ' stroke-dasharray="4 4"' : '';
            edgeSvg += `<line x1="${fromPos.x + ox}" y1="${fromPos.y + oy}" x2="${toPos.x + ox}" y2="${toPos.y + oy}" stroke="${color}" stroke-width="2"${dash} opacity="0.7"/>`;
            if (e.label) {
                const mx = (fromPos.x + toPos.x) / 2 + ox;
                const my = (fromPos.y + toPos.y) / 2 + oy;
                edgeSvg += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="8" fill="#999" font-family="Inter, sans-serif">${_svgEscape(e.label)}</text>`;
            }
        });

        // Draw nodes
        Object.entries(positions).forEach(([id, pos]) => {
            const n = nodeMap[id] || nodeMap[Number(id)];
            if (!n) return;
            const cx = pos.x + ox;
            const cy = pos.y + oy;
            const r = n.in_inventory ? 20 : 14;
            const fill = n.in_inventory ? (tc.vendorColors?.unknown || '#607D8B') : 'none';
            const stroke = n.in_inventory ? '#fff' : '#999';
            const dashAttr = n.in_inventory ? '' : ' stroke-dasharray="5 5"';
            nodeSvg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="2"${dashAttr}/>`;
            nodeSvg += `<text x="${cx}" y="${cy + r + 14}" text-anchor="middle" font-size="11" fill="#ddd" font-family="Inter, sans-serif">${_svgEscape(n.label)}</text>`;
        });

        // Title
        const groupFilter = document.getElementById('topology-group-filter');
        const groupName = groupFilter?.selectedOptions?.[0]?.textContent || 'All Groups';
        const dateStr = new Date().toLocaleDateString();
        const titleSvg = `<text x="${width / 2}" y="24" text-anchor="middle" font-size="16" font-weight="bold" fill="#ccc" font-family="Inter, sans-serif">Network Topology — ${_svgEscape(groupName)} — ${dateStr}</text>`;

        const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height + 40}" viewBox="0 0 ${width} ${height + 40}">
<rect width="100%" height="100%" fill="#1a1a2e"/>
<g transform="translate(0,40)">
${titleSvg}
${edgeSvg}
${nodeSvg}
</g>
</svg>`;

        const blob = new Blob([svg], { type: 'image/svg+xml' });
        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.svg`;
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        showToast('SVG exported', 'success');
    } catch (err) {
        showError('Failed to export SVG: ' + err.message);
    }
}

function _svgEscape(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Topology Change Detection UI ─────────────────────────────────────────────

function _updateTopologyChangeBadge(count) {
    const badge = document.getElementById('topology-change-badge');
    const btn = document.getElementById('topology-changes-btn');
    if (!badge || !btn) return;
    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.style.display = 'inline-flex';
        btn.classList.add('has-changes');
    } else {
        badge.style.display = 'none';
        btn.classList.remove('has-changes');
    }
}

async function showTopologyChanges() {
    try {
        const resp = await api.getTopologyChanges(false, 200);
        const changes = resp.changes || [];
        if (changes.length === 0) {
            showToast('No topology changes recorded', 'info');
            return;
        }

        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        title.textContent = 'Topology Changes';

        let html = `<div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="color:var(--text-muted); font-size:0.85rem;">${changes.length} change${changes.length !== 1 ? 's' : ''} detected</span>
            <button class="btn btn-secondary btn-sm" onclick="acknowledgeTopologyChanges()">Acknowledge All</button>
        </div>`;
        html += '<div style="max-height:400px; overflow-y:auto;">';
        const cs = getComputedStyle(document.documentElement);
        const successColor = cs.getPropertyValue('--success').trim() || '#00e676';
        const dangerColor = cs.getPropertyValue('--danger').trim() || '#ef5350';

        for (const c of changes) {
            const isAdded = c.change_type === 'added';
            const icon = isAdded ? '+' : '&minus;';
            const color = isAdded ? successColor : dangerColor;
            const bg = color + '14';
            const ackClass = c.acknowledged ? ' style="opacity:0.5;"' : '';
            const proto = { cdp: 'CDP', lldp: 'LLDP', ospf: 'OSPF', bgp: 'BGP' }[c.protocol] || escapeHtml(c.protocol?.toUpperCase() || '');

            html += `<div class="topology-change-item"${ackClass} style="background:${bg}; border-left:3px solid ${color}; padding:0.5rem 0.75rem; margin-bottom:0.4rem; border-radius:0.25rem;">
                <div style="display:flex; justify-content:space-between; align-items:baseline;">
                    <span style="font-weight:600; color:${color}; font-size:0.9rem;">${icon} ${c.change_type.toUpperCase()}</span>
                    <span style="font-size:0.7rem; color:var(--text-muted);">${new Date(c.detected_at + 'Z').toLocaleString()}</span>
                </div>
                <div style="font-size:0.82rem; margin-top:0.2rem;">
                    <strong>${escapeHtml(c.source_hostname || 'Host #' + c.source_host_id)}</strong>
                    ${c.source_interface ? `(${escapeHtml(c.source_interface)})` : ''}
                    &harr;
                    <strong>${escapeHtml(c.target_device_name || c.target_ip || 'unknown')}</strong>
                    ${c.target_interface ? `(${escapeHtml(c.target_interface)})` : ''}
                    ${proto ? `<span style="margin-left:0.4rem; font-size:0.7rem; padding:0.1rem 0.35rem; background:rgba(255,255,255,0.07); border-radius:0.2rem;">${proto}</span>` : ''}
                </div>
            </div>`;
        }
        html += '</div>';
        body.innerHTML = html;
        document.getElementById('modal-overlay').classList.add('active');
    } catch (err) {
        showError('Failed to load topology changes: ' + err.message);
    }
}

async function acknowledgeTopologyChanges() {
    try {
        const resp = await api.acknowledgeTopologyChanges();
        showToast(`Acknowledged ${resp.acknowledged} change${resp.acknowledged !== 1 ? 's' : ''}`, 'success');
        _updateTopologyChangeBadge(0);
        closeAllModals();
    } catch (err) {
        showError('Failed to acknowledge: ' + err.message);
    }
}

// Expose topology functions for HTML onclick handlers
window.discoverTopology = discoverTopology;
window.refreshTopology = refreshTopology;
window.fitTopology = fitTopology;
window.closeTopologyDetails = closeTopologyDetails;
window.addTopologyNodeToInventory = addTopologyNodeToInventory;
window.togglePathMode = togglePathMode;
window.clearPathMode = clearPathMode;
window.exportTopologyPNG = exportTopologyPNG;
window.exportTopologyJSON = exportTopologyJSON;
window.exportTopologySVG = exportTopologySVG;
window.toggleUtilizationOverlay = toggleUtilizationOverlay;
window.toggleStpOverlay = toggleStpOverlay;
window.scanTopologyStp = scanTopologyStp;
window.showStpTopologyEvents = showStpTopologyEvents;
window.acknowledgeStpTopologyEvents = acknowledgeStpTopologyEvents;
window.showTopologyChanges = showTopologyChanges;
window.acknowledgeTopologyChanges = acknowledgeTopologyChanges;
window.resetTopologyPositions = resetTopologyPositions;
window.toggleTopologySettings = toggleTopologySettings;
window.onTopologySettingChange = onTopologySettingChange;
window.printTopology = printTopology;

// ── Cleanup ──

export function destroyTopology() {
    _stopUtilizationStream();
    clearTimeout(_savePositionTimer);
    _savePositionTimer = null;
    clearTimeout(_topoSearchDebounce);
    _topoSearchDebounce = null;
    _topoUtilOverlay = false;
    _topoStpOverlay = false;
    _topoPathMode = false;
    _topoPathSource = null;
    _topoOriginalColors = null;
    _topoThemeColors = null;
    _topoSavedPositions = {};
    _topoStpStateByPort = new Map();
    _stpLegendVisible(false);
    if (_topologyNetwork) {
        _topologyNetwork.destroy();
    }
    _topologyNetwork = null;
    _topologyData = null;
    _topoNodesDS = null;
    _topoEdgesDS = null;
    // Remove document-level listener
    _removeTopoDocListeners();
}

// ── Exports ──

export { loadTopology };
export { _getTopoThemeColors, _topologyNetwork, _topologyData, _topoNodesDS, _topoEdgesDS, _topoSavedPositions, _buildVisNode, _buildVisEdge };

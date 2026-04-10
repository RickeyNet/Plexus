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

let _utilEventSource = null;

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
    _applyUtilizationToEdges();
}

function _applyUtilizationToEdges() {
    if (_topologyNetwork && _topologyData) {
        const edgesDS = _topologyNetwork.body.data.edges;
        const updates = _topologyData.edges.map(e => {
            const util = e.utilization;
            const hasUtil = _topoUtilOverlay && util && util.utilization_pct != null;
            const utilPct = hasUtil ? util.utilization_pct : 0;
            const utilWidth = hasUtil ? 2 + (utilPct / 100) * 6 : 2;
            const utilColor = hasUtil ? _utilColor(utilPct) : null;
            let edgeLabel = e.label || '';
            if (hasUtil) edgeLabel = `${edgeLabel ? edgeLabel + ' ' : ''}(${utilPct}%)`;
            return {
                id: e.id,
                label: edgeLabel,
                color: utilColor || _topoEdgeColor(e.protocol),
                width: utilWidth,
                shadow: {
                    enabled: true,
                    color: hasUtil ? _utilShadow(utilPct) : ({ lldp: 'rgba(0,230,118,0.3)', ospf: 'rgba(255,171,64,0.3)', bgp: 'rgba(224,64,251,0.3)' }[e.protocol] || 'rgba(0,176,255,0.3)'),
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
                    if (_topoUtilOverlay) _applyUtilizationToEdges();
                }
            } catch (e) { /* parse error, skip */ }
        };
        _utilEventSource.onerror = () => {
            // Reconnect on error after a delay
            _stopUtilizationStream();
            if (_topoUtilOverlay) {
                setTimeout(() => { if (_topoUtilOverlay) _startUtilizationStream(); }, 10000);
            }
        };
    } catch (e) { /* SSE not supported or error */ }
}

function _stopUtilizationStream() {
    if (_utilEventSource) {
        _utilEventSource.close();
        _utilEventSource = null;
    }
}

async function loadTopology(options = {}) {
    const { preserveContent = false } = options;
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
        // Update change badge
        _updateTopologyChangeBadge(data.unacknowledged_changes || 0);
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
        title: `${n.label}\n${n.ip || ''}\nType: ${n.device_type}${n.group_name ? '\nGroup: ' + n.group_name : ''}${n.in_inventory ? '' : '\n(External)'}`,
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
    }
    return node;
}

function _buildVisEdge(e) {
    const util = e.utilization;
    const hasUtil = _topoUtilOverlay && util && util.utilization_pct != null;
    const utilPct = hasUtil ? util.utilization_pct : 0;
    // Use weathermap color/width from API if available, fallback to local calculation
    const utilWidth = hasUtil ? (util.width || (2 + (utilPct / 100) * 6)) : 2;
    const utilColor = hasUtil ? (util.color || _utilColor(utilPct)) : null;
    let edgeLabel = e.label || '';
    if (hasUtil) edgeLabel = `${edgeLabel ? edgeLabel + ' ' : ''}(${utilPct}%)`;
    return {
        id: e.id,
        from: e.from,
        to: e.to,
        label: edgeLabel,
        color: utilColor || _topoEdgeColor(e.protocol),
        dashes: e.protocol === 'lldp' ? [8, 5] : e.protocol === 'ospf' ? [12, 4, 4, 4] : e.protocol === 'bgp' ? [4, 4] : false,
        width: utilWidth,
        hoverWidth: 0.5,
        selectionWidth: 1,
        shadow: {
            enabled: true,
            color: hasUtil ? _utilShadow(utilPct) : ({ lldp: 'rgba(0,230,118,0.3)', ospf: 'rgba(255,171,64,0.3)', bgp: 'rgba(224,64,251,0.3)' }[e.protocol] || 'rgba(0,176,255,0.3)'),
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
    const usePhysics = layoutMode === 'physics' && !allPinned;

    const graphOptions = {
        physics: {
            enabled: usePhysics,
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
        layout: layoutMode === 'hierarchical'
            ? { hierarchical: { direction: 'UD', sortMethod: 'hubsize', nodeSpacing: 180, levelSeparation: 140 } }
            : {},
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

    // Fit after stabilization (only if physics ran)
    if (usePhysics) {
        _topologyNetwork.once('stabilizationIterationsDone', () => {
            _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        });
    } else if (allPinned) {
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
            html += `<div class="topology-detail-row" style="flex-direction:column; align-items:flex-start; gap:0.15rem;">
                <span style="font-weight:500; color:var(--text-color);">${esc(peerLabel)}</span>
                <span style="font-size:0.75rem; color:var(--text-muted);">${esc(edge.source_interface || '')} &harr; ${esc(edge.target_interface || '')} &middot; ${esc(proto)}</span>
                ${utilHtml}
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

document.getElementById('topology-search')?.addEventListener('input', _onTopoSearchInput);
document.getElementById('topology-search')?.addEventListener('keydown', (e) => {
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
});
document.getElementById('topology-search-results')?.addEventListener('click', _onTopoSearchResultClick);
// Close search results when clicking elsewhere
document.addEventListener('click', (e) => {
    if (!e.target.closest('.topology-search-wrap')) {
        const el = document.getElementById('topology-search-results');
        if (el) el.style.display = 'none';
    }
});

// ── Export ──

function exportTopologyPNG() {
    if (!_topologyNetwork) { showToast('No topology to export', 'warning'); return; }
    const canvas = document.getElementById('topology-canvas')?.querySelector('canvas');
    if (!canvas) { showToast('Canvas not found', 'warning'); return; }
    try {
        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.png`;
        link.href = canvas.toDataURL('image/png');
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

// Event listeners for topology controls
document.getElementById('topology-group-filter')?.addEventListener('change', () => {
    invalidatePageCache('topology');
    loadTopology({ preserveContent: false });
});
document.getElementById('topology-layout')?.addEventListener('change', () => {
    // Layout change requires a rebuild (hierarchical vs physics are fundamentally different)
    if (_topologyData) renderTopologyGraph(_topologyData);
});

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
window.toggleUtilizationOverlay = toggleUtilizationOverlay;
window.showTopologyChanges = showTopologyChanges;
window.acknowledgeTopologyChanges = acknowledgeTopologyChanges;
window.resetTopologyPositions = resetTopologyPositions;

// ── Cleanup ──

export function destroyTopology() {
    _stopUtilizationStream();
    if (_topologyNetwork) {
        _topologyNetwork.destroy();
    }
    _topologyNetwork = null;
    _topologyData = null;
    _topoNodesDS = null;
    _topoEdgesDS = null;
}

// ── Exports ──

export { loadTopology };
export { _getTopoThemeColors, _topologyNetwork, _topologyData, _topoNodesDS, _topoEdgesDS, _topoSavedPositions, _buildVisNode, _buildVisEdge };

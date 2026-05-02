/**
 * Page Templates — Lazy DOM creation.
 *
 * Each page's inner HTML is generated on first visit instead of being
 * pre-rendered in index.html.  The `ensurePageDOM(page)` function is
 * called from navigateToPage() before loadPageData().
 */

// ── Template registry ────────────────────────────────────────────────────────

const _templates = {
    dashboard: templateDashboard,
    inventory: templateInventory,
    playbooks: templatePlaybooks,
    jobs: templateJobs,
    templates: templateTemplates,
    credentials: templateCredentials,
    topology: templateTopology,
    configuration: templateConfiguration,
    compliance: templateCompliance,
    'change-management': templateChangeManagement,
    monitoring: templateMonitoring,
    'cloud-visibility': templateCloudVisibility,
    reports: templateReports,
    'device-detail': templateDeviceDetail,
    'graph-templates': templateGraphTemplates,
    'mac-tracking': templateMacTracking,
    'traffic-analysis': templateTrafficAnalysis,
    upgrades: templateUpgrades,
    settings: templateSettings,
};

/**
 * Ensure the page container has its DOM populated.
 * Called once per page — subsequent visits are a no-op.
 */
export function ensurePageDOM(page) {
    const container = document.getElementById(`page-${page}`);
    if (!container || container.dataset.initialized) return false;
    const templateFn = _templates[page];
    if (!templateFn) return false;
    container.innerHTML = templateFn();
    container.dataset.initialized = 'true';
    return true;
}

/**
 * Ensure a modal's DOM exists in the document.
 * Returns the modal element.
 */
export function ensureModalDOM(id, templateFn) {
    let el = document.getElementById(id);
    if (!el) {
        document.body.insertAdjacentHTML('beforeend', templateFn());
        el = document.getElementById(id);
    }
    return el;
}

// ── Skeleton helper ──────────────────────────────────────────────────────────

function skel(count = 2, style = 'margin-bottom: 0.75rem;') {
    return Array.from({ length: count }, () =>
        `<div class="skeleton skeleton-card" style="${style}"></div>`
    ).join('\n');
}

// ── Page templates ───────────────────────────────────────────────────────────

function templateDashboard() {
    return `
    <h2>Dashboard</h2>
    <div class="stats-grid">
        <div class="stat-card stat-card-ring">
            <div class="stat-ring-wrap">
                <svg class="stat-ring" viewBox="0 0 80 80">
                    <circle class="stat-ring-bg" cx="40" cy="40" r="34" />
                    <circle class="stat-ring-fill" id="ring-hosts" cx="40" cy="40" r="34" />
                </svg>
                <div class="stat-ring-value" id="stat-hosts">-</div>
            </div>
            <div class="stat-label">Total Hosts</div>
        </div>
        <div class="stat-card stat-card-ring">
            <div class="stat-ring-wrap">
                <svg class="stat-ring" viewBox="0 0 80 80">
                    <circle class="stat-ring-bg" cx="40" cy="40" r="34" />
                    <circle class="stat-ring-fill" id="ring-playbooks" cx="40" cy="40" r="34" />
                </svg>
                <div class="stat-ring-value" id="stat-playbooks">-</div>
            </div>
            <div class="stat-label">Playbooks</div>
        </div>
        <div class="stat-card stat-card-ring">
            <div class="stat-ring-wrap">
                <svg class="stat-ring" viewBox="0 0 80 80">
                    <circle class="stat-ring-bg" cx="40" cy="40" r="34" />
                    <circle class="stat-ring-fill" id="ring-jobs" cx="40" cy="40" r="34" />
                </svg>
                <div class="stat-ring-value" id="stat-jobs">-</div>
            </div>
            <div class="stat-label">Total Jobs</div>
        </div>
    </div>

    <!-- Network Health Overview (SolarWinds-style) -->
    <div class="section" id="network-health-section">
        <div class="page-header" style="margin-bottom: 1rem;">
            <h3>Network Health Overview</h3>
            <div style="display:flex; gap:0.5rem; align-items:center;">
                <select id="health-group-filter" class="form-select" style="min-width:160px; font-size:0.85rem;">
                    <option value="">All Groups</option>
                </select>
                <select id="health-sort" class="form-select" style="min-width:140px; font-size:0.85rem;">
                    <option value="severity">Severity</option>
                    <option value="name">Name A-Z</option>
                    <option value="cpu">CPU Usage</option>
                    <option value="memory">Memory Usage</option>
                </select>
            </div>
        </div>

        <!-- Health summary tiles -->
        <div id="health-summary-tiles" class="health-summary-tiles">
            ${skel(4, 'min-height:80px;')}
        </div>

        <!-- Device status table -->
        <div id="device-health-table-wrap" class="device-health-table-wrap" style="margin-top:1rem;">
            ${skel(2)}
        </div>
    </div>

    <!-- Recent Alerts -->
    <div class="section" id="dashboard-alerts-section">
        <h3>Active Alerts</h3>
        <div id="dashboard-alerts-list">
            ${skel(2)}
        </div>
    </div>

    <!-- Custom Dashboards Section -->
    <div id="dashboard-default-content-end"></div>
    <div id="dashboards-list-view" class="section">
        <div class="page-header">
            <h3>My Dashboards</h3>
            <button class="btn btn-primary" onclick="showCreateDashboardModal()">+ New Dashboard</button>
        </div>
        <div id="dashboards-list" class="dashboards-card-grid"></div>
        <div id="dashboards-empty" class="empty-state" style="display:none;">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.3;"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
            <p>No dashboards yet</p>
            <button class="btn btn-primary" onclick="showCreateDashboardModal()">Create Your First Dashboard</button>
        </div>
    </div>
    <div id="dashboard-viewer" class="dashboard-viewer" style="display:none">
        <div class="page-header">
            <div style="display:flex; align-items:center; gap:0.75rem;">
                <button class="btn btn-sm btn-secondary" onclick="backToDashboardsList()">&larr; Back</button>
                <h2 id="dashboard-viewer-title" style="margin:0; font-size:1.25rem;">Dashboard</h2>
            </div>
            <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
                <div id="dashboard-variables" class="dashboard-variables"></div>
                <button class="btn btn-secondary" id="dashboard-edit-toggle" onclick="toggleDashboardEditMode()">Edit</button>
                <button class="btn btn-secondary" onclick="refreshDashboardPanels()">Refresh</button>
                <button class="btn btn-danger btn-sm" id="dashboard-delete-btn" style="display:none" onclick="confirmDeleteDashboard()">Delete</button>
            </div>
        </div>
        <div id="dashboard-grid" class="dashboard-grid"></div>
        <button class="btn btn-primary" id="dashboard-add-panel-btn" style="display:none" onclick="showAddPanelModal()">+ Add Panel</button>
    </div>`;
}

function templateInventory() {
    return `
    <div class="page-header">
        <h2>Inventory Management</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-secondary" onclick="showSnmpProfilesModal()">SNMP Profiles</button>
            <button class="btn btn-secondary" onclick="showGlobalDiscoveryModal()">Discover Devices</button>
            <button class="btn btn-secondary" onclick="exportInventoryCSV()">Export CSV</button>
            <button class="btn btn-primary" onclick="showCreateGroupModal()">+ New Group</button>
        </div>
    </div>
    <div class="list-controls">
        <input id="inventory-search" class="form-input list-control-search" type="search" placeholder="Search groups, hosts, IPs, device types">
        <select id="inventory-sort" class="form-select list-control-select">
            <option value="custom">Custom (drag to reorder)</option>
            <option value="name_asc">Name: A-Z</option>
            <option value="name_desc">Name: Z-A</option>
            <option value="hosts_desc">Host Count: High-Low</option>
            <option value="hosts_asc">Host Count: Low-High</option>
        </select>
        <button id="inventory-density-toggle" class="btn btn-secondary btn-sm" onclick="toggleInventoryDensity()" title="Toggle compact mode">Compact</button>
        <button id="inventory-collapse-all" class="btn btn-secondary btn-sm" onclick="toggleAllInventoryGroups()" title="Collapse or expand all groups">Collapse All</button>
    </div>
    <div id="inventory-groups" class="groups-list">
        ${skel(3)}
    </div>`;
}

function templatePlaybooks() {
    return `
    <div class="page-header">
        <h2>Playbooks</h2>
        <button class="btn btn-primary" onclick="showCreatePlaybookModal()">+ New Playbook</button>
    </div>
    <div class="list-controls">
        <input id="playbooks-search" class="form-input list-control-search" type="search" placeholder="Search playbooks, tags, filenames">
        <select id="playbooks-sort" class="form-select list-control-select">
            <option value="name_asc">Name: A-Z</option>
            <option value="name_desc">Name: Z-A</option>
            <option value="updated_desc">Updated: Newest</option>
            <option value="updated_asc">Updated: Oldest</option>
        </select>
    </div>
    <div id="playbooks-list" class="playbooks-grid">
        ${skel(2)}
    </div>`;
}

function templateJobs() {
    return `
    <div class="page-header">
        <h2>Job Execution</h2>
        <button class="btn btn-primary" onclick="showLaunchJobModal()">Launch Job</button>
    </div>
    <!-- Queue Status Panel -->
    <div id="jobs-queue-panel" class="card jobs-queue-panel" style="margin-bottom:1rem; padding:0.75rem 1rem; display:none">
        <div style="display:flex; align-items:center; gap:1.5rem; flex-wrap:wrap;">
            <div style="font-weight:600; font-size:0.9em;">Queue</div>
            <div><span style="color:var(--text-muted); font-size:0.85em;">Running:</span> <strong id="jobs-q-running">0</strong><span style="color:var(--text-muted); font-size:0.8em;">/<span id="jobs-q-max">4</span></span></div>
            <div><span style="color:var(--text-muted); font-size:0.85em;">Queued:</span> <strong id="jobs-q-queued">0</strong></div>
            <div id="jobs-q-items" style="display:flex; gap:0.4rem; flex-wrap:wrap; flex:1;"></div>
        </div>
    </div>
    <div class="list-controls list-controls-jobs">
        <input id="jobs-search" class="form-input list-control-search" type="search" placeholder="Search playbook, group, status">
        <select id="jobs-status-filter" class="form-select list-control-select">
            <option value="all">Status: All</option>
            <option value="queued">Status: Queued</option>
            <option value="running">Status: Running</option>
            <option value="success">Status: Success</option>
            <option value="failed">Status: Failed</option>
            <option value="cancelled">Status: Cancelled</option>
        </select>
        <select id="jobs-dryrun-filter" class="form-select list-control-select">
            <option value="all">Dry Run: All</option>
            <option value="yes">Dry Run: Yes</option>
            <option value="no">Dry Run: No</option>
        </select>
        <select id="jobs-date-filter" class="form-select list-control-select">
            <option value="all">Date: All</option>
            <option value="today">Date: Today</option>
            <option value="7d">Date: Last 7 days</option>
            <option value="30d">Date: Last 30 days</option>
        </select>
        <select id="jobs-sort" class="form-select list-control-select">
            <option value="started_desc">Started: Newest</option>
            <option value="started_asc">Started: Oldest</option>
        </select>
    </div>
    <div id="jobs-list" class="jobs-list">
        ${skel(3)}
    </div>`;
}

function templateTemplates() {
    return `
    <div class="page-header">
        <h2>Config Templates</h2>
        <button class="btn btn-primary" onclick="showCreateTemplateModal()">+ New Template</button>
    </div>
    <div class="list-controls">
        <input id="templates-search" class="form-input list-control-search" type="search" placeholder="Search templates and content">
        <select id="templates-sort" class="form-select list-control-select">
            <option value="name_asc">Name: A-Z</option>
            <option value="name_desc">Name: Z-A</option>
            <option value="updated_desc">Updated: Newest</option>
            <option value="updated_asc">Updated: Oldest</option>
        </select>
    </div>
    <div id="templates-list" class="templates-list">
        ${skel(2)}
    </div>`;
}

function templateCredentials() {
    return `
    <div class="page-header">
        <h2>Credentials</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-primary" onclick="showCreateCredentialModal()">+ New Credential</button>
            <button class="btn btn-secondary" onclick="showCreateSecretVarModal()">+ New Secret Variable</button>
        </div>
    </div>
    <!-- Tab Controls -->
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary cred-tab-btn active" data-cred-tab="credentials" onclick="switchCredentialTab('credentials')">Device Credentials</button>
        <button class="btn btn-sm btn-secondary cred-tab-btn" data-cred-tab="secrets" onclick="switchCredentialTab('secrets')">Secret Variables</button>
    </div>
    <!-- Device Credentials Tab -->
    <div id="cred-tab-credentials" class="cred-tab">
        <div class="list-controls">
            <input id="credentials-search" class="form-input list-control-search" type="search" placeholder="Search credential name or username">
            <select id="credentials-sort" class="form-select list-control-select">
                <option value="name_asc">Name: A-Z</option>
                <option value="name_desc">Name: Z-A</option>
                <option value="created_desc">Created: Newest</option>
                <option value="created_asc">Created: Oldest</option>
            </select>
        </div>
        <div id="credentials-list" class="credentials-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Secret Variables Tab -->
    <div id="cred-tab-secrets" class="cred-tab" style="display:none">
        <div style="padding:0.5rem 0 1rem; opacity:0.7; font-size:0.9em;">
            Encrypted secrets for use in config templates via <code>{{secret.NAME}}</code> syntax.
            Values are encrypted at rest and only decrypted at job execution time.
        </div>
        <div id="secret-variables-list">
            ${skel(1)}
        </div>
    </div>`;
}

function templateTopology() {
    return `
    <div class="page-header">
        <h2>Network Topology</h2>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <div class="topology-search-wrap">
                <input type="text" id="topology-search" class="form-input" placeholder="Search nodes..." autocomplete="off">
                <div id="topology-search-results" class="topology-search-results" style="display:none"></div>
            </div>
            <select id="topology-group-filter" class="form-select" style="min-width:160px;">
                <option value="">All Groups</option>
            </select>
            <select id="topology-layout" class="form-select" style="min-width:140px;">
                <option value="physics">Force-Directed</option>
                <option value="hierarchical-UD">Hierarchical &darr;</option>
                <option value="hierarchical-DU">Hierarchical &uarr;</option>
                <option value="hierarchical-LR">Hierarchical &rarr;</option>
                <option value="hierarchical-RL">Hierarchical &larr;</option>
                <option value="circular">Circular</option>
            </select>
            <button class="btn btn-secondary" id="topology-discover-btn" onclick="discoverTopology()">Discover Neighbors</button>
            <button class="btn btn-secondary" onclick="refreshTopology()">Refresh</button>
            <button class="btn btn-secondary" id="topology-fit-btn" onclick="fitTopology()" title="Fit graph to view">Fit</button>
            <button class="btn btn-secondary" id="topology-path-btn" onclick="togglePathMode()" title="Find shortest path between two nodes">Path</button>
            <button class="btn btn-secondary" id="topology-util-btn" onclick="toggleUtilizationOverlay()" title="Toggle interface utilization overlay">Util</button>
            <button class="btn btn-secondary" id="topology-labels-btn" onclick="toggleEdgeLabels()" title="Toggle edge interface labels">Labels</button>
            <input type="number" id="topology-stp-vlan" class="form-input" value="1" min="1" max="4094" style="width:88px;" title="STP instance/VLAN">
            <label style="display:inline-flex; align-items:center; gap:0.3rem; font-size:0.78rem; color:var(--text-muted); white-space:nowrap;">
                <input type="checkbox" id="topology-stp-all-vlans"> All VLANs
            </label>
            <button class="btn btn-secondary" id="topology-stp-scan-btn" onclick="scanTopologyStp()" title="Poll STP state from devices">Scan STP</button>
            <button class="btn btn-secondary" id="topology-stp-btn" onclick="toggleStpOverlay()" title="Overlay STP forwarding/blocked states">STP</button>
            <button class="btn btn-secondary topology-changes-btn" id="topology-stp-events-btn" onclick="showStpTopologyEvents()" title="View STP topology events">
                STP Events <span id="topology-stp-event-badge" class="topology-change-badge" style="display:none">0</span>
            </button>
            <button class="btn btn-secondary topology-changes-btn" id="topology-changes-btn" onclick="showTopologyChanges()" title="View topology changes">
                Changes <span id="topology-change-badge" class="topology-change-badge" style="display:none">0</span>
            </button>
            <button class="btn btn-secondary" id="topology-reset-pos-btn" onclick="resetTopologyPositions()" title="Reset all saved node positions">Reset Layout</button>
            <div class="topology-settings-wrap" style="position:relative;">
                <button class="btn btn-secondary" id="topology-settings-btn" onclick="toggleTopologySettings()" title="Layout settings">&#9881;</button>
                <div id="topology-settings-popover" class="topology-settings-popover" style="display:none">
                    <div class="topology-settings-title">Layout Settings</div>
                    <label class="topology-settings-label">Node Spacing <span id="topo-setting-spacing-val">220</span></label>
                    <input type="range" id="topo-setting-spacing" class="topology-settings-slider" min="80" max="400" value="220" step="10" oninput="onTopologySettingChange()">
                    <label class="topology-settings-label">Repulsion <span id="topo-setting-repulsion-val">8000</span></label>
                    <input type="range" id="topo-setting-repulsion" class="topology-settings-slider" min="1000" max="12000" value="8000" step="500" oninput="onTopologySettingChange()">
                    <label class="topology-settings-label">Edge Length <span id="topo-setting-edgelen-val">280</span></label>
                    <input type="range" id="topo-setting-edgelen" class="topology-settings-slider" min="60" max="400" value="280" step="10" oninput="onTopologySettingChange()">
                </div>
            </div>
            <div class="topology-export-group">
                <button class="btn btn-secondary" onclick="exportTopologyPNG()" title="Export as PNG image">PNG</button>
                <button class="btn btn-secondary" onclick="exportTopologySVG()" title="Export as SVG vector">SVG</button>
                <button class="btn btn-secondary" onclick="exportTopologyJSON()" title="Export as JSON data">JSON</button>
                <button class="btn btn-secondary" onclick="printTopology()" title="Print topology map">Print</button>
            </div>
        </div>
    </div>
    <div id="topology-path-bar" class="topology-path-bar" style="display:none">
        <span id="topology-path-status">Click a source node to start path tracing...</span>
        <button class="btn btn-secondary btn-sm" onclick="clearPathMode()">Cancel</button>
    </div>
    <div class="topology-container">
        <div id="topology-canvas" class="topology-canvas"></div>
        <div id="topology-details" class="topology-details" style="display:none">
            <div class="topology-details-header">
                <h3 id="topology-details-title">Node Details</h3>
                <button class="btn-icon" onclick="closeTopologyDetails()" title="Close">&times;</button>
            </div>
            <div id="topology-details-content"></div>
        </div>
    </div>
    <div id="topology-legend" class="topology-legend">
        <span class="topology-legend-item"><span class="topology-legend-dot topology-legend-dot-inventory"></span> Inventory Device</span>
        <span class="topology-legend-item"><span class="topology-legend-dot topology-legend-dot-dashed"></span> External Neighbor</span>
        <span class="topology-legend-item"><span class="topology-legend-line topology-legend-line-cdp"></span> CDP</span>
        <span class="topology-legend-item"><span class="topology-legend-line topology-legend-line-lldp"></span> LLDP</span>
        <span class="topology-legend-item"><span class="topology-legend-line topology-legend-line-ospf"></span> OSPF</span>
        <span class="topology-legend-item"><span class="topology-legend-line topology-legend-line-bgp"></span> BGP</span>
        <span class="topology-legend-item topology-legend-util" id="topology-legend-util" style="display:none">
            <span class="topology-legend-gradient"></span> Utilization (links + IPAM nodes, 0-100%)
        </span>
        <span class="topology-legend-item topology-legend-stp" id="topology-legend-stp-forwarding" style="display:none">
            <span class="topology-legend-line topology-legend-line-stp-fwd"></span> STP Forwarding
        </span>
        <span class="topology-legend-item topology-legend-stp" id="topology-legend-stp-learning" style="display:none">
            <span class="topology-legend-line topology-legend-line-stp-learn"></span> STP Learning
        </span>
        <span class="topology-legend-item topology-legend-stp" id="topology-legend-stp-blocked" style="display:none">
            <span class="topology-legend-line topology-legend-line-stp-block"></span> STP Blocked
        </span>
    </div>
    <div id="topology-empty" class="empty-state" style="display:none">
        <svg width="140" height="140" viewBox="0 0 140 140" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <filter id="topo-glow">
                    <feGaussianBlur stdDeviation="3" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
            </defs>
            <line x1="44" y1="35" x2="96" y2="35" class="topo-empty-edge-cdp" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.5" filter="url(#topo-glow)"/>
            <line x1="38" y1="45" x2="62" y2="95" class="topo-empty-edge-lldp" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.4" filter="url(#topo-glow)"/>
            <line x1="102" y1="45" x2="78" y2="95" class="topo-empty-edge-cdp" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.4" filter="url(#topo-glow)"/>
            <circle cx="30" cy="35" r="14" class="topo-empty-node-inv" stroke-width="2" filter="url(#topo-glow)"/>
            <circle cx="110" cy="35" r="14" class="topo-empty-node-inv2" stroke-width="2" filter="url(#topo-glow)"/>
            <circle cx="70" cy="105" r="14" class="topo-empty-node-ext" stroke-width="2" stroke-dasharray="4 3"/>
        </svg>
        <h3>No Topology Data</h3>
        <p style="color:var(--text-muted); margin-bottom:1rem;">Run neighbor discovery on your inventory groups to map network connections.</p>
        <button class="btn btn-primary btn-sm" onclick="discoverTopology()">Discover Neighbors</button>
    </div>`;
}

function templateConfiguration() {
    return `
    <div class="page-header">
        <h2>Configuration</h2>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <button class="btn btn-primary" onclick="showSetBaselineModal()">+ Set Baseline</button>
            <button class="btn btn-secondary" onclick="showCaptureSnapshotModal()">Capture Config</button>
            <button class="btn btn-secondary" onclick="showCreateBackupPolicyModal()">+ New Policy</button>
            <button class="btn btn-secondary" onclick="refreshConfiguration()">Refresh</button>
        </div>
    </div>
    <!-- Summary Cards -->
    <div class="drift-summary-grid" id="configuration-summary">
        <div class="stat-card"><div class="stat-ring-value" id="drift-stat-baselined">-</div><div class="stat-label">Baselined</div></div>
        <div class="stat-card"><div class="stat-ring-value drift-compliant" id="drift-stat-compliant">-</div><div class="stat-label">Compliant</div></div>
        <div class="stat-card"><div class="stat-ring-value drift-drifted" id="drift-stat-drifted">-</div><div class="stat-label">Drifted</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="drift-stat-open">-</div><div class="stat-label">Open Events</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="backup-stat-policies">-</div><div class="stat-label">Policies</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="backup-stat-backups">-</div><div class="stat-label">Total Backups</div></div>
    </div>
    <!-- Tab Controls -->
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary config-tab-btn active" data-config-tab="drift" onclick="switchConfigurationTab('drift')">Drift Events</button>
        <button class="btn btn-sm btn-secondary config-tab-btn" data-config-tab="policies" onclick="switchConfigurationTab('policies')">Backup Policies</button>
        <button class="btn btn-sm btn-secondary config-tab-btn" data-config-tab="history" onclick="switchConfigurationTab('history')">Backup History</button>
        <button class="btn btn-sm btn-secondary config-tab-btn" data-config-tab="search" onclick="switchConfigurationTab('search')">Config Search</button>
        <input id="configuration-search" class="form-input list-control-search" type="search" placeholder="Search..." style="margin-left:auto; max-width:220px;">
    </div>
    <!-- Drift Events Tab -->
    <div id="config-tab-drift" class="config-tab">
        <div class="list-controls list-controls-drift" style="margin-bottom:0.75rem;">
            <input id="drift-search" class="form-input list-control-search" type="search" placeholder="Search hostname or IP...">
            <select id="drift-status-filter" class="form-select list-control-select">
                <option value="all">All Statuses</option>
                <option value="open" selected>Open</option>
                <option value="resolved">Resolved</option>
                <option value="accepted">Accepted</option>
            </select>
            <select id="drift-sort" class="form-select list-control-select">
                <option value="detected_desc">Detected: Newest</option>
                <option value="detected_asc">Detected: Oldest</option>
                <option value="host_asc">Host: A-Z</option>
            </select>
        </div>
        <div id="drift-events-list">
            ${skel(3)}
        </div>
    </div>
    <!-- Backup Policies Tab -->
    <div id="config-tab-policies" class="config-tab" style="display:none">
        <div class="drift-summary-grid" id="backup-summary" style="margin-bottom:1rem;">
            <div class="stat-card"><div class="stat-ring-value" id="backup-stat-hosts">-</div><div class="stat-label">Hosts Covered</div></div>
            <div class="stat-card"><div class="stat-ring-value" id="backup-stat-last">-</div><div class="stat-label">Last Backup</div></div>
        </div>
        <div id="backup-policies-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Backup History Tab -->
    <div id="config-tab-history" class="config-tab" style="display:none">
        <div style="display:flex; justify-content:flex-end; margin-bottom:0.75rem;">
            <button class="btn btn-sm btn-secondary" onclick="downloadAllBackups()" title="Download every successful backup as a ZIP of .txt files">
                Download All (.zip)
            </button>
        </div>
        <div id="backup-history-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Config Search Tab -->
    <div id="config-tab-search" class="config-tab" style="display:none">
        <div class="card" style="padding:1rem; margin-bottom:0.75rem;">
            <div class="list-controls" style="margin-bottom:0.5rem;">
                <input id="config-backup-search-query" class="form-input list-control-search" type="search" placeholder="e.g. snmp-server community public">
                <select id="config-backup-search-mode" class="form-select list-control-select">
                    <option value="fulltext">Full Text</option>
                    <option value="substring">Substring</option>
                    <option value="regex">Regex</option>
                </select>
                <input id="config-backup-search-limit" class="form-input list-control-select" type="number" min="1" max="200" value="50" style="max-width:110px;" title="Max results">
                <button id="config-backup-search-btn" class="btn btn-sm btn-primary" onclick="runConfigBackupSearch()">Search</button>
            </div>
            <div id="config-backup-search-example" style="font-size:0.8em; color:var(--text-muted); margin-bottom:0.35rem;">
                Example: <code>snmp-server community public</code>
            </div>
            <div style="font-size:0.85em; color:var(--text-muted);">
                Search all successful backed-up configurations. Results include match context and direct backup diff links.
            </div>
        </div>
        <div id="config-backup-search-results">
            <div class="card" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Run a search to scan backed-up configurations.</div>
        </div>
    </div>
    </div>`;
}

function templateCompliance() {
    return `
    <div class="page-header">
        <h2>Compliance</h2>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <button class="btn btn-primary" onclick="showRunComplianceScanModal()">Run Scan</button>
            <button class="btn btn-secondary" onclick="showCreateComplianceProfileModal()">+ New Profile</button>
            <button class="btn btn-secondary" onclick="loadBuiltinProfiles()">Load Built-in Profiles</button>
            <button class="btn btn-secondary" onclick="refreshCompliance()">Refresh</button>
        </div>
    </div>
    <!-- Summary Cards -->
    <div class="drift-summary-grid" id="compliance-summary">
        <div class="stat-card"><div class="stat-ring-value" id="compliance-stat-profiles">-</div><div class="stat-label">Profiles</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="compliance-stat-assignments">-</div><div class="stat-label">Active Scans</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="compliance-stat-scanned">-</div><div class="stat-label">Hosts Scanned</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="compliance-stat-violations">-</div><div class="stat-label">Non-Compliant</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="compliance-stat-last">-</div><div class="stat-label">Last Scan</div></div>
    </div>
    <!-- Tab Toggle -->
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary compliance-tab-btn active" id="compliance-tab-profiles" onclick="switchComplianceTab('profiles')">Profiles</button>
        <button class="btn btn-sm btn-secondary compliance-tab-btn" id="compliance-tab-assignments" onclick="switchComplianceTab('assignments')">Assignments</button>
        <button class="btn btn-sm btn-secondary compliance-tab-btn" id="compliance-tab-results" onclick="switchComplianceTab('results')">Scan Results</button>
        <button class="btn btn-sm btn-secondary compliance-tab-btn" id="compliance-tab-status" onclick="switchComplianceTab('status')">Host Status</button>
        <input id="compliance-search" class="form-input list-control-search" type="search" placeholder="Search..." style="margin-left:auto;">
    </div>
    <!-- Profiles List -->
    <div id="compliance-profiles-list">
        ${skel(1)}
    </div>
    <!-- Assignments List -->
    <div id="compliance-assignments-list" style="display:none">
        ${skel(1)}
    </div>
    <!-- Scan Results -->
    <div id="compliance-results-list" style="display:none">
        ${skel(1)}
    </div>
    <!-- Host Status -->
    <div id="compliance-status-list" style="display:none">
        ${skel(1)}
    </div>`;
}

function templateChangeManagement() {
    return `
    <div class="page-header">
        <h2>Change Management</h2>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <button class="btn btn-primary" onclick="showNewRiskAnalysisModal()">+ New Analysis</button>
            <button class="btn btn-secondary" onclick="showNewDeploymentModal()">+ New Deployment</button>
            <button class="btn btn-secondary" onclick="refreshChangeManagement()">Refresh</button>
        </div>
    </div>
    <!-- Summary Cards -->
    <div class="drift-summary-grid" id="change-mgmt-summary">
        <div class="stat-card"><div class="stat-ring-value" id="risk-stat-total">-</div><div class="stat-label">Analyses</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="risk-stat-high">-</div><div class="stat-label">High/Critical</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="risk-stat-pending">-</div><div class="stat-label">Pending</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="deploy-stat-total">-</div><div class="stat-label">Deployments</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="deploy-stat-completed">-</div><div class="stat-label">Completed</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="deploy-stat-failed">-</div><div class="stat-label">Failed</div></div>
    </div>
    <!-- Tab Controls -->
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary change-tab-btn active" data-change-tab="risk" onclick="switchChangeTab('risk')">Risk Analysis</button>
        <button class="btn btn-sm btn-secondary change-tab-btn" data-change-tab="deployments" onclick="switchChangeTab('deployments')">Deployments</button>
        <input id="change-mgmt-search" class="form-input list-control-search" type="search" placeholder="Search..." style="margin-left:auto; max-width:220px;">
    </div>
    <!-- Risk Analysis Tab -->
    <div id="change-tab-risk" class="change-tab">
        <div class="list-controls" style="margin-bottom:0.75rem;">
            <select id="risk-filter-level" class="form-select" style="max-width:160px;" onchange="filterRiskAnalyses()">
                <option value="">All Levels</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
            </select>
            <button class="btn btn-secondary btn-sm" onclick="showOfflineRiskAnalysisModal()" style="margin-left:0.5rem;">Offline Analysis</button>
            <input id="risk-search" class="form-input list-control-search" type="search" placeholder="Search analyses..." style="margin-left:auto;">
        </div>
        <div id="risk-analyses-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Deployments Tab -->
    <div id="change-tab-deployments" class="change-tab" style="display:none">
        <div class="drift-summary-grid" style="margin-bottom:1rem;">
            <div class="stat-card"><div class="stat-ring-value" id="deploy-stat-active">-</div><div class="stat-label">Active</div></div>
            <div class="stat-card"><div class="stat-ring-value" id="deploy-stat-rolled-back">-</div><div class="stat-label">Rolled Back</div></div>
        </div>
        <div class="list-controls" style="margin-bottom:0.75rem;">
            <select id="deploy-filter-status" class="form-select" style="max-width:180px;" onchange="filterDeployments()">
                <option value="">All Statuses</option>
                <option value="planning">Planning</option>
                <option value="executing">Executing</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="rolled-back">Rolled Back</option>
            </select>
            <input id="deploy-search" class="form-input list-control-search" type="search" placeholder="Search deployments..." style="margin-left:auto;">
        </div>
        <div id="deployments-list">
            ${skel(2)}
        </div>
    </div>`;
}

function templateMonitoring() {
    return `
    <div class="page-header">
        <h2>Monitoring</h2>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <button id="poll-now-btn" class="btn btn-primary" onclick="runMonitoringPollNow()">Poll Now</button>
            <button class="btn btn-secondary" onclick="refreshMonitoring()">Refresh</button>
        </div>
    </div>
    <!-- Poll Progress -->
    <div id="poll-progress" style="display:none; margin-bottom:1rem;">
        <div class="card" style="padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                <strong id="poll-progress-title">Polling devices...</strong>
                <span id="poll-progress-count" style="color:var(--text-muted); font-size:0.85em;">0 / 0</span>
            </div>
            <div style="background:var(--bg-secondary); border-radius:4px; height:8px; overflow:hidden;">
                <div id="poll-progress-bar" style="background:var(--primary); height:100%; width:0%; transition:width 0.3s ease; border-radius:4px;"></div>
            </div>
            <div id="poll-progress-log" style="margin-top:0.75rem; max-height:200px; overflow-y:auto; font-size:0.82em; font-family:monospace; color:var(--text-muted);"></div>
        </div>
    </div>
    <!-- Summary Cards -->
    <div class="drift-summary-grid" id="monitoring-summary">
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-hosts">-</div><div class="stat-label">Monitored</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-cpu">-</div><div class="stat-label">Avg CPU</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-mem">-</div><div class="stat-label">Avg Memory</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-if-up">-</div><div class="stat-label">IF Up</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-if-down">-</div><div class="stat-label">IF Down</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-vpn-up">-</div><div class="stat-label">VPN Up</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-vpn-down">-</div><div class="stat-label">VPN Down</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-routes">-</div><div class="stat-label">Routes</div></div>
        <div class="stat-card"><div class="stat-ring-value" id="mon-stat-alerts">-</div><div class="stat-label">Open Alerts</div></div>
    </div>
    <!-- Tab Controls -->
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary mon-tab-btn active" data-mon-tab="devices" onclick="switchMonitoringTab('devices')">Devices</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="alerts" onclick="switchMonitoringTab('alerts')">Alerts</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="routes" onclick="switchMonitoringTab('routes')">Route Churn</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="rules" onclick="switchMonitoringTab('rules')">Rules</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="suppressions" onclick="switchMonitoringTab('suppressions')">Suppressions</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="sla" onclick="switchMonitoringTab('sla')">SLA &amp; Availability</button>
        <button class="btn btn-sm btn-secondary mon-tab-btn" data-mon-tab="capacity" onclick="switchMonitoringTab('capacity')">Capacity</button>
        <input id="monitoring-search" class="form-input list-control-search" type="search" placeholder="Search..." style="margin-left:auto; max-width:220px;">
    </div>
    <!-- Devices Tab -->
    <div id="monitoring-tab-devices" class="monitoring-tab">
        <div id="monitoring-devices-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Alerts Tab -->
    <div id="monitoring-tab-alerts" class="monitoring-tab" style="display:none">
        <div style="margin-bottom:0.75rem; display:flex; gap:0.5rem; align-items:center;">
            <select id="mon-alert-filter-severity" class="form-select" style="max-width:150px;" onchange="filterMonitoringAlerts()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
            </select>
            <select id="mon-alert-filter-ack" class="form-select" style="max-width:150px;" onchange="filterMonitoringAlerts()">
                <option value="false">Open</option>
                <option value="">All</option>
                <option value="true">Acknowledged</option>
            </select>
        </div>
        <div id="monitoring-alerts-list">
            ${skel(1)}
        </div>
    </div>
    <!-- Route Churn Tab -->
    <div id="monitoring-tab-routes" class="monitoring-tab" style="display:none">
        <div id="monitoring-routes-list">
            ${skel(1)}
        </div>
    </div>
    <!-- Rules Tab -->
    <div id="monitoring-tab-rules" class="monitoring-tab" style="display:none">
        <div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="color:var(--text-muted); font-size:0.9em;">Define custom alert rules for metrics and thresholds.</span>
            <button class="btn btn-primary btn-sm" onclick="showCreateAlertRuleModal()">+ New Rule</button>
        </div>
        <div id="monitoring-rules-list">
            ${skel(1)}
        </div>
    </div>
    <!-- Suppressions Tab -->
    <div id="monitoring-tab-suppressions" class="monitoring-tab" style="display:none">
        <div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="color:var(--text-muted); font-size:0.9em;">Suppress alerts during maintenance windows.</span>
            <button class="btn btn-primary btn-sm" onclick="showCreateSuppressionModal()">+ New Suppression</button>
        </div>
        <div id="monitoring-suppressions-list">
            ${skel(1)}
        </div>
    </div>
    <!-- SLA & Availability Tab -->
    <div id="monitoring-tab-sla" class="monitoring-tab" style="display:none">
        <div style="margin-bottom:1rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <select id="sla-period-select" class="form-select" style="max-width:160px;" onchange="loadSla()">
                <option value="7">Last 7 days</option>
                <option value="30" selected>Last 30 days</option>
                <option value="90">Last 90 days</option>
            </select>
            <select id="availability-group-filter" class="form-select" style="max-width:200px;" onchange="loadAvailability()">
                <option value="">All Groups</option>
            </select>
            <select id="availability-period" class="form-select" style="max-width:140px;" onchange="loadAvailability()">
                <option value="1">Last 24h</option>
                <option value="7" selected>Last 7d</option>
                <option value="30">Last 30d</option>
                <option value="90">Last 90d</option>
            </select>
            <button class="btn btn-secondary btn-sm" onclick="loadSla(); loadAvailability();">Refresh</button>
        </div>
        <!-- SLA Gauges -->
        <div class="drift-summary-grid" id="sla-summary-cards">
            <div class="stat-card sla-gauge-card">
                <div class="sla-gauge" id="sla-gauge-uptime">
                    <svg viewBox="0 0 120 120" class="sla-gauge-svg">
                        <circle cx="60" cy="60" r="52" class="sla-gauge-bg"></circle>
                        <circle cx="60" cy="60" r="52" class="sla-gauge-fill" id="sla-gauge-uptime-fill" stroke-dasharray="0 327"></circle>
                    </svg>
                    <div class="sla-gauge-value" id="sla-val-uptime">-</div>
                </div>
                <div class="stat-label">Uptime</div>
            </div>
            <div class="stat-card sla-gauge-card">
                <div class="sla-gauge" id="sla-gauge-latency">
                    <svg viewBox="0 0 120 120" class="sla-gauge-svg">
                        <circle cx="60" cy="60" r="52" class="sla-gauge-bg"></circle>
                        <circle cx="60" cy="60" r="52" class="sla-gauge-fill sla-gauge-latency" id="sla-gauge-latency-fill" stroke-dasharray="0 327"></circle>
                    </svg>
                    <div class="sla-gauge-value" id="sla-val-latency">-</div>
                </div>
                <div class="stat-label">Latency</div>
            </div>
            <div class="stat-card sla-gauge-card">
                <div class="sla-gauge" id="sla-gauge-jitter">
                    <svg viewBox="0 0 120 120" class="sla-gauge-svg">
                        <circle cx="60" cy="60" r="52" class="sla-gauge-bg"></circle>
                        <circle cx="60" cy="60" r="52" class="sla-gauge-fill sla-gauge-jitter" id="sla-gauge-jitter-fill" stroke-dasharray="0 327"></circle>
                    </svg>
                    <div class="sla-gauge-value" id="sla-val-jitter">-</div>
                </div>
                <div class="stat-label">Jitter</div>
            </div>
            <div class="stat-card sla-gauge-card">
                <div class="sla-gauge" id="sla-gauge-pktloss">
                    <svg viewBox="0 0 120 120" class="sla-gauge-svg">
                        <circle cx="60" cy="60" r="52" class="sla-gauge-bg"></circle>
                        <circle cx="60" cy="60" r="52" class="sla-gauge-fill sla-gauge-pktloss" id="sla-gauge-pktloss-fill" stroke-dasharray="0 327"></circle>
                    </svg>
                    <div class="sla-gauge-value" id="sla-val-pktloss">-</div>
                </div>
                <div class="stat-label">Packet Loss</div>
            </div>
            <div class="stat-card">
                <div class="stat-ring-value" id="sla-val-mttr">-</div>
                <div class="stat-label">MTTR</div>
            </div>
            <div class="stat-card">
                <div class="stat-ring-value" id="sla-val-mttd">-</div>
                <div class="stat-label">MTTD</div>
            </div>
        </div>
        <!-- SLA Sub-tabs -->
        <div class="tab-controls">
            <button class="btn btn-sm btn-secondary sla-tab-btn active" data-sla-tab="hosts" onclick="switchSlaTab('hosts')">Host SLAs</button>
            <button class="btn btn-sm btn-secondary sla-tab-btn" data-sla-tab="trends" onclick="switchSlaTab('trends')">Trends</button>
            <button class="btn btn-sm btn-secondary sla-tab-btn" data-sla-tab="incidents" onclick="switchSlaTab('incidents')">Incidents</button>
            <button class="btn btn-sm btn-secondary sla-tab-btn" data-sla-tab="targets" onclick="switchSlaTab('targets')">Targets</button>
            <button class="btn btn-sm btn-secondary sla-tab-btn" data-sla-tab="availability" onclick="switchSlaTab('availability')">Availability</button>
            <input id="sla-search" class="form-input list-control-search" type="search" placeholder="Search hosts..." style="margin-left:auto; max-width:220px;">
        </div>
        <!-- Host SLAs Tab -->
        <div id="sla-tab-hosts" class="sla-tab">
            <div id="sla-hosts-list">
                ${skel(2)}
            </div>
        </div>
        <!-- Trends Tab -->
        <div id="sla-tab-trends" class="sla-tab" style="display:none">
            <div id="sla-trends-container">
                <div class="skeleton skeleton-card" style="height:300px; margin-bottom:0.75rem"></div>
            </div>
        </div>
        <!-- Incidents Tab -->
        <div id="sla-tab-incidents" class="sla-tab" style="display:none">
            <div id="sla-incidents-list">
                ${skel(1)}
            </div>
        </div>
        <!-- Targets Tab -->
        <div id="sla-tab-targets" class="sla-tab" style="display:none">
            <div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
                <span style="color:var(--text-muted); font-size:0.9em;">Define SLA targets for hosts or groups.</span>
                <button class="btn btn-primary btn-sm" onclick="showCreateSlaTargetModal()">+ New Target</button>
            </div>
            <div id="sla-targets-list">
                ${skel(1)}
            </div>
        </div>
        <!-- Availability Tab -->
        <div id="sla-tab-availability" class="sla-tab" style="display:none">
            <div class="drift-summary-grid" id="availability-summary-cards"></div>
            <div class="tab-controls">
                <button class="btn btn-sm btn-secondary avail-tab-btn active" data-avail-tab="hosts" onclick="switchAvailTab('hosts')">Host Availability</button>
                <button class="btn btn-sm btn-secondary avail-tab-btn" data-avail-tab="outages" onclick="switchAvailTab('outages')">Outage History</button>
                <button class="btn btn-sm btn-secondary avail-tab-btn" data-avail-tab="transitions" onclick="switchAvailTab('transitions')">State Transitions</button>
                <input id="availability-search" class="form-input list-control-search" type="search" placeholder="Search..." style="margin-left:auto; max-width:220px;">
            </div>
            <div id="avail-tab-hosts" class="avail-tab">
                <div id="availability-hosts-list"></div>
            </div>
            <div id="avail-tab-outages" class="avail-tab" style="display:none">
                <div id="availability-outages-list"></div>
            </div>
            <div id="avail-tab-transitions" class="avail-tab" style="display:none">
                <div id="availability-transitions-list"></div>
            </div>
        </div>
    </div>
    <!-- Capacity Tab -->
    <div id="monitoring-tab-capacity" class="monitoring-tab" style="display:none">
        <div style="margin-bottom:1rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <select id="cap-plan-metric" class="form-select" style="min-width:160px;" onchange="loadCapacityPlanning()">
                <option value="cpu_percent">CPU Utilization</option>
                <option value="memory_percent">Memory Utilization</option>
                <option value="route_count">Route Table Size</option>
                <option value="if_up_count">Interfaces Up</option>
                <option value="vpn_tunnels_up">VPN Tunnels Up</option>
            </select>
            <select id="cap-plan-group" class="form-select" style="min-width:160px;">
                <option value="">All Groups</option>
            </select>
            <select id="cap-plan-range" class="form-select" style="min-width:120px;" onchange="loadCapacityPlanning()">
                <option value="30d">30 Days</option>
                <option value="90d" selected>90 Days</option>
                <option value="180d">180 Days</option>
                <option value="365d">1 Year</option>
            </select>
            <button class="btn btn-secondary btn-sm" onclick="loadCapacityPlanning()">Refresh</button>
        </div>
        <div style="display:grid; grid-template-columns:1fr; gap:1rem;">
            <div class="card" style="padding:1rem;">
                <h4 style="margin:0 0 0.5rem;">Trend + Projection</h4>
                <div id="cap-plan-chart-main" style="height:350px;"></div>
            </div>
            <div class="card" style="padding:1rem;">
                <h4 style="margin:0 0 0.5rem;">Capacity Threshold Estimates</h4>
                <div id="cap-plan-thresholds"></div>
            </div>
        </div>
        <div id="cap-plan-empty" class="empty-state" style="display:none">
            <h3>No Capacity Data</h3>
            <p style="color:var(--text-muted);">Enable monitoring and wait for daily rollups to accumulate capacity planning data.</p>
        </div>
    </div>`;
}

function templateCloudVisibility() {
    return `
    <div class="page-header">
        <h2>Cloud Visibility</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-secondary" onclick="refreshCloudVisibility()">Refresh</button>
            <button class="btn btn-primary" onclick="showCreateCloudAccountModal()">+ Add Cloud Account</button>
        </div>
    </div>

    <div class="list-controls">
        <select id="cloud-provider-filter" class="form-select list-control-select" onchange="onCloudProviderFilterChange()">
            <option value="">All Providers</option>
        </select>
        <select id="cloud-account-filter" class="form-select list-control-select" onchange="onCloudAccountFilterChange()">
            <option value="">All Accounts</option>
        </select>
    </div>
    <div id="cloud-provider-capabilities" style="margin-bottom:0.8rem;"></div>

    <div class="section">
        <h3>Cloud Accounts</h3>
        <div id="cloud-accounts-list">
            ${skel(2)}
        </div>
    </div>

    <div class="section">
        <h3>Hybrid Topology Snapshot</h3>
        <div id="cloud-topology-summary" style="margin-bottom:0.85rem;">
            ${skel(1)}
        </div>
        <div class="card" style="padding:1rem; margin-bottom:0.75rem;">
            <h4 style="margin:0 0 0.55rem;">Resources</h4>
            <div id="cloud-resources-list">${skel(1)}</div>
        </div>
        <div class="card" style="padding:1rem; margin-bottom:0.75rem;">
            <h4 style="margin:0 0 0.55rem;">Cloud Connections</h4>
            <div id="cloud-connections-list">${skel(1)}</div>
        </div>
        <div class="card" style="padding:1rem;">
            <h4 style="margin:0 0 0.55rem;">Hybrid Links (On-Prem to Cloud)</h4>
            <div id="cloud-hybrid-links-list">${skel(1)}</div>
        </div>
    </div>`;
}

function templateReports() {
    return `
    <div class="page-header">
        <h2>Reports & Export</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-primary" onclick="showGenerateReport()">Generate Report</button>
        </div>
    </div>
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary report-tab-btn active" data-report-tab="generate" onclick="switchReportTab('generate')">Generate</button>
        <button class="btn btn-sm btn-secondary report-tab-btn" data-report-tab="history" onclick="switchReportTab('history')">Report History</button>
        <button class="btn btn-sm btn-secondary report-tab-btn" data-report-tab="export" onclick="switchReportTab('export')">Quick Export</button>
        <button class="btn btn-sm btn-secondary report-tab-btn" data-report-tab="billing" onclick="switchReportTab('billing')">Billing</button>
        <button class="btn btn-sm btn-secondary report-tab-btn" data-report-tab="events" onclick="switchReportTab('events')">Event Log</button>
        <button class="btn btn-sm btn-secondary report-tab-btn" data-report-tab="oid-profiles" onclick="switchReportTab('oid-profiles')">OID Profiles</button>
    </div>
    <div id="report-tab-generate" class="report-tab">
        <div class="card" style="padding:1.5rem; max-width:600px;">
            <div class="form-group"><label class="form-label">Report Type</label>
                <select id="report-type" class="form-select" onchange="updateReportParams()">
                    <option value="availability">Availability Report</option>
                    <option value="compliance">Compliance Report</option>
                    <option value="interface">Interface Utilization Report</option>
                    <option value="network_documentation">Network Documentation (Inventory + Topology + IP/VLAN)</option>
                </select></div>
            <div class="form-group"><label class="form-label">Group (optional)</label>
                <select id="report-group" class="form-select">
                    <option value="">All Groups</option>
                </select></div>
            <div class="form-group" id="report-days-group"><label class="form-label">Period (days)</label>
                <select id="report-days" class="form-select">
                    <option value="1">Last 24 hours</option>
                    <option value="7">Last 7 days</option>
                    <option value="30" selected>Last 30 days</option>
                    <option value="90">Last 90 days</option>
                </select></div>
            <div style="display:flex; gap:0.5rem; margin-top:1rem;">
                <button class="btn btn-primary" onclick="generateAndShowReport()">Generate</button>
            </div>
        </div>
        <div id="report-result" style="margin-top:1.5rem;"></div>
    </div>
    <div id="report-tab-history" class="report-tab" style="display:none">
        <div id="report-runs-list"></div>
    </div>
    <div id="report-tab-export" class="report-tab" style="display:none">
        <div class="card" style="padding:1.5rem; max-width:500px;">
            <h3 style="margin-bottom:1rem;">Quick CSV Export</h3>
            <div style="display:flex; flex-direction:column; gap:0.75rem;">
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/availability?days=30', 'availability_report.csv')">Availability Report (30d)</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/compliance', 'compliance_report.csv')">Compliance Report</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/interface?days=1', 'interface_report.csv')">Interface Utilization (24h)</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/network_documentation', 'network_documentation_report.csv')">Network Documentation (CSV)</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/network_documentation.svg', 'network_documentation_topology.svg')">Network Topology Diagram (SVG)</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/network_documentation.drawio', 'network_documentation_topology.drawio')">Network Topology Diagram (draw.io)</button>
                <button class="btn btn-secondary" onclick="downloadReportExport('/api/reports/export/network_documentation.pdf', 'network_documentation_report.pdf')">Network Documentation (PDF)</button>
            </div>
        </div>
    </div>
    <!-- Billing Tab -->
    <div id="report-tab-billing" class="report-tab" style="display:none">
        <div style="margin-bottom:1rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <select id="billing-customer-filter" class="form-select" style="max-width:200px;" onchange="loadBillingTab()">
                <option value="">All Customers</option>
            </select>
            <button class="btn btn-primary btn-sm" onclick="showCreateCircuitModal()">+ New Circuit</button>
            <button class="btn btn-secondary btn-sm" onclick="showGenerateBillingModal()">Generate Billing</button>
            <a id="billing-export-link" class="btn btn-secondary btn-sm" href="/api/billing/export/periods" download>Export CSV</a>
        </div>
        <div class="drift-summary-grid" id="billing-summary-cards"></div>
        <h3 style="margin-top:1.5rem; margin-bottom:0.75rem;">Billing Circuits</h3>
        <div id="billing-circuits-list"></div>
        <h3 style="margin-top:1.5rem; margin-bottom:0.75rem;">Billing Periods</h3>
        <div id="billing-periods-list"></div>
    </div>
    <!-- Event Log Tab -->
    <div id="report-tab-events" class="report-tab" style="display:none">
        <div style="margin-bottom:1rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <select id="syslog-severity-filter" class="form-select" style="max-width:140px;" onchange="loadSyslog()">
                <option value="">All Severities</option>
                <option value="emergency">Emergency</option>
                <option value="alert">Alert</option>
                <option value="critical">Critical</option>
                <option value="error">Error</option>
                <option value="warning">Warning</option>
                <option value="notice">Notice</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
            </select>
            <select id="syslog-type-filter" class="form-select" style="max-width:140px;" onchange="loadSyslog()">
                <option value="">All Types</option>
                <option value="syslog">Syslog</option>
                <option value="trap">SNMP Trap</option>
            </select>
            <button class="btn btn-secondary btn-sm" onclick="loadSyslog({force:true})">Refresh</button>
        </div>
        <div class="drift-summary-grid" id="syslog-summary-cards"></div>
        <input id="syslog-search" class="form-input" type="search" placeholder="Search messages..." style="max-width:400px; margin-bottom:1rem;">
        <div id="syslog-events-list"></div>
    </div>
    <!-- OID Profiles Tab -->
    <div id="report-tab-oid-profiles" class="report-tab" style="display:none">
        <div style="margin-bottom:1rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
            <select id="oid-vendor-filter" class="form-select" style="max-width:180px;" onchange="loadOidProfiles()">
                <option value="">All Vendors</option>
            </select>
            <button class="btn btn-primary btn-sm" onclick="showCreateOidProfile()">+ New Profile</button>
        </div>
        <div id="oid-profiles-list"></div>
        <h3 style="margin-top:2rem;">Built-in Vendor OID Defaults</h3>
        <div id="vendor-oid-defaults-list"></div>
    </div>`;
}

function templateDeviceDetail() {
    return `
    <div class="page-header">
        <h2 id="device-detail-title">Device Detail</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-secondary" onclick="navigateToPage('monitoring')">Back to Monitoring</button>
            <button class="btn btn-secondary" onclick="refreshDeviceDetail()">Refresh</button>
        </div>
    </div>
    <div id="device-detail-info" class="device-info-bar"></div>
    <div id="device-ipam-context" style="padding:0.3rem 0 0.5rem; min-height:1.4rem;"></div>
    <div class="tab-controls">
        <button class="btn btn-sm btn-secondary dev-tab-btn active" data-dev-tab="overview" onclick="switchDeviceTab('overview')">Overview</button>
        <button class="btn btn-sm btn-secondary dev-tab-btn" data-dev-tab="interfaces" onclick="switchDeviceTab('interfaces')">Interfaces</button>
        <button class="btn btn-sm btn-secondary dev-tab-btn" data-dev-tab="alerts" onclick="switchDeviceTab('alerts')">Alert History</button>
        <button class="btn btn-sm btn-secondary dev-tab-btn" data-dev-tab="errors" onclick="switchDeviceTab('errors')">Interface Errors</button>
        <button class="btn btn-sm btn-secondary dev-tab-btn" data-dev-tab="syslog" onclick="switchDeviceTab('syslog')">Syslog</button>
        <button class="btn btn-sm btn-secondary dev-tab-btn" data-dev-tab="compliance" onclick="switchDeviceTab('compliance')">Compliance</button>
    </div>
    <div id="device-tab-overview" class="device-tab">
        <div class="chart-grid-2col">
            <div class="card"><div class="card-title">CPU Utilization</div><div id="device-chart-cpu" class="chart-container"></div></div>
            <div class="card"><div class="card-title">Memory Utilization</div><div id="device-chart-memory" class="chart-container"></div></div>
        </div>
        <div class="chart-grid-2col">
            <div class="card"><div class="card-title">Response Time</div><div id="device-chart-response" class="chart-container"></div></div>
            <div class="card"><div class="card-title">Packet Loss</div><div id="device-chart-pktloss" class="chart-container"></div></div>
        </div>
        <div class="card"><div class="card-title">Interface Summary</div><div id="device-chart-if-summary" class="chart-container"></div></div>
    </div>
    <div id="device-tab-interfaces" class="device-tab" style="display:none">
        <div id="device-interface-charts"></div>
    </div>
    <div id="device-tab-alerts" class="device-tab" style="display:none">
        <div id="device-alert-history"></div>
    </div>
    <div id="device-tab-errors" class="device-tab" style="display:none">
        <div id="device-error-trending"></div>
    </div>
    <div id="device-tab-syslog" class="device-tab" style="display:none">
        <div id="device-syslog-events"></div>
    </div>
    <div id="device-tab-compliance" class="device-tab" style="display:none">
        <div id="device-compliance-status"></div>
    </div>`;
}

function templateGraphTemplates() {
    return `
    <div class="page-header">
        <h2>Graph Templates</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-primary" onclick="showCreateGraphTemplateModal()">+ New Template</button>
        </div>
    </div>
    <div class="page-header" style="margin-top: 0;">
        <input id="graph-templates-search" class="form-input list-control-search" type="search" placeholder="Search templates...">
        <div class="list-controls">
            <select id="graph-templates-tab" class="form-select list-control-select" onchange="switchGraphTemplatesTab(this.value)">
                <option value="graph-templates">Graph Templates</option>
                <option value="host-templates">Host Templates</option>
                <option value="graph-trees">Graph Trees</option>
            </select>
            <select id="graph-templates-category" class="form-select list-control-select" onchange="filterGraphTemplatesCategory(this.value)">
                <option value="">All Categories</option>
                <option value="system">System</option>
                <option value="traffic">Traffic</option>
                <option value="availability">Availability</option>
            </select>
        </div>
    </div>
    <div id="graph-templates-list-view">
        <div id="graph-templates-list"></div>
    </div>
    <div id="host-templates-list-view" style="display:none">
        <div id="host-templates-list"></div>
    </div>
    <div id="graph-trees-list-view" style="display:none">
        <div id="graph-trees-list"></div>
    </div>
    <div id="graph-templates-empty" class="empty-state" style="display:none">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
            <path d="M18 20V10"></path><path d="M12 20V4"></path><path d="M6 20v-6"></path>
        </svg>
        <p>No graph templates yet. Built-in templates are created on first startup.</p>
        <button class="btn btn-primary" onclick="showCreateGraphTemplateModal()">Create Template</button>
    </div>`;
}

function templateMacTracking() {
    return `
    <div class="page-header">
        <h2>MAC/ARP Tracking</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-primary" onclick="triggerMacCollectionUI()">Collect Now</button>
        </div>
    </div>
    <div class="page-header" style="margin-top: 0;">
        <input id="mac-tracking-search" class="form-input list-control-search" type="search"
               placeholder="Search by MAC, IP, or port name..."
               onkeydown="if(event.key==='Enter') searchMacTrackingUI()">
        <button class="btn btn-sm" onclick="searchMacTrackingUI()">Search</button>
    </div>
    <div id="mac-tracking-results"></div>
    <div id="mac-tracking-empty" class="empty-state">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
            <line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line>
        </svg>
        <p>Search for a MAC address, IP address, or port name to see endpoint locations.</p>
        <p style="font-size:0.85em; opacity:0.7;">MAC/ARP tables are collected automatically during topology discovery.</p>
    </div>`;
}

function templateTrafficAnalysis() {
    return `
    <div class="page-header">
        <h2>Traffic Analysis</h2>
        <div style="display:flex; gap:0.5rem; align-items:center;">
            <select id="traffic-time-range" class="form-select list-control-select" onchange="loadTrafficAnalysis()">
                <option value="1">Last 1 Hour</option>
                <option value="6" selected>Last 6 Hours</option>
                <option value="24">Last 24 Hours</option>
                <option value="168">Last 7 Days</option>
            </select>
            <span id="flow-collector-status" class="badge"></span>
        </div>
    </div>
    <div id="traffic-analysis-content">
        <div class="chart-grid-2col" style="margin-bottom:1rem;">
            <div class="glass-card card"><h4 style="margin:0 0 0.5rem">Top Sources</h4><div id="traffic-top-src"></div></div>
            <div class="glass-card card"><h4 style="margin:0 0 0.5rem">Top Destinations</h4><div id="traffic-top-dst"></div></div>
        </div>
        <div class="chart-grid-2col" style="margin-bottom:1rem;">
            <div class="glass-card card"><h4 style="margin:0 0 0.5rem">Top Applications</h4><div id="traffic-top-apps"></div></div>
            <div class="glass-card card"><h4 style="margin:0 0 0.5rem">Top Conversations</h4><div id="traffic-top-convos"></div></div>
        </div>
        <div class="glass-card card"><h4 style="margin:0 0 0.5rem">Traffic Timeline</h4><div id="traffic-timeline-chart" style="height:250px;"></div></div>
    </div>
    <div id="traffic-analysis-empty" class="empty-state" style="display:none">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>
        <p>No flow data available. Configure devices to send NetFlow/sFlow/IPFIX to Plexus.</p>
        <p style="font-size:0.85em; opacity:0.7;">Collector port: UDP 2055 (NetFlow), 6343 (sFlow)</p>
    </div>`;
}

function templateUpgrades() {
    return `
    <div class="page-header">
        <h2>Upgrade Tool</h2>
        <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-secondary" onclick="showUpgradeImagesModal()">Software Images</button>
            <button class="btn btn-primary" onclick="showCreateCampaignModal()">+ New Campaign</button>
        </div>
    </div>
    <!-- Campaign subtabs -->
    <div class="tab-controls" id="upgrades-tabs">
        <button class="btn btn-sm btn-secondary upgrade-tab-btn active" data-upgrade-tab="campaigns" onclick="switchUpgradeTab('campaigns')">Campaigns</button>
        <button class="btn btn-sm btn-secondary upgrade-tab-btn" data-upgrade-tab="images" onclick="switchUpgradeTab('images')">Image Library</button>
        <button class="btn btn-sm btn-secondary upgrade-tab-btn" data-upgrade-tab="backups" onclick="switchUpgradeTab('backups')">Config Backups</button>
    </div>
    <!-- Campaigns List -->
    <div id="upgrade-tab-campaigns" class="tab-pane">
        <div class="list-controls">
            <input id="upgrade-campaign-search" class="form-input list-control-search" type="search" placeholder="Search campaigns...">
        </div>
        <div id="upgrade-campaigns-list">
            ${skel(2)}
        </div>
    </div>
    <!-- Image Library Tab -->
    <div id="upgrade-tab-images" class="tab-pane" style="display:none">
        <div style="display:flex; justify-content:flex-end; margin-bottom:0.75rem;">
            <button class="btn btn-primary" onclick="showUploadImageModal()">Upload Image</button>
        </div>
        <div id="upgrade-images-list">
            ${skel(1)}
        </div>
    </div>
    <!-- Config Backups Tab -->
    <div id="upgrade-tab-backups" class="tab-pane" style="display:none">
        <div id="upgrade-backups-list">
            ${skel(1)}
        </div>
    </div>`;
}

function templateSettings() {
    return `
    <h2>Admin Settings</h2>
    <div class="section">
        <h3>Appearance</h3>
        <div style="max-width: 260px;">
            <label class="form-label" for="theme-select-settings">Theme</label>
            <select id="theme-select-settings" class="theme-select" aria-label="Select theme in settings">
                <option value="forest">Forest</option>
                <option value="dark-modern">Dark</option>
                <option value="astral">Astral</option>
                <option value="light">Light</option>
                <option value="void">Void</option>
                <option value="coral">Coral</option>
                <option value="sandstone">Sandstone</option>
                <option value="voyager">Voyager</option>
            </select>
        </div>
        <div style="max-width: 320px; margin-top: 1rem;">
            <label class="form-label" for="space-intensity-settings">Space Depth Intensity</label>
            <select id="space-intensity-settings" class="theme-select" aria-label="Select space depth intensity">
                <option value="off">Off</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
            </select>
        </div>
        <div style="margin-top: 0.75rem; max-width: 320px;">
            <label style="display:flex; align-items:center; gap:0.5rem; color:var(--text);">
                <input type="checkbox" id="space-parallax-settings" checked>
                Enable background parallax motion
            </label>
        </div>
    </div>
    <div class="section">
        <div class="page-header" style="margin-bottom: 0.5rem;">
            <h3 style="margin: 0;">Feature Visibility</h3>
            <button type="button" class="btn btn-primary" id="feature-visibility-save">Save Visibility</button>
        </div>
        <p style="color: var(--text-muted); margin: 0 0 0.75rem 0; font-size: 0.85rem;">
            Hide navigation entries for features your team doesn't use. This only affects what's shown in the sidebar — it does not remove permissions or stop background services.
        </p>
        <div id="feature-visibility-list" style="display:grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.4rem 1rem;">
            ${skel(2)}
        </div>
    </div>
    <div class="section">
        <div class="page-header" style="margin-bottom: 1rem;">
            <h3 style="margin: 0;">User Management</h3>
            <button class="btn btn-primary" onclick="showCreateAdminUserModal()">+ New User</button>
        </div>
        <div id="admin-users-list" class="admin-users-list">
            ${skel(2)}
        </div>
    </div>
    <div class="section">
        <div class="page-header" style="margin-bottom: 1rem;">
            <h3 style="margin: 0;">User Groups</h3>
            <button class="btn btn-primary" onclick="showCreateAccessGroupModal()">+ New Group</button>
        </div>
        <div id="admin-groups-list" class="admin-groups-list">
            ${skel(2)}
        </div>
    </div>
    <div class="section">
        <h3>Login Rules</h3>
        <form id="admin-login-rules-form" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; max-width: 560px;">
            <div class="form-group">
                <label class="form-label" for="login-max-attempts">Max Attempts</label>
                <input type="number" id="login-max-attempts" class="form-input" min="1">
            </div>
            <div class="form-group">
                <label class="form-label" for="login-lockout-time">Lockout Time (sec)</label>
                <input type="number" id="login-lockout-time" class="form-input" min="1">
            </div>
            <div class="form-group">
                <label class="form-label" for="login-rate-window">Rate Limit Window (sec)</label>
                <input type="number" id="login-rate-window" class="form-input" min="1">
            </div>
            <div class="form-group">
                <label class="form-label" for="login-rate-max">Rate Limit Max</label>
                <input type="number" id="login-rate-max" class="form-input" min="1">
            </div>
            <div style="grid-column: 1 / -1;">
                <button type="submit" class="btn btn-primary">Save Rules</button>
            </div>
        </form>
    </div>
    <div class="section">
        <h3>Authentication Provider</h3>
        <form id="admin-auth-config-form" style="display: grid; gap: 0.8rem; max-width: 700px;">
            <div class="form-group">
                <label class="form-label" for="auth-provider">Active Provider</label>
                <select id="auth-provider" class="form-select">
                    <option value="local">Local Database</option>
                    <option value="radius">RADIUS</option>
                    <option value="ldap">LDAP / Active Directory</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label" for="default-credential-id">Default Network Credential</label>
                <select id="default-credential-id" class="form-select">
                    <option value="">-- None --</option>
                </select>
                <small style="color: var(--text-muted);">Used by monitoring polls, background tasks, and jobs when no credential is explicitly selected.</small>
            </div>
            <div class="form-group">
                <label class="form-label" for="job-retention-days">Job History Retention (days)</label>
                <input type="number" id="job-retention-days" class="form-input" min="30" step="1" value="30">
                <small style="color: var(--text-muted);">Completed jobs older than this are deleted automatically. Minimum is 30 days.</small>
            </div>
            <div id="radius-config-panel" style="display:none; border: 1px solid var(--border); background: var(--bg-secondary); border-radius: 0.5rem; padding: 0.75rem;">
                <div class="form-group">
                    <label><input type="checkbox" id="radius-enabled"> Enable RADIUS login path</label>
                </div>
                <div class="form-group" style="display: grid; gap: 0.4rem; margin-top: 0.35rem;">
                    <label><input type="checkbox" id="radius-fallback-local" checked> Fallback to local auth when RADIUS is unavailable</label>
                    <label><input type="checkbox" id="radius-fallback-reject"> Allow fallback to local auth on RADIUS reject</label>
                    <small style="color: var(--text-muted);">Recommended: keep reject fallback disabled so invalid RADIUS credentials are denied immediately.</small>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 140px; gap: 0.75rem;">
                    <div class="form-group">
                        <label class="form-label" for="radius-server">RADIUS Server</label>
                        <input type="text" id="radius-server" class="form-input" placeholder="10.0.0.50">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="radius-port">Port</label>
                        <input type="number" id="radius-port" class="form-input" min="1">
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 140px; gap: 0.75rem;">
                    <div class="form-group">
                        <label class="form-label" for="radius-secret">Shared Secret</label>
                        <input type="password" id="radius-secret" class="form-input" placeholder="Stored in app settings">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="radius-timeout">Timeout (sec)</label>
                        <input type="number" id="radius-timeout" class="form-input" min="1">
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Default Access Groups for New RADIUS Users</label>
                    <div id="radius-default-groups" style="display:grid; gap:0.35rem; max-height:160px; overflow:auto; border:1px solid var(--border); border-radius:0.375rem; padding:0.6rem;"></div>
                    <small style="color: var(--text-muted);">Applied only when a RADIUS user signs in for the first time. Existing users keep their assigned groups.</small>
                </div>
            </div>
            <div id="ldap-config-panel" style="display:none; border: 1px solid var(--border); background: var(--bg-secondary); border-radius: 0.5rem; padding: 0.75rem;">
                <div class="form-group">
                    <label><input type="checkbox" id="ldap-enabled"> Enable LDAP / Active Directory authentication</label>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 100px 100px; gap: 0.75rem;">
                    <div class="form-group">
                        <label class="form-label" for="ldap-server">LDAP Server</label>
                        <input type="text" id="ldap-server" class="form-input" placeholder="dc01.corp.local">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="ldap-port">Port</label>
                        <input type="number" id="ldap-port" class="form-input" min="1" value="389">
                    </div>
                    <div class="form-group" style="display:flex; align-items:end; padding-bottom:0.25rem;">
                        <label><input type="checkbox" id="ldap-use-ssl"> Use SSL</label>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
                    <div class="form-group">
                        <label class="form-label" for="ldap-bind-dn">Service Account DN (Bind DN)</label>
                        <input type="text" id="ldap-bind-dn" class="form-input" placeholder="CN=svc_plexus,OU=Service Accounts,DC=corp,DC=local">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="ldap-bind-password">Service Account Password</label>
                        <input type="password" id="ldap-bind-password" class="form-input" placeholder="Service account password">
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label" for="ldap-base-dn">Base DN (Search Root)</label>
                    <input type="text" id="ldap-base-dn" class="form-input" placeholder="DC=corp,DC=local">
                    <small style="color: var(--text-muted);">The root of the LDAP tree to search for users.</small>
                </div>
                <div class="form-group">
                    <label class="form-label" for="ldap-user-search-filter">User Search Filter</label>
                    <input type="text" id="ldap-user-search-filter" class="form-input" value="(sAMAccountName={username})" placeholder="(sAMAccountName={username})">
                    <small style="color: var(--text-muted);">Use <code>{username}</code> as a placeholder. For AD: <code>(sAMAccountName={username})</code>. For OpenLDAP: <code>(uid={username})</code>.</small>
                </div>
                <div class="form-group">
                    <label class="form-label" for="ldap-admin-group-dn">Admin Group DN (optional)</label>
                    <input type="text" id="ldap-admin-group-dn" class="form-input" placeholder="CN=Plexus Admins,OU=Groups,DC=corp,DC=local">
                    <small style="color: var(--text-muted);">Users in this AD group are auto-promoted to admin role. Leave blank if all LDAP users should be regular users.</small>
                </div>
                <div class="form-group" style="display: grid; gap: 0.4rem; margin-top: 0.35rem;">
                    <label><input type="checkbox" id="ldap-fallback-local" checked> Fallback to local auth when LDAP is unavailable</label>
                    <label><input type="checkbox" id="ldap-fallback-reject"> Allow fallback to local auth on LDAP reject</label>
                </div>
                <div class="form-group">
                    <label class="form-label" for="ldap-timeout">Timeout (seconds)</label>
                    <input type="number" id="ldap-timeout" class="form-input" min="1" value="10" style="max-width:100px;">
                </div>
            </div>
            <div>
                <button type="submit" class="btn btn-primary">Save Auth Configuration</button>
            </div>
        </form>
    </div>
    <div class="section">
        <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.75rem;">
            <h3 style="margin:0;">Outbound Syslog</h3>
            <span id="syslog-status" class="status-badge">Disabled</span>
        </div>
        <form id="admin-syslog-form" style="display: grid; grid-template-columns: auto minmax(180px, 1fr); gap: 0.75rem 1rem; max-width: 700px; align-items: center;">
            <label class="form-label" style="margin:0;">Enabled</label>
            <label><input type="checkbox" id="syslog-enabled"> Send Plexus logs and audit events to syslog</label>

            <label class="form-label" for="syslog-host" style="margin:0;">Server</label>
            <input type="text" id="syslog-host" class="form-input" placeholder="10.0.0.25">

            <label class="form-label" for="syslog-port" style="margin:0;">Port</label>
            <input type="number" id="syslog-port" class="form-input" min="1" max="65535" value="514">

            <label class="form-label" for="syslog-protocol" style="margin:0;">Protocol</label>
            <select id="syslog-protocol" class="form-select">
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
            </select>

            <label class="form-label" for="syslog-facility" style="margin:0;">Facility</label>
            <select id="syslog-facility" class="form-select">
                <option value="local0">local0</option>
                <option value="local1">local1</option>
                <option value="local2">local2</option>
                <option value="local3">local3</option>
                <option value="local4">local4</option>
                <option value="local5">local5</option>
                <option value="local6">local6</option>
                <option value="local7">local7</option>
                <option value="daemon">daemon</option>
                <option value="auth">auth</option>
                <option value="user">user</option>
            </select>

            <label class="form-label" for="syslog-level" style="margin:0;">Minimum Level</label>
            <select id="syslog-level" class="form-select">
                <option value="DEBUG">Debug</option>
                <option value="INFO">Info</option>
                <option value="WARNING">Warning</option>
                <option value="ERROR">Error</option>
                <option value="CRITICAL">Critical</option>
            </select>

            <label class="form-label" for="syslog-app-name" style="margin:0;">App Name</label>
            <input type="text" id="syslog-app-name" class="form-input" value="plexus" maxlength="64">

            <div style="grid-column: 1 / -1; display:flex; gap:0.5rem; flex-wrap:wrap;">
                <button type="submit" class="btn btn-primary">Save Syslog</button>
                <button type="button" class="btn btn-secondary" onclick="sendSyslogTest()">Send Test</button>
            </div>
        </form>
    </div>
    <div class="section">
        <h3>Monitoring</h3>
        <p style="color: var(--text-muted); margin-bottom: 0.75rem; font-size: 0.85rem;">
            Periodically poll devices via SNMP/SSH to collect CPU, memory, response time, packet loss, and interface metrics.
        </p>
        <form id="admin-monitoring-form" style="display: grid; grid-template-columns: auto 1fr; gap: 0.75rem 1rem; max-width: 520px; align-items: center;">
            <label class="form-label" style="margin:0;">Enabled</label>
            <label><input type="checkbox" id="mon-enabled"> Enable monitoring polling</label>

            <label class="form-label" for="mon-interval" style="margin:0;">Poll Interval (seconds)</label>
            <input type="number" id="mon-interval" class="form-input" min="60" max="86400" step="60" value="300">

            <label class="form-label" for="mon-retention" style="margin:0;">Retention (days)</label>
            <input type="number" id="mon-retention" class="form-input" min="1" max="365" value="30">

            <label class="form-label" for="mon-cpu-threshold" style="margin:0;">CPU Threshold (%)</label>
            <input type="number" id="mon-cpu-threshold" class="form-input" min="1" max="100" value="90">

            <label class="form-label" for="mon-mem-threshold" style="margin:0;">Memory Threshold (%)</label>
            <input type="number" id="mon-mem-threshold" class="form-input" min="1" max="100" value="90">

            <label class="form-label" style="margin:0;">Collection</label>
            <div style="display: grid; gap: 0.4rem;">
                <label><input type="checkbox" id="mon-collect-routes" checked> Collect routes</label>
                <label><input type="checkbox" id="mon-collect-vpn" checked> Collect VPN tunnels</label>
            </div>

            <label class="form-label" style="margin:0;">Escalation</label>
            <label><input type="checkbox" id="mon-escalation-enabled" checked> Enable alert escalation</label>

            <label class="form-label" for="mon-escalation-after" style="margin:0;">Escalate After (minutes)</label>
            <input type="number" id="mon-escalation-after" class="form-input" min="1" max="1440" value="30">

            <label class="form-label" for="mon-escalation-check" style="margin:0;">Escalation Check Interval (s)</label>
            <input type="number" id="mon-escalation-check" class="form-input" min="10" max="3600" value="60">

            <label class="form-label" for="mon-cooldown" style="margin:0;">Alert Cooldown (minutes)</label>
            <input type="number" id="mon-cooldown" class="form-input" min="1" max="1440" value="15">

            <div style="grid-column: 1 / -1; display:flex; gap:0.5rem;">
                <button type="submit" class="btn btn-primary">Save</button>
                <button type="button" class="btn btn-secondary" id="mon-poll-now-btn" onclick="runMonitoringPollNow()">Poll Now</button>
            </div>
        </form>
    </div>
    <div class="section">
        <h3>Scheduled Topology Discovery</h3>
        <p style="color: var(--text-muted); margin-bottom: 0.75rem; font-size: 0.85rem;">
            Automatically run neighbor discovery on all SNMP-enabled groups at a regular interval to keep the topology map current.
        </p>
        <form id="admin-topology-discovery-form" style="display: grid; grid-template-columns: auto 1fr; gap: 0.75rem 1rem; max-width: 480px; align-items: center;">
            <label class="form-label" style="margin:0;">Enabled</label>
            <label><input type="checkbox" id="topo-disc-enabled"> Enable scheduled discovery</label>
            <label class="form-label" for="topo-disc-interval" style="margin:0;">Interval (seconds)</label>
            <input type="number" id="topo-disc-interval" class="form-input" min="300" max="86400" step="60" value="3600">
            <div style="grid-column: 1 / -1; display:flex; gap:0.5rem;">
                <button type="submit" class="btn btn-primary">Save</button>
                <button type="button" class="btn btn-secondary" onclick="runTopologyDiscoveryNow()">Run Now</button>
            </div>
        </form>
    </div>
    <div class="section">
        <h3>Scheduled STP Polling</h3>
        <p style="color: var(--text-muted); margin-bottom: 0.75rem; font-size: 0.85rem;">
            Automatically collect STP state and events to keep VLAN root and blocked-port visibility current.
        </p>
        <form id="admin-stp-discovery-form" style="display: grid; grid-template-columns: auto 1fr; gap: 0.75rem 1rem; max-width: 560px; align-items: center;">
            <label class="form-label" style="margin:0;">Enabled</label>
            <label><input type="checkbox" id="stp-disc-enabled"> Enable scheduled STP polling</label>
            <label class="form-label" for="stp-disc-interval" style="margin:0;">Interval (seconds)</label>
            <input type="number" id="stp-disc-interval" class="form-input" min="300" max="86400" step="60" value="3600">
            <label class="form-label" style="margin:0;">Scope</label>
            <label><input type="checkbox" id="stp-disc-all-vlans" checked> Poll all discovered VLANs</label>
            <label class="form-label" for="stp-disc-vlan" style="margin:0;">Single VLAN</label>
            <input type="number" id="stp-disc-vlan" class="form-input" min="1" max="4094" value="1">
            <label class="form-label" for="stp-disc-max-vlans" style="margin:0;">Max VLANs (all)</label>
            <input type="number" id="stp-disc-max-vlans" class="form-input" min="1" max="256" value="64">
            <div style="grid-column: 1 / -1; display:flex; gap:0.5rem;">
                <button type="submit" class="btn btn-primary">Save</button>
                <button type="button" class="btn btn-secondary" onclick="runTopologyStpDiscoveryNow()">Run Now</button>
            </div>
        </form>
    </div>
    <div class="section">
        <h3>STP Expected Root Policy</h3>
        <p style="color: var(--text-muted); margin-bottom: 0.75rem; font-size: 0.85rem;">
            Define the expected STP root bridge per group/VLAN so unexpected elections trigger explicit alerts.
        </p>
        <form id="admin-stp-root-policy-form" style="display: grid; grid-template-columns: auto 1fr; gap: 0.75rem 1rem; max-width: 680px; align-items: center;">
            <label class="form-label" for="stp-root-group-id" style="margin:0;">Inventory Group</label>
            <select id="stp-root-group-id" class="form-select"></select>
            <label class="form-label" for="stp-root-vlan" style="margin:0;">VLAN</label>
            <input type="number" id="stp-root-vlan" class="form-input" min="1" max="4094" value="1">
            <label class="form-label" for="stp-root-bridge-id" style="margin:0;">Expected Root Bridge ID</label>
            <input type="text" id="stp-root-bridge-id" class="form-input" placeholder="e.g. 32768 00:11:22:33:44:55">
            <label class="form-label" for="stp-root-hostname" style="margin:0;">Expected Root Hostname</label>
            <input type="text" id="stp-root-hostname" class="form-input" placeholder="Optional display label">
            <label class="form-label" style="margin:0;">Enabled</label>
            <label><input type="checkbox" id="stp-root-enabled" checked> Policy active</label>
            <div style="grid-column: 1 / -1; display:flex; gap:0.5rem;">
                <button type="submit" class="btn btn-primary">Save Policy</button>
            </div>
        </form>
        <div id="stp-root-policy-list" style="margin-top:0.85rem;"></div>
    </div>`;
}

// ── Modal templates (created on demand) ──────────────────────────────────────

export function templateSlaHostDetailModal() {
    return `
    <div id="sla-host-detail-modal" class="modal" style="display:none;">
        <div class="modal-backdrop" onclick="closeSlaHostDetailModal()"></div>
        <div class="modal-content" style="max-width:800px;">
            <div class="modal-header">
                <h3 id="sla-host-detail-title">Host SLA Detail</h3>
                <button class="modal-close" onclick="closeSlaHostDetailModal()">&times;</button>
            </div>
            <div id="sla-host-detail-body" style="padding:1rem;">
                <div class="skeleton skeleton-card" style="height:200px;"></div>
            </div>
        </div>
    </div>`;
}

export function templateSlaTargetModal() {
    return `
    <div id="sla-target-modal" class="modal" style="display:none;">
        <div class="modal-backdrop" onclick="closeSlaTargetModal()"></div>
        <div class="modal-content" style="max-width:500px;">
            <div class="modal-header">
                <h3 id="sla-target-modal-title">New SLA Target</h3>
                <button class="modal-close" onclick="closeSlaTargetModal()">&times;</button>
            </div>
            <div style="padding:1rem;">
                <input type="hidden" id="sla-target-edit-id">
                <div class="form-group" style="margin-bottom:0.75rem;">
                    <label class="form-label">Name</label>
                    <input id="sla-target-name" class="form-input" placeholder="e.g. Core Router Uptime SLA">
                </div>
                <div class="form-group" style="margin-bottom:0.75rem;">
                    <label class="form-label">Metric</label>
                    <select id="sla-target-metric" class="form-select">
                        <option value="uptime">Uptime %</option>
                        <option value="latency">Latency (ms)</option>
                        <option value="jitter">Jitter (ms)</option>
                        <option value="packet_loss">Packet Loss %</option>
                    </select>
                </div>
                <div style="display:flex; gap:0.75rem; margin-bottom:0.75rem;">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Target Value</label>
                        <input id="sla-target-value" class="form-input" type="number" step="0.01" value="99.9">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Warning Value</label>
                        <input id="sla-target-warning" class="form-input" type="number" step="0.01" value="99.0">
                    </div>
                </div>
                <div class="form-group" style="margin-bottom:0.75rem;">
                    <label class="form-label">Scope (optional)</label>
                    <select id="sla-target-scope" class="form-select" onchange="toggleSlaTargetScope()">
                        <option value="global">Global (all hosts)</option>
                        <option value="group">Group</option>
                        <option value="host">Host</option>
                    </select>
                </div>
                <div id="sla-target-scope-group" style="display:none; margin-bottom:0.75rem;">
                    <label class="form-label">Group</label>
                    <select id="sla-target-group-id" class="form-select"></select>
                </div>
                <div id="sla-target-scope-host" style="display:none; margin-bottom:0.75rem;">
                    <label class="form-label">Host</label>
                    <select id="sla-target-host-id" class="form-select"></select>
                </div>
                <div style="display:flex; gap:0.5rem; justify-content:flex-end;">
                    <button class="btn btn-secondary" onclick="closeSlaTargetModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="saveSlaTarget()">Save</button>
                </div>
            </div>
        </div>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Empty State SVG Illustrations
// ═══════════════════════════════════════════════════════════════════════════════

const EMPTY_ILLUSTRATIONS = {
    inventory: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="20" y="30" width="80" height="60" rx="6" opacity="0.3"/>
        <rect x="30" y="42" width="25" height="4" rx="2" opacity="0.5"/>
        <rect x="30" y="52" width="40" height="4" rx="2" opacity="0.4"/>
        <rect x="30" y="62" width="20" height="4" rx="2" opacity="0.3"/>
        <line x1="75" y1="45" x2="85" y2="45" opacity="0.4"/>
        <line x1="75" y1="55" x2="85" y2="55" opacity="0.3"/>
        <circle cx="80" cy="75" r="12" opacity="0.2" fill="currentColor"/>
        <line x1="75" y1="75" x2="85" y2="75" opacity="0.6"/>
        <line x1="80" y1="70" x2="80" y2="80" opacity="0.6"/>
    </svg>`,
    playbooks: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M35 25h50a5 5 0 015 5v60a5 5 0 01-5 5H35a5 5 0 01-5-5V30a5 5 0 015-5z" opacity="0.3"/>
        <path d="M30 30h5v60h-5" opacity="0.2" fill="currentColor"/>
        <rect x="42" y="40" width="35" height="3" rx="1.5" opacity="0.5"/>
        <rect x="42" y="50" width="25" height="3" rx="1.5" opacity="0.4"/>
        <rect x="42" y="60" width="30" height="3" rx="1.5" opacity="0.3"/>
        <rect x="42" y="70" width="20" height="3" rx="1.5" opacity="0.25"/>
        <circle cx="80" cy="80" r="12" opacity="0.2" fill="currentColor"/>
        <line x1="75" y1="80" x2="85" y2="80" opacity="0.6"/>
        <line x1="80" y1="75" x2="80" y2="85" opacity="0.6"/>
    </svg>`,
    jobs: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="60,20 95,40 95,80 60,100 25,80 25,40" opacity="0.2"/>
        <polygon points="60,20 95,40 60,60 25,40" opacity="0.15" fill="currentColor"/>
        <line x1="60" y1="60" x2="60" y2="100" opacity="0.3"/>
        <line x1="25" y1="40" x2="60" y2="60" opacity="0.3"/>
        <line x1="95" y1="40" x2="60" y2="60" opacity="0.3"/>
        <circle cx="60" cy="58" r="10" opacity="0.3"/>
        <polyline points="55,58 59,62 66,54" opacity="0.5"/>
    </svg>`,
    templates: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="25" y="25" width="70" height="70" rx="6" opacity="0.2"/>
        <line x1="25" y1="45" x2="95" y2="45" opacity="0.2"/>
        <line x1="55" y1="45" x2="55" y2="95" opacity="0.2"/>
        <rect x="30" y="30" width="20" height="4" rx="2" opacity="0.4"/>
        <rect x="35" y="55" width="12" height="8" rx="2" opacity="0.15" fill="currentColor"/>
        <rect x="65" y="55" width="20" height="8" rx="2" opacity="0.15" fill="currentColor"/>
        <rect x="35" y="72" width="12" height="8" rx="2" opacity="0.1" fill="currentColor"/>
        <rect x="65" y="72" width="20" height="8" rx="2" opacity="0.1" fill="currentColor"/>
    </svg>`,
    credentials: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="25" y="45" width="70" height="40" rx="6" opacity="0.3"/>
        <path d="M60 45V35a12 12 0 0124 0v10" opacity="0.3"/>
        <circle cx="60" cy="62" r="5" opacity="0.4"/>
        <line x1="60" y1="67" x2="60" y2="75" opacity="0.4"/>
    </svg>`,
    default: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="60" cy="50" r="25" opacity="0.2"/>
        <line x1="60" y1="40" x2="60" y2="55" opacity="0.4"/>
        <circle cx="60" cy="62" r="2" opacity="0.4" fill="currentColor"/>
        <rect x="35" y="85" width="50" height="4" rx="2" opacity="0.15"/>
        <rect x="42" y="93" width="36" height="4" rx="2" opacity="0.1"/>
    </svg>`,
};

function getEmptyIllustration(type) {
    return EMPTY_ILLUSTRATIONS[type] || EMPTY_ILLUSTRATIONS.default;
}

export function emptyStateHTML(message, type, actionBtn) {
    return `<div class="empty-state">
        <div class="empty-state-illustration">${getEmptyIllustration(type)}</div>
        <div class="empty-state-title">${message}</div>
        <div class="empty-state-text">Get started by creating your first ${type.replace(/s$/, '')}.</div>
        ${actionBtn || ''}
    </div>`;
}

export function templateOidProfileModal() {
    return `
    <div id="oid-profile-modal" class="modal" style="display:none;">
        <div class="modal-backdrop" onclick="closeOidProfileModal()"></div>
        <div class="modal-content" style="max-width:600px;">
            <div class="modal-header">
                <h3 id="oid-profile-modal-title">New OID Profile</h3>
                <button class="modal-close" onclick="closeOidProfileModal()">&times;</button>
            </div>
            <div style="padding:1rem;">
                <input type="hidden" id="oid-profile-edit-id">
                <div class="form-group"><label class="form-label">Name</label>
                    <input id="oid-profile-name" class="form-input" placeholder="e.g. Cisco Catalyst 9300"></div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                    <div class="form-group"><label class="form-label">Vendor</label>
                        <input id="oid-profile-vendor" class="form-input" placeholder="e.g. Cisco"></div>
                    <div class="form-group"><label class="form-label">Device Type</label>
                        <input id="oid-profile-device-type" class="form-input" placeholder="e.g. cisco_ios"></div>
                </div>
                <div class="form-group"><label class="form-label">Description</label>
                    <textarea id="oid-profile-description" class="form-input" rows="2"></textarea></div>
                <div class="form-group"><label class="form-label">OID Mappings (JSON)</label>
                    <textarea id="oid-profile-oids" class="form-input" rows="8" placeholder='[{"oid":"1.3.6.1.4.1.9.9.109.1.1.1.1.8","metric_name":"cpu_percent","label":"CPU 5min","type":"gauge"}]'></textarea></div>
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1rem;">
                    <button class="btn btn-secondary" onclick="closeOidProfileModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="saveOidProfile()">Save</button>
                </div>
            </div>
        </div>
    </div>`;
}

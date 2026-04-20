/**
 * Cloud Visibility Module
 * AWS / Azure / GCP account inventory + hybrid topology foundation
 */
import * as api from '../api.js';
import {
    escapeHtml,
    showConfirm,
    showError,
    showFormModal,
    showSuccess,
    skeletonCards,
    formatDate,
} from '../app.js';

let _cloudProviders = [];
let _cloudAccounts = [];
let _cloudFlowSyncConfig = null;
let _cloudFlowSyncCursors = [];
let _cloudTrafficSyncConfig = null;
let _cloudTrafficSyncCursors = [];

function _ensureCloudVisibilityLayout() {
    const page = document.getElementById('page-cloud-visibility');
    if (!page) return null;
    if (page.querySelector('#cloud-accounts-list')) return page;

    page.innerHTML = `
        <div class="page-header" style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:1rem;">
            <h2 style="margin:0;">Cloud Visibility</h2>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                <button class="btn btn-primary" onclick="showCreateCloudAccountModal()">Add Cloud Account</button>
                <button class="btn btn-secondary" onclick="refreshCloudVisibility()">Refresh</button>
            </div>
        </div>

        <div class="card" style="padding:0.9rem; margin-bottom:1rem;">
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:0.75rem;">
                <label>Provider Filter
                    <select id="cloud-provider-filter" class="form-select" onchange="onCloudProviderFilterChange()">
                        <option value="">All Providers</option>
                    </select>
                </label>
                <label>Account Filter
                    <select id="cloud-account-filter" class="form-select" onchange="onCloudAccountFilterChange()">
                        <option value="">All Accounts</option>
                    </select>
                </label>
                <label>Flow Hours
                    <select id="cloud-flow-hours" class="form-select" onchange="onCloudAnalyticsFilterChange()">
                        <option value="1">Last 1 hour</option>
                        <option value="6">Last 6 hours</option>
                        <option value="24" selected>Last 24 hours</option>
                        <option value="72">Last 72 hours</option>
                        <option value="168">Last 7 days</option>
                    </select>
                </label>
                <label>Top Talkers
                    <select id="cloud-flow-direction" class="form-select" onchange="onCloudAnalyticsFilterChange()">
                        <option value="src" selected>Source IP</option>
                        <option value="dst">Destination IP</option>
                    </select>
                </label>
                <label>Talker Limit
                    <input id="cloud-flow-limit" class="form-input" type="number" min="5" max="200" value="20" oninput="onCloudAnalyticsFilterChange()">
                </label>
                <label>Timeline Bucket
                    <select id="cloud-flow-bucket" class="form-select" onchange="onCloudAnalyticsFilterChange()">
                        <option value="1">1 minute</option>
                        <option value="5" selected>5 minutes</option>
                        <option value="15">15 minutes</option>
                        <option value="30">30 minutes</option>
                        <option value="60">60 minutes</option>
                    </select>
                </label>
            </div>
        </div>

        <h3 style="margin:0.25rem 0 0.5rem;">Provider Capability Hints</h3>
        <div id="cloud-provider-capabilities" style="margin-bottom:1rem;"></div>

        <h3 style="margin:0.25rem 0 0.5rem;">Flow Sync Controls</h3>
        <div class="card" style="padding:0.9rem; margin-bottom:1rem;">
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:0.75rem; align-items:end;">
                <label style="display:flex; align-items:center; gap:0.5rem; margin:0;">
                    <input id="cloud-flow-sync-enabled" type="checkbox">
                    Enable Scheduled Pulling
                </label>
                <label>Interval Seconds
                    <input id="cloud-flow-sync-interval" class="form-input" type="number" min="60" max="3600" value="300">
                </label>
                <label>Lookback Minutes
                    <input id="cloud-flow-sync-lookback" class="form-input" type="number" min="1" max="1440" value="15">
                </label>
                <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                    <button class="btn btn-secondary" onclick="saveCloudFlowSyncConfig()">Save Sync Config</button>
                    <button class="btn btn-primary" onclick="runCloudFlowSyncPull()">Pull All Accounts</button>
                    <button class="btn btn-secondary" onclick="runCloudFlowSyncPull(true)">Pull Selected Account</button>
                </div>
            </div>
            <div id="cloud-flow-sync-status" style="margin-top:0.6rem; color:var(--text-muted);"></div>
            <div id="cloud-flow-cursors" style="margin-top:0.75rem;"></div>
        </div>

        <h3 style="margin:0.25rem 0 0.5rem;">Cloud Flow Analytics</h3>
        <div id="cloud-flow-summary" style="margin-bottom:1rem;"></div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:1rem; margin-bottom:1rem;">
            <div>
                <h4 style="margin:0 0 0.45rem;">Top Talkers</h4>
                <div id="cloud-flow-top-talkers"></div>
            </div>
            <div>
                <h4 style="margin:0 0 0.45rem;">Traffic Timeline</h4>
                <div id="cloud-flow-timeline"></div>
            </div>
        </div>

        <h3 style="margin:0.25rem 0 0.5rem;">Cloud Traffic Metrics</h3>
        <div class="card" style="padding:0.9rem; margin-bottom:1rem;">
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:0.75rem; align-items:end;">
                <label style="display:flex; align-items:center; gap:0.5rem; margin:0;">
                    <input id="cloud-traffic-sync-enabled" type="checkbox">
                    Enable Scheduled Metric Pulling
                </label>
                <label>Interval Seconds
                    <input id="cloud-traffic-sync-interval" class="form-input" type="number" min="60" max="3600" value="300">
                </label>
                <label>Lookback Minutes
                    <input id="cloud-traffic-sync-lookback" class="form-input" type="number" min="1" max="1440" value="15">
                </label>
                <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                    <button class="btn btn-secondary" onclick="saveCloudTrafficSyncConfig()">Save Metric Sync Config</button>
                    <button class="btn btn-primary" onclick="runCloudTrafficSyncPull()">Pull All Accounts</button>
                    <button class="btn btn-secondary" onclick="runCloudTrafficSyncPull(true)">Pull Selected Account</button>
                </div>
            </div>
            <div id="cloud-traffic-sync-status" style="margin-top:0.6rem; color:var(--text-muted);"></div>
            <div id="cloud-traffic-cursors" style="margin-top:0.75rem;"></div>
        </div>

        <div id="cloud-traffic-metric-summary" style="margin-bottom:1rem;"></div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:1rem; margin-bottom:1rem;">
            <div>
                <h4 style="margin:0 0 0.45rem;">Top Resources</h4>
                <div id="cloud-traffic-metric-top-resources"></div>
            </div>
            <div>
                <h4 style="margin:0 0 0.45rem;">Metric Timeline</h4>
                <div id="cloud-traffic-metric-timeline"></div>
            </div>
        </div>

        <h3 style="margin:0.25rem 0 0.5rem;">Cloud Accounts</h3>
        <div id="cloud-accounts-list" style="margin-bottom:1rem;"></div>

        <h3 style="margin:0.25rem 0 0.5rem;">Hybrid Topology Snapshot</h3>
        <div id="cloud-topology-summary" style="margin-bottom:1rem;"></div>

        <h4 style="margin:0.25rem 0 0.45rem;">Resources</h4>
        <div id="cloud-resources-list" style="margin-bottom:1rem;"></div>

        <h4 style="margin:0.25rem 0 0.45rem;">Connections</h4>
        <div id="cloud-connections-list" style="margin-bottom:1rem;"></div>

        <h4 style="margin:0.25rem 0 0.45rem;">Hybrid Links</h4>
        <div id="cloud-hybrid-links-list"></div>
    `;
    return page;
}

function _providerLabel(provider) {
    const p = String(provider || '').toLowerCase();
    if (p === 'aws') return 'AWS';
    if (p === 'azure') return 'Azure';
    if (p === 'gcp') return 'GCP';
    return provider || '';
}

function _normalizeProviderOptions() {
    const fromApi = _cloudProviders.map((p) => String(p.id || '').toLowerCase()).filter(Boolean);
    const fromAccounts = _cloudAccounts.map((a) => String(a.provider || '').toLowerCase()).filter(Boolean);
    return [...new Set([...fromApi, ...fromAccounts])].sort();
}

function _currentProviderFilter() {
    return document.getElementById('cloud-provider-filter')?.value || '';
}

function _currentAccountFilter() {
    const raw = document.getElementById('cloud-account-filter')?.value || '';
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function _currentFlowHours() {
    const raw = document.getElementById('cloud-flow-hours')?.value || '24';
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 24;
}

function _currentTalkerDirection() {
    const value = String(document.getElementById('cloud-flow-direction')?.value || 'src').toLowerCase();
    return value === 'dst' ? 'dst' : 'src';
}

function _currentTalkerLimit() {
    const raw = document.getElementById('cloud-flow-limit')?.value || '20';
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? Math.max(5, Math.min(parsed, 200)) : 20;
}

function _currentTimelineBucketMinutes() {
    const raw = document.getElementById('cloud-flow-bucket')?.value || '5';
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? Math.max(1, Math.min(parsed, 60)) : 5;
}

function _currentCloudQueryParams() {
    const params = { hours: _currentFlowHours() };
    const provider = _currentProviderFilter();
    const accountId = _currentAccountFilter();
    if (provider) params.provider = provider;
    if (accountId) params.account_id = accountId;
    return params;
}

function _formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(2)} KB`;
    return `${bytes} B`;
}

function _formatCount(value) {
    return Number(value || 0).toLocaleString();
}

function _formatMetricValue(value) {
    const numeric = Number(value) || 0;
    if (Math.abs(numeric) >= 1000) {
        return numeric.toLocaleString(undefined, { maximumFractionDigits: 2 });
    }
    return numeric.toFixed(2);
}

function _toIsoOrDash(raw) {
    if (!raw) return '-';
    try {
        return formatDate(raw);
    } catch {
        return String(raw);
    }
}

function _parseJsonInput(raw, fallback = {}) {
    const text = String(raw || '').trim();
    if (!text) return fallback;
    try {
        return JSON.parse(text);
    } catch {
        throw new Error('Invalid JSON in auth config');
    }
}

async function _ensureProvidersLoaded() {
    if (_cloudProviders.length) return;
    try {
        const result = await api.getCloudProviders();
        _cloudProviders = result?.providers || [];
    } catch (error) {
        // Non-fatal: we can still use provider values from accounts.
        console.warn('Failed to load cloud providers:', error);
    }
}

function _renderProviderCapabilities() {
    const container = document.getElementById('cloud-provider-capabilities');
    if (!container) return;
    if (!_cloudProviders.length) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = _cloudProviders.map((provider) => {
        const missing = Array.isArray(provider?.missing_dependencies) ? provider.missing_dependencies : [];
        const liveSupported = Boolean(provider?.live_supported);
        return `
            <div class="card" style="padding:0.65rem 0.85rem; margin-bottom:0.4rem;">
                <strong>${escapeHtml(_providerLabel(provider.id))}</strong>
                <span style="margin-left:0.45rem;" class="badge badge-${liveSupported ? 'success' : 'warning'}">
                    ${liveSupported ? 'Live collector ready' : 'Live collector unavailable'}
                </span>
                ${missing.length ? `<div style="margin-top:0.35rem; color:var(--text-muted); font-size:0.85em;">Missing deps: ${escapeHtml(missing.join(', '))}</div>` : ''}
            </div>`;
    }).join('');
}

function _renderProviderFilter() {
    const select = document.getElementById('cloud-provider-filter');
    if (!select) return;
    const current = select.value || '';
    const providers = _normalizeProviderOptions();
    select.innerHTML = `<option value="">All Providers</option>${providers.map((p) =>
        `<option value="${escapeHtml(p)}">${escapeHtml(_providerLabel(p))}</option>`).join('')}`;
    if (providers.includes(current)) select.value = current;
}

function _renderAccountFilter() {
    const select = document.getElementById('cloud-account-filter');
    if (!select) return;
    const current = select.value || '';
    const provider = _currentProviderFilter();
    const accounts = _cloudAccounts.filter((a) => !provider || String(a.provider || '').toLowerCase() === provider);
    select.innerHTML = `<option value="">All Accounts</option>${accounts.map((a) =>
        `<option value="${a.id}">${escapeHtml(a.name)} (${escapeHtml(_providerLabel(a.provider))})</option>`).join('')}`;
    if (current && accounts.some((a) => String(a.id) === String(current))) {
        select.value = current;
    }
}

async function loadCloudAccounts({ preserveContent = false } = {}) {
    const container = document.getElementById('cloud-accounts-list');
    if (!container) return;
    if (!preserveContent) container.innerHTML = skeletonCards(2);

    const provider = _currentProviderFilter();
    const result = await api.getCloudAccounts(provider ? { provider } : {});
    _cloudAccounts = result?.accounts || [];
    _renderProviderFilter();
    _renderAccountFilter();
    _renderProviderCapabilities();

    if (!_cloudAccounts.length) {
        container.innerHTML = `
            <div class="card" style="padding:1.25rem;">
                <p style="margin:0; color:var(--text-muted);">
                    No cloud accounts configured yet. Add an AWS/Azure/GCP account to start building hybrid visibility.
                </p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <table class="chart-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Provider</th>
                    <th>Account</th>
                    <th>Scope</th>
                    <th>Last Sync</th>
                    <th>Resources</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${_cloudAccounts.map((a) => `
                    <tr>
                        <td>${escapeHtml(a.name || '')}</td>
                        <td>${escapeHtml(_providerLabel(a.provider))}</td>
                        <td>${escapeHtml(a.account_identifier || '-')}</td>
                        <td>${escapeHtml(a.region_scope || '-')}</td>
                        <td>
                            <div>${escapeHtml(a.last_sync_status || 'never')}</div>
                            <small style="color:var(--text-muted);">${escapeHtml(a.last_sync_at ? formatDate(a.last_sync_at) : 'Never')}</small>
                        </td>
                        <td>
                            <span class="badge badge-info">${a.resource_count ?? 0} nodes</span>
                            <span class="badge badge-info">${a.connection_count ?? 0} edges</span>
                        </td>
                        <td style="white-space:nowrap;">
                            <button class="btn btn-sm btn-secondary" onclick="runCloudValidation(${a.id})">Validate</button>
                            <button class="btn btn-sm btn-secondary" onclick="runCloudDiscovery(${a.id})">Discover</button>
                            <button class="btn btn-sm btn-secondary" onclick="editCloudAccount(${a.id})">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteCloudAccount(${a.id})">Delete</button>
                        </td>
                    </tr>`).join('')}
            </tbody>
        </table>`;
}

async function loadCloudTopology({ preserveContent = false } = {}) {
    const summaryEl = document.getElementById('cloud-topology-summary');
    const resourcesEl = document.getElementById('cloud-resources-list');
    const connectionsEl = document.getElementById('cloud-connections-list');
    const hybridEl = document.getElementById('cloud-hybrid-links-list');
    if (!summaryEl || !resourcesEl || !connectionsEl || !hybridEl) return;

    if (!preserveContent) {
        summaryEl.innerHTML = skeletonCards(1, 'margin-bottom:0;');
        resourcesEl.innerHTML = skeletonCards(1, 'margin-bottom:0;');
        connectionsEl.innerHTML = skeletonCards(1, 'margin-bottom:0;');
        hybridEl.innerHTML = skeletonCards(1, 'margin-bottom:0;');
    }

    const params = {};
    const provider = _currentProviderFilter();
    const accountId = _currentAccountFilter();
    if (provider) params.provider = provider;
    if (accountId) params.account_id = accountId;

    const snapshot = await api.getCloudTopology(params);
    const resources = snapshot?.resources || [];
    const connections = snapshot?.connections || [];
    const hybridLinks = snapshot?.hybrid_links || [];
    const summary = snapshot?.summary || {};

    summaryEl.innerHTML = `
        <div class="drift-summary-grid">
            <div class="drift-summary-card"><div class="drift-summary-value">${summary.account_count ?? 0}</div><div class="drift-summary-label">Accounts</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${summary.resource_count ?? 0}</div><div class="drift-summary-label">Cloud Resources</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${summary.connection_count ?? 0}</div><div class="drift-summary-label">Cloud Links</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${summary.hybrid_link_count ?? 0}</div><div class="drift-summary-label">Hybrid Links</div></div>
        </div>`;

    if (!resources.length) {
        resourcesEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No cloud resources yet. Run discovery on an account.</p></div>';
    } else {
        resourcesEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Provider</th><th>Type</th><th>Name</th><th>Region</th><th>CIDR</th><th>Status</th></tr></thead>
                <tbody>${resources.map((r) => `
                    <tr>
                        <td>${escapeHtml(_providerLabel(r.provider))}</td>
                        <td>${escapeHtml(r.resource_type || '')}</td>
                        <td>${escapeHtml(r.name || r.resource_uid || '')}</td>
                        <td>${escapeHtml(r.region || '-')}</td>
                        <td>${escapeHtml(r.cidr || '-')}</td>
                        <td>${escapeHtml(r.status || '-')}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }

    if (!connections.length) {
        connectionsEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No cloud-to-cloud links available.</p></div>';
    } else {
        connectionsEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Provider</th><th>From</th><th>To</th><th>Type</th><th>State</th></tr></thead>
                <tbody>${connections.map((c) => `
                    <tr>
                        <td>${escapeHtml(_providerLabel(c.provider))}</td>
                        <td>${escapeHtml(c.source_name || c.source_resource_uid || '')}</td>
                        <td>${escapeHtml(c.target_name || c.target_resource_uid || '')}</td>
                        <td>${escapeHtml(c.connection_type || '')}</td>
                        <td>${escapeHtml(c.state || '-')}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }

    if (!hybridLinks.length) {
        hybridEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No on-prem to cloud links mapped yet.</p></div>';
    } else {
        hybridEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>On-Prem Host</th><th>Cloud Resource</th><th>Type</th><th>State</th></tr></thead>
                <tbody>${hybridLinks.map((link) => `
                    <tr>
                        <td>${escapeHtml(link.host_hostname || link.host_label || '-')}</td>
                        <td>${escapeHtml(link.cloud_resource_name || link.cloud_resource_uid || '-')}</td>
                        <td>${escapeHtml(link.connection_type || '')}</td>
                        <td>${escapeHtml(link.state || '-')}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }
}

async function loadCloudFlowAnalytics({ preserveContent = false } = {}) {
    const summaryEl = document.getElementById('cloud-flow-summary');
    const talkersEl = document.getElementById('cloud-flow-top-talkers');
    const timelineEl = document.getElementById('cloud-flow-timeline');
    if (!summaryEl || !talkersEl || !timelineEl) return;

    if (!preserveContent) {
        summaryEl.innerHTML = skeletonCards(1);
        talkersEl.innerHTML = skeletonCards(1);
        timelineEl.innerHTML = skeletonCards(1);
    }

    const baseParams = _currentCloudQueryParams();
    const direction = _currentTalkerDirection();
    const limit = _currentTalkerLimit();
    const bucketMinutes = _currentTimelineBucketMinutes();

    const [summaryResp, talkersResp, timelineResp] = await Promise.all([
        api.getCloudFlowSummary(baseParams),
        api.getCloudFlowTopTalkers({ ...baseParams, direction, limit }),
        api.getCloudFlowTimeline({ ...baseParams, bucket_minutes: bucketMinutes }),
    ]);

    const summary = summaryResp?.summary || {};
    const talkers = Array.isArray(talkersResp?.talkers) ? talkersResp.talkers : [];
    const timeline = Array.isArray(timelineResp?.timeline) ? timelineResp.timeline : [];

    summaryEl.innerHTML = `
        <div class="drift-summary-grid">
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.flow_count)}</div><div class="drift-summary-label">Flows</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${escapeHtml(_formatBytes(summary.total_bytes))}</div><div class="drift-summary-label">Total Bytes</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.total_packets)}</div><div class="drift-summary-label">Total Packets</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.unique_sources)}</div><div class="drift-summary-label">Unique Sources</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.unique_destinations)}</div><div class="drift-summary-label">Unique Destinations</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value" style="font-size:1rem;">${escapeHtml(_toIsoOrDash(summary.last_seen))}</div><div class="drift-summary-label">Last Seen</div></div>
        </div>`;

    if (!talkers.length) {
        talkersEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No flow talkers found for current filters.</p></div>';
    } else {
        talkersEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>${direction === 'dst' ? 'Destination IP' : 'Source IP'}</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr></thead>
                <tbody>${talkers.map((row) => `
                    <tr>
                        <td>${escapeHtml(row.ip || '-')}</td>
                        <td>${escapeHtml(_formatBytes(row.total_bytes))}</td>
                        <td>${_formatCount(row.total_packets)}</td>
                        <td>${_formatCount(row.flow_count)}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }

    if (!timeline.length) {
        timelineEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No timeline data available for current filters.</p></div>';
    } else {
        timelineEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Bucket</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr></thead>
                <tbody>${timeline.map((row) => `
                    <tr>
                        <td>${escapeHtml(_toIsoOrDash(row.bucket))}</td>
                        <td>${escapeHtml(_formatBytes(row.total_bytes))}</td>
                        <td>${_formatCount(row.total_packets)}</td>
                        <td>${_formatCount(row.flow_count)}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }
}

async function loadCloudTrafficMetricAnalytics({ preserveContent = false } = {}) {
    const summaryEl = document.getElementById('cloud-traffic-metric-summary');
    const resourcesEl = document.getElementById('cloud-traffic-metric-top-resources');
    const timelineEl = document.getElementById('cloud-traffic-metric-timeline');
    if (!summaryEl || !resourcesEl || !timelineEl) return;

    if (!preserveContent) {
        summaryEl.innerHTML = skeletonCards(1);
        resourcesEl.innerHTML = skeletonCards(1);
        timelineEl.innerHTML = skeletonCards(1);
    }

    const baseParams = _currentCloudQueryParams();
    const limit = _currentTalkerLimit();
    const bucketMinutes = _currentTimelineBucketMinutes();

    const [summaryResp, topResourcesResp, timelineResp] = await Promise.all([
        api.getCloudTrafficMetricSummary(baseParams),
        api.getCloudTrafficMetricTopResources({ ...baseParams, limit }),
        api.getCloudTrafficMetricTimeline({ ...baseParams, bucket_minutes: bucketMinutes }),
    ]);

    const summary = summaryResp?.summary || {};
    const resources = Array.isArray(topResourcesResp?.resources) ? topResourcesResp.resources : [];
    const timeline = Array.isArray(timelineResp?.timeline) ? timelineResp.timeline : [];

    summaryEl.innerHTML = `
        <div class="drift-summary-grid">
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.sample_count)}</div><div class="drift-summary-label">Samples</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.metric_count)}</div><div class="drift-summary-label">Metric Names</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${_formatCount(summary.resource_count)}</div><div class="drift-summary-label">Resources</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${escapeHtml(_formatMetricValue(summary.total_value))}</div><div class="drift-summary-label">Total Value</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value">${escapeHtml(_formatMetricValue(summary.avg_value))}</div><div class="drift-summary-label">Average Value</div></div>
            <div class="drift-summary-card"><div class="drift-summary-value" style="font-size:1rem;">${escapeHtml(_toIsoOrDash(summary.last_seen))}</div><div class="drift-summary-label">Last Seen</div></div>
        </div>`;

    if (!resources.length) {
        resourcesEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No traffic metric resources found for current filters.</p></div>';
    } else {
        resourcesEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Resource</th><th>Total Value</th><th>Average</th><th>Samples</th></tr></thead>
                <tbody>${resources.map((row) => `
                    <tr>
                        <td>${escapeHtml(row.resource_uid || '-')}</td>
                        <td>${escapeHtml(_formatMetricValue(row.total_value))}</td>
                        <td>${escapeHtml(_formatMetricValue(row.avg_value))}</td>
                        <td>${_formatCount(row.sample_count)}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }

    if (!timeline.length) {
        timelineEl.innerHTML = '<div class="card" style="padding:1rem;"><p class="text-muted" style="margin:0;">No traffic metric timeline data available for current filters.</p></div>';
    } else {
        timelineEl.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Bucket</th><th>Total Value</th><th>Average</th><th>Samples</th></tr></thead>
                <tbody>${timeline.map((row) => `
                    <tr>
                        <td>${escapeHtml(_toIsoOrDash(row.bucket))}</td>
                        <td>${escapeHtml(_formatMetricValue(row.total_value))}</td>
                        <td>${escapeHtml(_formatMetricValue(row.avg_value))}</td>
                        <td>${_formatCount(row.sample_count)}</td>
                    </tr>`).join('')}</tbody>
            </table>`;
    }
}

function _renderFlowSyncControls() {
    const enabledEl = document.getElementById('cloud-flow-sync-enabled');
    const intervalEl = document.getElementById('cloud-flow-sync-interval');
    const lookbackEl = document.getElementById('cloud-flow-sync-lookback');
    const statusEl = document.getElementById('cloud-flow-sync-status');
    if (!enabledEl || !intervalEl || !lookbackEl || !statusEl) return;

    const config = _cloudFlowSyncConfig || {};
    enabledEl.checked = Boolean(config.enabled);
    intervalEl.value = String(config.interval_seconds || 300);
    lookbackEl.value = String(config.lookback_minutes || 15);
    statusEl.textContent = `Current config: ${config.enabled ? 'enabled' : 'disabled'}, interval ${config.interval_seconds || 300}s, lookback ${config.lookback_minutes || 15}m.`;
}

function _renderFlowSyncCursors() {
    const container = document.getElementById('cloud-flow-cursors');
    if (!container) return;

    if (!_cloudFlowSyncCursors.length) {
        container.innerHTML = '<div class="card" style="padding:0.75rem;"><p class="text-muted" style="margin:0;">No flow-sync cursors yet. Run a manual pull or wait for scheduler.</p></div>';
        return;
    }

    container.innerHTML = `
        <table class="chart-table">
            <thead><tr><th>Account</th><th>Provider</th><th>Last Pull End</th><th>Updated</th></tr></thead>
            <tbody>${_cloudFlowSyncCursors.map((c) => `
                <tr>
                    <td>${escapeHtml(c.account_name || `Account #${c.account_id}`)}</td>
                    <td>${escapeHtml(_providerLabel(c.provider || ''))}</td>
                    <td>${escapeHtml(_toIsoOrDash(c.last_pull_end))}</td>
                    <td>${escapeHtml(_toIsoOrDash(c.updated_at))}</td>
                </tr>`).join('')}</tbody>
        </table>`;
}

async function loadCloudFlowSync({ preserveContent = false } = {}) {
    const statusEl = document.getElementById('cloud-flow-sync-status');
    const cursorsEl = document.getElementById('cloud-flow-cursors');
    if (!statusEl || !cursorsEl) return;

    if (!preserveContent) {
        statusEl.textContent = 'Loading flow sync config...';
        cursorsEl.innerHTML = skeletonCards(1);
    }

    const [configResp, cursorsResp] = await Promise.all([
        api.getCloudFlowSyncConfig(),
        api.getCloudFlowSyncCursors(),
    ]);
    _cloudFlowSyncConfig = configResp?.config || null;
    _cloudFlowSyncCursors = Array.isArray(cursorsResp?.cursors) ? cursorsResp.cursors : [];
    _renderFlowSyncControls();
    _renderFlowSyncCursors();
}

function _renderTrafficSyncControls() {
    const enabledEl = document.getElementById('cloud-traffic-sync-enabled');
    const intervalEl = document.getElementById('cloud-traffic-sync-interval');
    const lookbackEl = document.getElementById('cloud-traffic-sync-lookback');
    const statusEl = document.getElementById('cloud-traffic-sync-status');
    if (!enabledEl || !intervalEl || !lookbackEl || !statusEl) return;

    const config = _cloudTrafficSyncConfig || {};
    enabledEl.checked = Boolean(config.enabled);
    intervalEl.value = String(config.interval_seconds || 300);
    lookbackEl.value = String(config.lookback_minutes || 15);
    statusEl.textContent = `Current config: ${config.enabled ? 'enabled' : 'disabled'}, interval ${config.interval_seconds || 300}s, lookback ${config.lookback_minutes || 15}m.`;
}

function _renderTrafficSyncCursors() {
    const container = document.getElementById('cloud-traffic-cursors');
    if (!container) return;

    if (!_cloudTrafficSyncCursors.length) {
        container.innerHTML = '<div class="card" style="padding:0.75rem;"><p class="text-muted" style="margin:0;">No traffic-sync cursors yet. Run a manual pull or wait for scheduler.</p></div>';
        return;
    }

    container.innerHTML = `
        <table class="chart-table">
            <thead><tr><th>Account</th><th>Provider</th><th>Last Pull End</th><th>Updated</th></tr></thead>
            <tbody>${_cloudTrafficSyncCursors.map((c) => `
                <tr>
                    <td>${escapeHtml(c.account_name || `Account #${c.account_id}`)}</td>
                    <td>${escapeHtml(_providerLabel(c.provider || ''))}</td>
                    <td>${escapeHtml(_toIsoOrDash(c.last_pull_end))}</td>
                    <td>${escapeHtml(_toIsoOrDash(c.updated_at))}</td>
                </tr>`).join('')}</tbody>
        </table>`;
}

async function loadCloudTrafficSync({ preserveContent = false } = {}) {
    const statusEl = document.getElementById('cloud-traffic-sync-status');
    const cursorsEl = document.getElementById('cloud-traffic-cursors');
    if (!statusEl || !cursorsEl) return;

    if (!preserveContent) {
        statusEl.textContent = 'Loading traffic sync config...';
        cursorsEl.innerHTML = skeletonCards(1);
    }

    const [configResp, cursorsResp] = await Promise.all([
        api.getCloudTrafficSyncConfig(),
        api.getCloudTrafficSyncCursors(),
    ]);
    _cloudTrafficSyncConfig = configResp?.config || null;
    _cloudTrafficSyncCursors = Array.isArray(cursorsResp?.cursors) ? cursorsResp.cursors : [];
    _renderTrafficSyncControls();
    _renderTrafficSyncCursors();
}

function _buildAccountFormHtml(account = null) {
    const providers = _normalizeProviderOptions();
    const providerOptions = providers.length ? providers : ['aws', 'azure', 'gcp'];
    const authConfigText = JSON.stringify(account?.auth_config || {}, null, 2);
    return `
        <form id="cloud-account-form" class="settings-grid" style="display:grid; gap:0.75rem;">
            <label>Provider
                <select id="cloud-account-provider" class="form-select">
                    ${providerOptions.map((provider) => `
                        <option value="${escapeHtml(provider)}" ${String(account?.provider || '').toLowerCase() === provider ? 'selected' : ''}>
                            ${escapeHtml(_providerLabel(provider))}
                        </option>`).join('')}
                </select>
            </label>
            <label>Name
                <input id="cloud-account-name" class="form-input" type="text" value="${escapeHtml(account?.name || '')}" placeholder="Prod AWS Core" required>
            </label>
            <label>Account / Subscription / Project
                <input id="cloud-account-identifier" class="form-input" type="text" value="${escapeHtml(account?.account_identifier || '')}" placeholder="123456789012 / sub-id / project-id">
            </label>
            <label>Region Scope
                <input id="cloud-account-region-scope" class="form-input" type="text" value="${escapeHtml(account?.region_scope || '')}" placeholder="us-east-1,us-west-2">
            </label>
            <label>Auth Type
                <select id="cloud-account-auth-type" class="form-select">
                    ${['manual', 'api_keys', 'assume_role', 'service_principal', 'workload_identity'].map((t) =>
                        `<option value="${t}" ${account?.auth_type === t ? 'selected' : ''}>${escapeHtml(t)}</option>`).join('')}
                </select>
            </label>
            <label>Auth Config (JSON references, non-secret)
                <textarea id="cloud-account-auth-config" class="form-input" rows="4" placeholder='{"secret_ref":"aws-prod-readonly"}'>${escapeHtml(authConfigText)}</textarea>
            </label>
            <label>Notes
                <textarea id="cloud-account-notes" class="form-input" rows="3" placeholder="Optional notes">${escapeHtml(account?.notes || '')}</textarea>
            </label>
            <label style="display:flex; align-items:center; gap:0.5rem;">
                <input id="cloud-account-enabled" type="checkbox" ${account?.enabled === 0 ? '' : 'checked'}>
                Enabled
            </label>
        </form>`;
}

async function _saveAccountFromModal(account = null) {
    const provider = document.getElementById('cloud-account-provider')?.value || '';
    const name = (document.getElementById('cloud-account-name')?.value || '').trim();
    const accountIdentifier = (document.getElementById('cloud-account-identifier')?.value || '').trim();
    const regionScope = (document.getElementById('cloud-account-region-scope')?.value || '').trim();
    const authType = (document.getElementById('cloud-account-auth-type')?.value || '').trim();
    const authConfigRaw = document.getElementById('cloud-account-auth-config')?.value || '';
    const notes = (document.getElementById('cloud-account-notes')?.value || '').trim();
    const enabled = Boolean(document.getElementById('cloud-account-enabled')?.checked);

    if (!name) {
        throw new Error('Account name is required');
    }
    const authConfig = _parseJsonInput(authConfigRaw, {});
    const payload = {
        provider,
        name,
        account_identifier: accountIdentifier,
        region_scope: regionScope,
        auth_type: authType || 'manual',
        auth_config: authConfig,
        notes,
        enabled,
    };

    if (account?.id) {
        await api.updateCloudAccount(account.id, payload);
    } else {
        await api.createCloudAccount(payload);
    }
}

function showCreateCloudAccountModal() {
    showFormModal('Add Cloud Account', _buildAccountFormHtml(), async () => {
        await _saveAccountFromModal(null);
        showSuccess('Cloud account created');
        await refreshCloudVisibility();
    });
}
window.showCreateCloudAccountModal = showCreateCloudAccountModal;

async function editCloudAccount(accountId) {
    const account = _cloudAccounts.find((a) => Number(a.id) === Number(accountId));
    if (!account) {
        showError('Cloud account not found');
        return;
    }
    showFormModal('Edit Cloud Account', _buildAccountFormHtml(account), async () => {
        await _saveAccountFromModal(account);
        showSuccess('Cloud account updated');
        await refreshCloudVisibility();
    });
}
window.editCloudAccount = editCloudAccount;

async function deleteCloudAccount(accountId) {
    const account = _cloudAccounts.find((a) => Number(a.id) === Number(accountId));
    const confirmed = await showConfirm({
        title: 'Delete Cloud Account',
        message: `Delete "${account?.name || `Account #${accountId}`}" and all discovered cloud topology data?`,
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!confirmed) return;
    await api.deleteCloudAccount(accountId);
    showSuccess('Cloud account deleted');
    await refreshCloudVisibility();
}
window.deleteCloudAccount = deleteCloudAccount;

async function runCloudValidation(accountId) {
    const account = _cloudAccounts.find((a) => Number(a.id) === Number(accountId));
    const result = await api.validateCloudAccount(accountId, { mode: 'live' });
    const accountLabel = account?.name || `Account #${accountId}`;
    if (result?.valid) {
        showSuccess(`${accountLabel}: ${result?.message || 'Cloud account validation succeeded'}`);
        return;
    }

    let detail = result?.message || 'Cloud account validation failed';
    const missing = Array.isArray(result?.missing_dependencies) ? result.missing_dependencies : [];
    if (result?.status === 'unavailable' && missing.length) {
        detail += ` (missing: ${missing.join(', ')})`;
    }
    showError(`${accountLabel}: ${detail}`);
}
window.runCloudValidation = runCloudValidation;

async function runCloudDiscovery(accountId) {
    const account = _cloudAccounts.find((a) => Number(a.id) === Number(accountId));
    const confirmed = await showConfirm({
        title: 'Run Cloud Discovery',
        message: `Refresh cloud topology snapshot for "${account?.name || `Account #${accountId}`}"? Auto mode will try live provider APIs first, then fall back to sample if dependencies/credentials are missing.`,
        confirmText: 'Discover',
        confirmClass: 'btn-primary',
    });
    if (!confirmed) return;
    const result = await api.discoverCloudAccount(accountId, { mode: 'auto', include_hybrid_links: true });
    if (result?.fallback_used) {
        showSuccess(result?.message || 'Cloud discovery completed with sample fallback');
    } else {
        showSuccess(result?.message || 'Cloud discovery snapshot updated');
    }
    await refreshCloudVisibility();
}
window.runCloudDiscovery = runCloudDiscovery;

async function onCloudProviderFilterChange() {
    _renderAccountFilter();
    await loadCloudAccounts({ preserveContent: false });
    await loadCloudTopology({ preserveContent: false });
    await loadCloudFlowAnalytics({ preserveContent: false });
    await loadCloudTrafficMetricAnalytics({ preserveContent: false });
}
window.onCloudProviderFilterChange = onCloudProviderFilterChange;

async function onCloudAccountFilterChange() {
    await loadCloudTopology({ preserveContent: false });
    await loadCloudFlowAnalytics({ preserveContent: false });
    await loadCloudTrafficMetricAnalytics({ preserveContent: false });
}
window.onCloudAccountFilterChange = onCloudAccountFilterChange;

async function onCloudAnalyticsFilterChange() {
    await loadCloudFlowAnalytics({ preserveContent: false });
    await loadCloudTrafficMetricAnalytics({ preserveContent: false });
}
window.onCloudAnalyticsFilterChange = onCloudAnalyticsFilterChange;

async function saveCloudFlowSyncConfig() {
    const enabled = Boolean(document.getElementById('cloud-flow-sync-enabled')?.checked);
    const intervalRaw = document.getElementById('cloud-flow-sync-interval')?.value || '300';
    const lookbackRaw = document.getElementById('cloud-flow-sync-lookback')?.value || '15';
    const intervalSeconds = Number.parseInt(intervalRaw, 10);
    const lookbackMinutes = Number.parseInt(lookbackRaw, 10);
    const payload = {
        enabled,
        interval_seconds: Number.isFinite(intervalSeconds) ? intervalSeconds : 300,
        lookback_minutes: Number.isFinite(lookbackMinutes) ? lookbackMinutes : 15,
    };
    const result = await api.updateCloudFlowSyncConfig(payload);
    _cloudFlowSyncConfig = result?.config || payload;
    _renderFlowSyncControls();
    showSuccess('Cloud flow sync config saved');
}
window.saveCloudFlowSyncConfig = saveCloudFlowSyncConfig;

async function runCloudFlowSyncPull(selectedOnly = false) {
    const accountId = _currentAccountFilter();
    const params = selectedOnly && accountId ? { account_id: accountId } : {};
    const result = await api.triggerCloudFlowSyncPull(params);
    const ingested = Number(result?.ingested ?? result?.total_ingested ?? 0);
    if (selectedOnly && accountId) {
        showSuccess(`Cloud flow pull complete for account ${accountId}: ${ingested} ingested`);
    } else {
        showSuccess(`Cloud flow pull complete: ${ingested} ingested`);
    }
    await Promise.all([
        loadCloudFlowSync({ preserveContent: false }),
        loadCloudFlowAnalytics({ preserveContent: false }),
        loadCloudTrafficMetricAnalytics({ preserveContent: false }),
    ]);
}
window.runCloudFlowSyncPull = runCloudFlowSyncPull;

async function saveCloudTrafficSyncConfig() {
    const enabled = Boolean(document.getElementById('cloud-traffic-sync-enabled')?.checked);
    const intervalRaw = document.getElementById('cloud-traffic-sync-interval')?.value || '300';
    const lookbackRaw = document.getElementById('cloud-traffic-sync-lookback')?.value || '15';
    const intervalSeconds = Number.parseInt(intervalRaw, 10);
    const lookbackMinutes = Number.parseInt(lookbackRaw, 10);
    const payload = {
        enabled,
        interval_seconds: Number.isFinite(intervalSeconds) ? intervalSeconds : 300,
        lookback_minutes: Number.isFinite(lookbackMinutes) ? lookbackMinutes : 15,
    };
    const result = await api.updateCloudTrafficSyncConfig(payload);
    _cloudTrafficSyncConfig = result?.config || payload;
    _renderTrafficSyncControls();
    showSuccess('Cloud traffic sync config saved');
}
window.saveCloudTrafficSyncConfig = saveCloudTrafficSyncConfig;

async function runCloudTrafficSyncPull(selectedOnly = false) {
    const accountId = _currentAccountFilter();
    const params = selectedOnly && accountId ? { account_id: accountId } : {};
    const result = await api.triggerCloudTrafficSyncPull(params);
    const ingested = Number(result?.ingested ?? result?.total_ingested ?? 0);
    if (selectedOnly && accountId) {
        showSuccess(`Cloud traffic metric pull complete for account ${accountId}: ${ingested} ingested`);
    } else {
        showSuccess(`Cloud traffic metric pull complete: ${ingested} ingested`);
    }
    await Promise.all([
        loadCloudTrafficSync({ preserveContent: false }),
        loadCloudTrafficMetricAnalytics({ preserveContent: false }),
    ]);
}
window.runCloudTrafficSyncPull = runCloudTrafficSyncPull;

async function refreshCloudVisibility() {
    await loadCloudAccounts({ preserveContent: false });
    await Promise.all([
        loadCloudTopology({ preserveContent: false }),
        loadCloudFlowAnalytics({ preserveContent: false }),
        loadCloudTrafficMetricAnalytics({ preserveContent: false }),
        loadCloudFlowSync({ preserveContent: false }),
        loadCloudTrafficSync({ preserveContent: false }),
    ]);
}
window.refreshCloudVisibility = refreshCloudVisibility;

export async function loadCloudVisibility({ preserveContent = false } = {}) {
    _ensureCloudVisibilityLayout();
    const accountsEl = document.getElementById('cloud-accounts-list');
    const topologyEl = document.getElementById('cloud-topology-summary');
    const summaryEl = document.getElementById('cloud-flow-summary');
    const trafficMetricSummaryEl = document.getElementById('cloud-traffic-metric-summary');
    const syncStatusEl = document.getElementById('cloud-flow-sync-status');
    const trafficSyncStatusEl = document.getElementById('cloud-traffic-sync-status');
    if (accountsEl && !preserveContent) accountsEl.innerHTML = skeletonCards(2);
    if (topologyEl && !preserveContent) topologyEl.innerHTML = skeletonCards(1);
    if (summaryEl && !preserveContent) summaryEl.innerHTML = skeletonCards(1);
    if (trafficMetricSummaryEl && !preserveContent) trafficMetricSummaryEl.innerHTML = skeletonCards(1);
    if (syncStatusEl && !preserveContent) syncStatusEl.textContent = 'Loading flow sync config...';
    if (trafficSyncStatusEl && !preserveContent) trafficSyncStatusEl.textContent = 'Loading traffic sync config...';

    await _ensureProvidersLoaded();
    await loadCloudAccounts({ preserveContent });
    await Promise.all([
        loadCloudTopology({ preserveContent }),
        loadCloudFlowAnalytics({ preserveContent }),
        loadCloudTrafficMetricAnalytics({ preserveContent }),
        loadCloudFlowSync({ preserveContent }),
        loadCloudTrafficSync({ preserveContent }),
    ]);
}

export function destroyCloudVisibility() {
    _cloudProviders = [];
    _cloudAccounts = [];
    _cloudFlowSyncConfig = null;
    _cloudFlowSyncCursors = [];
    _cloudTrafficSyncConfig = null;
    _cloudTrafficSyncCursors = [];
}

/**
 * IPAM Module
 * Lightweight IP address management overview page.
 */
import * as api from '../api.js';
import {
    escapeHtml,
    showError,
    skeletonCards,
} from '../app.js';

let _overview = null;
let _groups = [];
let _selectedGroupId = '';
let _includeCloud = true;

function _ensureIpamLayout() {
    const page = document.getElementById('page-ipam');
    if (!page) return null;
    if (page.querySelector('#ipam-summary')) return page;

    page.innerHTML = `
        <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
            <div>
                <h2 style="margin:0;">IP Address Management</h2>
                <p class="text-muted" style="margin:0.35rem 0 0;max-width:72ch;">Track inferred inventory subnets, discovered cloud CIDRs, utilization, and duplicate IP conflicts from one view.</p>
            </div>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:end;">
                <label>Inventory Group
                    <select id="ipam-group-filter" class="form-select" onchange="onIpamFiltersChange()">
                        <option value="">All Groups</option>
                    </select>
                </label>
                <label style="display:flex;align-items:center;gap:0.5rem;margin:0 0 0.2rem;">
                    <input id="ipam-include-cloud" type="checkbox" checked onchange="onIpamFiltersChange()">
                    Include Cloud CIDRs
                </label>
                <button class="btn btn-secondary" onclick="refreshIpam()">Refresh</button>
            </div>
        </div>
        <div id="ipam-summary" style="margin-bottom:1rem;">${skeletonCards(4)}</div>
        <div style="display:grid;grid-template-columns:minmax(0,2.1fr) minmax(320px,1fr);gap:1rem;align-items:start;">
            <div class="card" style="padding:1rem;overflow:auto;">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:0.75rem;flex-wrap:wrap;">
                    <h3 style="margin:0;">Subnet Inventory</h3>
                    <div class="text-muted" id="ipam-subnet-count"></div>
                </div>
                <div id="ipam-subnets"></div>
            </div>
            <div style="display:grid;gap:1rem;">
                <div class="card" style="padding:1rem;">
                    <h3 style="margin:0 0 0.75rem;">Duplicate IP Conflicts</h3>
                    <div id="ipam-duplicates"></div>
                </div>
                <div class="card" style="padding:1rem;">
                    <h3 style="margin:0 0 0.75rem;">Scope Notes</h3>
                    <div class="text-muted" style="display:grid;gap:0.65rem;line-height:1.55;">
                        <div>Inventory subnets are inferred from host addresses. Plain IPv4 addresses default to /24 and plain IPv6 addresses default to /64 when prefixes are not stored.</div>
                        <div>Cloud CIDRs come from discovered cloud resources such as VPCs, VNets, and subnets.</div>
                        <div>Duplicate IP conflicts are detected across inventory groups so address reuse is visible even when each group stays internally unique.</div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return page;
}

function _renderGroupFilter() {
    const select = document.getElementById('ipam-group-filter');
    if (!select) return;
    select.innerHTML = ['<option value="">All Groups</option>']
        .concat(_groups.map((group) => `<option value="${group.id}">${escapeHtml(group.name || `Group ${group.id}`)}</option>`))
        .join('');
    select.value = String(_selectedGroupId || '');

    const cloudToggle = document.getElementById('ipam-include-cloud');
    if (cloudToggle) cloudToggle.checked = _includeCloud;
}

function _renderSummary() {
    const container = document.getElementById('ipam-summary');
    if (!container || !_overview) return;
    const summary = _overview.summary || {};
    const cards = [
        { label: 'Tracked Hosts', value: summary.inventory_host_count || 0 },
        { label: 'Total Subnets', value: summary.total_subnets || 0 },
        { label: 'Cloud CIDRs', value: summary.cloud_subnets || 0 },
        { label: 'Duplicate IPs', value: summary.duplicate_ip_count || 0, color: 'var(--danger-color)' },
        { label: 'Inventory Subnets', value: summary.inventory_subnets || 0 },
        { label: 'Inventory / Cloud Overlaps', value: summary.exact_source_overlap_count || 0, color: 'var(--warning-color)' },
    ];
    container.innerHTML = `
        <div class="stats-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;">
            ${cards.map((card) => `
                <div class="stat-card">
                    <div class="stat-value" style="${card.color ? `color:${card.color};` : ''}">${escapeHtml(String(card.value))}</div>
                    <div class="stat-label">${escapeHtml(card.label)}</div>
                </div>
            `).join('')}
        </div>
    `;
}

function _renderSubnets() {
    const container = document.getElementById('ipam-subnets');
    const countEl = document.getElementById('ipam-subnet-count');
    if (!container || !_overview) return;

    const subnets = Array.isArray(_overview.subnets) ? _overview.subnets : [];
    if (countEl) {
        countEl.textContent = `${subnets.length} visible subnet${subnets.length === 1 ? '' : 's'}`;
    }

    if (!subnets.length) {
        container.innerHTML = '<div class="empty-state"><p>No IPAM data found for the current filter.</p></div>';
        return;
    }

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Subnet</th>
                    <th>Usage</th>
                    <th>Groups</th>
                    <th>Sources</th>
                    <th>Preview</th>
                </tr>
            </thead>
            <tbody>
                ${subnets.map((item) => {
                    const groups = Array.isArray(item.group_names) ? item.group_names : [];
                    const sources = Array.isArray(item.source_types) ? item.source_types : [];
                    const hostPreview = Array.isArray(item.hostnames_preview) ? item.hostnames_preview : [];
                    const cloudPreview = Array.isArray(item.cloud_resource_names_preview) ? item.cloud_resource_names_preview : [];
                    const previewParts = [];
                    if (hostPreview.length) {
                        previewParts.push(`Hosts: ${hostPreview.join(', ')}${item.host_preview_truncated ? ` +${item.host_preview_truncated}` : ''}`);
                    }
                    if (cloudPreview.length) {
                        previewParts.push(`Cloud: ${cloudPreview.join(', ')}${item.cloud_preview_truncated ? ` +${item.cloud_preview_truncated}` : ''}`);
                    }
                    return `
                        <tr>
                            <td>
                                <div style="font-weight:600;">${escapeHtml(item.subnet || '')}</div>
                                <div class="text-muted" style="font-size:0.85em;">IPv${escapeHtml(String(item.version || ''))} /${escapeHtml(String(item.prefix_length || ''))} · ${escapeHtml(String(item.total_addresses || 0))} addresses</div>
                            </td>
                            <td>
                                <div>${escapeHtml(String(item.inventory_host_count || 0))} hosts</div>
                                <div class="text-muted" style="font-size:0.85em;">${escapeHtml(String(item.utilization_pct || 0))}% utilized</div>
                            </td>
                            <td>${groups.length ? escapeHtml(groups.join(', ')) : '<span class="text-muted">Cloud only</span>'}</td>
                            <td>${sources.map((source) => `<span class="badge badge-secondary" style="margin-right:0.35rem;">${escapeHtml(source)}</span>`).join('')}</td>
                            <td class="text-muted" style="max-width:420px;">${escapeHtml(previewParts.join(' | ') || 'No preview')}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

function _renderDuplicates() {
    const container = document.getElementById('ipam-duplicates');
    if (!container || !_overview) return;
    const duplicates = Array.isArray(_overview.duplicate_ips) ? _overview.duplicate_ips : [];
    if (!duplicates.length) {
        container.innerHTML = '<p class="text-muted" style="margin:0;">No duplicate inventory IPs detected for the current scope.</p>';
        return;
    }

    container.innerHTML = duplicates.map((item) => {
        const hosts = Array.isArray(item.hosts) ? item.hosts : [];
        return `
            <div style="padding:0.8rem 0;border-bottom:1px solid rgba(255,255,255,0.08);">
                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:flex-start;">
                    <div>
                        <div style="font-weight:600;color:var(--danger-color);">${escapeHtml(item.ip_address || '')}</div>
                        <div class="text-muted" style="font-size:0.9em;">${escapeHtml(String(item.host_count || 0))} inventory entries</div>
                    </div>
                    <span class="badge badge-danger">Conflict</span>
                </div>
                <div style="display:grid;gap:0.45rem;margin-top:0.65rem;">
                    ${hosts.map((host) => `
                        <div class="text-muted" style="line-height:1.45;">
                            <strong style="color:var(--text-primary);">${escapeHtml(host.hostname || 'Unknown host')}</strong>
                            <span> in ${escapeHtml(host.group_name || 'Unknown group')}</span>
                            ${host.status ? `<span> · ${escapeHtml(host.status)}</span>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function _renderAll() {
    _renderGroupFilter();
    _renderSummary();
    _renderSubnets();
    _renderDuplicates();
}

async function _loadAll() {
    const groupId = _selectedGroupId ? Number(_selectedGroupId) : null;
    const [groupsResponse, overview] = await Promise.all([
        api.getInventoryGroups(false),
        api.getIpamOverview(groupId, _includeCloud),
    ]);
    _groups = Array.isArray(groupsResponse) ? groupsResponse : [];
    _overview = overview;
}

export async function loadIpam({ preserveContent = false } = {}) {
    const page = _ensureIpamLayout();
    if (!page) return;
    if (!preserveContent) {
        const summary = document.getElementById('ipam-summary');
        const subnets = document.getElementById('ipam-subnets');
        const duplicates = document.getElementById('ipam-duplicates');
        if (summary) summary.innerHTML = skeletonCards(4);
        if (subnets) subnets.innerHTML = '<div class="text-muted">Loading subnet inventory...</div>';
        if (duplicates) duplicates.innerHTML = '<div class="text-muted">Loading duplicate IP analysis...</div>';
    }
    try {
        await _loadAll();
        _renderAll();
    } catch (error) {
        if (error.name === 'AbortError') throw error;
        console.error('Failed to load IPAM overview:', error);
        showError(`Failed to load IPAM overview: ${error.message}`);
    }
}

window.onIpamFiltersChange = async function () {
    const groupSelect = document.getElementById('ipam-group-filter');
    const cloudToggle = document.getElementById('ipam-include-cloud');
    _selectedGroupId = groupSelect ? groupSelect.value : '';
    _includeCloud = cloudToggle ? cloudToggle.checked : true;
    try {
        await loadIpam({ preserveContent: false });
    } catch (error) {
        if (error.name !== 'AbortError') {
            showError(`Failed to apply IPAM filters: ${error.message}`);
        }
    }
};

window.refreshIpam = async function () {
    api.invalidateApiCache('/ipam/overview', '/inventory');
    try {
        await loadIpam({ preserveContent: false });
    } catch (error) {
        if (error.name !== 'AbortError') {
            showError(`Failed to refresh IPAM overview: ${error.message}`);
        }
    }
};

export function destroyIpam() {
    delete window.onIpamFiltersChange;
    delete window.refreshIpam;
}
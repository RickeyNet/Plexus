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
let _selectedSubnet = '';
let _subnetDetail = null;
let _subnetDetailLoading = false;

function _ensureIpamLayout() {
    const page = document.getElementById('page-ipam');
    if (!page) return null;
    if (page.querySelector('#ipam-summary')) return page;

    page.innerHTML = `
        <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
            <div>
                <h2 style="margin:0;">IP Address Management</h2>
                <p class="text-muted" style="margin:0.35rem 0 0;max-width:72ch;">Track inferred inventory subnets, discovered cloud CIDRs, synced external IPAM prefixes, utilization, and duplicate conflicts from one view.</p>
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
                    <h3 style="margin:0 0 0.75rem;">Subnet Drilldown</h3>
                    <div id="ipam-drilldown"></div>
                </div>
                <div class="card" style="padding:1rem;">
                    <h3 style="margin:0 0 0.75rem;">Duplicate IP Conflicts</h3>
                    <div id="ipam-duplicates"></div>
                </div>
                <div class="card" style="padding:1rem;">
                    <h3 style="margin:0 0 0.75rem;">Scope Notes</h3>
                    <div class="text-muted" style="display:grid;gap:0.65rem;line-height:1.55;">
                        <div>Inventory subnets are inferred from host addresses. Plain IPv4 addresses default to /24 and plain IPv6 addresses default to /64 when prefixes are not stored.</div>
                        <div>Cloud CIDRs come from discovered cloud resources such as VPCs, VNets, and subnets.</div>
                        <div>Available-address calculations now subtract reserved ranges before utilization is computed, and the drilldown shows any allocations that collide with reserved space.</div>
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
        { label: 'External Subnets', value: summary.external_subnets || 0 },
        { label: 'Duplicate IPs', value: summary.duplicate_ip_count || 0, color: 'var(--danger-color)' },
        { label: 'Inventory Subnets', value: summary.inventory_subnets || 0 },
        { label: 'External Allocations', value: summary.external_allocation_count || 0 },
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

function _formatSubnetPreview(item) {
    const previewParts = [];
    const hostPreview = Array.isArray(item.hostnames_preview) ? item.hostnames_preview : [];
    const cloudPreview = Array.isArray(item.cloud_resource_names_preview) ? item.cloud_resource_names_preview : [];
    const externalPreview = Array.isArray(item.external_source_names_preview) ? item.external_source_names_preview : [];
    const availablePreview = Array.isArray(item.available_preview) ? item.available_preview : [];
    if (hostPreview.length) {
        previewParts.push(`Hosts: ${hostPreview.join(', ')}${item.host_preview_truncated ? ` +${item.host_preview_truncated}` : ''}`);
    }
    if (cloudPreview.length) {
        previewParts.push(`Cloud: ${cloudPreview.join(', ')}${item.cloud_preview_truncated ? ` +${item.cloud_preview_truncated}` : ''}`);
    }
    if (externalPreview.length) {
        previewParts.push(`External: ${externalPreview.join(', ')}${item.external_source_preview_truncated ? ` +${item.external_source_preview_truncated}` : ''}`);
    }
    if (availablePreview.length) {
        previewParts.push(`Available: ${availablePreview.join(', ')}`);
    }
    return previewParts.join(' | ') || 'No preview';
}

function _renderDrilldown() {
    const container = document.getElementById('ipam-drilldown');
    if (!container) return;
    if (_subnetDetailLoading) {
        container.innerHTML = '<div class="text-muted">Loading subnet allocations and reservation data...</div>';
        return;
    }
    if (!_selectedSubnet) {
        container.innerHTML = '<p class="text-muted" style="margin:0;">Select a subnet to inspect allocations, reserved ranges, and first-available capacity.</p>';
        return;
    }
    if (!_subnetDetail) {
        container.innerHTML = '<p class="text-muted" style="margin:0;">No drilldown data available for the selected subnet.</p>';
        return;
    }

    const summary = _subnetDetail.summary || {};
    const reservations = Array.isArray(_subnetDetail.reservations) ? _subnetDetail.reservations : [];
    const allocations = Array.isArray(_subnetDetail.allocations) ? _subnetDetail.allocations : [];
    const cloudResources = Array.isArray(_subnetDetail.cloud_resources) ? _subnetDetail.cloud_resources : [];
    const externalPrefixes = Array.isArray(_subnetDetail.external_prefixes) ? _subnetDetail.external_prefixes : [];
    const availablePreview = Array.isArray(_subnetDetail.available_preview) ? _subnetDetail.available_preview : [];

    container.innerHTML = `
        <div style="display:grid;gap:1rem;">
            <div>
                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:flex-start;flex-wrap:wrap;">
                    <div>
                        <div style="font-size:1rem;font-weight:700;">${escapeHtml(_subnetDetail.subnet || _selectedSubnet)}</div>
                        <div class="text-muted" style="font-size:0.9em;">${escapeHtml(String(summary.total_addresses || 0))} total addresses · ${escapeHtml(String(summary.usable_address_count || 0))} usable</div>
                    </div>
                    <button class="btn btn-secondary" onclick="showIpamSubnetDetail('${encodeURIComponent(_selectedSubnet)}', true)">Refresh Detail</button>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0.75rem;">
                <div class="stat-card"><div class="stat-value">${escapeHtml(String(summary.available_address_count || 0))}</div><div class="stat-label">Available</div></div>
                <div class="stat-card"><div class="stat-value">${escapeHtml(String(summary.allocated_address_count || 0))}</div><div class="stat-label">Allocated</div></div>
                <div class="stat-card"><div class="stat-value">${escapeHtml(String(summary.reserved_address_count || 0))}</div><div class="stat-label">Reserved</div></div>
                <div class="stat-card"><div class="stat-value">${escapeHtml(String(summary.utilization_pct || 0))}%</div><div class="stat-label">Utilized</div></div>
            </div>
            <div>
                <div style="font-weight:600;margin-bottom:0.45rem;">Available Address Preview</div>
                <div class="text-muted" style="line-height:1.5;">${escapeHtml(availablePreview.join(', ') || 'Preview unavailable for this subnet size.')}</div>
            </div>
            <div>
                <div style="font-weight:600;margin-bottom:0.45rem;">Reserved Ranges</div>
                ${reservations.length ? reservations.map((item) => `
                    <div style="padding:0.5rem 0;border-bottom:1px solid rgba(255,255,255,0.08);">
                        <div style="display:flex;justify-content:space-between;gap:0.75rem;flex-wrap:wrap;">
                            <div>
                                <strong>${escapeHtml(item.start_ip || '')}</strong>
                                <span class="text-muted"> to ${escapeHtml(item.end_ip || '')}</span>
                            </div>
                            <span class="badge ${item.kind === 'custom' ? 'badge-warning' : 'badge-secondary'}">${escapeHtml(item.kind || 'reserved')}</span>
                        </div>
                        <div class="text-muted" style="font-size:0.9em;line-height:1.45;">${escapeHtml(String(item.address_count || 0))} addresses · ${escapeHtml(item.reason || 'Reserved range')}</div>
                    </div>
                `).join('') : '<p class="text-muted" style="margin:0;">No reserved ranges recorded for this subnet.</p>'}
            </div>
            <div>
                <div style="font-weight:600;margin-bottom:0.45rem;">Allocations</div>
                ${allocations.length ? `
                    <div style="display:grid;gap:0.5rem;max-height:360px;overflow:auto;">
                        ${allocations.map((item) => `
                            <div style="padding:0.6rem 0.7rem;border:1px solid rgba(255,255,255,0.08);border-radius:10px;">
                                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:flex-start;flex-wrap:wrap;">
                                    <div>
                                        <div style="font-weight:600;">${escapeHtml(item.ip_address || '')}</div>
                                        <div class="text-muted" style="font-size:0.9em;line-height:1.45;">
                                            ${escapeHtml(item.hostname || item.dns_name || item.source_name || 'Allocation')}
                                            ${item.group_name ? ` · ${escapeHtml(item.group_name)}` : ''}
                                            ${item.description ? ` · ${escapeHtml(item.description)}` : ''}
                                        </div>
                                    </div>
                                    <div style="display:flex;gap:0.35rem;flex-wrap:wrap;justify-content:flex-end;">
                                        <span class="badge badge-secondary">${escapeHtml(item.source_type || 'allocation')}</span>
                                        ${item.status ? `<span class="badge badge-secondary">${escapeHtml(item.status)}</span>` : ''}
                                        ${item.is_duplicate ? '<span class="badge badge-danger">Duplicate</span>' : ''}
                                        ${item.is_reserved ? '<span class="badge badge-warning">Reserved</span>' : ''}
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                ` : '<p class="text-muted" style="margin:0;">No allocations tracked for this subnet.</p>'}
            </div>
            ${(externalPrefixes.length || cloudResources.length) ? `
                <div style="display:grid;gap:0.75rem;">
                    ${externalPrefixes.length ? `
                        <div>
                            <div style="font-weight:600;margin-bottom:0.45rem;">External Prefix Context</div>
                            <div class="text-muted" style="display:grid;gap:0.35rem;line-height:1.45;">
                                ${externalPrefixes.map((item) => `${escapeHtml(item.source_name || item.provider || 'External IPAM')}: ${escapeHtml(item.description || item.status || 'Tracked prefix')}`).join('<br>')}
                            </div>
                        </div>
                    ` : ''}
                    ${cloudResources.length ? `
                        <div>
                            <div style="font-weight:600;margin-bottom:0.45rem;">Cloud Resources</div>
                            <div class="text-muted" style="display:grid;gap:0.35rem;line-height:1.45;">
                                ${cloudResources.map((item) => `${escapeHtml(item.provider || 'cloud')}: ${escapeHtml(item.name || item.resource_type || 'resource')}${item.account_name ? ` (${escapeHtml(item.account_name)})` : ''}`).join('<br>')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            ` : ''}
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
                    <th>Capacity</th>
                    <th>Groups</th>
                    <th>Sources</th>
                    <th>Preview</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                ${subnets.map((item) => {
                    const groups = Array.isArray(item.group_names) ? item.group_names : [];
                    const sources = Array.isArray(item.source_types) ? item.source_types : [];
                    const externalSources = Array.isArray(item.external_source_names_preview) ? item.external_source_names_preview : [];
                    const selectedStyle = _selectedSubnet === item.subnet ? 'background:rgba(255,255,255,0.04);' : '';
                    return `
                        <tr style="${selectedStyle}">
                            <td>
                                <div style="font-weight:600;">${escapeHtml(item.subnet || '')}</div>
                                <div class="text-muted" style="font-size:0.85em;">IPv${escapeHtml(String(item.version || ''))} /${escapeHtml(String(item.prefix_length || ''))} · ${escapeHtml(String(item.total_addresses || 0))} addresses</div>
                            </td>
                            <td>
                                <div>${escapeHtml(String(item.available_address_count || 0))} available</div>
                                <div class="text-muted" style="font-size:0.85em;">${escapeHtml(String(item.allocated_address_count || 0))} allocated · ${escapeHtml(String(item.reserved_address_count || 0))} reserved</div>
                                <div class="text-muted" style="font-size:0.85em;">${escapeHtml(String(item.utilization_pct || 0))}% utilized</div>
                            </td>
                            <td>${groups.length ? escapeHtml(groups.join(', ')) : '<span class="text-muted">No inventory groups</span>'}</td>
                            <td>
                                ${sources.map((source) => `<span class="badge badge-secondary" style="margin-right:0.35rem;margin-bottom:0.35rem;">${escapeHtml(source)}</span>`).join('')}
                                ${externalSources.map((source) => `<span class="badge badge-secondary" style="margin-right:0.35rem;margin-bottom:0.35rem;">${escapeHtml(source)}</span>`).join('')}
                            </td>
                            <td class="text-muted" style="max-width:420px;">${escapeHtml(_formatSubnetPreview(item))}</td>
                            <td>
                                <button class="btn btn-secondary" onclick="showIpamSubnetDetail('${encodeURIComponent(item.subnet || '')}')">Drilldown</button>
                            </td>
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
    _renderDrilldown();
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
    const visibleSubnets = new Set((Array.isArray(_overview?.subnets) ? _overview.subnets : []).map((item) => item.subnet));
    if (_selectedSubnet && !visibleSubnets.has(_selectedSubnet)) {
        _selectedSubnet = '';
        _subnetDetail = null;
    }
}

export async function loadIpam({ preserveContent = false } = {}) {
    const page = _ensureIpamLayout();
    if (!page) return;
    if (!preserveContent) {
        const summary = document.getElementById('ipam-summary');
        const subnets = document.getElementById('ipam-subnets');
        const drilldown = document.getElementById('ipam-drilldown');
        const duplicates = document.getElementById('ipam-duplicates');
        if (summary) summary.innerHTML = skeletonCards(4);
        if (subnets) subnets.innerHTML = '<div class="text-muted">Loading subnet inventory...</div>';
        if (drilldown) drilldown.innerHTML = '<div class="text-muted">Loading subnet drilldown context...</div>';
        if (duplicates) duplicates.innerHTML = '<div class="text-muted">Loading duplicate IP analysis...</div>';
    }
    try {
        await _loadAll();
        _renderAll();
        if (_selectedSubnet) {
            await window.showIpamSubnetDetail(encodeURIComponent(_selectedSubnet), true);
        }
    } catch (error) {
        if (error.name === 'AbortError') throw error;
        console.error('Failed to load IPAM overview:', error);
        showError(`Failed to load IPAM overview: ${error.message}`);
    }
}

window.showIpamSubnetDetail = async function (encodedSubnet, skipSelectionUpdate = false) {
    const subnet = decodeURIComponent(String(encodedSubnet || ''));
    if (!skipSelectionUpdate) {
        _selectedSubnet = subnet;
    }
    _subnetDetailLoading = true;
    _renderSubnets();
    _renderDrilldown();
    try {
        const groupId = _selectedGroupId ? Number(_selectedGroupId) : null;
        _subnetDetail = await api.getIpamSubnetDetail(subnet, groupId, _includeCloud, true);
        _selectedSubnet = subnet;
    } catch (error) {
        _subnetDetail = null;
        showError(`Failed to load subnet drilldown: ${error.message}`);
    } finally {
        _subnetDetailLoading = false;
        _renderSubnets();
        _renderDrilldown();
    }
};

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
    api.invalidateApiCache('/ipam/overview', '/ipam/subnets', '/inventory');
    try {
        await loadIpam({ preserveContent: false });
    } catch (error) {
        if (error.name !== 'AbortError') {
            showError(`Failed to refresh IPAM overview: ${error.message}`);
        }
    }
};

export function destroyIpam() {
    _selectedSubnet = '';
    _subnetDetail = null;
    _subnetDetailLoading = false;
    delete window.onIpamFiltersChange;
    delete window.refreshIpam;
    delete window.showIpamSubnetDetail;
}
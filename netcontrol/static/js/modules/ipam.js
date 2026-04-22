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
let _sources = [];
let _providers = [];
let _syncConfig = { enabled: true, interval_seconds: 1800 };
let _editingSource = null; // null = creating new, object = editing existing

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
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:0.75rem;flex-wrap:wrap;">
                        <h3 style="margin:0;">External IPAM Sources</h3>
                        <button class="btn btn-primary" onclick="openIpamSourceModal(null)">+ Add Source</button>
                    </div>
                    <div id="ipam-sync-health" style="margin-bottom:0.75rem;"></div>
                    <div id="ipam-sources"></div>
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
        <div id="ipam-source-modal" style="display:none;position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,0.6);overflow:auto;padding:2rem 1rem;" onclick="if(event.target===this)closeIpamSourceModal()">
            <div style="background:var(--bg-card);border-radius:12px;max-width:560px;margin:auto;padding:1.5rem;position:relative;">
                <h3 id="ipam-modal-title" style="margin:0 0 1rem;">Add IPAM Source</h3>
                <form id="ipam-source-form" onsubmit="submitIpamSourceForm(event)" style="display:grid;gap:0.85rem;">
                    <label>Provider
                        <select id="ipam-form-provider" class="form-select" required>
                            <option value="">Select provider…</option>
                        </select>
                    </label>
                    <label>Name
                        <input id="ipam-form-name" class="form-control" type="text" maxlength="120" required placeholder="e.g. Production NetBox">
                    </label>
                    <label>Base URL
                        <input id="ipam-form-url" class="form-control" type="url" required placeholder="https://netbox.example.com">
                    </label>
                    <label>Auth Type
                        <select id="ipam-form-auth-type" class="form-select">
                            <option value="token">API Token</option>
                            <option value="basic">Basic Auth</option>
                        </select>
                    </label>
                    <label>API Token / Password
                        <input id="ipam-form-token" class="form-control" type="password" maxlength="512" placeholder="Leave blank to keep existing">
                    </label>
                    <label id="ipam-form-username-row">Username (Basic Auth)
                        <input id="ipam-form-username" class="form-control" type="text" maxlength="120">
                    </label>
                    <label>Sync Scope <span class="text-muted">(optional — site/tenant filter)</span>
                        <input id="ipam-form-scope" class="form-control" type="text" maxlength="255">
                    </label>
                    <label>Notes
                        <input id="ipam-form-notes" class="form-control" type="text" maxlength="512">
                    </label>
                    <div style="display:flex;gap:1.25rem;flex-wrap:wrap;">
                        <label style="display:flex;align-items:center;gap:0.5rem;">
                            <input id="ipam-form-enabled" type="checkbox" checked> Enabled
                        </label>
                        <label style="display:flex;align-items:center;gap:0.5rem;">
                            <input id="ipam-form-tls" type="checkbox" checked> Verify TLS
                        </label>
                    </div>
                    <div style="display:flex;gap:0.75rem;justify-content:flex-end;margin-top:0.25rem;">
                        <button type="button" class="btn btn-secondary" onclick="closeIpamSourceModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary" id="ipam-form-submit">Save Source</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    const authTypeSelect = document.getElementById('ipam-form-auth-type');
    if (authTypeSelect) {
        authTypeSelect.addEventListener('change', _updateAuthTypeVisibility);
    }
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
                        <div style="display:flex;justify-content:space-between;gap:0.75rem;flex-wrap:wrap;align-items:flex-start;">
                            <div>
                                <strong>${escapeHtml(item.start_ip || '')}</strong>
                                <span class="text-muted"> to ${escapeHtml(item.end_ip || '')}</span>
                            </div>
                            <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
                                <span class="badge ${item.kind === 'custom' ? 'badge-warning' : 'badge-secondary'}">${escapeHtml(item.kind || 'reserved')}</span>
                                ${item.kind === 'custom' ? `<button class="btn btn-secondary" style="padding:0.2rem 0.55rem;font-size:0.8em;" onclick="deleteIpamReservationById(${Number(item.id)}, '${encodeURIComponent(_selectedSubnet)}')">Delete</button>` : ''}
                            </div>
                        </div>
                        <div class="text-muted" style="font-size:0.9em;line-height:1.45;">${escapeHtml(String(item.address_count || 0))} addresses · ${escapeHtml(item.reason || 'Reserved range')}</div>
                    </div>
                `).join('') : '<p class="text-muted" style="margin:0;">No reserved ranges recorded for this subnet.</p>'}
                <details style="margin-top:0.75rem;">
                    <summary style="cursor:pointer;font-size:0.9em;color:var(--accent-color);">+ Add Reservation</summary>
                    <form onsubmit="submitIpamReservation(event, '${encodeURIComponent(_selectedSubnet)}')" style="display:grid;gap:0.6rem;margin-top:0.65rem;">
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;">
                            <label style="font-size:0.9em;">Start IP
                                <input class="form-control" type="text" name="start_ip" required placeholder="10.0.0.10" style="margin-top:0.25rem;">
                            </label>
                            <label style="font-size:0.9em;">End IP <span class="text-muted">(optional)</span>
                                <input class="form-control" type="text" name="end_ip" placeholder="10.0.0.20" style="margin-top:0.25rem;">
                            </label>
                        </div>
                        <label style="font-size:0.9em;">Reason
                            <input class="form-control" type="text" name="reason" maxlength="255" placeholder="Reserved range" style="margin-top:0.25rem;">
                        </label>
                        <button type="submit" class="btn btn-primary" style="justify-self:start;">Reserve</button>
                    </form>
                </details>
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

function _renderSyncHealth() {
    const container = document.getElementById('ipam-sync-health');
    if (!container) return;
    const enabled = _syncConfig.enabled;
    const intervalMin = Math.round(_syncConfig.interval_seconds / 60);
    container.innerHTML = `
        <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;padding:0.6rem 0.75rem;background:rgba(255,255,255,0.03);border-radius:8px;">
            <span class="badge ${enabled ? 'badge-success' : 'badge-secondary'}">${enabled ? 'Auto-sync on' : 'Auto-sync off'}</span>
            <span class="text-muted" style="font-size:0.9em;">Every ${escapeHtml(String(intervalMin))} min</span>
            <button class="btn btn-secondary" style="padding:0.2rem 0.55rem;font-size:0.82em;margin-left:auto;" onclick="openIpamSyncSchedulePanel()">Schedule</button>
        </div>
        <div id="ipam-sync-schedule-panel" style="display:none;padding:0.75rem;background:rgba(255,255,255,0.03);border-radius:8px;margin-top:0.5rem;">
            <form onsubmit="submitIpamSyncConfig(event)" style="display:grid;gap:0.6rem;">
                <label style="display:flex;align-items:center;gap:0.5rem;">
                    <input type="checkbox" id="ipam-sync-enabled" ${enabled ? 'checked' : ''}> Enable scheduled auto-sync
                </label>
                <label style="font-size:0.9em;">Interval (minutes)
                    <input class="form-control" type="number" id="ipam-sync-interval-min" min="5" max="1440" value="${intervalMin}" style="margin-top:0.25rem;width:120px;">
                </label>
                <div style="display:flex;gap:0.5rem;">
                    <button type="submit" class="btn btn-primary" style="font-size:0.9em;">Save Schedule</button>
                    <button type="button" class="btn btn-secondary" style="font-size:0.9em;" onclick="closeIpamSyncSchedulePanel()">Cancel</button>
                </div>
            </form>
        </div>
    `;
}

function _renderSources() {
    const container = document.getElementById('ipam-sources');
    if (!container) return;
    if (!_sources.length) {
        container.innerHTML = '<p class="text-muted" style="margin:0;">No external IPAM sources configured. Add one to start syncing subnets and allocations.</p>';
        return;
    }
    container.innerHTML = _sources.map((src) => {
        const statusColor = src.last_sync_status === 'success'
            ? 'var(--success-color, #4caf50)'
            : src.last_sync_status === 'error'
                ? 'var(--danger-color)'
                : 'var(--text-muted)';
        const statusClass = src.last_sync_status === 'success'
            ? 'badge-success'
            : src.last_sync_status === 'error'
                ? 'badge-danger'
                : 'badge-secondary';
        const syncTime = src.last_sync_at
            ? new Date(src.last_sync_at + (src.last_sync_at.endsWith('Z') ? '' : 'Z')).toLocaleString()
            : 'Never';
        return `
            <div style="padding:0.75rem 0;border-bottom:1px solid rgba(255,255,255,0.08);">
                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:flex-start;flex-wrap:wrap;">
                    <div>
                        <div style="font-weight:600;">${escapeHtml(src.name || '')}</div>
                        <div class="text-muted" style="font-size:0.85em;">${escapeHtml(src.provider || '')} · ${escapeHtml(src.base_url || '')}</div>
                    </div>
                    <div style="display:flex;gap:0.4rem;flex-wrap:wrap;align-items:center;">
                        <span class="badge ${statusClass}">${escapeHtml(src.last_sync_status || 'never')}</span>
                        ${!src.enabled ? '<span class="badge badge-secondary">Disabled</span>' : ''}
                    </div>
                </div>
                <div class="text-muted" style="font-size:0.82em;margin:0.3rem 0;">${escapeHtml(syncTime)}${src.last_sync_message ? ` · ${escapeHtml(src.last_sync_message)}` : ''}</div>
                <div style="font-size:0.82em;color:var(--text-muted);">${escapeHtml(String(src.prefix_count || 0))} subnets · ${escapeHtml(String(src.allocation_count || 0))} allocations</div>
                <div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap;">
                    <button class="btn btn-primary" style="font-size:0.82em;padding:0.25rem 0.6rem;" onclick="triggerIpamSourceSync(${Number(src.id)})">Sync Now</button>
                    <button class="btn btn-secondary" style="font-size:0.82em;padding:0.25rem 0.6rem;" onclick="openIpamSourceModal(${Number(src.id)})">Edit</button>
                    <button class="btn btn-secondary" style="font-size:0.82em;padding:0.25rem 0.6rem;color:var(--danger-color);" onclick="confirmDeleteIpamSource(${Number(src.id)}, '${escapeHtml(src.name || '')}')">Delete</button>
                </div>
            </div>
        `;
    }).join('');
}

function _updateAuthTypeVisibility() {
    const authType = document.getElementById('ipam-form-auth-type')?.value;
    const usernameRow = document.getElementById('ipam-form-username-row');
    if (usernameRow) usernameRow.style.display = authType === 'basic' ? '' : 'none';
}

function _populateProviderSelect() {
    const select = document.getElementById('ipam-form-provider');
    if (!select) return;
    const current = select.value;
    select.innerHTML = '<option value="">Select provider…</option>'
        + _providers.map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
    if (current) select.value = current;
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
    _renderSyncHealth();
    _renderSources();
}

async function _loadAll() {
    const groupId = _selectedGroupId ? Number(_selectedGroupId) : null;
    const [groupsResponse, overview, sourcesResponse, providersResponse, syncConfigResponse] = await Promise.all([
        api.getInventoryGroups(false),
        api.getIpamOverview(groupId, _includeCloud),
        api.getIpamSources().catch(() => ({ sources: [] })),
        api.getIpamProviders().catch(() => ({ providers: [] })),
        api.getIpamSyncConfig().catch(() => ({ config: {} })),
    ]);
    _groups = Array.isArray(groupsResponse) ? groupsResponse : [];
    _overview = overview;
    _sources = Array.isArray(sourcesResponse?.sources) ? sourcesResponse.sources : [];
    _providers = Array.isArray(providersResponse?.providers) ? providersResponse.providers : [];
    if (syncConfigResponse?.config && typeof syncConfigResponse.config === 'object') {
        _syncConfig = { ..._syncConfig, ...syncConfigResponse.config };
    }
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

window.openIpamSourceModal = function (sourceId) {
    const modal = document.getElementById('ipam-source-modal');
    if (!modal) return;
    const title = document.getElementById('ipam-modal-title');
    const submitBtn = document.getElementById('ipam-form-submit');
    _populateProviderSelect();
    if (sourceId === null || sourceId === undefined) {
        _editingSource = null;
        if (title) title.textContent = 'Add IPAM Source';
        if (submitBtn) submitBtn.textContent = 'Add Source';
        document.getElementById('ipam-form-provider').value = '';
        document.getElementById('ipam-form-name').value = '';
        document.getElementById('ipam-form-url').value = '';
        document.getElementById('ipam-form-auth-type').value = 'token';
        document.getElementById('ipam-form-token').value = '';
        document.getElementById('ipam-form-username').value = '';
        document.getElementById('ipam-form-scope').value = '';
        document.getElementById('ipam-form-notes').value = '';
        document.getElementById('ipam-form-enabled').checked = true;
        document.getElementById('ipam-form-tls').checked = true;
    } else {
        const src = _sources.find((s) => s.id === sourceId);
        if (!src) return;
        _editingSource = src;
        if (title) title.textContent = `Edit: ${src.name}`;
        if (submitBtn) submitBtn.textContent = 'Save Changes';
        document.getElementById('ipam-form-provider').value = src.provider || '';
        document.getElementById('ipam-form-name').value = src.name || '';
        document.getElementById('ipam-form-url').value = src.base_url || '';
        document.getElementById('ipam-form-auth-type').value = src.auth_type || 'token';
        document.getElementById('ipam-form-token').value = '';
        document.getElementById('ipam-form-username').value = '';
        document.getElementById('ipam-form-scope').value = src.sync_scope || '';
        document.getElementById('ipam-form-notes').value = src.notes || '';
        document.getElementById('ipam-form-enabled').checked = src.enabled;
        document.getElementById('ipam-form-tls').checked = src.verify_tls !== false;
    }
    _updateAuthTypeVisibility();
    modal.style.display = '';
};

window.closeIpamSourceModal = function () {
    const modal = document.getElementById('ipam-source-modal');
    if (modal) modal.style.display = 'none';
    _editingSource = null;
};

window.submitIpamSourceForm = async function (event) {
    event.preventDefault();
    const provider = document.getElementById('ipam-form-provider')?.value?.trim();
    const name = document.getElementById('ipam-form-name')?.value?.trim();
    const base_url = document.getElementById('ipam-form-url')?.value?.trim();
    const auth_type = document.getElementById('ipam-form-auth-type')?.value || 'token';
    const tokenValue = document.getElementById('ipam-form-token')?.value?.trim();
    const usernameValue = document.getElementById('ipam-form-username')?.value?.trim();
    const sync_scope = document.getElementById('ipam-form-scope')?.value?.trim() || '';
    const notes = document.getElementById('ipam-form-notes')?.value?.trim() || '';
    const enabled = document.getElementById('ipam-form-enabled')?.checked ?? true;
    const verify_tls = document.getElementById('ipam-form-tls')?.checked ?? true;

    const auth_config = {};
    if (tokenValue) {
        if (auth_type === 'basic') {
            auth_config.username = usernameValue;
            auth_config.password = tokenValue;
        } else {
            auth_config.token = tokenValue;
        }
    }

    const payload = { provider, name, base_url, auth_type, auth_config, sync_scope, notes, enabled, verify_tls };

    const submitBtn = document.getElementById('ipam-form-submit');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Saving…'; }
    try {
        if (_editingSource) {
            await api.updateIpamSource(_editingSource.id, payload);
        } else {
            await api.createIpamSource(payload);
        }
        window.closeIpamSourceModal();
        const sourcesResponse = await api.getIpamSources().catch(() => ({ sources: [] }));
        _sources = Array.isArray(sourcesResponse?.sources) ? sourcesResponse.sources : [];
        _renderSources();
    } catch (error) {
        showError(`Failed to save IPAM source: ${error.message}`);
    } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = _editingSource ? 'Save Changes' : 'Add Source'; }
    }
};

window.triggerIpamSourceSync = async function (sourceId) {
    try {
        const result = await api.syncIpamSource(sourceId);
        if (result?.source) {
            const idx = _sources.findIndex((s) => s.id === sourceId);
            if (idx >= 0) _sources[idx] = result.source;
            _renderSources();
        }
    } catch (error) {
        showError(`Sync failed: ${error.message}`);
    }
};

window.confirmDeleteIpamSource = async function (sourceId, sourceName) {
    if (!confirm(`Delete IPAM source "${sourceName}"? This also removes all synced prefixes and allocations.`)) return;
    try {
        await api.deleteIpamSource(sourceId);
        _sources = _sources.filter((s) => s.id !== sourceId);
        _renderSources();
    } catch (error) {
        showError(`Failed to delete IPAM source: ${error.message}`);
    }
};

window.openIpamSyncSchedulePanel = function () {
    const panel = document.getElementById('ipam-sync-schedule-panel');
    if (panel) panel.style.display = '';
};

window.closeIpamSyncSchedulePanel = function () {
    const panel = document.getElementById('ipam-sync-schedule-panel');
    if (panel) panel.style.display = 'none';
};

window.submitIpamSyncConfig = async function (event) {
    event.preventDefault();
    const enabled = document.getElementById('ipam-sync-enabled')?.checked ?? true;
    const intervalMin = parseInt(document.getElementById('ipam-sync-interval-min')?.value || '30', 10);
    const interval_seconds = Math.max(300, intervalMin * 60);
    try {
        const result = await api.updateIpamSyncConfig({ enabled, interval_seconds });
        if (result?.config) _syncConfig = result.config;
        _renderSyncHealth();
        window.closeIpamSyncSchedulePanel();
    } catch (error) {
        showError(`Failed to update sync schedule: ${error.message}`);
    }
};

window.submitIpamReservation = async function (event, encodedSubnet) {
    event.preventDefault();
    const subnet = decodeURIComponent(String(encodedSubnet || ''));
    const form = event.target;
    const start_ip = form.elements.start_ip?.value?.trim();
    const end_ip = form.elements.end_ip?.value?.trim() || null;
    const reason = form.elements.reason?.value?.trim() || 'Reserved range';
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Saving…'; }
    try {
        await api.createIpamReservation(subnet, { start_ip, end_ip, reason });
        form.reset();
        // refresh drilldown
        _subnetDetailLoading = true;
        _renderDrilldown();
        const groupId = _selectedGroupId ? Number(_selectedGroupId) : null;
        _subnetDetail = await api.getIpamSubnetDetail(subnet, groupId, _includeCloud, true).catch(() => null);
        _selectedSubnet = subnet;
    } catch (error) {
        showError(`Failed to create reservation: ${error.message}`);
    } finally {
        _subnetDetailLoading = false;
        _renderDrilldown();
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Reserve'; }
    }
};

window.deleteIpamReservationById = async function (reservationId, encodedSubnet) {
    if (!confirm('Delete this reserved range?')) return;
    const subnet = decodeURIComponent(String(encodedSubnet || ''));
    try {
        await api.deleteIpamReservation(reservationId);
        _subnetDetailLoading = true;
        _renderDrilldown();
        const groupId = _selectedGroupId ? Number(_selectedGroupId) : null;
        _subnetDetail = await api.getIpamSubnetDetail(subnet, groupId, _includeCloud, true).catch(() => null);
        _selectedSubnet = subnet;
    } catch (error) {
        showError(`Failed to delete reservation: ${error.message}`);
    } finally {
        _subnetDetailLoading = false;
        _renderDrilldown();
    }
};

export function destroyIpam() {
    _selectedSubnet = '';
    _subnetDetail = null;
    _subnetDetailLoading = false;
    _sources = [];
    _providers = [];
    _editingSource = null;
    delete window.onIpamFiltersChange;
    delete window.refreshIpam;
    delete window.showIpamSubnetDetail;
    delete window.openIpamSourceModal;
    delete window.closeIpamSourceModal;
    delete window.submitIpamSourceForm;
    delete window.triggerIpamSourceSync;
    delete window.confirmDeleteIpamSource;
    delete window.openIpamSyncSchedulePanel;
    delete window.closeIpamSyncSchedulePanel;
    delete window.submitIpamSyncConfig;
    delete window.submitIpamReservation;
    delete window.deleteIpamReservationById;
}
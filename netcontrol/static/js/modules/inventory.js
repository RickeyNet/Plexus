/**
 * Inventory Module — Inventory groups, hosts, SNMP profiles, and discovery
 * Lazy-loaded when user navigates to #inventory
 */
import * as api from '../api.js';
import { getCsrfToken, invalidateApiCache } from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    showModal, closeAllModals, showConfirm, formatDate, navigateToPage,
    skeletonCards, emptyStateHTML, debounce,
    _groupCache, _hostCache, _snmpProfilesCache, _groupSnmpAssignments,
    textMatch, byNameAsc, byNameDesc
} from '../app.js';

function applyInventoryFilters() {
    const state = listViewState.inventory;
    const query = state.query.trim().toLowerCase();
    const filtered = state.items.filter((group) => {
        if (!query) return true;
        if (textMatch(group.name, query) || textMatch(group.description, query)) return true;
        return (group.hosts || []).some((host) =>
            textMatch(host.hostname, query) || textMatch(host.ip_address, query) || textMatch(host.device_type, query)
        );
    });
    if (state.sort === 'hosts_desc') filtered.sort((a, b) => (b.host_count || (b.hosts || []).length || 0) - (a.host_count || (a.hosts || []).length || 0));
    else if (state.sort === 'hosts_asc') filtered.sort((a, b) => (a.host_count || (a.hosts || []).length || 0) - (b.host_count || (b.hosts || []).length || 0));
    else if (state.sort === 'name_desc') filtered.sort(byNameDesc);
    else filtered.sort(byNameAsc);
    return filtered;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Module-level resource tracking
// ═══════════════════════════════════════════════════════════════════════════════
let _scanElapsedInterval = null;
let _lastInventoryFingerprint = null;

// ═══════════════════════════════════════════════════════════════════════════════
// Inventory
// ═══════════════════════════════════════════════════════════════════════════════

async function loadInventory(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('inventory-groups');
    // Invalidate fingerprint so fresh data always re-renders
    _lastInventoryFingerprint = null;
    if (!preserveContent) {
        container.innerHTML = skeletonCards(4);
    }

    try {
        const [groups, profiles] = await Promise.all([
            api.getInventoryGroups(true),
            api.listSnmpProfiles().catch(() => []),
        ]);
        _snmpProfilesCache.length = 0;
        (profiles || []).forEach(p => _snmpProfilesCache.push(p));
        listViewState.inventory.items = groups || [];
        if (!groups.length) {
            container.innerHTML = emptyStateHTML('No inventory groups', 'inventory', '<button class="btn btn-primary btn-sm" onclick="showCreateGroupModal()">+ New Group</button>');
            return;
        }
        renderInventoryGroups(applyInventoryFilters());
        // Load SNMP profile assignments for each group and populate selects
        await _populateSnmpProfileSelects(groups);
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}</div>`;
    }
}

window.exportInventoryCSV = async function() {
    try {
        const csvHeaders = {};
        const csrf = getCsrfToken();
        if (csrf) csvHeaders['X-CSRF-Token'] = csrf;
        const resp = await fetch('/api/inventory/export/csv', { credentials: 'same-origin', headers: csvHeaders });
        if (!resp.ok) {
            const err = await resp.text();
            throw new Error(err || `HTTP ${resp.status}`);
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'inventory_export.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        showToast('Inventory CSV exported', 'success');
    } catch (error) {
        showToast('CSV export failed: ' + error.message, 'error');
    }
}

function renderInventoryGroups(groups) {
    const container = document.getElementById('inventory-groups');
    const query = (listViewState.inventory.query || '').trim().toLowerCase();
    const hostMatchesQuery = (host) => query && (
        textMatch(host.hostname, query) || textMatch(host.ip_address, query) || textMatch(host.device_type, query)
    );

    // Skip render if data hasn't changed (prevents DOM thrash on redundant search/sort)
    const fingerprint = JSON.stringify(groups.map(g => [g.id, (g.hosts || []).length])) + '|' + query + '|' + (listViewState.inventory.sort || '');
    if (fingerprint === _lastInventoryFingerprint) return;
    _lastInventoryFingerprint = fingerprint;

    // Preserve scroll position across re-renders
    const scrollTop = container.scrollTop;

    container.innerHTML = groups.map((group, i) => {
        const hosts = group.hosts || [];
        // When searching, sort matching hosts to the top
        const sortedHosts = query ? [...hosts].sort((a, b) => (hostMatchesQuery(b) ? 1 : 0) - (hostMatchesQuery(a) ? 1 : 0)) : hosts;
        return `
        <div class="card animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s">
            <div class="card-header">
                <div>
                    <div class="card-title">${escapeHtml(group.name)}</div>
                    <div class="card-description">${escapeHtml(group.description || '')}</div>
                </div>
                <div style="display: flex; gap: 0.25rem; align-items: center;">
                    <select class="form-select" style="font-size:0.75rem; padding:0.2rem 0.4rem; height:auto; min-width:120px;"
                            id="snmp-profile-select-${group.id}"
                            onchange="assignSnmpProfile(${group.id}, this.value)"
                            title="SNMP Profile">
                        <option value="">No SNMP Profile</option>
                    </select>
                    <button class="btn btn-sm btn-secondary" onclick="showDiscoveryModal('sync', ${group.id})">Sync</button>
                    <button class="btn btn-sm btn-secondary" onclick="showBulkSerialModal(${group.id})">Fetch Serials</button>
                    <button class="btn btn-sm btn-secondary" onclick="showEditGroupModal(${group.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteGroup(${group.id})">Delete</button>
                </div>
            </div>
            <div class="hosts-list">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        ${sortedHosts.length ? `<input type="checkbox" data-select-all="${group.id}" onchange="toggleSelectAllHosts(${group.id}, this.checked)" title="Select all hosts">` : ''}
                        <strong>Hosts</strong>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.25rem;">
                        <span id="bulk-actions-${group.id}" style="display:none; gap:0.25rem;">
                            <button class="btn btn-sm btn-secondary" onclick="bulkMoveHosts(${group.id})">Move</button>
                            <button class="btn btn-sm btn-danger" onclick="bulkDeleteHosts(${group.id})">Delete</button>
                        </span>
                        <button class="btn btn-sm btn-primary" onclick="showAddHostModal(${group.id})">+ Add Host</button>
                    </div>
                </div>
                ${sortedHosts.length ? `
                    <div class="host-columns-header">
                        <span class="host-col-cb"></span>
                        <span class="host-col-name">Hostname</span>
                        <span class="host-col-ip">IP Address</span>
                        <span class="host-col-type">Type</span>
                        <span class="host-col-model">Model</span>
                        <span class="host-col-serial">Serial Number</span>
                        <span class="host-col-sw">Software Version</span>
                        <span class="host-col-actions"></span>
                    </div>` +
                    sortedHosts.map(host => {
                        // Store host data for the edit modal
                        _hostCache[host.id] = { groupId: group.id, ...host };
                        const isMatch = hostMatchesQuery(host);
                        return `
                        <div class="host-item host-columns-row"${isMatch ? ' style="background: var(--highlight-bg, rgba(59,130,246,0.08)); border-radius: 4px;"' : ''}>
                            <span class="host-col-cb"><input type="checkbox" class="host-select" data-host-id="${host.id}" data-group-id="${group.id}" onchange="onHostSelectChange(${group.id})"></span>
                            <span class="host-col-name host-name">${escapeHtml(host.hostname)}</span>
                            <span class="host-col-ip host-ip">${escapeHtml(host.ip_address)}</span>
                            <span class="host-col-type host-type">${escapeHtml(host.device_type || 'cisco_ios')}</span>
                            <span class="host-col-model">${escapeHtml(host.model || '\u2014')}</span>
                            <span class="host-col-serial" id="serial-cell-${host.id}">${escapeHtml(host.serial_number || '\u2014')}</span>
                            <span class="host-col-sw">${escapeHtml(host.software_version || '\u2014')}</span>
                            <span class="host-col-actions">
                                <button class="btn btn-sm btn-secondary" onclick="showFetchSerialModal(${host.id})">Serial</button>
                                <button class="btn btn-sm btn-secondary" onclick="showEditHostModal(${host.id})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteHost(${group.id}, ${host.id})">Delete</button>
                            </span>
                        </div>
                    `;}).join('') :
                    '<div class="empty-state" style="padding: 1rem;">No hosts</div>'
                }
            </div>
        </div>`;
    }).join('');

    // Restore scroll position after DOM rebuild
    container.scrollTop = scrollTop;

    groups.forEach(group => {
        _groupCache[group.id] = {
            id: group.id,
            name: group.name,
            description: group.description || '',
            hosts: group.hosts || [],
        };
    });
}

async function _populateSnmpProfileSelects(groups) {
    // Fetch all assignments in parallel
    const assignments = await Promise.all(
        groups.map(g => api.getGroupSnmpAssignment(g.id).catch(() => ({ group_id: g.id, snmp_profile_id: '' })))
    );
    // Clear and repopulate _groupSnmpAssignments
    Object.keys(_groupSnmpAssignments).forEach(k => delete _groupSnmpAssignments[k]);
    assignments.forEach(a => { _groupSnmpAssignments[a.group_id] = a.snmp_profile_id || ''; });
    // Populate each dropdown
    groups.forEach(g => {
        const sel = document.getElementById(`snmp-profile-select-${g.id}`);
        if (!sel) return;
        const current = _groupSnmpAssignments[g.id] || '';
        sel.innerHTML = '<option value="">No SNMP Profile</option>' +
            _snmpProfilesCache.map(p =>
                `<option value="${escapeHtml(p.id)}" ${p.id === current ? 'selected' : ''}>${escapeHtml(p.name)}</option>`
            ).join('');
    });
}

window.assignSnmpProfile = async function(groupId, profileId) {
    try {
        await api.updateGroupSnmpAssignment(groupId, profileId);
        _groupSnmpAssignments[groupId] = profileId;
    } catch (error) {
        showError(`Failed to assign SNMP profile: ${error.message}`);
    }
};

window.showFetchSerialModal = async function(hostId) {
    let credentials = [];
    try {
        credentials = await api.getCredentials();
    } catch (e) {
        showError('Failed to load credentials: ' + e.message);
        return;
    }
    if (!credentials.length) {
        showError('No credentials found. Add credentials under the Credentials section first.');
        return;
    }
    const credOptions = credentials.map(c =>
        `<option value="${escapeHtml(String(c.id))}">${escapeHtml(c.name)}</option>`
    ).join('');
    showModal('Fetch Serial Number', `
        <p style="margin-bottom:1rem; color:var(--text-muted); font-size:0.88rem;">
            Runs <code>show version | include System Serial Number</code> via SSH
            and stores the result.
        </p>
        <form onsubmit="doFetchSerial(event, ${hostId})">
            <div class="form-group">
                <label class="form-label">Credential</label>
                <select class="form-select" name="credential_id" required>${credOptions}</select>
            </div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary" id="fetch-serial-btn">Fetch</button>
            </div>
        </form>
    `);
};

window.doFetchSerial = async function(event, hostId) {
    event.preventDefault();
    const form = event.target;
    const credentialId = parseInt(form.credential_id.value, 10);
    const btn = document.getElementById('fetch-serial-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching…'; }
    try {
        const result = await api.fetchHostSerial(hostId, credentialId);
        closeAllModals();
        // Update the serial cell in-place
        const cell = document.getElementById(`serial-cell-${hostId}`);
        if (cell) cell.textContent = result.serial_number;
        showToast(`Serial: ${result.serial_number}`, 'success');
    } catch (error) {
        if (btn) { btn.disabled = false; btn.textContent = 'Fetch'; }
        showError('Failed to fetch serial: ' + error.message);
    }
};

window.showBulkSerialModal = async function(groupId) {
    let credentials = [];
    try {
        credentials = await api.getCredentials();
    } catch (e) {
        showError('Failed to load credentials: ' + e.message);
        return;
    }
    if (!credentials.length) {
        showError('No credentials found. Add credentials under the Credentials section first.');
        return;
    }
    const credOptions = credentials.map(c =>
        `<option value="${escapeHtml(String(c.id))}">${escapeHtml(c.name)}</option>`
    ).join('');
    showModal('Fetch All Serials', `
        <p style="margin-bottom:1rem; color:var(--text-muted); font-size:0.88rem;">
            Runs <code>show version | include System Serial Number</code> on every host in this
            group via SSH (up to 5 concurrent connections) and stores the results.
        </p>
        <form onsubmit="doBulkFetchSerial(event, ${groupId})">
            <div class="form-group">
                <label class="form-label">Credential</label>
                <select class="form-select" name="credential_id" required>${credOptions}</select>
            </div>
            <div id="bulk-serial-progress" style="display:none; margin-top:0.75rem; font-size:0.82rem; color:var(--text-muted);"></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary" id="bulk-serial-btn">Fetch All</button>
            </div>
        </form>
    `);
};

window.doBulkFetchSerial = async function(event, groupId) {
    event.preventDefault();
    const form = event.target;
    const credentialId = parseInt(form.credential_id.value, 10);
    const btn = document.getElementById('bulk-serial-btn');
    const progress = document.getElementById('bulk-serial-progress');
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching…'; }
    if (progress) { progress.style.display = ''; progress.textContent = 'Connecting to devices…'; }
    try {
        const result = await api.fetchGroupSerials(groupId, credentialId);
        const results = result.results || [];
        const ok = results.filter(r => r.ok);
        const failed = results.filter(r => !r.ok);
        // Update serial cells in-place for successful results
        for (const r of ok) {
            const cell = document.getElementById(`serial-cell-${r.host_id}`);
            if (cell) cell.textContent = r.serial_number;
        }
        closeAllModals();
        if (failed.length === 0) {
            showToast(`Fetched ${ok.length} serial number${ok.length !== 1 ? 's' : ''}.`, 'success');
        } else {
            showToast(`${ok.length} succeeded, ${failed.length} failed. Check device connectivity.`, 'warning');
        }
    } catch (error) {
        if (btn) { btn.disabled = false; btn.textContent = 'Fetch All'; }
        if (progress) { progress.style.display = 'none'; }
        showError('Bulk serial fetch failed: ' + error.message);
    }
};

window.showGlobalDiscoveryModal = function() {    const groups = Object.values(_groupCache);
    if (!groups.length) {
        showError('No inventory groups found. Create a group first before discovering devices.');
        return;
    }
    const groupOptions = groups
        .map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`)
        .join('');
    showModal('Discover Devices', `
        <form onsubmit="runGlobalDiscovery(event)">
            <div class="form-group">
                <label class="form-label">Target Inventory Group</label>
                <select class="form-select" name="group_id" required>${groupOptions}</select>
                <div class="form-help">Discovered devices will be onboarded into this group.</div>
            </div>
            <div class="form-group">
                <label class="form-label">CIDR Targets</label>
                <textarea class="form-textarea" name="cidrs" placeholder="10.0.0.0/24\n10.0.1.0/24" required></textarea>
                <div class="form-help">One CIDR per line or comma-separated.</div>
            </div>
            <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
                <div>
                    <label class="form-label">Timeout Seconds</label>
                    <input type="number" class="form-input" name="timeout_seconds" value="0.35" step="0.05" min="0.05" max="5">
                </div>
                <div>
                    <label class="form-label">Max Hosts</label>
                    <input type="number" class="form-input" name="max_hosts" value="256" min="1" max="4096">
                </div>
            </div>
            <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
                <div>
                    <label class="form-label">Device Type</label>
                    <input type="text" class="form-input" name="device_type" value="unknown">
                </div>
                <div>
                    <label class="form-label">Hostname Prefix</label>
                    <input type="text" class="form-input" name="hostname_prefix" value="discovered">
                </div>
            </div>
            <label style="display:flex; align-items:center; gap:0.4rem; margin-top:0.5rem;">
                <input type="checkbox" name="use_snmp" value="1" checked> Use SNMP discovery first (falls back to TCP probe)
            </label>
            <label style="display:flex; align-items:center; gap:0.4rem; margin-top:0.5rem;">
                <input type="checkbox" name="test_only" value="1"> Test only (validate SNMP credentials against a single IP without scanning)
            </label>
            <div id="test-only-ip-group" style="display:none; margin-top:0.5rem;">
                <label class="form-label">Test Target IP</label>
                <input type="text" class="form-input" name="test_target_ip" placeholder="e.g. 10.0.0.1"
                       pattern="^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"
                       title="Enter a valid IPv4 address">
                <div class="form-help">Single IP to test SNMP credentials against.</div>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary" id="global-discovery-submit-btn">Scan Network</button>
            </div>
        </form>
    `);
    // Wire up the test-only checkbox toggle
    const testOnlyCb = document.querySelector('[name="test_only"]');
    const testIpGroup = document.getElementById('test-only-ip-group');
    const submitBtn = document.getElementById('global-discovery-submit-btn');
    if (testOnlyCb) {
        testOnlyCb.addEventListener('change', () => {
            testIpGroup.style.display = testOnlyCb.checked ? 'block' : 'none';
            submitBtn.textContent = testOnlyCb.checked ? 'Test SNMP' : 'Scan Network';
            const ipInput = document.querySelector('[name="test_target_ip"]');
            if (testOnlyCb.checked) {
                ipInput.setAttribute('required', '');
            } else {
                ipInput.removeAttribute('required');
            }
        });
    }
};

window.runGlobalDiscovery = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const groupId = Number(formData.get('group_id'));
    const testOnly = formData.get('test_only') === '1';

    // Handle test-only mode
    if (testOnly) {
        const targetIp = String(formData.get('test_target_ip') || '').trim();
        if (!targetIp) {
            showError('A target IP is required for SNMP test.');
            return;
        }
        const btn = document.getElementById('global-discovery-submit-btn');
        btn.disabled = true;
        btn.textContent = 'Testing...';
        try {
            const resp = await api.testGroupSnmpProfile(groupId, targetIp);
            closeAllModals();
            if (resp.success) {
                const r = resp.result;
                const d = r.discovery || {};
                showModal('SNMP Test Result', `
                    <div class="card" style="border-left: 3px solid var(--success-color, #22c55e);">
                        <div style="padding: 0.75rem;">
                            <strong>SNMP OK</strong> &mdash; credentials validated
                            <table style="width:100%; margin-top:0.5rem; font-size:0.85rem;">
                                <tr><td style="opacity:0.7;">Hostname</td><td>${escapeHtml(r.hostname || '')}</td></tr>
                                <tr><td style="opacity:0.7;">IP</td><td>${escapeHtml(r.ip_address || '')}</td></tr>
                                <tr><td style="opacity:0.7;">Device Type</td><td>${escapeHtml(r.device_type || '')}</td></tr>
                                <tr><td style="opacity:0.7;">Protocol</td><td>${escapeHtml(d.protocol || '')}</td></tr>
                                <tr><td style="opacity:0.7;">Vendor</td><td>${escapeHtml(d.vendor || 'unknown')}</td></tr>
                                <tr><td style="opacity:0.7;">OS</td><td>${escapeHtml(d.os || 'unknown')}</td></tr>
                                <tr><td style="opacity:0.7;">sysDescr</td><td style="word-break:break-word;">${escapeHtml(d.sys_descr || '')}</td></tr>
                            </table>
                        </div>
                    </div>
                    <div style="display:flex; justify-content:flex-end; margin-top:0.75rem;">
                        <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                    </div>
                `);
            } else {
                showModal('SNMP Test Result', `
                    <div class="card" style="border-left: 3px solid var(--danger-color, #ef4444);">
                        <div style="padding: 0.75rem;">
                            <strong>SNMP Failed</strong><br>
                            <span style="opacity:0.8;">${escapeHtml(resp.error || 'Unknown error')}</span>
                        </div>
                    </div>
                    <div style="display:flex; justify-content:flex-end; margin-top:0.75rem;">
                        <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                    </div>
                `);
            }
        } catch (error) {
            showError(`SNMP test failed: ${error.message}`);
        }
        return;
    }

    const cidrRaw = String(formData.get('cidrs') || '');
    const cidrs = cidrRaw.split(/[\n,]+/).map(v => v.trim()).filter(Boolean);

    if (!cidrs.length) {
        showError('At least one CIDR target is required.');
        return;
    }

    const options = {
        timeoutSeconds: Number(formData.get('timeout_seconds') || 0.35),
        maxHosts: Number(formData.get('max_hosts') || 256),
        deviceType: String(formData.get('device_type') || 'unknown').trim() || 'unknown',
        hostnamePrefix: String(formData.get('hostname_prefix') || 'discovered').trim() || 'discovered',
        useSnmp: formData.get('use_snmp') === '1',
    };

    const group = _groupCache[groupId];
    const groupName = group ? escapeHtml(group.name) : `Group ${groupId}`;

    // Show scanning progress modal with live updates
    showModal('Scanning Network', `
        <div style="padding: 1.5rem 1rem;">
            <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                <div class="discovery-spinner"></div>
                <div>
                    <div style="font-size: 1rem; font-weight: 600;" id="scan-title">Initializing scan...</div>
                    <div style="color: var(--text-muted); font-size: 0.85rem;">
                        Group: <strong>${groupName}</strong>${options.useSnmp ? ' &middot; SNMP enabled' : ''}
                    </div>
                </div>
            </div>
            <div style="margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.35rem;">
                    <span><span id="scan-scanned">0</span> / <span id="scan-total">?</span> scanned</span>
                    <span><span id="scan-found" style="color: var(--success-color, #22c55e); font-weight: 600;">0</span> found</span>
                </div>
                <div style="height: 6px; background: var(--bg-secondary); border-radius: 3px; overflow: hidden;">
                    <div id="scan-progress-bar" style="height: 100%; width: 0%; background: var(--primary); border-radius: 3px; transition: width 0.15s ease;"></div>
                </div>
            </div>
            <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.5rem;">
                Elapsed: <span id="scan-elapsed">0s</span> &middot; Currently scanning: <span id="scan-current-ip">...</span>
            </div>
            <div id="scan-live-feed" style="max-height: 180px; overflow-y: auto; border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.4rem 0.6rem; font-size: 0.8rem; font-family: monospace; background: var(--bg-secondary);"></div>
        </div>
    `);

    // Elapsed timer (tracked at module level for cleanup on page leave)
    clearInterval(_scanElapsedInterval);
    const scanStart = Date.now();
    _scanElapsedInterval = setInterval(() => {
        const el = document.getElementById('scan-elapsed');
        if (el) {
            const sec = Math.floor((Date.now() - scanStart) / 1000);
            el.textContent = sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
        }
    }, 1000);

    try {
        let finalResult = null;

        await api.scanInventoryGroupStream(groupId, cidrs, options, (event) => {
            if (event.type === 'start') {
                const totalEl = document.getElementById('scan-total');
                const titleEl = document.getElementById('scan-title');
                if (totalEl) totalEl.textContent = event.total;
                if (titleEl) titleEl.textContent = `Scanning ${event.total} host(s)...`;
            } else if (event.type === 'progress') {
                const scannedEl = document.getElementById('scan-scanned');
                const foundEl = document.getElementById('scan-found');
                const barEl = document.getElementById('scan-progress-bar');
                const ipEl = document.getElementById('scan-current-ip');
                const feedEl = document.getElementById('scan-live-feed');

                if (scannedEl) scannedEl.textContent = event.scanned;
                if (barEl && event.total) barEl.style.width = `${Math.round((event.scanned / event.total) * 100)}%`;
                if (ipEl) ipEl.textContent = event.ip;

                if (event.found && event.host) {
                    const count = parseInt(foundEl?.textContent || '0') + 1;
                    if (foundEl) foundEl.textContent = count;
                    if (feedEl) {
                        const entry = document.createElement('div');
                        entry.style.cssText = 'padding: 0.2rem 0; border-bottom: 1px solid var(--border); color: var(--success-color, #22c55e);';
                        entry.textContent = `\u2713 ${event.host.ip_address} \u2014 ${event.host.hostname || 'unknown'} (${event.host.device_type || 'unknown'})`;
                        feedEl.appendChild(entry);
                        feedEl.scrollTop = feedEl.scrollHeight;
                    }
                }
            } else if (event.type === 'done') {
                finalResult = event;
            }
        });

        if (!finalResult) {
            closeAllModals();
            showError('Scan completed but no results received.');
            return;
        }

        const discovered = finalResult.discovered_hosts || [];
        window._lastDiscoveryResults = discovered;

        showModal('Discovered Devices', `
            <div class="card-description" style="margin-bottom:0.75rem;">
                Scanned ${finalResult.scanned_hosts || 0} host(s) — found ${finalResult.discovered_count || 0} reachable device(s).
                Will onboard into <strong>${groupName}</strong>.
            </div>
            <div style="max-height: 340px; overflow:auto; border:1px solid var(--border); border-radius:0.5rem; padding:0.5rem;">
                ${discovered.length ? discovered.map((host, idx) => `
                    <div class="host-item" style="margin-bottom:0.4rem;">
                        <label style="display:flex; align-items:center; gap:0.5rem; width:100%;">
                            <input type="checkbox" class="discovery-onboard-host" value="${idx}" checked>
                            <span class="host-name">${escapeHtml(host.hostname || '-')}</span>
                            <span class="host-ip">${escapeHtml(host.ip_address || '-')}</span>
                            <span class="host-type">${escapeHtml(host.device_type || 'unknown')}</span>
                        </label>
                    </div>
                `).join('') : '<div class="empty-state" style="padding:1rem;">No reachable hosts discovered.</div>'}
            </div>
            <div style="display:flex; justify-content:space-between; margin-top:0.75rem; gap:0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="toggleDiscoverySelection(true)">Select All</button>
                <div style="display:flex; gap:0.5rem;">
                    <button type="button" class="btn btn-primary" onclick="onboardDiscoveredHosts(${groupId})">Onboard Selected</button>
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                </div>
            </div>
        `);
    } catch (error) {
        if (error.name === 'AbortError') return; // navigated away — silently cancel
        closeAllModals();
        showError(`Discovery scan failed: ${error.message}`);
    } finally {
        clearInterval(_scanElapsedInterval);
        _scanElapsedInterval = null;
    }
};

window.showDiscoveryModal = function(mode, groupId) {
    const group = _groupCache[groupId];
    if (!group) {
        showError('Group data not found');
        return;
    }
    const isSync = mode === 'sync';
    const title = isSync ? `Discovery Sync: ${group.name}` : `Discovery Scan: ${group.name}`;

    // For sync mode, pre-populate with the group's existing host IPs
    let prefillCidrs = '';
    if (isSync && group.hosts && group.hosts.length) {
        prefillCidrs = group.hosts.map(h => h.ip_address).filter(Boolean).join('\n');
    }

    showModal(title, `
        <form onsubmit="runInventoryDiscovery(event, ${groupId}, '${isSync ? 'sync' : 'scan'}')">
            <div class="form-group">
                <label class="form-label">CIDR Targets</label>
                <textarea class="form-textarea" name="cidrs" placeholder="10.0.0.0/24\n10.0.1.0/24" ${isSync ? '' : 'required'}>${isSync ? escapeHtml(prefillCidrs) : ''}</textarea>
                <div class="form-help">${isSync ? 'Pre-filled with group host IPs. Leave as-is to sync existing hosts, or edit to scan different targets.' : 'One CIDR per line or comma-separated.'}</div>
            </div>
            <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
                <div>
                    <label class="form-label">Timeout Seconds</label>
                    <input type="number" class="form-input" name="timeout_seconds" value="0.35" step="0.05" min="0.05" max="5">
                </div>
                <div>
                    <label class="form-label">Max Hosts</label>
                    <input type="number" class="form-input" name="max_hosts" value="256" min="1" max="4096">
                </div>
            </div>
            <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
                <div>
                    <label class="form-label">Device Type</label>
                    <input type="text" class="form-input" name="device_type" value="unknown">
                </div>
                <div>
                    <label class="form-label">Hostname Prefix</label>
                    <input type="text" class="form-input" name="hostname_prefix" value="discovered">
                </div>
            </div>
            <label style="display:flex; align-items:center; gap:0.4rem; margin-top:0.5rem;">
                <input type="checkbox" name="use_snmp" value="1" checked> Use SNMP discovery first (falls back to TCP probe)
            </label>
            ${isSync ? `
                <label style="display:flex; align-items:center; gap:0.4rem; margin-top:0.5rem;">
                    <input type="checkbox" name="remove_absent" value="1"> Remove hosts not found in this scan
                </label>
            ` : ''}
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">${isSync ? 'Run Sync' : 'Run Scan'}</button>
            </div>
        </form>
    `);
};

window.runInventoryDiscovery = async function(e, groupId, mode) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const cidrRaw = String(formData.get('cidrs') || '');
    const cidrs = cidrRaw
        .split(/[\n,]+/)
        .map((value) => value.trim())
        .filter(Boolean);

    if (!cidrs.length && mode !== 'sync') {
        showError('At least one CIDR target is required');
        return;
    }

    const options = {
        timeoutSeconds: Number(formData.get('timeout_seconds') || 0.35),
        maxHosts: Number(formData.get('max_hosts') || 256),
        deviceType: String(formData.get('device_type') || 'unknown').trim() || 'unknown',
        hostnamePrefix: String(formData.get('hostname_prefix') || 'discovered').trim() || 'discovered',
        useSnmp: formData.get('use_snmp') === '1',
        removeAbsent: formData.get('remove_absent') === '1',
    };

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const cancelBtn = e.target.querySelector('button[type="button"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.dataset.origText = submitBtn.textContent;
        submitBtn.textContent = mode === 'sync' ? 'Syncing\u2026' : 'Scanning\u2026';
    }
    if (cancelBtn) cancelBtn.disabled = true;

    try {
        const result = mode === 'sync'
            ? await api.syncInventoryGroup(groupId, cidrs, options)
            : await api.scanInventoryGroup(groupId, cidrs, options);

        closeAllModals();
        if (mode === 'sync') {
            await loadInventory();
            const sync = result.sync || {};
            showSuccess(`Sync complete. Added ${sync.added || 0}, updated ${sync.updated || 0}, removed ${sync.removed || 0}.`);
            return;
        }

        const discovered = result.discovered_hosts || [];
        window._lastDiscoveryResults = discovered;
        showModal('Discovery Scan Results', `
            <div class="card-description" style="margin-bottom:0.75rem;">
                Scanned ${result.scanned_hosts || 0} host(s); discovered ${result.discovered_count || 0} reachable device(s).
            </div>
            <div style="max-height: 340px; overflow:auto; border:1px solid var(--border); border-radius:0.5rem; padding:0.5rem;">
                ${discovered.length ? discovered.map((host, idx) => `
                    <div class="host-item" style="margin-bottom:0.4rem;">
                        <label style="display:flex; align-items:center; gap:0.5rem; width:100%;">
                            <input type="checkbox" class="discovery-onboard-host" value="${idx}" checked>
                            <span class="host-name">${escapeHtml(host.hostname || '-')}</span>
                            <span class="host-ip">${escapeHtml(host.ip_address || '-')}</span>
                            <span class="host-type">${escapeHtml(host.device_type || 'unknown')}</span>
                        </label>
                    </div>
                `).join('') : '<div class="empty-state" style="padding:1rem;">No reachable hosts discovered.</div>'}
            </div>
            <div style="display:flex; justify-content:space-between; margin-top:0.75rem; gap:0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="toggleDiscoverySelection(true)">Select All</button>
                <div style="display:flex; gap:0.5rem;">
                    <button type="button" class="btn btn-primary" onclick="onboardDiscoveredHosts(${groupId})">Onboard Selected</button>
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                </div>
            </div>
        `);
    } catch (error) {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = submitBtn.dataset.origText || (mode === 'sync' ? 'Run Sync' : 'Run Scan');
        }
        if (cancelBtn) cancelBtn.disabled = false;
        showError(`Discovery ${mode} failed: ${error.message}`);
    }
};

window.toggleDiscoverySelection = function(checked) {
    document.querySelectorAll('.discovery-onboard-host').forEach((cb) => {
        cb.checked = checked;
    });
};

window.onboardDiscoveredHosts = async function(groupId) {
    const discovered = window._lastDiscoveryResults || [];
    const selectedIndices = Array.from(document.querySelectorAll('.discovery-onboard-host:checked')).map((el) => Number(el.value));
    const selectedHosts = selectedIndices
        .filter((idx) => Number.isInteger(idx) && idx >= 0 && idx < discovered.length)
        .map((idx) => discovered[idx]);
    if (!selectedHosts.length) {
        showError('Select at least one discovered host to onboard.');
        return;
    }
    try {
        const result = await api.onboardDiscoveredHosts(groupId, selectedHosts);
        closeAllModals();
        await loadInventory();
        const sync = result.sync || {};
        showSuccess(`Onboard complete. Added ${sync.added || 0}, updated ${sync.updated || 0}.`);
    } catch (error) {
        showError(`Onboarding failed: ${error.message}`);
    }
};

// ── SNMP Profiles Management ─────────────────────────────────────────────────

window.showSnmpProfilesModal = async function() {
    try {
        const profiles = await api.listSnmpProfiles();
        _snmpProfilesCache.length = 0;
        (profiles || []).forEach(p => _snmpProfilesCache.push(p));
        const rows = profiles.length ? profiles.map(p => `
            <div class="host-item" style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.4rem; padding:0.5rem; border:1px solid var(--border); border-radius:0.5rem;">
                <div>
                    <strong>${escapeHtml(p.name)}</strong>
                    <span style="opacity:0.6; margin-left:0.5rem;">SNMPv${escapeHtml(p.version)}${p.version === '2c' ? ' / ' + escapeHtml(p.community || 'public') : ' / ' + escapeHtml((p.v3 && p.v3.username) || '')}</span>
                    <span style="opacity:0.5; margin-left:0.5rem;">${p.enabled ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div style="display:flex; gap:0.25rem;">
                    <button class="btn btn-sm btn-secondary" onclick="showEditSnmpProfileModal('${escapeHtml(p.id)}')">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSnmpProfile('${escapeHtml(p.id)}')">Delete</button>
                </div>
            </div>
        `).join('') : '<div class="empty-state" style="padding:1rem;">No SNMP profiles configured. Create one to get started.</div>';

        showModal('SNMP Profiles', `
            <div style="max-height:340px; overflow:auto; margin-bottom:0.75rem;">
                ${rows}
            </div>
            <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                <button type="button" class="btn btn-primary" onclick="showCreateSnmpProfileModal()">+ New Profile</button>
            </div>
        `);
    } catch (error) {
        showError(`Failed to load SNMP profiles: ${error.message}`);
    }
};

function _snmpProfileFormHtml(cfg = {}) {
    const v3 = cfg.v3 || {};
    return `
        <div class="form-group">
            <label class="form-label">Profile Name</label>
            <input type="text" class="form-input" name="name" value="${escapeHtml(cfg.name || '')}" required placeholder="e.g. Lab Switches">
        </div>
        <label style="display:flex; align-items:center; gap:0.4rem; margin-bottom:0.75rem;">
            <input type="checkbox" name="enabled" value="1" ${cfg.enabled ? 'checked' : ''}> Enabled
        </label>
        <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:0.75rem;">
            <div>
                <label class="form-label">Version</label>
                <select class="form-select" name="version">
                    <option value="2c" ${(cfg.version || '2c') === '2c' ? 'selected' : ''}>SNMPv2c</option>
                    <option value="3" ${cfg.version === '3' ? 'selected' : ''}>SNMPv3</option>
                </select>
            </div>
            <div>
                <label class="form-label">Port</label>
                <input type="number" class="form-input" name="port" value="${cfg.port || 161}" min="1" max="65535">
            </div>
            <div>
                <label class="form-label">Retries</label>
                <input type="number" class="form-input" name="retries" value="${cfg.retries || 0}" min="0" max="5">
            </div>
        </div>
        <div class="form-group">
            <label class="form-label">Community (v2c)</label>
            <input type="text" class="form-input" name="community" value="${escapeHtml(cfg.community || '')}">
        </div>
        <div class="form-group">
            <label class="form-label">Timeout Seconds</label>
            <input type="number" class="form-input" name="timeout_seconds" value="${cfg.timeout_seconds || 1.2}" min="0.2" max="10" step="0.1">
        </div>
        <div class="card-description" style="margin-bottom:0.5rem;">SNMPv3 Credentials</div>
        <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
            <div>
                <label class="form-label">Username</label>
                <input type="text" class="form-input" name="v3_username" value="${escapeHtml(v3.username || '')}">
            </div>
            <div>
                <label class="form-label">Auth Protocol</label>
                <select class="form-select" name="v3_auth_protocol">
                    <option value="sha" ${(v3.auth_protocol || 'sha') === 'sha' ? 'selected' : ''}>SHA</option>
                    <option value="sha256" ${(v3.auth_protocol || '') === 'sha256' ? 'selected' : ''}>SHA-256</option>
                    <option value="sha512" ${(v3.auth_protocol || '') === 'sha512' ? 'selected' : ''}>SHA-512</option>
                    <option value="md5" ${(v3.auth_protocol || '') === 'md5' ? 'selected' : ''}>MD5</option>
                </select>
            </div>
        </div>
        <div class="form-group" style="display:grid; grid-template-columns: 1fr 1fr; gap:0.75rem;">
            <div>
                <label class="form-label">Auth Password</label>
                <input type="${(v3.auth_password || '').includes('{{secret.') ? 'text' : 'password'}" class="form-input" name="v3_auth_password" value="${escapeHtml(v3.auth_password || '')}" placeholder="password or {{secret.NAME}}">
            </div>
            <div>
                <label class="form-label">Privacy Protocol</label>
                <select class="form-select" name="v3_priv_protocol">
                    <option value="aes128" ${(v3.priv_protocol || 'aes128') === 'aes128' ? 'selected' : ''}>AES128</option>
                    <option value="aes192" ${(v3.priv_protocol || '') === 'aes192' ? 'selected' : ''}>AES192</option>
                    <option value="aes256" ${(v3.priv_protocol || '') === 'aes256' ? 'selected' : ''}>AES256</option>
                    <option value="des" ${(v3.priv_protocol || '') === 'des' ? 'selected' : ''}>DES</option>
                </select>
            </div>
        </div>
        <div class="form-group">
            <label class="form-label">Privacy Password</label>
            <input type="${(v3.priv_password || '').includes('{{secret.') ? 'text' : 'password'}" class="form-input" name="v3_priv_password" value="${escapeHtml(v3.priv_password || '')}" placeholder="password or {{secret.NAME}}">
        </div>
        <div class="card-description" style="font-size:0.8rem; opacity:0.7; margin-top:-0.5rem;">
            Passwords support <code>{{secret.NAME}}</code> references from Credentials &rarr; Secret Variables.
        </div>
    `;
}

function _collectSnmpProfileForm(formData) {
    return {
        name: String(formData.get('name') || '').trim(),
        enabled: formData.get('enabled') === '1',
        version: String(formData.get('version') || '2c'),
        community: String(formData.get('community') || '').trim(),
        port: Number(formData.get('port') || 161),
        timeout_seconds: Number(formData.get('timeout_seconds') || 1.2),
        retries: Number(formData.get('retries') || 0),
        v3: {
            username: String(formData.get('v3_username') || '').trim(),
            auth_protocol: String(formData.get('v3_auth_protocol') || 'sha'),
            auth_password: String(formData.get('v3_auth_password') || ''),
            priv_protocol: String(formData.get('v3_priv_protocol') || 'aes128'),
            priv_password: String(formData.get('v3_priv_password') || ''),
        },
    };
}

window.showCreateSnmpProfileModal = function() {
    showModal('New SNMP Profile', `
        <form onsubmit="saveNewSnmpProfile(event)">
            ${_snmpProfileFormHtml({ enabled: true, version: '2c', port: 161, retries: 0, timeout_seconds: 1.2 })}
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="showSnmpProfilesModal()">Back</button>
                <button type="submit" class="btn btn-primary">Create Profile</button>
            </div>
        </form>
    `);
};

window.saveNewSnmpProfile = async function(e) {
    e.preventDefault();
    const payload = _collectSnmpProfileForm(new FormData(e.target));
    try {
        await api.createSnmpProfile(payload);
        showSuccess('SNMP profile created.');
        showSnmpProfilesModal();
    } catch (error) {
        showError(`Failed to create SNMP profile: ${error.message}`);
    }
};

window.showEditSnmpProfileModal = function(profileId) {
    const profile = _snmpProfilesCache.find(p => p.id === profileId);
    if (!profile) {
        showError('Profile not found');
        return;
    }
    showModal(`Edit SNMP Profile: ${escapeHtml(profile.name)}`, `
        <form onsubmit="saveEditSnmpProfile(event, '${escapeHtml(profileId)}')">
            ${_snmpProfileFormHtml(profile)}
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="showSnmpProfilesModal()">Back</button>
                <button type="submit" class="btn btn-primary">Save Profile</button>
            </div>
        </form>
    `);
};

window.saveEditSnmpProfile = async function(e, profileId) {
    e.preventDefault();
    const payload = _collectSnmpProfileForm(new FormData(e.target));
    try {
        await api.updateSnmpProfile(profileId, payload);
        showSuccess('SNMP profile updated.');
        showSnmpProfilesModal();
    } catch (error) {
        showError(`Failed to update SNMP profile: ${error.message}`);
    }
};

window.deleteSnmpProfile = async function(profileId) {
    if (!await showConfirm({ title: 'Delete SNMP Profile', message: 'Delete this SNMP profile? Any groups using it will be unassigned.', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteSnmpProfile(profileId);
        showSuccess('SNMP profile deleted.');
        showSnmpProfilesModal();
    } catch (error) {
        showError(`Failed to delete SNMP profile: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Inventory Groups & Hosts
// ═══════════════════════════════════════════════════════════════════════════════

window.showCreateGroupModal = function() {
    showModal('Create Inventory Group', `
        <form onsubmit="createGroup(event)">
            <div class="form-group">
                <label class="form-label">Group Name</label>
                <input type="text" class="form-input" name="name" required>
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea class="form-textarea" name="description"></textarea>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    `);
};

window.createGroup = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.createGroup(formData.get('name'), formData.get('description'));
        closeAllModals();
        await loadInventory();
        showSuccess('Group created successfully');
    } catch (error) {
        showError(`Failed to create group: ${error.message}`);
    }
};

window.showEditGroupModal = function(groupId) {
    const group = _groupCache[groupId];
    if (!group) {
        showError('Group data not found');
        return;
    }

    showModal('Edit Inventory Group', `
        <form onsubmit="updateGroup(event, ${groupId})">
            <div class="form-group">
                <label class="form-label">Group Name</label>
                <input type="text" class="form-input" name="name" value="${escapeHtml(group.name)}" required>
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea class="form-textarea" name="description">${escapeHtml(group.description || '')}</textarea>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Save</button>
            </div>
        </form>
    `);
};

window.updateGroup = async function(e, groupId) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.updateGroup(groupId, formData.get('name'), formData.get('description'));
        closeAllModals();
        await loadInventory();
        showSuccess('Group updated successfully');
    } catch (error) {
        showError(`Failed to update group: ${error.message}`);
    }
};

// Add Host Modal
window.showAddHostModal = function(groupId) {
    showModal('Add Host', `
        <form onsubmit="addHost(event, ${groupId})">
            <div class="form-group">
                <label class="form-label">Hostname</label>
                <input type="text" class="form-input" name="hostname" required>
            </div>
            <div class="form-group">
                <label class="form-label">IP Address</label>
                <input type="text" class="form-input" name="ip_address" required>
            </div>
            <div class="form-group">
                <label class="form-label">Device Type</label>
                <select class="form-select" name="device_type">
                    <option value="cisco_ios">Cisco IOS</option>
                    <option value="cisco_nxos">Cisco NX-OS</option>
                    <option value="cisco_asa">Cisco ASA</option>
                </select>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Add Host</button>
            </div>
        </form>
    `);
};

// Edit Host Modal
window.showEditHostModal = function(hostId) {
    const host = _hostCache[hostId];
    if (!host) {
        showError('Host data not found');
        return;
    }
    const hostname = host.hostname;
    const ipAddress = host.ip_address;
    const deviceType = host.device_type || 'cisco_ios';
    const groupId = host.groupId;

    const form = document.createElement('form');
    form.innerHTML = `
        <div class="form-group">
            <label class="form-label">Hostname</label>
            <input type="text" class="form-input" name="hostname" required>
        </div>
        <div class="form-group">
            <label class="form-label">IP Address</label>
            <input type="text" class="form-input" name="ip_address" required>
        </div>
        <div class="form-group">
            <label class="form-label">Device Type</label>
            <select class="form-select" name="device_type">
                <option value="cisco_ios">Cisco IOS</option>
                <option value="cisco_nxos">Cisco NX-OS</option>
                <option value="cisco_asa">Cisco ASA</option>
            </select>
        </div>
        <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
            <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button type="submit" class="btn btn-primary">Save</button>
        </div>
    `;

    form.querySelector('[name="hostname"]').value = hostname;
    form.querySelector('[name="ip_address"]').value = ipAddress;
    form.querySelector('[name="device_type"]').value = deviceType;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        try {
            await api.updateHost(hostId, formData.get('hostname'), formData.get('ip_address'), formData.get('device_type'));
            closeAllModals();
            await loadInventory();
            showSuccess('Host updated successfully');
        } catch (error) {
            showError(`Failed to update host: ${error.message}`);
        }
    });

    document.getElementById('modal-title').textContent = 'Edit Host';
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = '';
    modalBody.appendChild(form);
    document.getElementById('modal-overlay').classList.add('active');
};

window.addHost = async function(e, groupId) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.addHost(groupId, formData.get('hostname'), formData.get('ip_address'), formData.get('device_type'));
        invalidateApiCache('/inventory');
        closeAllModals();
        await loadInventory();
        showSuccess('Host added successfully');
    } catch (error) {
        showError(`Failed to add host: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Delete & Bulk Operations (Inventory)
// ═══════════════════════════════════════════════════════════════════════════════

window.deleteGroup = async function(groupId) {
    if (!await showConfirm('Delete Group', 'This will remove the group and all its hosts. This action cannot be undone.')) return;
    try {
        await api.deleteGroup(groupId);
        invalidateApiCache('/inventory');
        await loadInventory();
        showSuccess('Group deleted successfully');
    } catch (error) {
        showError(`Failed to delete group: ${error.message}`);
    }
};

window.deleteHost = async function(groupId, hostId) {
    if (!await showConfirm('Delete Host', 'This will permanently remove this host from the inventory.')) return;
    try {
        await api.deleteHost(groupId, hostId);
        invalidateApiCache('/inventory');
        await loadInventory();
        showSuccess('Host deleted successfully');
    } catch (error) {
        showError(`Failed to delete host: ${error.message}`);
    }
};

function getSelectedHostIds(groupId) {
    return Array.from(document.querySelectorAll(`.host-select[data-group-id="${groupId}"]:checked`))
        .map(cb => Number(cb.dataset.hostId));
}

window.onHostSelectChange = function(groupId) {
    const selected = getSelectedHostIds(groupId);
    const bar = document.getElementById(`bulk-actions-${groupId}`);
    if (bar) bar.style.display = selected.length ? 'flex' : 'none';
    const selectAll = document.querySelector(`[data-select-all="${groupId}"]`);
    if (selectAll) {
        const total = document.querySelectorAll(`.host-select[data-group-id="${groupId}"]`).length;
        selectAll.checked = selected.length === total && total > 0;
        selectAll.indeterminate = selected.length > 0 && selected.length < total;
    }
};

window.toggleSelectAllHosts = function(groupId, checked) {
    document.querySelectorAll(`.host-select[data-group-id="${groupId}"]`)
        .forEach(cb => { cb.checked = checked; });
    onHostSelectChange(groupId);
};

window.bulkDeleteHosts = async function(groupId) {
    const hostIds = getSelectedHostIds(groupId);
    if (!hostIds.length) return;
    if (!await showConfirm('Delete Hosts', `This will permanently remove ${hostIds.length} host(s) from the inventory.`)) return;
    try {
        await api.bulkDeleteHosts(hostIds);
        invalidateApiCache('/inventory');
        await loadInventory();
        showSuccess(`${hostIds.length} host(s) deleted.`);
    } catch (error) {
        showError(`Failed to delete hosts: ${error.message}`);
    }
};

window.bulkMoveHosts = function(groupId) {
    const hostIds = getSelectedHostIds(groupId);
    if (!hostIds.length) return;
    const groups = (listViewState.inventory.items || []).filter(g => g.id !== groupId);
    if (!groups.length) {
        showError('No other groups available to move hosts to.');
        return;
    }
    showModal(`Move ${hostIds.length} Host(s)`, `
        <form onsubmit="executeBulkMove(event, ${groupId})">
            <div class="form-group">
                <label class="form-label">Destination Group</label>
                <select class="form-select" name="target_group_id" required>
                    <option value="">-- Select group --</option>
                    ${groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}
                </select>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Move</button>
            </div>
        </form>
    `);
};

window.executeBulkMove = async function(e, sourceGroupId) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const targetGroupId = Number(formData.get('target_group_id'));
    if (!targetGroupId) return;
    const hostIds = getSelectedHostIds(sourceGroupId);
    if (!hostIds.length) return;
    try {
        await api.moveHosts(hostIds, targetGroupId);
        closeAllModals();
        await loadInventory();
        showSuccess(`${hostIds.length} host(s) moved.`);
    } catch (error) {
        showError(`Failed to move hosts: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

function destroyInventory() {
    clearInterval(_scanElapsedInterval);
    _scanElapsedInterval = null;
    _lastInventoryFingerprint = null;
}

export { loadInventory, destroyInventory, applyInventoryFilters, renderInventoryGroups };

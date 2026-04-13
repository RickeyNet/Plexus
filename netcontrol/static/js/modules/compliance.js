/**
 * Compliance Module — Policy compliance auditing
 * Lazy-loaded when user navigates to #compliance
 */
import * as api from '../api.js';
import {
    escapeHtml, showToast, showError, showModal, showConfirm, showSuccess,
    listViewState, emptyStateHTML, formatDate, closeAllModals, showFormModal,
    invalidatePageCache, initCopyableBlocks, createStreamHandler, copyableCodeBlock,
    skeletonCards, formatInterval, debounce
} from '../app.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Compliance Profiles & Scans
// ═══════════════════════════════════════════════════════════════════════════════

let _complianceCurrentTab = 'profiles';

// Temporary store for remediation commands, keyed by index — avoids quoting issues in onclick attrs
let _findingsRemediationMap = {};

export async function loadCompliance(options = {}) {
    const { preserveContent = false } = options;
    const profilesContainer = document.getElementById('compliance-profiles-list');
    if (!preserveContent && profilesContainer) profilesContainer.innerHTML = skeletonCards(2);
    // Restore tab from previous state
    const savedTab = listViewState.compliance.tab;
    if (savedTab && savedTab !== _complianceCurrentTab) {
        switchComplianceTab(savedTab);
    }
    try {
        const [summary, profiles, assignments, results, statusList] = await Promise.all([
            api.getComplianceSummary(),
            api.getComplianceProfiles(),
            api.getComplianceAssignments(),
            api.getComplianceScanResults({ limit: 200 }),
            api.getComplianceHostStatus(),
        ]);
        renderComplianceSummary(summary);
        listViewState.compliance.profiles = profiles || [];
        listViewState.compliance.assignments = assignments || [];
        listViewState.compliance.results = results || [];
        listViewState.compliance.statusList = statusList || [];
        renderComplianceProfiles(profiles || []);
        renderComplianceAssignments(assignments || []);
        renderComplianceResults(results || []);
        renderComplianceStatus(statusList || []);
        // Bind search handler once per DOM lifetime
        const searchInput = document.getElementById('compliance-search');
        if (searchInput && searchInput.dataset.bound !== '1') {
            searchInput.dataset.bound = '1';
            searchInput.addEventListener('input', debounce(() => {
                listViewState.compliance.query = searchInput.value;
                renderComplianceProfiles(listViewState.compliance.profiles);
                renderComplianceAssignments(listViewState.compliance.assignments);
                renderComplianceResults(listViewState.compliance.results);
                renderComplianceStatus(listViewState.compliance.statusList);
            }, 200));
        }
    } catch (error) {
        if (profilesContainer) profilesContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error loading compliance data: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadCompliance = loadCompliance;

function renderComplianceSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('compliance-stat-profiles', summary.total_profiles ?? '-');
    set('compliance-stat-assignments', summary.active_assignments ?? '-');
    set('compliance-stat-scanned', summary.hosts_scanned ?? '-');
    set('compliance-stat-violations', summary.hosts_non_compliant ?? '-');
    set('compliance-stat-last', summary.last_scan_at ? new Date(summary.last_scan_at + 'Z').toLocaleString() : 'Never');
}

function renderComplianceProfiles(profiles) {
    const container = document.getElementById('compliance-profiles-list');
    if (!container) return;
    const query = (listViewState.compliance.query || '').toLowerCase();
    const filtered = profiles.filter(p => !query || p.name.toLowerCase().includes(query) || (p.description || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No compliance profiles', 'compliance',
            '<button class="btn btn-primary btn-sm" onclick="showCreateComplianceProfileModal()">Create a Profile</button>');
        return;
    }
    container.innerHTML = filtered.map(p => {
        let rules = [];
        try { rules = JSON.parse(p.rules || '[]'); } catch (e) { /* ignore */ }
        const sevClass = p.severity === 'critical' ? 'danger' : p.severity === 'high' ? 'warning' : 'success';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(p.name)}</strong>
                    <span class="badge" style="margin-left:0.5rem; background:var(--${sevClass}); color:white; font-size:0.75em; padding:2px 8px; border-radius:4px;">${escapeHtml(p.severity)}</span>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">${rules.length} rules, ${p.assignment_count || 0} assignments</span>
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-secondary" onclick="showEditComplianceProfileModal(${p.id})">Edit</button>
                    <button class="btn btn-sm btn-secondary" onclick="showAssignComplianceProfileModal(${p.id})">Assign</button>
                    <button class="btn btn-sm" style="color:var(--danger)" onclick="confirmDeleteComplianceProfile(${p.id})">Delete</button>
                </div>
            </div>
            ${p.description ? `<div style="margin-top:0.5rem; font-size:0.9em; color:var(--text-muted)">${escapeHtml(p.description)}</div>` : ''}
            ${rules.length > 0 ? `<div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted)">Rules: ${rules.map(r => escapeHtml(r.name || r.pattern || '?')).join(', ')}</div>` : ''}
        </div>`;
    }).join('');
}

function renderComplianceAssignments(assignments) {
    const container = document.getElementById('compliance-assignments-list');
    if (!container) return;
    const query = (listViewState.compliance.query || '').toLowerCase();
    const filtered = assignments.filter(a => !query || (a.profile_name || '').toLowerCase().includes(query) || (a.group_name || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No compliance assignments', 'compliance',
            'Assign a profile to an inventory group to start scanning.');
        return;
    }
    container.innerHTML = filtered.map(a => {
        const enabled = a.enabled ? '<span style="color:var(--success)">Enabled</span>' : '<span style="color:var(--text-muted)">Disabled</span>';
        const interval = formatInterval(a.interval_seconds);
        const lastScan = a.last_scan_at ? new Date(a.last_scan_at + 'Z').toLocaleString() : 'Never';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(a.profile_name || '?')}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">→ ${escapeHtml(a.group_name || '?')} (${a.host_count || 0} hosts)</span>
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-primary" onclick="scanAssignmentNow(${a.id})" title="Scan all hosts in this assignment now">Scan Now</button>
                    <button class="btn btn-sm btn-secondary" onclick="toggleComplianceAssignment(${a.id}, ${a.enabled ? 'false' : 'true'})">${a.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm" style="color:var(--danger)" onclick="confirmDeleteComplianceAssignment(${a.id})">Delete</button>
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                ${enabled} · Every ${interval} · Last scan: ${lastScan}
            </div>
        </div>`;
    }).join('');
}

function renderComplianceResults(results) {
    const container = document.getElementById('compliance-results-list');
    if (!container) return;
    const query = (listViewState.compliance.query || '').toLowerCase();
    const filtered = results.filter(r => !query || (r.hostname || '').toLowerCase().includes(query) || (r.profile_name || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No scan results yet', 'compliance', 'Run a compliance scan to see results.');
        return;
    }
    container.innerHTML = filtered.map(r => {
        const statusColor = r.status === 'compliant' ? 'success' : r.status === 'error' ? 'danger' : 'warning';
        const scanned = r.scanned_at ? new Date(r.scanned_at + 'Z').toLocaleString() : '-';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <span style="color:var(--${statusColor}); font-weight:600;">${escapeHtml(r.status)}</span>
                    <strong style="margin-left:0.5rem;">${escapeHtml(r.hostname || '?')}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">${escapeHtml(r.ip_address || '')}</span>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">Profile: ${escapeHtml(r.profile_name || '?')}</span>
                </div>
                <div style="font-size:0.85em; color:var(--text-muted);">
                    ${r.passed_rules}/${r.total_rules} passed · ${scanned}
                </div>
            </div>
            ${r.failed_rules > 0 ? `<div style="margin-top:0.5rem;"><button class="btn btn-sm btn-secondary" onclick="showComplianceFindings(${r.id})">View ${r.failed_rules} violation(s)</button></div>` : ''}
        </div>`;
    }).join('');
}

function renderComplianceStatus(statusList) {
    const container = document.getElementById('compliance-status-list');
    if (!container) return;
    const query = (listViewState.compliance.query || '').toLowerCase();
    const filtered = statusList.filter(s => !query || (s.hostname || '').toLowerCase().includes(query) || (s.profile_name || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No compliance status data', 'compliance', 'Scan some hosts to see their compliance status.');
        return;
    }
    container.innerHTML = filtered.map(s => {
        const statusColor = s.status === 'compliant' ? 'success' : s.status === 'error' ? 'danger' : 'warning';
        const scanned = s.scanned_at ? new Date(s.scanned_at + 'Z').toLocaleString() : '-';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:var(--${statusColor}); margin-right:0.5rem;"></span>
                    <strong>${escapeHtml(s.hostname || '?')}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">${escapeHtml(s.ip_address || '')}</span>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">· ${escapeHtml(s.profile_name || '?')}</span>
                </div>
                <div style="font-size:0.85em;">
                    <span style="color:var(--${statusColor}); font-weight:600;">${escapeHtml(s.status)}</span>
                    · ${s.passed_rules}/${s.total_rules} passed · ${scanned}
                </div>
            </div>
        </div>`;
    }).join('');
}

function switchComplianceTab(tab) {
    _complianceCurrentTab = tab;
    listViewState.compliance.tab = tab;
    const tabs = ['profiles', 'assignments', 'results', 'status'];
    tabs.forEach(t => {
        const btn = document.getElementById(`compliance-tab-${t}`);
        const list = document.getElementById(`compliance-${t}-list`);
        if (btn) btn.className = t === tab ? 'btn btn-sm btn-secondary compliance-tab-btn active' : 'btn btn-sm btn-secondary compliance-tab-btn';
        if (list) list.style.display = t === tab ? '' : 'none';
    });
}
window.switchComplianceTab = switchComplianceTab;

function refreshCompliance() { loadCompliance(); }
window.refreshCompliance = refreshCompliance;

// ── On-demand Scan Modal ────────────────────────────────────────────────────

// Cached data for the scan modal, populated once per open
let _scanModalData = { groups: [], allHosts: [] };

async function showRunComplianceScanModal() {
    let groups = [], profiles = [], creds = [];
    try {
        [groups, profiles, creds] = await Promise.all([
            api.getInventoryGroups(true),
            api.getComplianceProfiles(),
            api.getCredentials(),
        ]);
    } catch (e) { showError(e.message); return; }

    if (!profiles || profiles.length === 0) {
        showError('No compliance profiles exist. Create or load built-in profiles first.');
        return;
    }

    const allHosts = (groups || []).flatMap(g =>
        (g.hosts || []).map(h => ({ ...h, group_name: g.name }))
    ).sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''));
    _scanModalData = { groups, allHosts };

    const profileOpts = (profiles || []).map(p =>
        `<option value="${p.id}">${escapeHtml(p.name)}</option>`
    ).join('');
    const credOpts = (creds || []).map(c =>
        `<option value="${c.id}">${escapeHtml(c.name)}</option>`
    ).join('');
    const groupOpts = (groups || []).map(g =>
        `<option value="${g.id}">${escapeHtml(g.name)} (${(g.hosts || []).length} hosts)</option>`
    ).join('');
    const hostOpts = allHosts.map(h =>
        `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)}) — ${escapeHtml(h.group_name)}</option>`
    ).join('');

    showModal('Run Compliance Scan', `
        <div style="margin-bottom:1rem;">
            <label class="form-label">Scope</label>
            <div style="display:flex; gap:0.5rem;">
                <button class="btn btn-sm btn-primary" id="scan-scope-all" onclick="setScanScope('all')">All Hosts</button>
                <button class="btn btn-sm btn-secondary" id="scan-scope-group" onclick="setScanScope('group')">By Group</button>
                <button class="btn btn-sm btn-secondary" id="scan-scope-single" onclick="setScanScope('single')">Single Host</button>
            </div>
        </div>
        <div id="scan-scope-group-row" style="display:none; margin-bottom:0.75rem;">
            <label class="form-label">Group</label>
            <select id="scan-group-select" class="form-select" onchange="setScanScope('group')">
                ${groupOpts}
            </select>
        </div>
        <div id="scan-scope-host-row" style="display:none; margin-bottom:0.75rem;">
            <label class="form-label">Host</label>
            <select id="scan-host-select" class="form-select">
                <option value="">Select a host...</option>
                ${hostOpts}
            </select>
        </div>
        <label class="form-label">Compliance Profile</label>
        <select id="scan-profile-select" class="form-select">
            ${profileOpts}
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Credential</label>
        <select id="scan-cred-select" class="form-select">
            <option value="">Select a credential...</option>
            ${credOpts}
        </select>
        <div id="scan-scope-hint" style="margin-top:0.75rem; font-size:0.85em; color:var(--text-muted);">
            Scans all ${allHosts.length} host(s) in the inventory.
        </div>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" id="scan-submit-btn" onclick="submitRunComplianceScan()">Scan All Hosts</button>
        </div>
    `);
}
window.showRunComplianceScanModal = showRunComplianceScanModal;

function setScanScope(scope) {
    document.getElementById('scan-scope-all')?.classList.toggle('btn-primary', scope === 'all');
    document.getElementById('scan-scope-all')?.classList.toggle('btn-secondary', scope !== 'all');
    document.getElementById('scan-scope-group')?.classList.toggle('btn-primary', scope === 'group');
    document.getElementById('scan-scope-group')?.classList.toggle('btn-secondary', scope !== 'group');
    document.getElementById('scan-scope-single')?.classList.toggle('btn-primary', scope === 'single');
    document.getElementById('scan-scope-single')?.classList.toggle('btn-secondary', scope !== 'single');

    document.getElementById('scan-scope-group-row').style.display = scope === 'group' ? '' : 'none';
    document.getElementById('scan-scope-host-row').style.display = scope === 'single' ? '' : 'none';

    const hint = document.getElementById('scan-scope-hint');
    const submitBtn = document.getElementById('scan-submit-btn');
    const { groups, allHosts } = _scanModalData;

    if (scope === 'all') {
        hint.textContent = `Scans all ${allHosts.length} host(s) in the inventory.`;
        submitBtn.textContent = 'Scan All Hosts';
    } else if (scope === 'group') {
        const groupId = parseInt(document.getElementById('scan-group-select')?.value);
        const g = (groups || []).find(g => g.id === groupId);
        const count = (g?.hosts || []).length;
        hint.textContent = `Scans all ${count} host(s) in the selected group.`;
        submitBtn.textContent = 'Scan Group';
    } else {
        hint.textContent = '';
        submitBtn.textContent = 'Run Scan';
    }

    document.getElementById('scan-submit-btn').dataset.scope = scope;
}
window.setScanScope = setScanScope;

async function submitRunComplianceScan() {
    const submitBtn = document.getElementById('scan-submit-btn');
    const scope = submitBtn?.dataset.scope || 'all';
    const profileId = parseInt(document.getElementById('scan-profile-select')?.value);
    const credId = parseInt(document.getElementById('scan-cred-select')?.value);
    if (!profileId || isNaN(profileId)) { showError('Select a compliance profile'); return; }
    if (!credId || isNaN(credId)) { showError('Select a credential'); return; }

    if (scope === 'single') {
        const hostId = parseInt(document.getElementById('scan-host-select')?.value);
        if (!hostId || isNaN(hostId)) { showError('Select a host'); return; }

        if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Scanning...'; }
        try {
            const res = await api.runComplianceScan({ host_id: hostId, profile_id: profileId, credential_id: credId });
            closeAllModals();
            if (res.status === 'compliant') {
                showSuccess(`Scan complete — Host is compliant (${res.passed_rules}/${res.total_rules} rules passed)`);
            } else if (res.status === 'error') {
                showError('Scan completed with errors — check findings for details');
            } else {
                showError(`Scan complete — ${res.failed_rules} violation(s) found (${res.passed_rules}/${res.total_rules} passed)`);
            }
            if (res.failed_rules > 0 && res.id) await showComplianceFindings(res.id);
        } catch (e) {
            showError(`Scan failed: ${e.message}`);
            if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Run Scan'; }
            return;
        }
    } else {
        let hostIds = [];
        if (scope === 'group') {
            const groupId = parseInt(document.getElementById('scan-group-select')?.value);
            if (!groupId || isNaN(groupId)) { showError('Select a group'); return; }
            const g = (_scanModalData.groups || []).find(g => g.id === groupId);
            hostIds = (g?.hosts || []).map(h => h.id);
            if (!hostIds.length) { showError('No hosts in the selected group'); return; }
        }
        // hostIds empty = all hosts (backend handles it)

        const label = submitBtn?.textContent || 'Scanning...';
        if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Scanning...'; }
        try {
            const res = await api.runComplianceScanBulk({ profile_id: profileId, credential_id: credId, host_ids: hostIds });
            closeAllModals();
            if (res.violations > 0) {
                showError(`Scan complete: ${res.hosts_scanned} host(s) scanned, ${res.violations} non-compliant, ${res.errors} error(s)`);
            } else if (res.errors > 0) {
                showError(`Scan complete: ${res.hosts_scanned} host(s) scanned, ${res.errors} error(s)`);
            } else {
                showSuccess(`Scan complete: ${res.hosts_scanned} host(s) scanned — all compliant!`);
            }
        } catch (e) {
            showError(`Scan failed: ${e.message}`);
            if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = label; }
            return;
        }
    }

    loadCompliance();
}
window.submitRunComplianceScan = submitRunComplianceScan;

async function scanAssignmentNow(assignmentId) {
    if (!await showConfirm({
        title: 'Run Assignment Scan Now',
        message: 'Scan all hosts in this assignment immediately? This may take a moment.',
        confirmText: 'Scan Now',
        confirmClass: 'btn-primary'
    })) return;

    try {
        const res = await api.scanComplianceAssignmentNow(assignmentId);
        if (res.violations > 0) {
            showError(`Scan complete: ${res.hosts_scanned} hosts scanned, ${res.violations} non-compliant, ${res.errors} errors`);
        } else if (res.errors > 0) {
            showError(`Scan complete: ${res.hosts_scanned} hosts scanned, ${res.errors} error(s)`);
        } else {
            showSuccess(`Scan complete: ${res.hosts_scanned} hosts scanned — all compliant!`);
        }
        loadCompliance();
    } catch (e) {
        showError(`Assignment scan failed: ${e.message}`);
    }
}
window.scanAssignmentNow = scanAssignmentNow;

async function loadBuiltinProfiles() {
    try {
        const res = await api.loadBuiltinComplianceProfiles();
        if (res.loaded > 0) {
            showSuccess(`Loaded ${res.loaded} built-in profile(s).${res.skipped > 0 ? ` ${res.skipped} already existed.` : ''}`);
        } else {
            showSuccess(`All ${res.total_available} built-in profiles already loaded.`);
        }
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.loadBuiltinProfiles = loadBuiltinProfiles;

async function showCreateComplianceProfileModal() {
    showModal('Create Compliance Profile', `
        <label class="form-label">Profile Name</label>
        <input id="cp-name" class="form-input" placeholder="PCI-DSS Baseline">
        <label class="form-label" style="margin-top:0.75rem;">Description</label>
        <input id="cp-desc" class="form-input" placeholder="Describe the compliance standard">
        <label class="form-label" style="margin-top:0.75rem;">Severity</label>
        <select id="cp-severity" class="form-select">
            <option value="low">Low</option>
            <option value="medium" selected>Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Rules (JSON array)</label>
        <textarea id="cp-rules" class="form-input" rows="8" placeholder='[{"name": "NTP configured", "type": "must_contain", "pattern": "ntp server"}]'></textarea>
        <div style="margin-top:0.5rem; font-size:0.8em; color:var(--text-muted);">
            Rule types: <code>must_contain</code>, <code>must_not_contain</code>, <code>regex_match</code><br>
            Each rule: <code>{"name": "...", "type": "...", "pattern": "..."}</code>
        </div>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitCreateComplianceProfile()">Create</button>
        </div>
    `);
}
window.showCreateComplianceProfileModal = showCreateComplianceProfileModal;

async function submitCreateComplianceProfile() {
    const name = document.getElementById('cp-name')?.value?.trim();
    if (!name) { showError('Profile name is required'); return; }
    let rules = [];
    const rulesText = document.getElementById('cp-rules')?.value?.trim();
    if (rulesText) {
        try { rules = JSON.parse(rulesText); } catch (e) { showError('Invalid JSON for rules'); return; }
        if (!Array.isArray(rules)) { showError('Rules must be a JSON array'); return; }
    }
    try {
        await api.createComplianceProfile({
            name,
            description: document.getElementById('cp-desc')?.value?.trim() || '',
            severity: document.getElementById('cp-severity')?.value || 'medium',
            rules,
        });
        closeAllModals();
        showSuccess('Compliance profile created');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.submitCreateComplianceProfile = submitCreateComplianceProfile;

let _editComplianceProfileId = null;
async function showEditComplianceProfileModal(profileId) {
    _editComplianceProfileId = profileId;
    let profile;
    try { profile = await api.getComplianceProfile(profileId); } catch (e) { showError(e.message); return; }
    let rulesStr = '';
    try { rulesStr = JSON.stringify(JSON.parse(profile.rules || '[]'), null, 2); } catch (e) { rulesStr = profile.rules || '[]'; }
    showModal('Edit Compliance Profile', `
        <label class="form-label">Profile Name</label>
        <input id="cp-name" class="form-input" value="${escapeHtml(profile.name)}">
        <label class="form-label" style="margin-top:0.75rem;">Description</label>
        <input id="cp-desc" class="form-input" value="${escapeHtml(profile.description || '')}">
        <label class="form-label" style="margin-top:0.75rem;">Severity</label>
        <select id="cp-severity" class="form-select">
            <option value="low" ${profile.severity === 'low' ? 'selected' : ''}>Low</option>
            <option value="medium" ${profile.severity === 'medium' ? 'selected' : ''}>Medium</option>
            <option value="high" ${profile.severity === 'high' ? 'selected' : ''}>High</option>
            <option value="critical" ${profile.severity === 'critical' ? 'selected' : ''}>Critical</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Rules (JSON array)</label>
        <textarea id="cp-rules" class="form-input" rows="8">${escapeHtml(rulesStr)}</textarea>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitEditComplianceProfile()">Save</button>
        </div>
    `);
}
window.showEditComplianceProfileModal = showEditComplianceProfileModal;

async function submitEditComplianceProfile() {
    const profileId = _editComplianceProfileId;
    if (!profileId) return;
    const name = document.getElementById('cp-name')?.value?.trim();
    if (!name) { showError('Profile name is required'); return; }
    let rules = [];
    const rulesText = document.getElementById('cp-rules')?.value?.trim();
    if (rulesText) {
        try { rules = JSON.parse(rulesText); } catch (e) { showError('Invalid JSON for rules'); return; }
        if (!Array.isArray(rules)) { showError('Rules must be a JSON array'); return; }
    }
    try {
        await api.updateComplianceProfile(profileId, {
            name,
            description: document.getElementById('cp-desc')?.value?.trim() || '',
            severity: document.getElementById('cp-severity')?.value || 'medium',
            rules,
        });
        closeAllModals();
        showSuccess('Profile updated');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.submitEditComplianceProfile = submitEditComplianceProfile;

let _assignComplianceProfileId = null;
async function showAssignComplianceProfileModal(profileId) {
    _assignComplianceProfileId = profileId;
    let groups = [], creds = [], existingAssignments = [];
    try {
        [groups, creds, existingAssignments] = await Promise.all([
            api.getInventoryGroups(),
            api.getCredentials(),
            api.getComplianceAssignments(profileId),
        ]);
    } catch (e) { /* ignore */ }
    const assignedGroupIds = new Set((existingAssignments || []).map(a => a.group_id));
    const groupCheckboxes = (groups || []).map(g => {
        const already = assignedGroupIds.has(g.id);
        return `<label style="display:flex; align-items:center; gap:0.5rem; padding:0.35rem 0; cursor:pointer;">
            <input type="checkbox" class="ca-group-cb" value="${g.id}" ${already ? 'disabled' : ''} />
            <span>${escapeHtml(g.name)}</span>
            ${already ? '<span style="font-size:0.8em; color:var(--text-muted);">(already assigned)</span>' : ''}
        </label>`;
    }).join('');
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    showModal('Assign Profile to Groups', `
        <label class="form-label">Inventory Groups</label>
        <div style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
            <button class="btn btn-sm btn-secondary" onclick="document.querySelectorAll('.ca-group-cb:not(:disabled)').forEach(cb => cb.checked = true)">Select All</button>
            <button class="btn btn-sm btn-secondary" onclick="document.querySelectorAll('.ca-group-cb:not(:disabled)').forEach(cb => cb.checked = false)">Deselect All</button>
        </div>
        <div style="max-height:200px; overflow-y:auto; border:1px solid var(--border-color); border-radius:0.5rem; padding:0.5rem 0.75rem;">
            ${groupCheckboxes || '<span style="color:var(--text-muted)">No inventory groups found</span>'}
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Credential</label>
        <select id="ca-cred" class="form-select">${credOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Scan Interval (hours)</label>
        <input id="ca-interval" class="form-input" type="number" value="24" min="1" max="168">
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitAssignComplianceProfile()">Assign</button>
        </div>
    `);
}
window.showAssignComplianceProfileModal = showAssignComplianceProfileModal;

async function submitAssignComplianceProfile() {
    const profileId = _assignComplianceProfileId;
    if (!profileId) return;
    const selectedGroups = [...document.querySelectorAll('.ca-group-cb:checked:not(:disabled)')].map(cb => parseInt(cb.value));
    const credId = parseInt(document.getElementById('ca-cred')?.value);
    const hours = parseInt(document.getElementById('ca-interval')?.value) || 24;
    if (selectedGroups.length === 0) { showError('Select at least one group'); return; }
    if (!credId) { showError('Credential is required'); return; }
    let success = 0;
    let failed = 0;
    for (const groupId of selectedGroups) {
        try {
            await api.createComplianceAssignment({
                profile_id: profileId,
                group_id: groupId,
                credential_id: credId,
                interval_seconds: hours * 3600,
            });
            success++;
        } catch (e) {
            failed++;
        }
    }
    closeAllModals();
    if (failed === 0) {
        showSuccess(`Profile assigned to ${success} group(s).`);
    } else {
        showError(`Assigned to ${success} group(s), ${failed} failed.`);
    }
    loadCompliance();
}
window.submitAssignComplianceProfile = submitAssignComplianceProfile;

async function confirmDeleteComplianceProfile(profileId) {
    if (!await showConfirm({ title: 'Delete Compliance Profile', message: 'Delete this compliance profile and all its assignments and scan results?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteComplianceProfile(profileId);
        showSuccess('Profile deleted');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.confirmDeleteComplianceProfile = confirmDeleteComplianceProfile;

async function toggleComplianceAssignment(assignmentId, enabled) {
    try {
        await api.updateComplianceAssignment(assignmentId, { enabled });
        showSuccess(enabled ? 'Assignment enabled' : 'Assignment disabled');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.toggleComplianceAssignment = toggleComplianceAssignment;

async function confirmDeleteComplianceAssignment(assignmentId) {
    if (!await showConfirm({ title: 'Delete Assignment', message: 'Delete this compliance assignment?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteComplianceAssignment(assignmentId);
        showSuccess('Assignment deleted');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.confirmDeleteComplianceAssignment = confirmDeleteComplianceAssignment;

async function showComplianceFindings(resultId) {
    let result, creds = [];
    try {
        [result, creds] = await Promise.all([
            api.getComplianceScanResult(resultId),
            api.getCredentials().catch(() => []),
        ]);
    } catch (e) { showError(e.message); return; }
    let findings = [];
    try { findings = JSON.parse(result.findings || '[]'); } catch (e) { /* ignore */ }

    const hasFailedWithFix = findings.some(f => !f.passed && f.remediation && f.remediation.length > 0);
    // Pre-select first credential for convenience
    const credOptions = (creds || []).map((c, i) => `<option value="${c.id}" ${i === 0 ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join('');

    _findingsRemediationMap = {};
    const rows = findings.map((f, idx) => {
        const color = f.passed ? 'success' : 'danger';
        const hasFix = !f.passed && f.remediation && f.remediation.length > 0;
        if (hasFix) _findingsRemediationMap[idx] = f.remediation;
        const escapedName = escapeHtml(f.name).replace(/'/g, "\\'");
        const fixBtn = hasFix
            ? `<button class="btn btn-sm btn-primary" onclick="remediateComplianceRule(${resultId}, '${escapedName}')">Fix</button>
               <button class="btn btn-sm btn-secondary" style="margin-left:0.25rem;" onclick="previewComplianceRemediation('${escapedName}', ${idx})">Preview</button>`
            : (!f.passed ? '<span style="font-size:0.8em; color:var(--text-muted);">Manual fix required</span>' : '');
        return `<tr>
            <td style="color:var(--${color})">${f.passed ? 'PASS' : 'FAIL'}</td>
            <td>${escapeHtml(f.name || '-')}</td>
            <td><code>${escapeHtml(f.type || '-')}</code></td>
            <td style="font-size:0.85em">${escapeHtml(f.detail || '-')}</td>
            <td style="white-space:nowrap;">${fixBtn}</td>
        </tr>`;
    }).join('');
    showModal(`Compliance Findings — ${escapeHtml(result.hostname || '?')}`, `
        <div style="margin-bottom:1rem;">
            <strong>Profile:</strong> ${escapeHtml(result.profile_name || '?')} ·
            <strong>Status:</strong> ${escapeHtml(result.status)} ·
            <strong>Score:</strong> ${result.passed_rules}/${result.total_rules} passed
        </div>
        ${hasFailedWithFix ? `
        <div style="margin-bottom:1rem; display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap;">
            <label style="font-weight:600; font-size:0.9em;">Credential for remediation:</label>
            <select id="remediation-cred-select" class="form-select" style="max-width:300px;">
                <option value="">Select credential...</option>
                ${credOptions}
            </select>
            <button class="btn btn-sm btn-primary" onclick="remediateAllFailedRules(${resultId})">Fix All</button>
        </div>
        ` : ''}
        <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:0.9em;">
                <thead><tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:0.5rem;">Result</th>
                    <th style="text-align:left; padding:0.5rem;">Rule</th>
                    <th style="text-align:left; padding:0.5rem;">Type</th>
                    <th style="text-align:left; padding:0.5rem;">Detail</th>
                    <th style="text-align:left; padding:0.5rem;">Action</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `);
}
window.showComplianceFindings = showComplianceFindings;

function previewComplianceRemediation(ruleName, idx) {
    const commands = _findingsRemediationMap[idx] || [];
    showModal(`Remediation Preview — ${escapeHtml(ruleName)}`, `
        <p style="margin-bottom:0.75rem;">The following commands will be pushed in config mode:</p>
        <pre style="background:var(--bg-secondary); padding:1rem; border-radius:0.5rem; overflow-x:auto; font-size:0.9em;">${commands.map(c => escapeHtml(c)).join('\n')}</pre>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
        </div>
    `);
}
window.previewComplianceRemediation = previewComplianceRemediation;

async function remediateComplianceRule(resultId, ruleName) {
    const credSelect = document.getElementById('remediation-cred-select');
    const credId = credSelect ? parseInt(credSelect.value) : NaN;
    if (!credId || isNaN(credId)) {
        showError('Select a credential before applying a fix.');
        return;
    }
    if (!await showConfirm({
        title: 'Apply Remediation',
        message: `Push fix commands to the device for rule "${ruleName}"?\n\nThis will modify the running config and save it.`,
        confirmText: 'Apply Fix',
        confirmClass: 'btn-primary'
    })) return;

    try {
        const res = await api.remediateComplianceFinding({
            result_id: resultId,
            rule_name: ruleName,
            credential_id: credId,
            dry_run: false,
        });
        if (res.rule_now_passes) {
            showSuccess(`${res.rule} — FIXED. New score: ${res.rescan_passed}/${res.rescan_total}`);
        } else {
            showError(`Remediation applied but rule still failing. Review device output. New score: ${res.rescan_passed}/${res.rescan_total}`);
        }
        // Re-open findings modal with the new scan result
        closeAllModals();
        await showComplianceFindings(res.rescan_id);
        loadCompliance();
    } catch (e) {
        showError(`Remediation failed: ${e.message}`);
    }
}
window.remediateComplianceRule = remediateComplianceRule;

async function remediateAllFailedRules(resultId) {
    const credSelect = document.getElementById('remediation-cred-select');
    const credId = credSelect ? parseInt(credSelect.value) : NaN;
    if (!credId || isNaN(credId)) {
        showError('Select a credential before applying fixes.');
        return;
    }

    let result;
    try { result = await api.getComplianceScanResult(resultId); } catch (e) { showError(e.message); return; }
    let findings = [];
    try { findings = JSON.parse(result.findings || '[]'); } catch (e) { /* ignore */ }
    const fixable = findings.filter(f => !f.passed && f.remediation && f.remediation.length > 0);

    if (fixable.length === 0) {
        showError('No auto-fixable rules found.');
        return;
    }

    if (!await showConfirm({
        title: 'Fix All Failed Rules',
        message: `Apply remediation for ${fixable.length} failed rule(s) on ${escapeHtml(result.hostname || '?')}?\n\nThis will push config changes and save.`,
        confirmText: `Fix ${fixable.length} Rule(s)`,
        confirmClass: 'btn-primary'
    })) return;

    let lastRescanId = resultId;
    let fixed = 0;
    let failed = 0;

    for (const f of fixable) {
        try {
            const res = await api.remediateComplianceFinding({
                result_id: lastRescanId,
                rule_name: f.name,
                credential_id: credId,
                dry_run: false,
            });
            lastRescanId = res.rescan_id;
            if (res.rule_now_passes) fixed++;
            else failed++;
        } catch (e) {
            failed++;
        }
    }

    if (failed === 0) {
        showSuccess(`All ${fixed} rule(s) remediated successfully.`);
    } else {
        showError(`${fixed} rule(s) fixed, ${failed} still failing — review manually.`);
    }

    closeAllModals();
    await showComplianceFindings(lastRescanId);
    loadCompliance();
}
window.remediateAllFailedRules = remediateAllFailedRules;

export function destroyCompliance() {
    _complianceCurrentTab = 'profiles';
    _editComplianceProfileId = null;
    _assignComplianceProfileId = null;
    listViewState.compliance.profiles = [];
    listViewState.compliance.assignments = [];
    listViewState.compliance.results = [];
    listViewState.compliance.statusList = [];
    listViewState.compliance.query = '';
}

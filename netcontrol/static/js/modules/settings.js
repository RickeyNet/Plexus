/**
 * Settings Module — Admin settings, user/group management, auth config
 * Lazy-loaded when user navigates to #settings
 */
import * as api from '../api.js';
import {
    escapeHtml, showError, showSuccess, showToast, formatDate,
    showModal, closeAllModals, showConfirm,
    emptyStateHTML, currentUserData, invalidatePageCache,
    initThemeControls, initSpaceControls
} from '../app.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Settings
// ═══════════════════════════════════════════════════════════════════════════════

const adminState = {
    capabilities: null,
    users: [],
    groups: [],
    loginRules: null,
    authConfig: null,
};

// Named handler references for proper cleanup
let _loginRulesHandler = null;
let _authConfigHandler = null;
let _authProviderHandler = null;
let _topoDiscoveryHandler = null;
let _stpDiscoveryHandler = null;
let _stpAllVlansHandler = null;
let _stpRootPolicyHandler = null;
let _monitoringHandler = null;

function getGroupNameMap() {
    const map = {};
    (adminState.groups || []).forEach((g) => {
        map[g.id] = g.name;
    });
    return map;
}

function featureLabel(feature) {
    return feature.charAt(0).toUpperCase() + feature.slice(1);
}

function renderFeatureCheckboxes(selected = []) {
    const features = adminState.capabilities?.feature_flags || [];
    const selectedSet = new Set(selected || []);
    return features.map((feature) => `
        <label style="display:flex; align-items:center; gap:0.35rem;">
            <input type="checkbox" name="feature_keys" value="${feature}" ${selectedSet.has(feature) ? 'checked' : ''}>
            <span>${featureLabel(feature)}</span>
        </label>
    `).join('');
}

function renderGroupCheckboxes(selected = []) {
    const selectedSet = new Set((selected || []).map((v) => Number(v)));
    return (adminState.groups || []).map((group) => `
        <label style="display:flex; align-items:center; gap:0.35rem;">
            <input type="checkbox" name="group_ids" value="${group.id}" ${selectedSet.has(Number(group.id)) ? 'checked' : ''}>
            <span>${escapeHtml(group.name)}</span>
        </label>
    `).join('');
}

function collectCheckedValues(formEl, name) {
    return Array.from(formEl.querySelectorAll(`input[name="${name}"]:checked`)).map((el) => el.value);
}

function renderAdminUsers() {
    const container = document.getElementById('admin-users-list');
    if (!container) return;
    if (!adminState.users.length) {
        container.innerHTML = emptyStateHTML('No user accounts found', 'default');
        return;
    }

    const groupNames = getGroupNameMap();
    container.innerHTML = adminState.users.map((user) => {
        const groupBadges = (user.group_ids || []).map((gid) => groupNames[gid] || `Group ${gid}`);
        const features = user.feature_access || [];
        return `
            <div class="card" style="margin-bottom:0.75rem;">
                <div class="card-header" style="margin-bottom:0.5rem;">
                    <div>
                        <div class="card-title">${escapeHtml(user.display_name || user.username)}</div>
                        <div class="card-description">@${escapeHtml(user.username)} • ${escapeHtml(user.role)} • Created ${formatDate(user.created_at)}</div>
                    </div>
                    <div style="display:flex; gap:0.35rem; flex-wrap:wrap;">
                        <button class="btn btn-sm btn-secondary" onclick="showEditAdminUserModal(${user.id})">Edit</button>
                        <button class="btn btn-sm btn-secondary" onclick="showResetAdminUserPasswordModal(${user.id})">Reset Password</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteAdminUser(${user.id})">Delete</button>
                    </div>
                </div>
                <div style="display:grid; gap:0.4rem;">
                    <div style="font-size:0.8rem; color:var(--text-muted);">Access Groups</div>
                    <div style="display:flex; flex-wrap:wrap; gap:0.4rem;">${groupBadges.length ? groupBadges.map((name) => `<span class="status-badge">${escapeHtml(name)}</span>`).join('') : '<span class="card-description">No groups assigned (full default access)</span>'}</div>
                    <div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.25rem;">Effective Features</div>
                    <div style="display:flex; flex-wrap:wrap; gap:0.4rem;">${features.map((name) => `<span class="status-badge status-running">${escapeHtml(name)}</span>`).join('')}</div>
                </div>
            </div>
        `;
    }).join('');
}

function renderAdminGroups() {
    const container = document.getElementById('admin-groups-list');
    if (!container) return;
    if (!adminState.groups.length) {
        container.innerHTML = emptyStateHTML('No access groups defined', 'default', '<button class="btn btn-primary btn-sm" onclick="showCreateAccessGroupModal()">+ New Group</button>');
        return;
    }

    container.innerHTML = adminState.groups.map((group) => `
        <div class="card" style="margin-bottom:0.75rem;">
            <div class="card-header" style="margin-bottom:0.5rem;">
                <div>
                    <div class="card-title">${escapeHtml(group.name)}</div>
                    <div class="card-description">${escapeHtml(group.description || '')}</div>
                    <div class="card-description">${group.member_count || 0} member(s)</div>
                </div>
                <div style="display:flex; gap:0.35rem;">
                    <button class="btn btn-sm btn-secondary" onclick="showEditAccessGroupModal(${group.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAccessGroupAdmin(${group.id})">Delete</button>
                </div>
            </div>
            <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
                ${(group.feature_keys || []).map((feature) => `<span class="status-badge">${escapeHtml(feature)}</span>`).join('') || '<span class="card-description">No features assigned</span>'}
            </div>
        </div>
    `).join('');
}

function bindLoginRulesForm() {
    const form = document.getElementById('admin-login-rules-form');
    if (!form) return;
    // Remove previous handler before attaching to prevent stacking
    if (_loginRulesHandler) form.removeEventListener('submit', _loginRulesHandler);
    _loginRulesHandler = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                max_attempts: Number(document.getElementById('login-max-attempts').value),
                lockout_time: Number(document.getElementById('login-lockout-time').value),
                rate_limit_window: Number(document.getElementById('login-rate-window').value),
                rate_limit_max: Number(document.getElementById('login-rate-max').value),
            };
            adminState.loginRules = await api.updateLoginRules(payload);
            showSuccess('Login rules updated');
        } catch (error) {
            showError(`Failed to save login rules: ${error.message}`);
        }
    };
    form.addEventListener('submit', _loginRulesHandler);
}

function renderLoginRules() {
    if (!adminState.loginRules) return;
    document.getElementById('login-max-attempts').value = adminState.loginRules.max_attempts;
    document.getElementById('login-lockout-time').value = adminState.loginRules.lockout_time;
    document.getElementById('login-rate-window').value = adminState.loginRules.rate_limit_window;
    document.getElementById('login-rate-max').value = adminState.loginRules.rate_limit_max;
}

function bindAuthConfigForm() {
    const form = document.getElementById('admin-auth-config-form');
    if (!form) return;
    // Remove previous handlers before attaching to prevent stacking
    if (_authConfigHandler) form.removeEventListener('submit', _authConfigHandler);
    _authConfigHandler = async (e) => {
        e.preventDefault();
        try {
            const retentionDays = Number(document.getElementById('job-retention-days').value);
            if (retentionDays < 30) {
                showError('Job retention must be at least 30 days');
                return;
            }
            const credVal = document.getElementById('default-credential-id').value;
            const payload = {
                provider: document.getElementById('auth-provider').value,
                default_credential_id: credVal ? Number(credVal) : null,
                job_retention_days: retentionDays,
                radius: {
                    enabled: document.getElementById('radius-enabled').checked,
                    fallback_to_local: document.getElementById('radius-fallback-local').checked,
                    fallback_on_reject: document.getElementById('radius-fallback-reject').checked,
                    server: document.getElementById('radius-server').value,
                    port: Number(document.getElementById('radius-port').value),
                    secret: document.getElementById('radius-secret').value,
                    timeout: Number(document.getElementById('radius-timeout').value),
                },
                ldap: {
                    enabled: document.getElementById('ldap-enabled').checked,
                    server: document.getElementById('ldap-server').value,
                    port: Number(document.getElementById('ldap-port').value),
                    use_ssl: document.getElementById('ldap-use-ssl').checked,
                    bind_dn: document.getElementById('ldap-bind-dn').value,
                    bind_password: document.getElementById('ldap-bind-password').value,
                    base_dn: document.getElementById('ldap-base-dn').value,
                    user_search_filter: document.getElementById('ldap-user-search-filter').value,
                    admin_group_dn: document.getElementById('ldap-admin-group-dn').value,
                    fallback_to_local: document.getElementById('ldap-fallback-local').checked,
                    fallback_on_reject: document.getElementById('ldap-fallback-reject').checked,
                    timeout: Number(document.getElementById('ldap-timeout').value),
                },
            };
            adminState.authConfig = await api.updateAuthConfig(payload);
            renderAuthConfig();
            showSuccess('Authentication settings saved');
        } catch (error) {
            showError(`Failed to save authentication settings: ${error.message}`);
        }
    };
    form.addEventListener('submit', _authConfigHandler);

    const providerEl = document.getElementById('auth-provider');
    if (providerEl) {
        if (_authProviderHandler) providerEl.removeEventListener('change', _authProviderHandler);
        _authProviderHandler = () => {
            const radiusPanel = document.getElementById('radius-config-panel');
            const ldapPanel = document.getElementById('ldap-config-panel');
            if (radiusPanel) radiusPanel.style.display = providerEl.value === 'radius' ? '' : 'none';
            if (ldapPanel) ldapPanel.style.display = providerEl.value === 'ldap' ? '' : 'none';
        };
        providerEl.addEventListener('change', _authProviderHandler);
    }
}

async function renderAuthConfig() {
    if (!adminState.authConfig) return;
    const cfg = adminState.authConfig;
    document.getElementById('auth-provider').value = cfg.provider || 'local';
    document.getElementById('job-retention-days').value = Math.max(30, Number(cfg.job_retention_days || 30));
    document.getElementById('radius-enabled').checked = !!cfg.radius?.enabled;
    document.getElementById('radius-fallback-local').checked = cfg.radius?.fallback_to_local !== false;
    document.getElementById('radius-fallback-reject').checked = !!cfg.radius?.fallback_on_reject;
    document.getElementById('radius-server').value = cfg.radius?.server || '';
    document.getElementById('radius-port').value = cfg.radius?.port || 1812;
    document.getElementById('radius-secret').value = cfg.radius?.secret || '';
    document.getElementById('radius-timeout').value = cfg.radius?.timeout || 5;
    const radiusPanel = document.getElementById('radius-config-panel');
    if (radiusPanel) {
        radiusPanel.style.display = cfg.provider === 'radius' ? '' : 'none';
    }
    // LDAP fields
    const ldapPanel = document.getElementById('ldap-config-panel');
    if (ldapPanel) {
        ldapPanel.style.display = cfg.provider === 'ldap' ? '' : 'none';
    }
    const ldapEl = (id) => document.getElementById(id);
    if (ldapEl('ldap-enabled')) ldapEl('ldap-enabled').checked = !!cfg.ldap?.enabled;
    if (ldapEl('ldap-server')) ldapEl('ldap-server').value = cfg.ldap?.server || '';
    if (ldapEl('ldap-port')) ldapEl('ldap-port').value = cfg.ldap?.port || 389;
    if (ldapEl('ldap-use-ssl')) ldapEl('ldap-use-ssl').checked = !!cfg.ldap?.use_ssl;
    if (ldapEl('ldap-bind-dn')) ldapEl('ldap-bind-dn').value = cfg.ldap?.bind_dn || '';
    if (ldapEl('ldap-bind-password')) ldapEl('ldap-bind-password').value = cfg.ldap?.bind_password || '';
    if (ldapEl('ldap-base-dn')) ldapEl('ldap-base-dn').value = cfg.ldap?.base_dn || '';
    if (ldapEl('ldap-user-search-filter')) ldapEl('ldap-user-search-filter').value = cfg.ldap?.user_search_filter || '(sAMAccountName={username})';
    if (ldapEl('ldap-admin-group-dn')) ldapEl('ldap-admin-group-dn').value = cfg.ldap?.admin_group_dn || '';
    if (ldapEl('ldap-fallback-local')) ldapEl('ldap-fallback-local').checked = cfg.ldap?.fallback_to_local !== false;
    if (ldapEl('ldap-fallback-reject')) ldapEl('ldap-fallback-reject').checked = !!cfg.ldap?.fallback_on_reject;
    if (ldapEl('ldap-timeout')) ldapEl('ldap-timeout').value = cfg.ldap?.timeout || 10;
    // Populate default credential dropdown
    const credSelect = document.getElementById('default-credential-id');
    if (credSelect) {
        try {
            const creds = await api.getCredentials();
            credSelect.innerHTML = '<option value="">-- None --</option>' +
                creds.map(c => `<option value="${c.id}">${escapeHtml(c.name)} (${escapeHtml(c.username)})</option>`).join('');
            credSelect.value = cfg.default_credential_id || '';
        } catch (_) {
            credSelect.value = cfg.default_credential_id || '';
        }
    }
}

async function refreshAdminData() {
    const [users, groups, loginRules, authConfig] = await Promise.all([
        api.getAdminUsers(),
        api.getAccessGroups(),
        api.getLoginRules(),
        api.getAuthConfig(),
    ]);
    adminState.users = users;
    adminState.groups = groups;
    adminState.loginRules = loginRules;
    adminState.authConfig = authConfig;
}

async function loadAdminSettings(_options = {}) {
    const page = document.getElementById('page-settings');
    if (!page) return;
    if (currentUserData?.role !== 'admin') {
        page.innerHTML = '<h2>Settings</h2><div class="error">Admin access is required to view settings.</div>';
        return;
    }

    try {
        if (!adminState.capabilities) {
            adminState.capabilities = await api.getAdminCapabilities();
        }
        await refreshAdminData();
        renderAdminUsers();
        renderAdminGroups();
        bindLoginRulesForm();
        bindAuthConfigForm();
        bindTopologyDiscoveryForm();
        bindStpDiscoveryForm();
        bindStpRootPolicyForm();
        bindMonitoringForm();
        renderLoginRules();
        renderAuthConfig();
        loadTopologyDiscoveryConfig();
        loadStpDiscoveryConfig();
        loadStpRootPolicies();
        loadMonitoringConfig();
        initThemeControls();
        initSpaceControls();
    } catch (error) {
        const usersContainer = document.getElementById('admin-users-list');
        if (usersContainer) {
            usersContainer.innerHTML = `<div class="error">Failed loading admin settings: ${escapeHtml(error.message)}</div>`;
        }
    }
}

// -- Topology Discovery Schedule --

async function loadTopologyDiscoveryConfig() {
    try {
        const cfg = await api.getTopologyDiscoveryConfig();
        document.getElementById('topo-disc-enabled').checked = !!cfg.enabled;
        document.getElementById('topo-disc-interval').value = cfg.interval_seconds || 3600;
    } catch { /* not admin or feature unavailable */ }
}

function bindTopologyDiscoveryForm() {
    const form = document.getElementById('admin-topology-discovery-form');
    if (!form) return;
    if (_topoDiscoveryHandler) form.removeEventListener('submit', _topoDiscoveryHandler);
    _topoDiscoveryHandler = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                enabled: document.getElementById('topo-disc-enabled').checked,
                interval_seconds: parseInt(document.getElementById('topo-disc-interval').value) || 3600,
            };
            await api.updateTopologyDiscoveryConfig(payload);
            showToast('Topology discovery schedule saved', 'success');
        } catch (err) {
            showError('Failed to save: ' + err.message);
        }
    };
    form.addEventListener('submit', _topoDiscoveryHandler);
}

async function runTopologyDiscoveryNow() {
    try {
        showToast('Running topology discovery...', 'info');
        const resp = await api.runTopologyDiscoveryNow();
        const r = resp.result || {};
        showToast(`Topology discovery complete: ${r.groups_scanned || 0} groups, ${r.links_discovered || 0} links, ${r.errors || 0} errors`,
            (r.errors > 0) ? 'warning' : 'success');
        invalidatePageCache('topology');
    } catch (err) {
        showError('Topology discovery failed: ' + err.message);
    }
}

window.runTopologyDiscoveryNow = runTopologyDiscoveryNow;

// -- STP Discovery Schedule + Root Policies --

function _syncStpDiscoveryFormState() {
    const allEl = document.getElementById('stp-disc-all-vlans');
    const vlanEl = document.getElementById('stp-disc-vlan');
    if (!allEl || !vlanEl) return;
    vlanEl.disabled = !!allEl.checked;
}

async function loadStpDiscoveryConfig() {
    try {
        const cfg = await api.getTopologyStpDiscoveryConfig();
        document.getElementById('stp-disc-enabled').checked = !!cfg.enabled;
        document.getElementById('stp-disc-interval').value = cfg.interval_seconds || 3600;
        document.getElementById('stp-disc-all-vlans').checked = cfg.all_vlans !== false;
        document.getElementById('stp-disc-vlan').value = cfg.vlan_id || 1;
        document.getElementById('stp-disc-max-vlans').value = cfg.max_vlans || 64;
        _syncStpDiscoveryFormState();
    } catch { /* not admin or feature unavailable */ }
}

function bindStpDiscoveryForm() {
    const form = document.getElementById('admin-stp-discovery-form');
    const allEl = document.getElementById('stp-disc-all-vlans');
    if (!form || !allEl) return;

    if (_stpDiscoveryHandler) form.removeEventListener('submit', _stpDiscoveryHandler);
    if (_stpAllVlansHandler) allEl.removeEventListener('change', _stpAllVlansHandler);

    _stpAllVlansHandler = () => _syncStpDiscoveryFormState();
    allEl.addEventListener('change', _stpAllVlansHandler);

    _stpDiscoveryHandler = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                enabled: document.getElementById('stp-disc-enabled').checked,
                interval_seconds: parseInt(document.getElementById('stp-disc-interval').value, 10) || 3600,
                all_vlans: document.getElementById('stp-disc-all-vlans').checked,
                vlan_id: parseInt(document.getElementById('stp-disc-vlan').value, 10) || 1,
                max_vlans: parseInt(document.getElementById('stp-disc-max-vlans').value, 10) || 64,
            };
            await api.updateTopologyStpDiscoveryConfig(payload);
            showToast('STP polling schedule saved', 'success');
            _syncStpDiscoveryFormState();
        } catch (err) {
            showError('Failed to save STP schedule: ' + err.message);
        }
    };
    form.addEventListener('submit', _stpDiscoveryHandler);
}

async function runTopologyStpDiscoveryNow() {
    try {
        showToast('Running STP polling...', 'info');
        const resp = await api.runTopologyStpDiscoveryNow();
        const r = resp.result || {};
        if (!r.enabled) {
            showToast('Scheduled STP polling is disabled. Enable it or run Scan STP from Topology.', 'info');
            return;
        }
        showToast(
            `STP polling complete: ${r.groups_scanned || 0} groups, ${r.ports_collected || 0} ports, ${r.errors || 0} errors`,
            (r.errors > 0) ? 'warning' : 'success',
        );
        invalidatePageCache('topology');
    } catch (err) {
        showError('STP polling failed: ' + err.message);
    }
}

async function loadStpRootPolicies() {
    const listEl = document.getElementById('stp-root-policy-list');
    const groupSelect = document.getElementById('stp-root-group-id');
    if (!listEl || !groupSelect) return;

    try {
        const [groups, resp] = await Promise.all([
            api.getInventoryGroups(false),
            api.getTopologyStpRootPolicies(null, null, false, 2000),
        ]);

        const currentGroupVal = groupSelect.value;
        groupSelect.innerHTML = (groups || []).map((g) =>
            `<option value="${g.id}">${escapeHtml(g.name)}</option>`
        ).join('');
        if (currentGroupVal) groupSelect.value = currentGroupVal;
        if (!groupSelect.value && groups?.length) groupSelect.value = String(groups[0].id);

        const policies = resp.policies || [];
        if (!policies.length) {
            listEl.innerHTML = '<div class="card-description">No STP root policies defined yet.</div>';
            return;
        }

        listEl.innerHTML = policies.map((p) => `
            <div class="card" style="margin-bottom:0.55rem; padding:0.65rem 0.8rem;">
                <div style="display:flex; justify-content:space-between; gap:0.75rem; align-items:flex-start;">
                    <div>
                        <div style="font-weight:600; font-size:0.9rem;">${escapeHtml(p.group_name || ('Group ' + p.group_id))} · VLAN ${escapeHtml(p.vlan_id || '')}</div>
                        <div style="font-family:monospace; font-size:0.78rem; margin-top:0.15rem;">${escapeHtml(p.expected_root_bridge_id || '')}</div>
                        <div class="card-description">${escapeHtml(p.expected_root_hostname || '')}</div>
                    </div>
                    <div style="display:flex; gap:0.4rem; align-items:center;">
                        <span class="status-badge ${p.enabled ? 'status-running' : 'status-pending'}">${p.enabled ? 'Enabled' : 'Disabled'}</span>
                        <button class="btn btn-sm btn-danger" onclick="deleteStpRootPolicy(${p.id})">Delete</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        listEl.innerHTML = `<div class="error">Failed loading STP root policies: ${escapeHtml(err.message)}</div>`;
    }
}

function bindStpRootPolicyForm() {
    const form = document.getElementById('admin-stp-root-policy-form');
    if (!form) return;
    if (_stpRootPolicyHandler) form.removeEventListener('submit', _stpRootPolicyHandler);

    _stpRootPolicyHandler = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                group_id: parseInt(document.getElementById('stp-root-group-id').value, 10) || 0,
                vlan_id: parseInt(document.getElementById('stp-root-vlan').value, 10) || 1,
                expected_root_bridge_id: (document.getElementById('stp-root-bridge-id').value || '').trim(),
                expected_root_hostname: (document.getElementById('stp-root-hostname').value || '').trim(),
                enabled: document.getElementById('stp-root-enabled').checked,
            };
            if (!payload.group_id || !payload.expected_root_bridge_id) {
                showError('Group and expected root bridge ID are required.');
                return;
            }
            await api.upsertTopologyStpRootPolicy(payload);
            showToast('STP root policy saved', 'success');
            await loadStpRootPolicies();
        } catch (err) {
            showError('Failed to save STP root policy: ' + err.message);
        }
    };
    form.addEventListener('submit', _stpRootPolicyHandler);
}

window.runTopologyStpDiscoveryNow = runTopologyStpDiscoveryNow;
window.deleteStpRootPolicy = async function(policyId) {
    if (!await showConfirm({
        title: 'Delete STP Root Policy',
        message: 'Delete this STP root policy?',
        confirmText: 'Delete',
        cancelText: 'Cancel',
        confirmClass: 'btn-danger',
    })) {
        return;
    }
    try {
        await api.deleteTopologyStpRootPolicy(policyId);
        showSuccess('STP root policy deleted');
        await loadStpRootPolicies();
    } catch (err) {
        showError('Failed to delete STP root policy: ' + err.message);
    }
};

// -- Monitoring Config --

async function loadMonitoringConfig() {
    try {
        const cfg = await api.getMonitoringConfig();
        document.getElementById('mon-enabled').checked = !!cfg.enabled;
        document.getElementById('mon-interval').value = cfg.interval_seconds || 300;
        document.getElementById('mon-retention').value = cfg.retention_days || 30;
        document.getElementById('mon-cpu-threshold').value = cfg.cpu_threshold || 90;
        document.getElementById('mon-mem-threshold').value = cfg.memory_threshold || 90;
        document.getElementById('mon-collect-routes').checked = cfg.collect_routes !== false;
        document.getElementById('mon-collect-vpn').checked = cfg.collect_vpn !== false;
        document.getElementById('mon-escalation-enabled').checked = cfg.escalation_enabled !== false;
        document.getElementById('mon-escalation-after').value = cfg.escalation_after_minutes || 30;
        document.getElementById('mon-escalation-check').value = cfg.escalation_check_interval || 60;
        document.getElementById('mon-cooldown').value = cfg.default_cooldown_minutes || 15;
    } catch { /* not admin or feature unavailable */ }
}

function bindMonitoringForm() {
    const form = document.getElementById('admin-monitoring-form');
    if (!form) return;
    if (_monitoringHandler) form.removeEventListener('submit', _monitoringHandler);
    _monitoringHandler = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                enabled: document.getElementById('mon-enabled').checked,
                interval_seconds: parseInt(document.getElementById('mon-interval').value) || 300,
                retention_days: parseInt(document.getElementById('mon-retention').value) || 30,
                cpu_threshold: parseInt(document.getElementById('mon-cpu-threshold').value) || 90,
                memory_threshold: parseInt(document.getElementById('mon-mem-threshold').value) || 90,
                collect_routes: document.getElementById('mon-collect-routes').checked,
                collect_vpn: document.getElementById('mon-collect-vpn').checked,
                escalation_enabled: document.getElementById('mon-escalation-enabled').checked,
                escalation_after_minutes: parseInt(document.getElementById('mon-escalation-after').value) || 30,
                escalation_check_interval: parseInt(document.getElementById('mon-escalation-check').value) || 60,
                default_cooldown_minutes: parseInt(document.getElementById('mon-cooldown').value) || 15,
            };
            await api.updateMonitoringConfig(payload);
            showToast('Monitoring configuration saved', 'success');
        } catch (err) {
            showError('Failed to save monitoring config: ' + err.message);
        }
    };
    form.addEventListener('submit', _monitoringHandler);
}

async function runMonitoringPollNow() {
    try {
        const btn = document.getElementById('mon-poll-now-btn');
        if (btn) { btn.disabled = true; btn.textContent = 'Polling...'; }
        showToast('Running monitoring poll...', 'info');
        const resp = await api.runMonitoringPollNow();
        showToast(`Monitoring poll complete: ${resp.hosts_polled || 0} hosts, ${resp.alerts_created || 0} alerts, ${resp.errors || 0} errors`,
            (resp.errors > 0) ? 'warning' : 'success');
    } catch (err) {
        showError('Monitoring poll failed: ' + err.message);
    } finally {
        const btn = document.getElementById('mon-poll-now-btn');
        if (btn) { btn.disabled = false; btn.textContent = 'Poll Now'; }
    }
}

window.runMonitoringPollNow = runMonitoringPollNow;

window.showCreateAdminUserModal = function() {
    showModal('Create User Account', `
        <form id="admin-create-user-form">
            <div class="form-group"><label class="form-label">Username</label><input class="form-input" name="username" required minlength="3"></div>
            <div class="form-group"><label class="form-label">Display Name</label><input class="form-input" name="display_name"></div>
            <div class="form-group"><label class="form-label">Password</label><input type="password" class="form-input" name="password" required minlength="8"></div>
            <div class="form-group"><label class="form-label">Confirm Password</label><input type="password" class="form-input" name="confirm_password" required minlength="8"></div>
            <div class="form-group"><label><input type="checkbox" id="admin-create-user-show-password"> Show passwords</label></div>
            <div class="form-group"><label class="form-label">Role</label><select class="form-select" name="role"><option value="user">User</option><option value="admin">Admin</option></select></div>
            <div class="form-group"><label class="form-label">Access Groups</label><div style="display:grid; gap:0.35rem; max-height:160px; overflow:auto; border:1px solid var(--border); border-radius:0.375rem; padding:0.6rem;">${renderGroupCheckboxes([]) || '<span class="card-description">Create access groups first.</span>'}</div></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;"><button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button><button class="btn btn-primary" type="submit">Create</button></div>
        </form>
    `);
    const createForm = document.getElementById('admin-create-user-form');
    const showPasswordToggle = document.getElementById('admin-create-user-show-password');
    const passwordInput = createForm?.elements?.password;
    const confirmPasswordInput = createForm?.elements?.confirm_password;

    function validatePasswordMatch() {
        if (!passwordInput || !confirmPasswordInput) return true;
        const matches = passwordInput.value === confirmPasswordInput.value;
        confirmPasswordInput.setCustomValidity(matches ? '' : 'Passwords do not match');
        return matches;
    }

    if (showPasswordToggle && passwordInput && confirmPasswordInput) {
        showPasswordToggle.addEventListener('change', () => {
            const inputType = showPasswordToggle.checked ? 'text' : 'password';
            passwordInput.type = inputType;
            confirmPasswordInput.type = inputType;
        });
    }

    if (passwordInput && confirmPasswordInput) {
        passwordInput.addEventListener('input', validatePasswordMatch);
        confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    }

    createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        if (!validatePasswordMatch()) {
            form.reportValidity();
            return;
        }
        const data = {
            username: form.username.value.trim(),
            display_name: form.display_name.value.trim(),
            password: form.password.value,
            role: form.role.value,
            group_ids: collectCheckedValues(form, 'group_ids').map((v) => Number(v)),
        };
        try {
            await api.createAdminUser(data);
            closeAllModals();
            await loadAdminSettings();
            showSuccess('User account created');
        } catch (error) {
            showError(`Failed to create user: ${error.message}`);
        }
    });
};

window.showEditAdminUserModal = function(userId) {
    const user = (adminState.users || []).find((u) => Number(u.id) === Number(userId));
    if (!user) return;
    showModal('Edit User Account', `
        <form id="admin-edit-user-form">
            <div class="form-group"><label class="form-label">Username</label><input class="form-input" name="username" required minlength="3" value="${escapeHtml(user.username)}"></div>
            <div class="form-group"><label class="form-label">Display Name</label><input class="form-input" name="display_name" value="${escapeHtml(user.display_name || '')}"></div>
            <div class="form-group"><label class="form-label">Role</label><select class="form-select" name="role"><option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option><option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option></select></div>
            <div class="form-group"><label class="form-label">Access Groups</label><div style="display:grid; gap:0.35rem; max-height:160px; overflow:auto; border:1px solid var(--border); border-radius:0.375rem; padding:0.6rem;">${renderGroupCheckboxes(user.group_ids || [])}</div></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;"><button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button><button class="btn btn-primary" type="submit">Save</button></div>
        </form>
    `);
    document.getElementById('admin-edit-user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        try {
            await api.updateAdminUser(userId, {
                username: form.username.value.trim(),
                display_name: form.display_name.value.trim(),
                role: form.role.value,
            });
            await api.setAdminUserGroups(userId, collectCheckedValues(form, 'group_ids').map((v) => Number(v)));
            closeAllModals();
            await loadAdminSettings();
            showSuccess('User account updated');
        } catch (error) {
            showError(`Failed to update user: ${error.message}`);
        }
    });
};

window.showResetAdminUserPasswordModal = function(userId) {
    const user = (adminState.users || []).find((u) => Number(u.id) === Number(userId));
    if (!user) return;
    showModal('Reset User Password', `
        <form id="admin-reset-user-password-form">
            <p class="card-description" style="margin-bottom:0.75rem;">Set a new login password for @${escapeHtml(user.username)}.</p>
            <div class="form-group"><label class="form-label">New Password</label><input type="password" class="form-input" name="new_password" required minlength="8"></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;"><button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button><button class="btn btn-primary" type="submit">Reset Password</button></div>
        </form>
    `);
    document.getElementById('admin-reset-user-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPassword = e.target.new_password.value;
        try {
            await api.resetAdminUserPassword(userId, newPassword);
            closeAllModals();
            showSuccess('Password reset successfully');
        } catch (error) {
            showError(`Failed to reset password: ${error.message}`);
        }
    });
};

window.deleteAdminUser = async function(userId) {
    const user = (adminState.users || []).find((u) => Number(u.id) === Number(userId));
    if (!user) return;
    if (!await showConfirm({ title: 'Delete User', message: `Delete @${user.username}?`, confirmText: 'Delete', cancelText: 'Cancel', confirmClass: 'btn-danger' })) {
        return;
    }
    try {
        await api.deleteAdminUser(userId);
        await loadAdminSettings();
        showSuccess('User deleted');
    } catch (error) {
        showError(`Failed to delete user: ${error.message}`);
    }
};

window.showCreateAccessGroupModal = function() {
    showModal('Create Access Group', `
        <form id="admin-create-access-group-form">
            <div class="form-group"><label class="form-label">Group Name</label><input class="form-input" name="name" required minlength="2"></div>
            <div class="form-group"><label class="form-label">Description</label><input class="form-input" name="description"></div>
            <div class="form-group"><label class="form-label">Feature Access</label><div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:0.4rem;">${renderFeatureCheckboxes([])}</div></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;"><button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button><button class="btn btn-primary" type="submit">Create Group</button></div>
        </form>
    `);
    document.getElementById('admin-create-access-group-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        try {
            await api.createAccessGroup({
                name: form.name.value.trim(),
                description: form.description.value.trim(),
                feature_keys: collectCheckedValues(form, 'feature_keys'),
            });
            closeAllModals();
            await loadAdminSettings();
            showSuccess('Access group created');
        } catch (error) {
            showError(`Failed to create access group: ${error.message}`);
        }
    });
};

window.showEditAccessGroupModal = function(groupId) {
    const group = (adminState.groups || []).find((g) => Number(g.id) === Number(groupId));
    if (!group) return;
    showModal('Edit Access Group', `
        <form id="admin-edit-access-group-form">
            <div class="form-group"><label class="form-label">Group Name</label><input class="form-input" name="name" required minlength="2" value="${escapeHtml(group.name)}"></div>
            <div class="form-group"><label class="form-label">Description</label><input class="form-input" name="description" value="${escapeHtml(group.description || '')}"></div>
            <div class="form-group"><label class="form-label">Feature Access</label><div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:0.4rem;">${renderFeatureCheckboxes(group.feature_keys || [])}</div></div>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;"><button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button><button class="btn btn-primary" type="submit">Save</button></div>
        </form>
    `);
    document.getElementById('admin-edit-access-group-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        try {
            await api.updateAccessGroup(groupId, {
                name: form.name.value.trim(),
                description: form.description.value.trim(),
                feature_keys: collectCheckedValues(form, 'feature_keys'),
            });
            closeAllModals();
            await loadAdminSettings();
            showSuccess('Access group updated');
        } catch (error) {
            showError(`Failed to update access group: ${error.message}`);
        }
    });
};

window.deleteAccessGroupAdmin = async function(groupId) {
    const group = (adminState.groups || []).find((g) => Number(g.id) === Number(groupId));
    if (!group) return;
    if (!await showConfirm({ title: 'Delete Access Group', message: `Delete group '${group.name}'?`, confirmText: 'Delete', cancelText: 'Cancel', confirmClass: 'btn-danger' })) {
        return;
    }
    try {
        await api.deleteAccessGroup(groupId);
        await loadAdminSettings();
        showSuccess('Access group deleted');
    } catch (error) {
        showError(`Failed to delete group: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

function destroySettings() {
    // Remove all named form handlers to prevent stacking on re-entry
    if (_loginRulesHandler) {
        document.getElementById('admin-login-rules-form')?.removeEventListener('submit', _loginRulesHandler);
        _loginRulesHandler = null;
    }
    if (_authConfigHandler) {
        document.getElementById('admin-auth-config-form')?.removeEventListener('submit', _authConfigHandler);
        _authConfigHandler = null;
    }
    if (_authProviderHandler) {
        document.getElementById('auth-provider')?.removeEventListener('change', _authProviderHandler);
        _authProviderHandler = null;
    }
    if (_topoDiscoveryHandler) {
        document.getElementById('admin-topology-discovery-form')?.removeEventListener('submit', _topoDiscoveryHandler);
        _topoDiscoveryHandler = null;
    }
    if (_stpDiscoveryHandler) {
        document.getElementById('admin-stp-discovery-form')?.removeEventListener('submit', _stpDiscoveryHandler);
        _stpDiscoveryHandler = null;
    }
    if (_stpAllVlansHandler) {
        document.getElementById('stp-disc-all-vlans')?.removeEventListener('change', _stpAllVlansHandler);
        _stpAllVlansHandler = null;
    }
    if (_stpRootPolicyHandler) {
        document.getElementById('admin-stp-root-policy-form')?.removeEventListener('submit', _stpRootPolicyHandler);
        _stpRootPolicyHandler = null;
    }
    if (_monitoringHandler) {
        document.getElementById('admin-monitoring-form')?.removeEventListener('submit', _monitoringHandler);
        _monitoringHandler = null;
    }
    // Clear cached admin data to free memory
    adminState.capabilities = null;
    adminState.users = [];
    adminState.groups = [];
    adminState.loginRules = null;
    adminState.authConfig = null;
}

export { loadAdminSettings, destroySettings };

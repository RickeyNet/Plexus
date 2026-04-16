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
}
window.onCloudProviderFilterChange = onCloudProviderFilterChange;

async function onCloudAccountFilterChange() {
    await loadCloudTopology({ preserveContent: false });
}
window.onCloudAccountFilterChange = onCloudAccountFilterChange;

async function refreshCloudVisibility() {
    await loadCloudAccounts({ preserveContent: false });
    await loadCloudTopology({ preserveContent: false });
}
window.refreshCloudVisibility = refreshCloudVisibility;

export async function loadCloudVisibility({ preserveContent = false } = {}) {
    const accountsEl = document.getElementById('cloud-accounts-list');
    const topologyEl = document.getElementById('cloud-topology-summary');
    if (accountsEl && !preserveContent) accountsEl.innerHTML = skeletonCards(2);
    if (topologyEl && !preserveContent) topologyEl.innerHTML = skeletonCards(1);

    await _ensureProvidersLoaded();
    await loadCloudAccounts({ preserveContent });
    await loadCloudTopology({ preserveContent });
}

export function destroyCloudVisibility() {
    _cloudProviders = [];
    _cloudAccounts = [];
}

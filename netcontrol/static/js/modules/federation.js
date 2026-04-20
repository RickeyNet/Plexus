/**
 * Federation Module
 * Multi-instance federation peer management and overview dashboard
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

let _peers = [];
let _overview = null;

// ── Helpers ─────────────────────────────────────────────────────────────────

function _syncStatusBadge(status) {
    const s = String(status || 'never').toLowerCase();
    if (s === 'ok') return '<span class="badge badge-success">Synced</span>';
    if (s === 'error') return '<span class="badge badge-danger">Error</span>';
    return '<span class="badge badge-secondary">Never</span>';
}

function _enabledBadge(enabled) {
    return enabled
        ? '<span class="badge badge-success">Enabled</span>'
        : '<span class="badge badge-secondary">Disabled</span>';
}

// ── Overview Cards ──────────────────────────────────────────────────────────

function _renderOverview(container) {
    if (!_overview) {
        container.innerHTML = '<p class="text-muted">No overview data yet. Sync peers to see aggregated metrics.</p>';
        return;
    }
    const t = _overview.totals || {};
    container.innerHTML = `
        <div class="stats-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem;">
            <div class="stat-card">
                <div class="stat-value">${escapeHtml(String(t.total_peers || 0))}</div>
                <div class="stat-label">Total Peers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${escapeHtml(String(t.healthy_peers || 0))}</div>
                <div class="stat-label">Healthy Peers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${escapeHtml(String(t.total_devices || 0))}</div>
                <div class="stat-label">Total Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:var(--success-color)">${escapeHtml(String(t.devices_up || 0))}</div>
                <div class="stat-label">Devices Up</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:var(--danger-color)">${escapeHtml(String(t.devices_down || 0))}</div>
                <div class="stat-label">Devices Down</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:var(--warning-color)">${escapeHtml(String(t.total_alerts || 0))}</div>
                <div class="stat-label">Active Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:var(--danger-color)">${escapeHtml(String(t.critical_alerts || 0))}</div>
                <div class="stat-label">Critical Alerts</div>
            </div>
        </div>
    `;
}

// ── Peer Table ──────────────────────────────────────────────────────────────

function _renderPeerTable(container) {
    if (!_peers.length) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No federation peers configured.</p>
                <button class="btn btn-primary" onclick="document.dispatchEvent(new Event('federation:add-peer'))">Add Peer</button>
            </div>`;
        return;
    }
    const rows = _peers.map(p => `
        <tr>
            <td>${escapeHtml(p.name)}</td>
            <td><code>${escapeHtml(p.url)}</code></td>
            <td>${_enabledBadge(p.enabled)}</td>
            <td>${_syncStatusBadge(p.last_sync_status)}</td>
            <td>${p.last_sync_at ? escapeHtml(formatDate(p.last_sync_at)) : '<span class="text-muted">—</span>'}</td>
            <td>${p.has_token ? '<span class="badge badge-info">Yes</span>' : '<span class="text-muted">No</span>'}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-sm btn-secondary" data-action="test" data-id="${p.id}" title="Test Connection">Test</button>
                    <button class="btn btn-sm btn-primary" data-action="sync" data-id="${p.id}" title="Sync Now">Sync</button>
                    <button class="btn btn-sm btn-secondary" data-action="edit" data-id="${p.id}" title="Edit">Edit</button>
                    <button class="btn btn-sm btn-danger" data-action="delete" data-id="${p.id}" title="Delete">Del</button>
                </div>
            </td>
        </tr>
    `).join('');

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Sync</th>
                    <th>Last Synced</th>
                    <th>Token</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

// ── Peer Detail Cards (from overview data) ──────────────────────────────────

function _renderPeerDetails(container) {
    if (!_overview || !_overview.peers || !_overview.peers.length) {
        container.innerHTML = '';
        return;
    }
    const cards = _overview.peers.map(p => {
        const dev = p.devices || {};
        const alerts = p.alerts || {};
        const comp = p.compliance || {};
        return `
            <div class="card" style="padding:1rem;">
                <h4 style="margin:0 0 .5rem 0;">${escapeHtml(p.name)}</h4>
                <div class="text-muted" style="margin-bottom:.5rem;">${escapeHtml(p.url)}${p.version ? ` — v${escapeHtml(p.version)}` : ''}</div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.5rem;">
                    <div><strong>${escapeHtml(String(dev.total || 0))}</strong> devices</div>
                    <div style="color:var(--success-color)"><strong>${escapeHtml(String(dev.up || 0))}</strong> up</div>
                    <div style="color:var(--danger-color)"><strong>${escapeHtml(String(dev.down || 0))}</strong> down</div>
                    <div style="color:var(--warning-color)"><strong>${escapeHtml(String(alerts.active || 0))}</strong> alerts</div>
                    <div><strong>${escapeHtml(String(comp.total_profiles || 0))}</strong> profiles</div>
                </div>
                <div class="text-muted" style="margin-top:.5rem;font-size:.85em;">
                    ${_syncStatusBadge(p.last_sync_status)}
                    ${p.last_sync_at ? ' — ' + escapeHtml(formatDate(p.last_sync_at)) : ''}
                </div>
            </div>
        `;
    }).join('');
    container.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-top:1rem;">${cards}</div>`;
}

// ── Event Handlers ──────────────────────────────────────────────────────────

async function _handleTableAction(e) {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = Number(btn.dataset.id);

    if (action === 'test') {
        btn.disabled = true;
        btn.textContent = '...';
        try {
            const result = await api.testFederationPeer(id);
            if (result.status === 'ok') {
                showSuccess(`Connection OK — remote version: ${result.remote_version || 'unknown'}`);
            } else {
                showError(`Connection failed: ${result.message || 'Unknown error'}`);
            }
        } catch (err) {
            showError('Test failed');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Test';
        }
    } else if (action === 'sync') {
        btn.disabled = true;
        btn.textContent = '...';
        try {
            await api.syncFederationPeer(id);
            showSuccess('Sync complete');
            await _loadAll();
            _renderPage();
        } catch (err) {
            showError('Sync failed');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Sync';
        }
    } else if (action === 'edit') {
        const peer = _peers.find(p => p.id === id);
        if (peer) _showPeerForm(peer);
    } else if (action === 'delete') {
        const peer = _peers.find(p => p.id === id);
        showConfirm(
            `Delete peer "${peer ? peer.name : id}"?`,
            'This will remove the peer and all cached sync data.',
            async () => {
                try {
                    await api.deleteFederationPeer(id);
                    showSuccess('Peer deleted');
                    await _loadAll();
                    _renderPage();
                } catch (err) {
                    showError('Delete failed');
                }
            }
        );
    }
}

function _showPeerForm(existing = null) {
    const isEdit = !!existing;
    const fields = [
        { name: 'name', label: 'Name', type: 'text', required: true, value: existing?.name || '' },
        { name: 'url', label: 'URL', type: 'text', required: true, value: existing?.url || '', placeholder: 'https://plexus-remote.example.com' },
        { name: 'api_token', label: 'API Token', type: 'password', value: '', placeholder: isEdit ? '(unchanged if empty)' : '' },
        { name: 'description', label: 'Description', type: 'text', value: existing?.description || '' },
        { name: 'enabled', label: 'Enabled', type: 'checkbox', value: existing ? existing.enabled : true },
    ];

    showFormModal({
        title: isEdit ? 'Edit Federation Peer' : 'Add Federation Peer',
        fields,
        onSubmit: async (values) => {
            const body = {
                name: values.name,
                url: values.url,
                description: values.description || '',
                enabled: !!values.enabled,
            };
            // Only include token if provided (for edit, empty means unchanged)
            if (values.api_token) {
                body.api_token = values.api_token;
            } else if (!isEdit) {
                body.api_token = '';
            }
            try {
                if (isEdit) {
                    await api.updateFederationPeer(existing.id, body);
                    showSuccess('Peer updated');
                } else {
                    await api.createFederationPeer(body);
                    showSuccess('Peer added');
                }
                await _loadAll();
                _renderPage();
            } catch (err) {
                showError(isEdit ? 'Update failed' : 'Create failed');
            }
        },
    });
}

// ── Data Loading ────────────────────────────────────────────────────────────

async function _loadAll() {
    const [peers, overview] = await Promise.allSettled([
        api.getFederationPeers(),
        api.getFederationOverview(),
    ]);
    _peers = peers.status === 'fulfilled' && Array.isArray(peers.value) ? peers.value : [];
    _overview = overview.status === 'fulfilled' ? overview.value : null;
}

// ── Render ──────────────────────────────────────────────────────────────────

function _renderPage() {
    const page = document.getElementById('page-federation');
    if (!page) return;

    page.innerHTML = `
        <div class="page-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
            <h2>Federation Overview</h2>
            <button class="btn btn-primary" id="federation-add-btn">Add Peer</button>
        </div>
        <div id="federation-overview"></div>
        <h3 style="margin-top:1.5rem;">Registered Peers</h3>
        <div id="federation-peers-table"></div>
        <div id="federation-peer-details"></div>
    `;

    _renderOverview(document.getElementById('federation-overview'));
    _renderPeerTable(document.getElementById('federation-peers-table'));
    _renderPeerDetails(document.getElementById('federation-peer-details'));

    // Bind events
    document.getElementById('federation-add-btn')?.addEventListener('click', () => _showPeerForm());
    document.getElementById('federation-peers-table')?.addEventListener('click', _handleTableAction);
    document.addEventListener('federation:add-peer', () => _showPeerForm(), { once: true });
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function loadFederation({ preserveContent = false } = {}) {
    const page = document.getElementById('page-federation');
    if (!page) return;

    if (!preserveContent) {
        page.innerHTML = skeletonCards(3);
    }

    try {
        await _loadAll();
        _renderPage();
    } catch (err) {
        page.innerHTML = '<p class="text-danger">Failed to load federation data.</p>';
    }
}

export function destroyFederation() {
    _peers = [];
    _overview = null;
}

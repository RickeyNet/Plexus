/**
 * Configuration Module — Config Drift Detection + Config Backups
 * Lazy-loaded when user navigates to #configuration
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    showModal, closeAllModals, showConfirm, formatDate,
    skeletonCards, emptyStateHTML, debounce, navigateToPage,
    copyableCodeBlock, copyableHtmlBlock, initCopyableBlocks,
    invalidatePageCache, activateFocusTrap, deactivateFocusTrap,
    textMatch, formatRelativeTime, formatInterval
} from '../app.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Config Drift Detection
// ═══════════════════════════════════════════════════════════════════════════════

let _driftEventsCache = {};
let _activeWebSockets = [];

function _trackWs(ws) {
    _activeWebSockets.push(ws);
    const orig = ws.onclose;
    ws.addEventListener('close', () => {
        _activeWebSockets = _activeWebSockets.filter(w => w !== ws);
    });
    return ws;
}

function _closeAllWs() {
    for (const ws of _activeWebSockets) {
        try { ws.close(); } catch (e) { /* ignore */ }
    }
    _activeWebSockets = [];
}

// The shared job output modal lives in index.html and calls closeJobOutputModal().
// On the Configuration page, jobs.js may not be loaded yet, so provide a local fallback.
if (typeof window.closeJobOutputModal !== 'function') {
    window.closeJobOutputModal = function() {
        const modal = document.getElementById('job-output-modal');
        if (modal) modal.classList.remove('active');
        _closeAllWs();
        deactivateFocusTrap('job-output-modal');
    };
}

async function loadConfigDrift(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('drift-events-list');
    if (!preserveContent && container) {
        container.innerHTML = skeletonCards(3);
    }
    try {
        const [summary, events] = await Promise.all([
            api.getConfigDriftSummary(),
            api.getConfigDriftEvents(
                listViewState.configDrift.status !== 'all' ? listViewState.configDrift.status : null,
                null, 200
            ),
        ]);
        renderDriftSummary(summary);
        listViewState.configDrift.items = events || [];
        _driftEventsCache = {};
        (events || []).forEach(e => { _driftEventsCache[e.id] = e; });
        if (!events || !events.length) {
            if (container) container.innerHTML = emptyStateHTML(
                'No drift events detected', 'config-drift',
                '<button class="btn btn-primary btn-sm" onclick="showSetBaselineModal()">Set a Baseline</button>'
            );
            return;
        }
        renderDriftEventsList(applyDriftFilters());
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading drift data: ${escapeHtml(error.message)}</div>`;
    }
}

function renderDriftSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('drift-stat-baselined', summary.total_baselined ?? '-');
    set('drift-stat-compliant', summary.compliant ?? '-');
    set('drift-stat-drifted', summary.drifted ?? '-');
    set('drift-stat-open', summary.open_events ?? '-');
}

function applyDriftFilters() {
    const state = listViewState.configDrift;
    const query = (state.query || '').trim().toLowerCase();
    let filtered = state.items.filter(item => {
        const matchText = !query ||
            textMatch(item.hostname, query) ||
            textMatch(item.ip_address, query) ||
            textMatch(item.device_type, query);
        const matchStatus = !state.status || state.status === 'all' ||
            String(item.status || '').toLowerCase() === state.status;
        return matchText && matchStatus;
    });
    switch (state.sort) {
        case 'detected_asc':
            filtered.sort((a, b) => String(a.detected_at || '').localeCompare(String(b.detected_at || '')));
            break;
        case 'host_asc':
            filtered.sort((a, b) => String(a.hostname || '').localeCompare(String(b.hostname || '')));
            break;
        default: // detected_desc
            filtered.sort((a, b) => String(b.detected_at || '').localeCompare(String(a.detected_at || '')));
    }
    return filtered;
}

let _driftViewMode = 'grouped'; // 'grouped' or 'flat'

function _normalizeDiffForGrouping(diffText) {
    if (!diffText) return '';
    // Strip header lines (--- a/... +++ b/...) and hunk positions (@@ ... @@) that contain host-specific paths
    // Keep only the actual change lines and context for grouping
    return diffText.split('\n').filter(line =>
        !line.startsWith('---') && !line.startsWith('+++') && !line.startsWith('@@')
    ).join('\n').trim();
}

function _groupDriftEvents(events) {
    const groups = new Map();
    for (const ev of events) {
        const key = _normalizeDiffForGrouping(ev.diff_text || '');
        if (!groups.has(key)) {
            groups.set(key, { diff_text: ev.diff_text, diff_lines_added: ev.diff_lines_added, diff_lines_removed: ev.diff_lines_removed, events: [], representative_id: ev.id });
        }
        groups.get(key).events.push(ev);
    }
    return [...groups.values()].sort((a, b) => b.events.length - a.events.length);
}

function _renderDriftCard(ev, i) {
    const statusColor = ev.status === 'open' ? 'var(--danger, #ef5350)' :
        ev.status === 'accepted' ? 'var(--warning, #ffa726)' : 'var(--success, #66bb6a)';
    const detected = ev.detected_at ? new Date(ev.detected_at + 'Z').toLocaleString() : '';
    return `<div class="card drift-event-card animate-in" style="animation-delay:${Math.min(i * 0.04, 0.3)}s">
        <div class="drift-event-header">
            <div>
                <div class="card-title">${escapeHtml(ev.hostname || '')} <span style="color:var(--text-muted);font-weight:400;font-size:0.85rem">${escapeHtml(ev.ip_address || '')}</span></div>
                <div class="drift-event-meta">
                    <span>${escapeHtml(ev.device_type || '')}</span>
                    <span style="opacity:0.4">|</span>
                    <span>${detected}</span>
                </div>
            </div>
            <div style="display:flex;gap:0.5rem;align-items:center;">
                <div class="drift-diff-stats">
                    <span class="drift-diff-added">+${ev.diff_lines_added || 0}</span>
                    <span class="drift-diff-removed">-${ev.diff_lines_removed || 0}</span>
                </div>
                <button class="btn btn-sm" style="background:${statusColor};color:#fff;padding:0.15rem 0.5rem;border-radius:0.25rem;font-size:0.7rem;font-weight:600;text-transform:uppercase;cursor:pointer;border:none;" onclick="showDriftDiffModal(${ev.id})">${escapeHtml(ev.status)}</button>
            </div>
        </div>
        <div style="margin-top:0.75rem;display:flex;gap:0.35rem;flex-wrap:wrap">
            <button class="btn btn-sm btn-secondary" onclick="showDriftDiffModal(${ev.id})">View Diff</button>
            <button class="btn btn-sm btn-secondary" onclick="showDriftEventHistory(${ev.id})">Event Log</button>
            <button class="btn btn-sm btn-secondary" onclick="showHostDriftHistory(${ev.host_id})">Snapshots</button>
            ${ev.status === 'open' ? `
                <button class="btn btn-sm btn-primary" onclick="acceptDriftEvent(${ev.id})">Accept</button>
                <button class="btn btn-sm btn-danger" onclick="showRevertDriftModal(${ev.id})">Revert</button>
                <button class="btn btn-sm btn-secondary" onclick="resolveDriftEvent(${ev.id})">Resolve</button>
            ` : ''}
        </div>
    </div>`;
}

function renderDriftEventsList(events) {
    const container = document.getElementById('drift-events-list');
    if (!container) return;
    if (!events.length) {
        container.innerHTML = '<div class="card" style="text-align:center;color:var(--text-muted);padding:2rem;">No matching drift events.</div>';
        return;
    }

    const openIds = events.filter(e => e.status === 'open').map(e => e.id);
    const openCount = openIds.length;
    const groups = _groupDriftEvents(events);

    // Toolbar: bulk actions + view toggle
    let toolbar = '<div style="margin-bottom:0.75rem;display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;justify-content:space-between">';
    toolbar += '<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">';
    if (openCount > 1) {
        toolbar += `<button class="btn btn-sm btn-primary" onclick="bulkAcceptDriftEvents([${openIds.join(',')}])">Accept All Open (${openCount})</button>`;
        toolbar += `<button class="btn btn-sm btn-secondary" onclick="bulkResolveDriftEvents([${openIds.join(',')}])">Resolve All Open (${openCount})</button>`;
    }
    toolbar += '</div>';
    const groupedActive = _driftViewMode === 'grouped' ? 'btn-primary' : 'btn-secondary';
    const flatActive = _driftViewMode === 'flat' ? 'btn-primary' : 'btn-secondary';
    toolbar += `<div style="display:flex;gap:0.25rem;align-items:center;">
        <button class="btn btn-sm ${groupedActive}" onclick="setDriftViewMode('grouped')" title="Group similar changes">Grouped</button>
        <button class="btn btn-sm ${flatActive}" onclick="setDriftViewMode('flat')" title="Show individual events">Flat</button>
    </div>`;
    toolbar += '</div>';

    if (_driftViewMode === 'grouped') {
        // Grouped view
        container.innerHTML = toolbar + groups.map((group, gi) => {
            const evs = group.events;
            const openInGroup = evs.filter(e => e.status === 'open').map(e => e.id);
            const hasDiff = group.diff_text != null && group.diff_text !== '';
            const diffHtml = hasDiff ? _renderUnifiedDiff(group.diff_text) : '';
            const hostList = evs.map(e =>
                `<span style="display:inline-flex;align-items:center;gap:0.25rem;background:var(--bg-secondary);padding:0.15rem 0.5rem;border-radius:0.25rem;font-size:0.85rem;">
                    ${escapeHtml(e.hostname || '')}
                    <span style="color:var(--text-muted);font-size:0.8em">${escapeHtml(e.ip_address || '')}</span>
                    <span style="color:${e.status === 'open' ? 'var(--danger)' : e.status === 'accepted' ? 'var(--warning)' : 'var(--success)'};font-size:0.7em;font-weight:600;text-transform:uppercase;">${escapeHtml(e.status)}</span>
                </span>`
            ).join(' ');
            const groupTitle = evs.length > 1
                ? `${evs.length} devices with identical changes`
                : `${escapeHtml(evs[0].hostname || '')} <span style="color:var(--text-muted);font-weight:400;font-size:0.85rem">${escapeHtml(evs[0].ip_address || '')}</span>`;

            return `<div class="card animate-in" style="animation-delay:${Math.min(gi * 0.06, 0.3)}s">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:0.5rem;">
                    <div>
                        <div class="card-title" style="font-size:1rem;">${groupTitle}</div>
                        <div class="drift-diff-stats" style="margin-top:0.25rem;">
                            <span class="drift-diff-added">+${group.diff_lines_added || 0}</span>
                            <span class="drift-diff-removed">-${group.diff_lines_removed || 0}</span>
                        </div>
                    </div>
                    <div style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                        ${openInGroup.length > 1 ? `
                            <button class="btn btn-sm btn-primary" onclick="bulkAcceptDriftEvents([${openInGroup.join(',')}])">Accept Group (${openInGroup.length})</button>
                            <button class="btn btn-sm btn-secondary" onclick="bulkResolveDriftEvents([${openInGroup.join(',')}])">Resolve Group</button>
                        ` : ''}
                        ${openInGroup.length === 1 ? `
                            <button class="btn btn-sm btn-primary" onclick="acceptDriftEvent(${openInGroup[0]})">Accept</button>
                            <button class="btn btn-sm btn-secondary" onclick="resolveDriftEvent(${openInGroup[0]})">Resolve</button>
                        ` : ''}
                    </div>
                </div>
                ${evs.length > 1 ? `<div style="margin:0.75rem 0;display:flex;flex-wrap:wrap;gap:0.35rem;">${hostList}</div>` : ''}
                <details class="drift-group-diff" data-representative-id="${group.representative_id}" style="margin-top:0.5rem;">
                    <summary style="cursor:pointer;color:var(--primary);font-size:0.9rem;font-weight:500;user-select:none;">View Diff</summary>
                    <pre class="drift-diff-block" ${hasDiff ? 'data-loaded="1"' : ''} style="margin-top:0.5rem;max-height:400px;overflow:auto;padding:0.75rem;background:var(--bg-primary);border:1px solid var(--border);border-radius:0.375rem;font-size:0.8rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;">${hasDiff ? diffHtml : '<span style="color:var(--text-muted)">Loading...</span>'}</pre>
                </details>
                ${evs.length > 1 ? `<details style="margin-top:0.35rem;">
                    <summary style="cursor:pointer;color:var(--text-muted);font-size:0.85rem;user-select:none;">Show individual devices (${evs.length})</summary>
                    <div style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.35rem;">
                        ${evs.map((ev, i) => _renderDriftCard(ev, i)).join('')}
                    </div>
                </details>` : ''}
            </div>`;
        }).join('');
        // Lazy-load diffs on expand for groups where diff_text was not in the list response
        container.querySelectorAll('details.drift-group-diff').forEach(det => {
            det.addEventListener('toggle', async function handler() {
                if (!det.open) return;
                const pre = det.querySelector('pre');
                if (pre.dataset.loaded) return;
                const repId = det.dataset.representativeId;
                if (!repId) return;
                try {
                    const ev = await api.getConfigDriftEvent(parseInt(repId));
                    if (ev && ev.diff_text) {
                        pre.innerHTML = _renderUnifiedDiff(ev.diff_text);
                    } else {
                        pre.innerHTML = '<span style="color:var(--text-muted)">No differences recorded.</span>';
                    }
                } catch (err) {
                    pre.innerHTML = `<span style="color:var(--danger)">Failed to load diff: ${escapeHtml(err.message)}</span>`;
                }
                pre.dataset.loaded = '1';
            });
        });
    } else {
        // Flat view (original)
        container.innerHTML = toolbar + events.map((ev, i) => _renderDriftCard(ev, i)).join('');
    }
}

window.showDriftDiffModal = async function(eventId) {
    try {
        const ev = await api.getConfigDriftEvent(eventId);
        if (!ev) { showError('Drift event not found'); return; }
        const diffHtml = _renderUnifiedDiff(ev.diff_text || '');
        showModal('Configuration Diff — ' + escapeHtml(ev.hostname || ''), `
            <div class="drift-event-meta" style="margin-bottom:0.75rem">
                <span>${escapeHtml(ev.ip_address || '')}</span>
                <span style="opacity:0.4">|</span>
                <span>Detected: ${ev.detected_at ? new Date(ev.detected_at + 'Z').toLocaleString() : ''}</span>
                <span style="opacity:0.4">|</span>
                <span class="drift-diff-added">+${ev.diff_lines_added || 0}</span>
                <span class="drift-diff-removed">-${ev.diff_lines_removed || 0}</span>
            </div>
            ${copyableHtmlBlock(diffHtml, ev.diff_text || '', { className: 'drift-diff-viewer' })}
            <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1rem">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                <button class="btn btn-secondary" onclick="closeAllModals();showDriftEventHistory(${eventId})">Event Log</button>
                ${ev.status === 'open' ? `
                    <button class="btn btn-primary" onclick="acceptDriftEvent(${eventId});closeAllModals()">Accept</button>
                    <button class="btn btn-danger" onclick="closeAllModals();showRevertDriftModal(${eventId})">Revert</button>
                    <button class="btn btn-secondary" onclick="resolveDriftEvent(${eventId});closeAllModals()">Resolve</button>
                ` : ''}
            </div>
        `);
        initCopyableBlocks();
    } catch (err) {
        showError('Failed to load drift details: ' + err.message);
    }
};

window.showDriftEventHistory = async function(eventId) {
    try {
        const [ev, history] = await Promise.all([
            api.getConfigDriftEvent(eventId),
            api.getConfigDriftEventHistory(eventId, 500),
        ]);
        if (!ev) {
            showError('Drift event not found');
            return;
        }

        const rows = (history || []).map((item) => {
            const when = item.created_at ? new Date(item.created_at + 'Z').toLocaleString() : '-';
            const actor = escapeHtml(item.actor || 'system');
            const action = escapeHtml(item.action || '');
            const fromStatus = escapeHtml(item.from_status || '-');
            const toStatus = escapeHtml(item.to_status || '-');
            const details = escapeHtml(item.details || '');
            return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem;">
                <div style="display:flex; justify-content:space-between; gap:0.5rem; flex-wrap:wrap;">
                    <strong>${action}</strong>
                    <span style="font-size:0.85em; color:var(--text-muted)">${when}</span>
                </div>
                <div style="margin-top:0.35rem; font-size:0.85em; color:var(--text-muted);">
                    Actor: ${actor} &bull; Status: ${fromStatus} → ${toStatus}
                </div>
                ${details ? `<div style="margin-top:0.35rem; font-size:0.85em;">${details}</div>` : ''}
            </div>`;
        }).join('');

        showModal(`Drift Event Log — ${escapeHtml(ev.hostname || ev.ip_address || '')}`, `
            <div class="drift-event-meta" style="margin-bottom:0.75rem">
                <span>Event ID: ${ev.id}</span>
                <span style="opacity:0.4">|</span>
                <span>Current Status: ${escapeHtml(ev.status || '')}</span>
                <span style="opacity:0.4">|</span>
                <span>Detected: ${ev.detected_at ? new Date(ev.detected_at + 'Z').toLocaleString() : ''}</span>
            </div>
            <div style="max-height:60vh; overflow:auto;">
                ${rows || '<div class="card" style="text-align:center;color:var(--text-muted);padding:1rem;">No history entries recorded yet.</div>'}
            </div>
            <div style="display:flex; justify-content:flex-end; margin-top:0.75rem;">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
    } catch (err) {
        showError('Failed to load event history: ' + err.message);
    }
};

function _renderUnifiedDiff(diffText) {
    if (!diffText) return '<span style="color:var(--text-muted)">No differences.</span>';
    return diffText.split('\n').map(line => {
        const esc = escapeHtml(line);
        if (line.startsWith('+++') || line.startsWith('---')) return `<span class="diff-meta">${esc}</span>`;
        if (line.startsWith('@@')) return `<span class="diff-hunk">${esc}</span>`;
        if (line.startsWith('+')) return `<span class="diff-added">${esc}</span>`;
        if (line.startsWith('-')) return `<span class="diff-removed">${esc}</span>`;
        return `<span class="diff-context">${esc}</span>`;
    }).join('\n');
}

window.showSetBaselineModal = async function() {
    let hostsOptions = '<option value="">Select a host...</option>';
    try {
        const groups = await api.getInventoryGroups(true);
        for (const g of (groups || [])) {
            for (const h of (g.hosts || [])) {
                hostsOptions += `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`;
            }
        }
    } catch (e) { /* ignore */ }
    showModal('Set Configuration Baseline', `
        <form onsubmit="createBaseline(event)">
            <div class="form-group">
                <label class="form-label">Host</label>
                <select class="form-select" name="host_id" required>${hostsOptions}</select>
            </div>
            <div class="form-group">
                <label class="form-label">Baseline Name</label>
                <input type="text" class="form-input" name="name" placeholder="e.g. Golden Config v1.0">
            </div>
            <div class="form-group">
                <label class="form-label">Intended Configuration</label>
                <textarea class="form-textarea drift-baseline-textarea" name="config_text" placeholder="Paste the intended/golden running-config here..." required></textarea>
            </div>
            <div style="display:flex;gap:0.5rem;justify-content:space-between;margin-top:1rem;flex-wrap:wrap">
                <button type="button" class="btn btn-secondary btn-sm" onclick="_fillFromLatestSnapshot()">Use Latest Snapshot</button>
                <div style="display:flex;gap:0.5rem">
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Baseline</button>
                </div>
            </div>
        </form>
    `);
};

window._fillFromLatestSnapshot = async function() {
    const hostSelect = document.querySelector('#modal-overlay select[name="host_id"]');
    const textarea = document.querySelector('#modal-overlay textarea[name="config_text"]');
    if (!hostSelect || !textarea || !hostSelect.value) {
        showError('Please select a host first');
        return;
    }
    try {
        const snapshots = await api.getConfigSnapshots(parseInt(hostSelect.value), 1);
        if (!snapshots || !snapshots.length) {
            showError('No snapshots available for this host. Capture a config first.');
            return;
        }
        const snap = await api.getConfigSnapshot(snapshots[0].id);
        if (snap && snap.config_text) {
            textarea.value = snap.config_text;
            showSuccess('Loaded latest snapshot config');
        }
    } catch (err) {
        showError('Failed to load snapshot: ' + err.message);
    }
};

window.createBaseline = async function(e) {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
        await api.createConfigBaseline({
            host_id: parseInt(fd.get('host_id')),
            name: fd.get('name') || '',
            config_text: fd.get('config_text'),
            source: 'manual',
        });
        closeAllModals();
        showSuccess('Baseline saved successfully');
        invalidatePageCache('configuration');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Failed to save baseline: ' + err.message);
    }
};

window.showCaptureSnapshotModal = async function() {
    let hostsOptions = '<option value="">Select a host...</option>';
    let groupOptions = '<option value="">-- Or select entire group --</option>';
    let credOptions = '<option value="">Select credentials...</option>';
    try {
        const [groups, creds] = await Promise.all([
            api.getInventoryGroups(true),
            api.getCredentials(),
        ]);
        for (const g of (groups || [])) {
            groupOptions += `<option value="${g.id}">${escapeHtml(g.name)} (${(g.hosts || []).length} hosts)</option>`;
            for (const h of (g.hosts || [])) {
                hostsOptions += `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`;
            }
        }
        for (const c of (creds || [])) {
            credOptions += `<option value="${c.id}">${escapeHtml(c.name)}</option>`;
        }
    } catch (e) { /* ignore */ }
    showModal('Capture Running Config', `
        <form onsubmit="captureSnapshot(event)">
            <div class="form-group">
                <label class="form-label">Single Host</label>
                <select class="form-select" name="host_id">${hostsOptions}</select>
            </div>
            <div class="form-group">
                <label class="form-label">Or Entire Group</label>
                <select class="form-select" name="group_id">${groupOptions}</select>
            </div>
            <div class="form-group">
                <label class="form-label">Credentials</label>
                <select class="form-select" name="credential_id" required>${credOptions}</select>
            </div>
            <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1rem">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Capture</button>
            </div>
        </form>
    `);
};

window.captureSnapshot = async function(e) {
    e.preventDefault();
    const fd = new FormData(e.target);
    const credId = parseInt(fd.get('credential_id'));
    const hostId = fd.get('host_id') ? parseInt(fd.get('host_id')) : null;
    const groupId = fd.get('group_id') ? parseInt(fd.get('group_id')) : null;
    if (!hostId && !groupId) {
        showError('Please select a host or group');
        return;
    }
    closeAllModals();

    try {
        // Start background capture job and get job_id
        let result;
        if (groupId) {
            result = await api.startCaptureJob(groupId, credId);
        } else {
            result = await api.startCaptureSingleJob(hostId, credId);
        }
        const jobId = result.job_id;

        // Open job output modal with live streaming
        const modal = document.getElementById('job-output-modal');
        const output = document.getElementById('job-output');
        output.innerHTML = '';
        modal.classList.add('active');
        activateFocusTrap('job-output-modal');

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = _trackWs(new WebSocket(`${protocol}//${window.location.host}/ws/config-capture/${jobId}`));

        ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                if (msg.type === 'line') {
                    const line = document.createElement('div');
                    line.className = 'job-output-line';
                    // Color code success/failure lines
                    if (msg.text.includes('\u2713')) line.className += ' success';
                    else if (msg.text.includes('\u2717') || msg.text.includes('FAILED')) line.className += ' error';
                    else if (msg.text.includes('Connecting')) line.className += ' info';
                    line.textContent = msg.text.replace(/\n$/, '');
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                } else if (msg.type === 'job_complete') {
                    const line = document.createElement('div');
                    line.className = 'job-output-line success';
                    line.textContent = `\n[Capture Job Complete] Status: ${msg.status}`;
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                    ws.close();
                    // Refresh the config drift list
                    invalidatePageCache('configuration');
                    loadConfigDrift({ preserveContent: false });
                }
            } catch (err) {
                console.error('Error parsing capture WebSocket message:', err);
            }
        };

        ws.onerror = () => {
            const line = document.createElement('div');
            line.className = 'job-output-line error';
            line.textContent = '[Error] WebSocket connection failed';
            output.appendChild(line);
        };

    } catch (err) {
        showError('Capture failed: ' + err.message);
    }
};

window.acceptDriftEvent = async function(eventId) {
    try {
        await api.updateConfigDriftEventStatus(eventId, 'accepted');
        showSuccess('Drift accepted — baseline updated to match current config');
        invalidatePageCache('configuration');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Failed to accept: ' + err.message);
    }
};

window.resolveDriftEvent = async function(eventId) {
    try {
        await api.updateConfigDriftEventStatus(eventId, 'resolved');
        showSuccess('Drift event resolved');
        invalidatePageCache('configuration');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Failed to resolve: ' + err.message);
    }
};

window.setDriftViewMode = function(mode) {
    _driftViewMode = mode;
    renderDriftEventsList(applyDriftFilters());
};

window.bulkAcceptDriftEvents = async function(eventIds) {
    try {
        const result = await api.bulkAcceptDriftEvents(eventIds);
        showSuccess(`${result.accepted} drift event(s) accepted — baselines updated`);
        invalidatePageCache('configuration');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Bulk accept failed: ' + err.message);
    }
};

window.bulkResolveDriftEvents = async function(eventIds) {
    try {
        let resolved = 0;
        for (const id of eventIds) {
            await api.updateConfigDriftEventStatus(id, 'resolved');
            resolved++;
        }
        showSuccess(`${resolved} drift event(s) resolved`);
        invalidatePageCache('configuration');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Bulk resolve failed: ' + err.message);
    }
};

window.showRevertDriftModal = async function(eventId) {
    const creds = await api.getCredentials();
    if (!creds || !creds.length) {
        showError('No credentials configured. Add credentials first.');
        return;
    }
    const credOptions = creds.map(c => `<option value="${c.id}">${escapeHtml(c.name)} (${escapeHtml(c.username)})</option>`).join('');
    showModal('Revert Device to Baseline', `
        <p style="margin-bottom:1rem;color:var(--text-muted);">This will push the baseline configuration back to the device, overwriting any unauthorized changes. The device will be re-captured afterward to verify compliance.</p>
        <form id="revert-drift-form">
            <input type="hidden" name="event_id" value="${eventId}">
            <div class="form-group" style="margin-bottom:1rem;">
                <label class="form-label">SSH Credential</label>
                <select name="credential_id" class="form-select" required>${credOptions}</select>
            </div>
            <div style="display:flex;gap:0.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-danger">Revert Device</button>
            </div>
        </form>
    `);
    document.getElementById('revert-drift-form').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const evId = parseInt(fd.get('event_id'));
        const credId = parseInt(fd.get('credential_id'));
        closeAllModals();
        try {
            const result = await api.revertDriftEvent(evId, credId);
            const jobId = result.job_id;
            // Open job output modal with WebSocket
            const modal = document.getElementById('job-output-modal');
            const output = document.getElementById('job-output');
            output.innerHTML = '';
            modal.classList.add('active');
            activateFocusTrap('job-output-modal');
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = _trackWs(new WebSocket(`${protocol}//${window.location.host}/ws/config-revert/${jobId}`));
            ws.onmessage = (ev) => {
                const data = JSON.parse(ev.data);
                if (data.type === 'line') {
                    const span = document.createElement('span');
                    span.textContent = data.data;
                    if (data.data.includes('FAILED')) span.style.color = 'var(--danger, #ef5350)';
                    else if (data.data.includes('successfully') || data.data.includes('compliant') || data.data.includes('complete'))
                        span.style.color = 'var(--success, #66bb6a)';
                    output.appendChild(span);
                    output.scrollTop = output.scrollHeight;
                } else if (data.type === 'job_complete') {
                    const done = document.createElement('div');
                    done.style.cssText = 'margin-top:0.5rem;padding:0.5rem;font-weight:600;';
                    done.style.color = data.status === 'completed' ? 'var(--success)' : 'var(--danger)';
                    done.textContent = data.status === 'completed' ? 'Revert completed.' : 'Revert failed.';
                    output.appendChild(done);
                    output.scrollTop = output.scrollHeight;
                    invalidatePageCache('configuration');
                    loadConfigDrift({ preserveContent: false });
                }
            };
            ws.onerror = () => {
                const err = document.createElement('div');
                err.style.color = 'var(--danger)';
                err.textContent = 'WebSocket connection error.';
                output.appendChild(err);
            };
        } catch (err) {
            showError('Revert failed: ' + err.message);
        }
    };
};

window.showHostDriftHistory = async function(hostId) {
    try {
        const snapshots = await api.getConfigSnapshots(hostId, 20);
        if (!snapshots || !snapshots.length) {
            showModal('Config History', '<div style="text-align:center;color:var(--text-muted);padding:2rem;">No snapshots found for this host.</div>');
            return;
        }
        const rows = snapshots.map(s => `
            <div class="card" style="margin-bottom:0.5rem;padding:0.75rem">
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <div>
                        <strong>${s.captured_at ? new Date(s.captured_at + 'Z').toLocaleString() : ''}</strong>
                        <span style="color:var(--text-muted);margin-left:0.5rem;font-size:0.8rem">${escapeHtml(s.capture_method || '')}</span>
                    </div>
                    <div style="display:flex;gap:0.25rem">
                        <button class="btn btn-sm btn-secondary" onclick="viewSnapshotConfig(${s.id})">View</button>
                    </div>
                </div>
                <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">${s.config_length || 0} chars</div>
            </div>
        `).join('');
        showModal('Config Snapshots', `
            <div style="max-height:60vh;overflow-y:auto">${rows}</div>
            <div style="display:flex;justify-content:flex-end;margin-top:1rem">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
    } catch (err) {
        showError('Failed to load history: ' + err.message);
    }
};

window.viewSnapshotConfig = async function(snapshotId) {
    try {
        const snap = await api.getConfigSnapshot(snapshotId);
        if (!snap) { showError('Snapshot not found'); return; }
        showModal('Snapshot Config', `
            <div class="drift-event-meta" style="margin-bottom:0.75rem">
                <span>Captured: ${snap.captured_at ? new Date(snap.captured_at + 'Z').toLocaleString() : ''}</span>
                <span style="opacity:0.4">|</span>
                <span>Method: ${escapeHtml(snap.capture_method || '')}</span>
            </div>
            ${copyableCodeBlock(snap.config_text || '', { style: 'max-height:400px; overflow:auto; font-size:0.8em; white-space:pre-wrap' })}
            <div style="display:flex;justify-content:flex-end;margin-top:1rem">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
        initCopyableBlocks();
    } catch (err) {
        showError('Failed to load snapshot: ' + err.message);
    }
};

window.refreshConfigDrift = async function() {
    invalidatePageCache('configuration');
    await loadConfigDrift({ preserveContent: false });
};

function _getConfigBackupSearchState() {
    if (!listViewState.configBackups.search) {
        listViewState.configBackups.search = {
            query: '',
            mode: 'fulltext',
            limit: 50,
            contextLines: 1,
            results: [],
            hasMore: false,
            searched: false,
            searching: false,
            activeMode: 'fulltext',
        };
    }
    return listViewState.configBackups.search;
}

function _getConfigBackupSearchModeUx(mode) {
    switch ((mode || '').toLowerCase()) {
        case 'substring':
            return {
                placeholder: 'e.g. ip access-list standard',
                example: 'Example: exact text substring like "ip access-list standard"',
            };
        case 'regex':
            return {
                placeholder: 'e.g. ^snmp-server community\\s+\\w+\\s+RO$',
                example: 'Example regex: ^snmp-server community\\s+\\w+\\s+RO$',
            };
        case 'fulltext':
        default:
            return {
                placeholder: 'e.g. snmp-server community public',
                example: 'Example: keyword search like "snmp server public"',
            };
    }
}

function _applyConfigBackupSearchModeUx(mode) {
    const queryInput = document.getElementById('config-backup-search-query');
    const exampleEl = document.getElementById('config-backup-search-example');
    const ux = _getConfigBackupSearchModeUx(mode);
    if (queryInput) {
        queryInput.placeholder = ux.placeholder;
    }
    if (exampleEl) {
        exampleEl.textContent = ux.example;
    }
}

function _setConfigurationSearchInputState(tab) {
    const searchInput = document.getElementById('configuration-search');
    if (!searchInput) return;
    if (tab === 'search') {
        searchInput.disabled = true;
        searchInput.placeholder = 'Use Config Search controls';
        return;
    }
    searchInput.disabled = false;
    searchInput.placeholder = 'Search...';
}

function _bindConfigurationSearchInput() {
    const searchInput = document.getElementById('configuration-search');
    if (!searchInput || searchInput.dataset.bound === '1') return;
    searchInput.dataset.bound = '1';
    searchInput.addEventListener('input', debounce(() => {
        if (searchInput.disabled) return;
        const q = searchInput.value;
        const tab = listViewState.configuration.tab;
        if (tab === 'drift') {
            listViewState.configDrift.query = q;
            renderDriftEventsList(applyDriftFilters());
            return;
        }
        listViewState.configBackups.query = q;
        renderBackupPolicies(listViewState.configBackups.policies);
        renderBackupHistory(listViewState.configBackups.backups);
    }, 200));
}

function _bindConfigBackupSearchControls() {
    const queryInput = document.getElementById('config-backup-search-query');
    const modeSelect = document.getElementById('config-backup-search-mode');
    const limitInput = document.getElementById('config-backup-search-limit');
    const searchBtn = document.getElementById('config-backup-search-btn');
    if (!queryInput || !modeSelect || !limitInput || !searchBtn) return;

    const state = _getConfigBackupSearchState();
    queryInput.value = state.query || '';
    modeSelect.value = state.mode || 'fulltext';
    limitInput.value = String(state.limit || 50);
    _applyConfigBackupSearchModeUx(modeSelect.value || state.mode || 'fulltext');

    if (queryInput.dataset.bound === '1') return;
    queryInput.dataset.bound = '1';

    queryInput.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        runConfigBackupSearch();
    });
    modeSelect.addEventListener('change', () => {
        state.mode = modeSelect.value || 'fulltext';
        _applyConfigBackupSearchModeUx(state.mode);
    });
    limitInput.addEventListener('change', () => {
        let parsed = parseInt(limitInput.value || '50', 10);
        if (!Number.isFinite(parsed)) parsed = 50;
        state.limit = Math.max(1, Math.min(200, parsed));
        limitInput.value = String(state.limit);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration Page Tab Switching
// ═══════════════════════════════════════════════════════════════════════════════

window.switchConfigurationTab = function(tab) {
    const selected = ['drift', 'policies', 'history', 'search'].includes(tab) ? tab : 'drift';
    listViewState.configuration.tab = selected;
    document.querySelectorAll('.config-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-config-tab') === selected));
    document.querySelectorAll('.config-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`config-tab-${selected}`);
    if (target) target.style.display = '';
    _setConfigurationSearchInputState(selected);
    if (selected === 'search') {
        _bindConfigBackupSearchControls();
        renderConfigBackupSearchResults();
    }
};

window.refreshConfiguration = async function() {
    invalidatePageCache('configuration');
    await loadConfigDrift({ preserveContent: false });
    await loadConfigBackups({ preserveContent: false });
};

// ═══════════════════════════════════════════════════════════════════════════════
// Config Backups
// ═══════════════════════════════════════════════════════════════════════════════

let _backupCurrentTab = 'policies';

async function loadConfigBackups(options = {}) {
    const { preserveContent = false } = options;
    const policiesContainer = document.getElementById('backup-policies-list');
    if (!preserveContent && policiesContainer) policiesContainer.innerHTML = skeletonCards(2);
    _bindConfigurationSearchInput();
    _bindConfigBackupSearchControls();
    try {
        const [summary, policies, backups] = await Promise.all([
            api.getConfigBackupSummary(),
            api.getConfigBackupPolicies(),
            api.getConfigBackups(),
        ]);
        renderBackupSummary(summary);
        listViewState.configBackups.policies = policies || [];
        listViewState.configBackups.backups = backups || [];
        renderBackupPolicies(policies || []);
        renderBackupHistory(backups || []);
    } catch (error) {
        if (policiesContainer) policiesContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error loading backup data: ${escapeHtml(error.message)}</div>`;
    } finally {
        window.switchConfigurationTab(listViewState.configuration.tab || 'drift');
        renderConfigBackupSearchResults();
    }
}
window.loadConfigBackups = loadConfigBackups;

function renderBackupSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('backup-stat-policies', summary.total_policies ?? '-');
    set('backup-stat-backups', summary.total_backups ?? '-');
    set('backup-stat-hosts', summary.hosts_backed_up ?? '-');
    set('backup-stat-last', summary.last_backup_at ? formatRelativeTime(new Date(summary.last_backup_at + 'Z')) : 'Never');
}

function renderBackupPolicies(policies) {
    const container = document.getElementById('backup-policies-list');
    if (!container) return;
    const query = (listViewState.configBackups.query || '').toLowerCase();
    const filtered = policies.filter(p => !query || p.name.toLowerCase().includes(query) || (p.group_name || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No backup policies', 'config-backups',
            '<button class="btn btn-primary btn-sm" onclick="showCreateBackupPolicyModal()">Create a Policy</button>');
        return;
    }
    container.innerHTML = filtered.map(p => {
        const enabled = p.enabled ? '<span style="color:var(--success)">Enabled</span>' : '<span style="color:var(--text-muted)">Disabled</span>';
        const interval = formatInterval(p.interval_seconds);
        const lastRun = p.last_run_at ? new Date(p.last_run_at + 'Z').toLocaleString() : 'Never';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(p.name)}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">Group: ${escapeHtml(p.group_name || '?')} (${p.host_count || 0} hosts)</span>
                </div>
                <div style="display:flex; gap:0.5rem; align-items:center;">
                    ${enabled}
                    <button class="btn btn-sm btn-secondary" data-run-policy="${p.id}" onclick="runBackupPolicyNow(${p.id})"${_runningBackupPolicies.has(p.id) ? ' disabled' : ''}>${_runningBackupPolicies.has(p.id) ? '<span class="backup-spinner"></span> Running\u2026' : 'Run Now'}</button>
                    <button class="btn btn-sm btn-secondary" onclick="showEditBackupPolicyModal(${p.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeleteBackupPolicy(${p.id}, '${escapeHtml(p.name)}')">Delete</button>
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                Interval: ${interval} &bull; Retention: ${p.retention_days}d &bull; Last Run: ${lastRun}
            </div>
        </div>`;
    }).join('');
}

function renderBackupHistory(backups) {
    const container = document.getElementById('backup-history-list');
    if (!container) return;
    const query = (listViewState.configBackups.query || '').toLowerCase();
    const filtered = backups.filter(b => !query || (b.hostname || '').toLowerCase().includes(query) || (b.ip_address || '').toLowerCase().includes(query));
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No backups yet', 'config-backups');
        return;
    }
    container.innerHTML = filtered.map(b => {
        const statusColor = b.status === 'success' ? 'var(--success)' : 'var(--danger)';
        const time = new Date(b.captured_at + 'Z').toLocaleString();
        const size = b.config_length ? `${(b.config_length / 1024).toFixed(1)} KB` : '-';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(b.hostname || b.ip_address || '?')}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">${b.ip_address || ''}</span>
                </div>
                <div style="display:flex; gap:0.5rem; align-items:center;">
                    <span style="color:${statusColor}; font-size:0.85em;">${b.status}</span>
                    <button class="btn btn-sm btn-secondary" onclick="viewBackupDetail(${b.id})">View</button>
                    ${b.status === 'success' ? `<button class="btn btn-sm btn-secondary" onclick="viewBackupDiff(${b.id})">Diff</button>` : ''}
                    <button class="btn btn-sm btn-secondary" onclick="showRestoreBackupModal(${b.id})">Restore</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeleteBackup(${b.id})">Delete</button>
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                ${time} &bull; ${b.capture_method} &bull; ${size}
                ${b.error_message ? ' &bull; <span style="color:var(--danger)">' + escapeHtml(b.error_message) + '</span>' : ''}
            </div>
        </div>`;
    }).join('');
}

function _renderConfigBackupSearchContext(result) {
    const beforeLines = Array.isArray(result.context_before_lines) ? result.context_before_lines : [];
    const afterLines = Array.isArray(result.context_after_lines) ? result.context_after_lines : [];
    const lineNum = Number(result.match_line_number || 0);

    const rows = [];
    const beforeStart = lineNum > 0 ? (lineNum - beforeLines.length) : 0;
    beforeLines.forEach((line, idx) => {
        const num = beforeStart > 0 ? `${beforeStart + idx}` : '';
        rows.push(`<span class="diff-context">${num ? `${num}: ` : ''}${escapeHtml(line || '')}</span>`);
    });
    rows.push(`<span class="diff-hunk">${lineNum ? `${lineNum}: ` : ''}${escapeHtml(result.match_line || '')}</span>`);
    afterLines.forEach((line, idx) => {
        const num = lineNum > 0 ? `${lineNum + idx + 1}` : '';
        rows.push(`<span class="diff-context">${num ? `${num}: ` : ''}${escapeHtml(line || '')}</span>`);
    });
    return `<pre class="drift-diff-viewer" style="max-height:220px; overflow:auto; margin-top:0.75rem;">${rows.join('\n')}</pre>`;
}

function renderConfigBackupSearchResults() {
    const container = document.getElementById('config-backup-search-results');
    if (!container) return;

    const state = _getConfigBackupSearchState();
    if (state.searching) {
        container.innerHTML = skeletonCards(2);
        return;
    }
    if (!state.searched) {
        container.innerHTML = '<div class="card" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Run a search to scan backed-up configurations.</div>';
        return;
    }
    if (!state.results.length) {
        container.innerHTML = `<div class="card" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No matches found for "${escapeHtml(state.query || '')}".</div>`;
        return;
    }

    const modeLabel = escapeHtml(state.activeMode || state.mode || 'fulltext');
    const summary = `<div class="card" style="margin-bottom:0.75rem; padding:0.75rem 1rem; color:var(--text-muted);">
        Found ${state.results.length} result(s) using <strong>${modeLabel}</strong> mode${state.hasMore ? ' (showing top matches)' : ''}.
    </div>`;

    container.innerHTML = summary + state.results.map((result) => {
        const host = escapeHtml(result.hostname || result.ip_address || 'Unknown host');
        const ip = escapeHtml(result.ip_address || '');
        const capturedAt = result.captured_at ? new Date(result.captured_at + 'Z').toLocaleString() : 'Unknown';
        const size = result.config_length ? `${(result.config_length / 1024).toFixed(1)} KB` : '-';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${host}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted);">${ip}</span>
                </div>
                <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
                    <span style="font-size:0.8em; color:var(--text-muted);">line ${result.match_line_number || '?'}</span>
                    <button class="btn btn-sm btn-secondary" onclick="viewBackupDetail(${result.backup_id})">View Backup</button>
                    <button class="btn btn-sm btn-secondary" onclick="viewBackupDiff(${result.backup_id})">View Diff</button>
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                Captured: ${capturedAt} &bull; Method: ${escapeHtml(result.capture_method || 'unknown')} &bull; Size: ${size}
            </div>
            ${_renderConfigBackupSearchContext(result)}
        </div>`;
    }).join('');
}

async function runConfigBackupSearch() {
    const queryInput = document.getElementById('config-backup-search-query');
    const modeSelect = document.getElementById('config-backup-search-mode');
    const limitInput = document.getElementById('config-backup-search-limit');
    const state = _getConfigBackupSearchState();

    if (!queryInput || !modeSelect || !limitInput) return;
    const query = (queryInput.value || '').trim();
    const mode = (modeSelect.value || 'fulltext').toLowerCase();
    let limit = parseInt(limitInput.value || '50', 10);
    if (!Number.isFinite(limit)) limit = 50;
    limit = Math.max(1, Math.min(200, limit));
    limitInput.value = String(limit);

    state.query = query;
    state.mode = mode;
    state.limit = limit;

    if (!query) {
        state.results = [];
        state.searched = false;
        state.hasMore = false;
        renderConfigBackupSearchResults();
        showToast('Enter text to search in configuration backups.', 'warning');
        return;
    }

    state.searching = true;
    renderConfigBackupSearchResults();
    try {
        const payload = await api.searchConfigBackups(query, mode, limit, state.contextLines || 1);
        state.results = payload.results || [];
        state.hasMore = Boolean(payload.has_more);
        state.activeMode = payload.mode || mode;
        state.searched = true;
    } catch (error) {
        state.results = [];
        state.hasMore = false;
        state.activeMode = mode;
        state.searched = true;
        showToast('Search failed: ' + error.message, 'danger');
    } finally {
        state.searching = false;
        renderConfigBackupSearchResults();
    }
}
window.runConfigBackupSearch = runConfigBackupSearch;

function switchBackupTab(tab) {
    _backupCurrentTab = tab;
    listViewState.configBackups.tab = tab;
    const policiesBtn = document.getElementById('backup-tab-policies');
    const historyBtn = document.getElementById('backup-tab-history');
    const policiesList = document.getElementById('backup-policies-list');
    const historyList = document.getElementById('backup-history-list');
    if (tab === 'policies') {
        if (policiesBtn) { policiesBtn.className = 'btn btn-sm btn-primary'; }
        if (historyBtn) { historyBtn.className = 'btn btn-sm btn-secondary'; }
        if (policiesList) policiesList.style.display = '';
        if (historyList) historyList.style.display = 'none';
    } else {
        if (policiesBtn) { policiesBtn.className = 'btn btn-sm btn-secondary'; }
        if (historyBtn) { historyBtn.className = 'btn btn-sm btn-primary'; }
        if (policiesList) policiesList.style.display = 'none';
        if (historyList) historyList.style.display = '';
    }
}
window.switchBackupTab = switchBackupTab;

function refreshConfigBackups() { loadConfigBackups(); }
window.refreshConfigBackups = refreshConfigBackups;

async function showCreateBackupPolicyModal() {
    let groups = [], creds = [];
    try {
        [groups, creds] = await Promise.all([api.getInventoryGroups(), api.getCredentials()]);
    } catch (e) { /* ignore */ }
    const groupOpts = (groups || []).map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    showModal('Create Backup Policy', `
        <label class="form-label">Policy Name</label>
        <input id="bp-name" class="form-input" placeholder="Daily backup">
        <label class="form-label" style="margin-top:0.75rem;">Inventory Group</label>
        <select id="bp-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Credential</label>
        <select id="bp-cred" class="form-select">${credOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Interval (hours)</label>
        <input id="bp-interval" class="form-input" type="number" value="24" min="1" max="168">
        <label class="form-label" style="margin-top:0.75rem;">Retention (days)</label>
        <input id="bp-retention" class="form-input" type="number" value="30" min="1" max="365">
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitCreateBackupPolicy()">Create</button>
        </div>
    `);
}
window.showCreateBackupPolicyModal = showCreateBackupPolicyModal;

async function submitCreateBackupPolicy() {
    const name = document.getElementById('bp-name').value.trim();
    const group_id = parseInt(document.getElementById('bp-group').value);
    const credential_id = parseInt(document.getElementById('bp-cred').value);
    const interval_seconds = parseInt(document.getElementById('bp-interval').value || '24') * 3600;
    const retention_days = parseInt(document.getElementById('bp-retention').value || '30');
    if (!name) return alert('Name is required');
    try {
        await api.createConfigBackupPolicy({ name, group_id, credential_id, interval_seconds, retention_days });
        closeAllModals();
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
}
window.submitCreateBackupPolicy = submitCreateBackupPolicy;

async function showEditBackupPolicyModal(policyId) {
    let policy, creds = [];
    try {
        [policy, creds] = await Promise.all([api.getConfigBackupPolicies(), api.getCredentials()]);
        policy = (policy || []).find(p => p.id === policyId);
    } catch (e) { return alert('Error loading policy'); }
    if (!policy) return alert('Policy not found');
    const credOpts = (creds || []).map(c => `<option value="${c.id}" ${c.id === policy.credential_id ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join('');
    showModal('Edit Backup Policy', `
        <input type="hidden" id="bp-edit-id" value="${policyId}">
        <label class="form-label">Policy Name</label>
        <input id="bp-edit-name" class="form-input" value="${escapeHtml(policy.name)}">
        <label class="form-label" style="margin-top:0.75rem;">Enabled</label>
        <select id="bp-edit-enabled" class="form-select">
            <option value="true" ${policy.enabled ? 'selected' : ''}>Enabled</option>
            <option value="false" ${!policy.enabled ? 'selected' : ''}>Disabled</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Credential</label>
        <select id="bp-edit-cred" class="form-select">${credOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Interval (hours)</label>
        <input id="bp-edit-interval" class="form-input" type="number" value="${Math.round(policy.interval_seconds / 3600)}" min="1" max="168">
        <label class="form-label" style="margin-top:0.75rem;">Retention (days)</label>
        <input id="bp-edit-retention" class="form-input" type="number" value="${policy.retention_days}" min="1" max="365">
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitEditBackupPolicy()">Save</button>
        </div>
    `);
}
window.showEditBackupPolicyModal = showEditBackupPolicyModal;

async function submitEditBackupPolicy() {
    const policyId = parseInt(document.getElementById('bp-edit-id').value);
    try {
        await api.updateConfigBackupPolicy(policyId, {
            name: document.getElementById('bp-edit-name').value.trim(),
            enabled: document.getElementById('bp-edit-enabled').value === 'true',
            credential_id: parseInt(document.getElementById('bp-edit-cred').value),
            interval_seconds: parseInt(document.getElementById('bp-edit-interval').value || '24') * 3600,
            retention_days: parseInt(document.getElementById('bp-edit-retention').value || '30'),
        });
        closeAllModals();
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
}
window.submitEditBackupPolicy = submitEditBackupPolicy;

async function confirmDeleteBackupPolicy(id, name) {
    const ok = await showConfirm({
        title: 'Delete Backup Policy',
        message: `Are you sure you want to delete the backup policy "${name}"? This cannot be undone.`,
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!ok) return;
    try {
        await api.deleteConfigBackupPolicy(id);
        loadConfigBackups();
    } catch (e) { showToast('Error: ' + e.message, 'danger'); }
}
window.confirmDeleteBackupPolicy = confirmDeleteBackupPolicy;

const _runningBackupPolicies = new Set();

async function runBackupPolicyNow(id) {
    if (_runningBackupPolicies.has(id)) return; // already running
    _runningBackupPolicies.add(id);

    // Update all Run Now buttons for this policy to show running state
    const btns = document.querySelectorAll(`button[data-run-policy="${id}"]`);
    btns.forEach(btn => {
        btn.disabled = true;
        btn._prevHTML = btn.innerHTML;
        btn.innerHTML = '<span class="backup-spinner"></span> Running\u2026';
        btn.classList.add('btn-running');
    });

    try {
        const result = await api.runConfigBackupPolicy(id);
        const skipped = result.skipped || 0;
        let msg = `Backup complete: ${result.backed_up} saved, ${result.errors} errors`;
        if (skipped > 0) msg += `, ${skipped} unchanged (skipped)`;
        showToast(msg, result.errors > 0 ? 'warning' : 'success');
        loadConfigBackups();
    } catch (e) {
        if (e.message && e.message.includes('already running')) {
            showToast('This backup policy is already running.', 'warning');
        } else {
            showToast('Backup error: ' + e.message, 'danger');
        }
    } finally {
        _runningBackupPolicies.delete(id);
        btns.forEach(btn => {
            btn.disabled = false;
            btn.innerHTML = btn._prevHTML || 'Run Now';
            btn.classList.remove('btn-running');
        });
    }
}
window.runBackupPolicyNow = runBackupPolicyNow;

async function viewBackupDetail(id) {
    try {
        const backup = await api.getConfigBackup(id);
        showModal(`Backup Detail — ${escapeHtml(backup.hostname || backup.ip_address)}`, `
            <div style="font-size:0.85em; margin-bottom:0.75rem; color:var(--text-muted);">
                Captured: ${new Date(backup.captured_at + 'Z').toLocaleString()} &bull;
                Method: ${backup.capture_method} &bull; Status: ${backup.status}
            </div>
            ${copyableCodeBlock(backup.config_text || '(empty)')}
        `);
        initCopyableBlocks();
    } catch (e) { showToast('Error: ' + e.message, 'danger'); }
}
window.viewBackupDetail = viewBackupDetail;

async function viewBackupDiff(backupId) {
    try {
        const diff = await api.getConfigBackupDiff(backupId);
        const diffHtml = _renderUnifiedDiff(diff.diff_text || '');
        showModal(`Backup Diff — ${escapeHtml(diff.hostname || diff.ip_address || '')}`, `
            <div class="drift-event-meta" style="margin-bottom:0.75rem">
                <span>${escapeHtml(diff.ip_address || '')}</span>
                <span style="opacity:0.4">|</span>
                <span>Current: ${diff.captured_at ? new Date(diff.captured_at + 'Z').toLocaleString() : ''}</span>
                <span style="opacity:0.4">|</span>
                <span>Previous: ${diff.previous_captured_at ? new Date(diff.previous_captured_at + 'Z').toLocaleString() : ''}</span>
                <span style="opacity:0.4">|</span>
                <span class="drift-diff-added">+${diff.diff_lines_added || 0}</span>
                <span class="drift-diff-removed">-${diff.diff_lines_removed || 0}</span>
            </div>
            ${copyableHtmlBlock(diffHtml, diff.diff_text || '', { className: 'drift-diff-viewer' })}
            <div style="display:flex; justify-content:flex-end; margin-top:1rem;">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
        initCopyableBlocks();
    } catch (error) {
        showToast('Error: ' + error.message, 'danger');
    }
}
window.viewBackupDiff = viewBackupDiff;

async function showRestoreBackupModal(backupId) {
    let creds = [];
    try { creds = await api.getCredentials(); } catch (e) { /* ignore */ }
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    showModal('Restore from Backup', `
        <p style="color:var(--warning); margin-bottom:1rem;">This will push the backup configuration to the device and validate the result.</p>
        <input type="hidden" id="restore-backup-id" value="${backupId}">
        <label class="form-label">Credential for SSH</label>
        <select id="restore-cred" class="form-select">${credOpts}</select>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitRestoreBackup()">Restore</button>
        </div>
    `);
}
window.showRestoreBackupModal = showRestoreBackupModal;

async function submitRestoreBackup() {
    const backupId = parseInt(document.getElementById('restore-backup-id').value);
    const credential_id = parseInt(document.getElementById('restore-cred').value);
    try {
        const result = await api.restoreConfigBackup({ backup_id: backupId, credential_id });
        closeAllModals();
        const msg = result.validated
            ? `Restore validated successfully for ${result.hostname}. No config differences detected.`
            : `Restore completed for ${result.hostname} but validation found ${result.lines_changed} line(s) changed.\n\n${result.diff_text || ''}`;
        alert(msg);
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
}
window.submitRestoreBackup = submitRestoreBackup;

async function confirmDeleteBackup(id) {
    const ok = await showConfirm({
        title: 'Delete Backup',
        message: 'Are you sure you want to delete this backup? This cannot be undone.',
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!ok) return;
    try {
        await api.deleteConfigBackup(id);
        loadConfigBackups();
    } catch (e) { showToast('Error: ' + e.message, 'danger'); }
}
window.confirmDeleteBackup = confirmDeleteBackup;

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

function destroyConfiguration() {
    _closeAllWs();
    _driftEventsCache = {};
    _runningBackupPolicies.clear();
    _driftViewMode = 'grouped';
    _backupCurrentTab = 'policies';
    listViewState.configDrift.items = [];
    listViewState.configDrift.query = '';
    listViewState.configBackups.policies = [];
    listViewState.configBackups.backups = [];
    listViewState.configBackups.query = '';
    listViewState.configuration.tab = 'drift';
    const searchState = _getConfigBackupSearchState();
    searchState.query = '';
    searchState.mode = 'fulltext';
    searchState.limit = 50;
    searchState.contextLines = 1;
    searchState.results = [];
    searchState.hasMore = false;
    searchState.searched = false;
    searchState.searching = false;
    searchState.activeMode = 'fulltext';
    _setConfigurationSearchInputState('drift');
}

export { loadConfigDrift, loadConfigBackups, destroyConfiguration, applyDriftFilters };

/**
 * Upgrades Module — Firmware upgrade campaigns, image library, config backups
 * Lazy-loaded when user navigates to #upgrades
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    showModal, closeAllModals, showConfirm, formatDate, formatRelativeTime,
    skeletonCards, emptyStateHTML, navigateToPage, PlexusChart, debounce
} from '../app.js';
import { connectUpgradeWebSocket, disconnectUpgradeWebSocket } from '../websocket.js';

// ═══════════════════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════════════════

let _upgradeCurrentTab = 'campaigns';

// ═══════════════════════════════════════════════════════════════════════════════
// Tab Switching
// ═══════════════════════════════════════════════════════════════════════════════

function switchUpgradeTab(tab) {
    _upgradeCurrentTab = tab;
    document.querySelectorAll('.upgrade-tab-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-tab') === tab);
    });
    document.getElementById('upgrade-tab-campaigns').style.display = tab === 'campaigns' ? '' : 'none';
    document.getElementById('upgrade-tab-images').style.display = tab === 'images' ? '' : 'none';
    document.getElementById('upgrade-tab-backups').style.display = tab === 'backups' ? '' : 'none';
    if (tab === 'images') loadUpgradeImages();
    if (tab === 'campaigns') loadUpgradeCampaigns();
    if (tab === 'backups') loadUpgradeBackups();
}
window.switchUpgradeTab = switchUpgradeTab;

// ═══════════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════════════════

export async function loadUpgradesPage({ preserveContent } = {}) {
    if (_upgradeCurrentTab === 'images') {
        await loadUpgradeImages();
    } else if (_upgradeCurrentTab === 'backups') {
        await loadUpgradeBackups();
    } else {
        await loadUpgradeCampaigns();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Backups
// ═══════════════════════════════════════════════════════════════════════════════

async function loadUpgradeBackups() {
    const container = document.getElementById('upgrade-backups-list');
    if (!container) return;

    try {
        const backups = await api.apiGet('/api/upgrades/backups');
        if (!backups.length) {
            container.innerHTML = '<div style="text-align:center; padding:2rem; opacity:0.5;">No config backups yet. Backups are created during the Prestage phase.</div>';
            return;
        }

        container.innerHTML = `<table class="data-table" style="width:100%;">
            <thead><tr>
                <th style="text-align:left;">Filename</th>
                <th style="text-align:left;">Size</th>
                <th style="text-align:left;">Date</th>
                <th style="text-align:left;">Actions</th>
            </tr></thead>
            <tbody>${backups.map(b => `<tr>
                <td style="text-align:left;"><code>${escapeHtml(b.filename)}</code></td>
                <td style="text-align:left;">${(b.size / 1024).toFixed(1)} KB</td>
                <td style="text-align:left; white-space:nowrap;">${b.modified?.replace('T', ' ').substring(0, 19) || ''}</td>
                <td style="text-align:left; white-space:nowrap;">
                    <button class="btn btn-sm btn-secondary" onclick="downloadUpgradeBackup('${escapeHtml(b.filename)}')">Download</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUpgradeBackup('${escapeHtml(b.filename)}')">Delete</button>
                </td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (err) {
        container.innerHTML = `<div style="color:var(--error-color); padding:1rem;">Failed to load backups: ${escapeHtml(err.message)}</div>`;
    }
}

function downloadUpgradeBackup(filename) {
    const link = document.createElement('a');
    link.href = `/api/upgrades/backups/${encodeURIComponent(filename)}`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
window.downloadUpgradeBackup = downloadUpgradeBackup;

async function deleteUpgradeBackup(filename) {
    const confirmed = await showConfirm({
        title: 'Delete Backup',
        message: `Delete backup file "${filename}"? This cannot be undone.`,
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!confirmed) return;
    try {
        await api.apiDelete(`/api/upgrades/backups/${encodeURIComponent(filename)}`);
        showToast('Backup deleted', 'success');
        loadUpgradeBackups();
    } catch (err) {
        showToast('Delete failed: ' + err.message, 'error');
    }
}
window.deleteUpgradeBackup = deleteUpgradeBackup;

// ═══════════════════════════════════════════════════════════════════════════════
// Campaign List
// ═══════════════════════════════════════════════════════════════════════════════

async function loadUpgradeCampaigns() {
    const container = document.getElementById('upgrade-campaigns-list');
    try {
        const campaigns = await api.apiGet('/api/upgrades/campaigns');
        if (!campaigns || !campaigns.length) {
            container.innerHTML = `<div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                <p>No upgrade campaigns yet</p>
                <button class="btn btn-primary" onclick="showCreateCampaignModal()">Create First Campaign</button>
            </div>`;
            return;
        }

        const search = (document.getElementById('upgrade-campaign-search')?.value || '').toLowerCase();
        const filtered = campaigns.filter(c => !search ||
            c.name?.toLowerCase().includes(search) ||
            c.description?.toLowerCase().includes(search) ||
            c.status?.toLowerCase().includes(search));

        container.innerHTML = filtered.map(c => {
            const statusClass = c.status?.includes('failed') ? 'badge-error'
                : c.status?.includes('running') ? 'badge-info'
                : c.status?.includes('complete') ? 'badge-success'
                : 'badge-secondary';
            const pct = c.device_count ? Math.round((c.devices_completed / c.device_count) * 100) : 0;
            return `<div class="glass-card card" style="margin-bottom:0.75rem; cursor:pointer;" onclick="viewCampaign(${c.id})">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3 style="margin:0 0 0.25rem">${escapeHtml(c.name)}</h3>
                        <p style="margin:0; opacity:0.7; font-size:0.85em;">${escapeHtml(c.description || '')}</p>
                    </div>
                    <div style="text-align:right;">
                        <span class="badge ${statusClass}">${escapeHtml(c.status || 'created')}</span>
                        <div style="font-size:0.85em; margin-top:0.25rem; opacity:0.7;">
                            ${c.devices_completed}/${c.device_count} devices &bull; ${pct}%
                        </div>
                    </div>
                </div>
                <div style="margin-top:0.5rem;">
                    <div class="progress-bar-bg" style="height:6px; border-radius:3px; background:var(--glass-border);">
                        <div style="width:${pct}%; height:100%; border-radius:3px; background:var(--success-color); transition:width 0.3s;"></div>
                    </div>
                </div>
                <div style="font-size:0.8em; opacity:0.5; margin-top:0.25rem;">
                    Created ${c.created_at?.replace('T', ' ').substring(0, 16) || ''} by ${escapeHtml(c.created_by || '')}
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><p>Failed to load campaigns: ${escapeHtml(err.message)}</p></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Image Library
// ═══════════════════════════════════════════════════════════════════════════════

async function loadUpgradeImages() {
    const container = document.getElementById('upgrade-images-list');
    try {
        const images = await api.apiGet('/api/upgrades/images');
        if (!images || !images.length) {
            container.innerHTML = `<div class="empty-state">
                <p>No software images uploaded yet</p>
                <button class="btn btn-primary" onclick="showUploadImageModal()">Upload Image</button>
            </div>`;
            return;
        }
        container.innerHTML = `<table class="data-table" style="width:100%;">
            <thead><tr>
                <th style="text-align:left;">Filename</th>
                <th style="text-align:left;">Version</th>
                <th style="text-align:left;">Model Pattern</th>
                <th style="text-align:left;">Size</th>
                <th style="text-align:left;">MD5</th>
                <th style="text-align:left;">Uploaded</th>
                <th style="text-align:left;">Actions</th>
            </tr></thead>
            <tbody>${images.map(img => `<tr>
                <td style="text-align:left;"><code>${escapeHtml(img.filename)}</code></td>
                <td style="text-align:left;">${escapeHtml(img.version || '-')}</td>
                <td style="text-align:left;"><code>${escapeHtml(img.model_pattern || '-')}</code></td>
                <td style="text-align:left;">${(img.file_size / 1024 / 1024).toFixed(1)} MB</td>
                <td style="text-align:left;" title="${escapeHtml(img.md5_hash || '')}"><code>${escapeHtml(img.md5_hash || '')}</code></td>
                <td style="text-align:left; white-space:nowrap;">${img.created_at?.replace('T', ' ').substring(0, 16) || ''}</td>
                <td style="text-align:left; white-space:nowrap;">
                    <button class="btn btn-sm btn-secondary" onclick="editUpgradeImage(${img.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUpgradeImage(${img.id}, '${escapeHtml(img.filename)}')">Delete</button>
                </td>
            </tr>`).join('')}</tbody>
        </table>`;
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><p>Failed to load images: ${escapeHtml(err.message)}</p></div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Upload Image Modal
// ═══════════════════════════════════════════════════════════════════════════════

function showUploadImageModal() {
    showModal('Upload Software Image', `
        <form id="upload-image-form" enctype="multipart/form-data">
            <div class="form-group">
                <label class="form-label">IOS-XE Image File (.bin)</label>
                <input type="file" id="upload-image-file" class="form-input" accept=".bin,.SPA.bin" required>
            </div>
            <p style="font-size:0.85em; opacity:0.7;">
                Image will be stored on the server and MD5 hash will be computed automatically.
                Model pattern and version will be auto-detected from the filename.
            </p>
            <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary" id="upload-image-btn">Upload</button>
            </div>
        </form>
    `);

    document.getElementById('upload-image-form').onsubmit = async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('upload-image-file');
        if (!fileInput.files.length) return;

        const btn = document.getElementById('upload-image-btn');
        btn.disabled = true;
        btn.textContent = 'Uploading...';

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        try {
            const csrfToken = api.getCsrfToken();
            const resp = await fetch('/api/upgrades/images', {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || resp.statusText);
            }
            const result = await resp.json();
            showToast(`Image uploaded: ${result.filename} (MD5: ${result.md5_hash?.substring(0, 12)}...)`, 'success');
            closeAllModals();
            loadUpgradeImages();
        } catch (err) {
            showToast('Upload failed: ' + err.message, 'error');
            btn.disabled = false;
            btn.textContent = 'Upload';
        }
    };
}
window.showUploadImageModal = showUploadImageModal;
window.showUpgradeImagesModal = function() { switchUpgradeTab('images'); };

async function editUpgradeImage(imageId) {
    try {
        const img = await api.apiGet(`/api/upgrades/images/${imageId}`);
        showModal('Edit Image', `
            <form id="edit-image-form">
                <div class="form-group">
                    <label class="form-label">Filename</label>
                    <input class="form-input" value="${escapeHtml(img.filename)}" disabled>
                </div>
                <div class="form-group">
                    <label class="form-label">Model Pattern (e.g. "9200", "C9300", "C9200L")</label>
                    <input id="edit-img-pattern" class="form-input" value="${escapeHtml(img.model_pattern || '')}">
                </div>
                <div class="form-group">
                    <label class="form-label">Version</label>
                    <input id="edit-img-version" class="form-input" value="${escapeHtml(img.version || '')}">
                </div>
                <div class="form-group">
                    <label class="form-label">Notes</label>
                    <textarea id="edit-img-notes" class="form-input" rows="3">${escapeHtml(img.notes || '')}</textarea>
                </div>
                <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save</button>
                </div>
            </form>
        `);
        document.getElementById('edit-image-form').onsubmit = async (e) => {
            e.preventDefault();
            try {
                await api.apiPatch(`/api/upgrades/images/${imageId}`, {
                    model_pattern: document.getElementById('edit-img-pattern').value,
                    version: document.getElementById('edit-img-version').value,
                    notes: document.getElementById('edit-img-notes').value,
                });
                showToast('Image updated', 'success');
                closeAllModals();
                loadUpgradeImages();
            } catch (err) {
                showToast('Update failed: ' + err.message, 'error');
            }
        };
    } catch (err) {
        showToast('Failed to load image: ' + err.message, 'error');
    }
}
window.editUpgradeImage = editUpgradeImage;

async function deleteUpgradeImage(imageId, filename) {
    const confirmed = await showConfirm({
        title: 'Delete Image',
        message: `Delete <strong>${escapeHtml(filename)}</strong>? This removes the file from the server.`,
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!confirmed) return;
    try {
        await api.apiDelete(`/api/upgrades/images/${imageId}`);
        showToast('Image deleted', 'success');
        loadUpgradeImages();
    } catch (err) {
        showToast('Delete failed: ' + err.message, 'error');
    }
}
window.deleteUpgradeImage = deleteUpgradeImage;

// ═══════════════════════════════════════════════════════════════════════════════
// Create Campaign Modal
// ═══════════════════════════════════════════════════════════════════════════════

async function showCreateCampaignModal() {
    // Load images and inventory in parallel
    const [images, groups, creds] = await Promise.all([
        api.apiGet('/api/upgrades/images').catch(() => []),
        api.getInventoryGroups(true).catch(() => []),
        api.getCredentials().catch(() => []),
    ]);

    // Build image map options from available images
    const imageOptions = images.map(img =>
        `<option value="${escapeHtml(img.filename)}" data-pattern="${escapeHtml(img.model_pattern || '')}">${escapeHtml(img.filename)} (${escapeHtml(img.model_pattern || 'no pattern')} / v${escapeHtml(img.version || '?')})</option>`
    ).join('');

    showModal('Create Upgrade Campaign', `
        <form id="create-campaign-form">
            <div class="form-group">
                <label class="form-label">Campaign Name</label>
                <input id="campaign-name" class="form-input" required placeholder="e.g. Q2 2026 IOS-XE 17.15 Upgrade">
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea id="campaign-desc" class="form-input" rows="2" placeholder="Optional description..."></textarea>
            </div>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Image Map</legend>
                <p style="font-size:0.85em; opacity:0.7; margin-top:0;">Map model patterns to images. 9200 switches need the "lite" image, 9300 need regular.</p>
                <div id="campaign-image-map-rows">
                    <div class="image-map-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                        <input class="form-input img-map-pattern" placeholder="Model pattern (e.g. 9200)" style="flex:1;" value="9200">
                        <select class="form-select img-map-image" style="flex:2;">${imageOptions}</select>
                        <button type="button" class="btn btn-sm btn-secondary" onclick="this.closest('.image-map-row').remove()">X</button>
                    </div>
                </div>
                <button type="button" class="btn btn-sm btn-secondary" onclick="addImageMapRow()">+ Add Mapping</button>
            </fieldset>

            <div class="form-group">
                <label class="form-label">Credential</label>
                <select id="campaign-cred" class="form-select" required>
                    <option value="">Select credential...</option>
                    ${creds.map(c => `<option value="${c.id}">${escapeHtml(c.name || 'Credential ' + c.id)}</option>`).join('')}
                </select>
            </div>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Target Devices</legend>
                <div style="max-height:250px; overflow-y:auto;">
                    ${groups.map(g => {
                        const groupHosts = g.hosts || [];
                        return `<div style="margin-bottom:0.75rem;">
                            <label style="font-weight:600; display:flex; align-items:center; gap:0.5rem;">
                                <input type="checkbox" class="campaign-group-cb" data-group-id="${g.id}"
                                    onchange="toggleCampaignGroupHosts(this, ${g.id})">
                                ${escapeHtml(g.name)} (${groupHosts.length} hosts)
                            </label>
                            <div style="margin-left:1.5rem;">
                                ${groupHosts.map(h => `<label style="display:flex; align-items:center; gap:0.5rem; font-size:0.9em;">
                                    <input type="checkbox" class="campaign-host-cb" data-host-id="${h.id}" data-group-id="${g.id}" value="${h.id}">
                                    ${escapeHtml(h.hostname || h.ip_address)} <span style="opacity:0.5;">${h.ip_address}</span>
                                    ${h.model ? `<code style="font-size:0.8em;">${escapeHtml(h.model)}</code>` : ''}
                                </label>`).join('')}
                            </div>
                        </div>`;
                    }).join('')}
                </div>
                <div class="form-group" style="margin-top:0.75rem;">
                    <label class="form-label">Ad-hoc IPs (one per line)</label>
                    <textarea id="campaign-adhoc-ips" class="form-input" rows="2" placeholder="10.0.1.1&#10;10.0.1.2"></textarea>
                </div>
            </fieldset>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Options</legend>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-backup"> Skip config backup
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-md5"> Skip MD5 verification
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-health"> Skip health check
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-verify" checked> Verify upgrade after reboot
                    </label>
                </div>
                <div style="display:flex; gap:1rem; margin-top:0.75rem;">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Parallel Workers</label>
                        <input type="number" id="campaign-opt-parallel" class="form-input" value="4" min="1" max="8">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">SSH Retries</label>
                        <input type="number" id="campaign-opt-retries" class="form-input" value="2" min="0" max="5">
                    </div>
                </div>
            </fieldset>

            <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create Campaign</button>
            </div>
        </form>
    `, { wide: true });

    // Auto-select appropriate image for default patterns
    const mapRows = document.querySelectorAll('.image-map-row');
    mapRows.forEach(row => {
        const pattern = row.querySelector('.img-map-pattern')?.value || '';
        const select = row.querySelector('.img-map-image');
        if (select) {
            for (const opt of select.options) {
                if (opt.dataset.pattern && opt.dataset.pattern.includes(pattern)) {
                    opt.selected = true;
                    break;
                }
            }
        }
    });

    document.getElementById('create-campaign-form').onsubmit = async (e) => {
        e.preventDefault();
        // Build image map from rows
        const imageMap = {};
        document.querySelectorAll('.image-map-row').forEach(row => {
            const pattern = row.querySelector('.img-map-pattern')?.value?.trim();
            const image = row.querySelector('.img-map-image')?.value;
            if (pattern && image) imageMap[pattern] = image;
        });

        // Collect host IDs
        const hostIds = [];
        document.querySelectorAll('.campaign-host-cb:checked').forEach(cb => {
            hostIds.push(parseInt(cb.value));
        });

        // Collect ad-hoc IPs
        const adhocText = document.getElementById('campaign-adhoc-ips').value;
        const adHocIps = adhocText.split(/[\n,]+/).map(s => s.trim()).filter(s => s);

        if (!hostIds.length && !adHocIps.length) {
            showToast('Select at least one device or enter ad-hoc IPs', 'error');
            return;
        }
        if (Object.keys(imageMap).length === 0) {
            showToast('Add at least one image mapping', 'error');
            return;
        }

        try {
            const result = await api.apiPost('/api/upgrades/campaigns', {
                name: document.getElementById('campaign-name').value,
                description: document.getElementById('campaign-desc').value,
                image_map: imageMap,
                credential_id: parseInt(document.getElementById('campaign-cred').value),
                host_ids: hostIds,
                ad_hoc_ips: adHocIps,
                options: {
                    skip_backup: document.getElementById('campaign-opt-skip-backup').checked,
                    skip_md5: document.getElementById('campaign-opt-skip-md5').checked,
                    skip_health_check: document.getElementById('campaign-opt-skip-health').checked,
                    verify_upgrade: document.getElementById('campaign-opt-verify').checked,
                    parallel: parseInt(document.getElementById('campaign-opt-parallel').value) || 4,
                    retries: parseInt(document.getElementById('campaign-opt-retries').value) || 2,
                },
            });

            showToast(`Campaign created with ${result.devices_added} devices`, 'success');
            closeAllModals();
            loadUpgradeCampaigns();
        } catch (err) {
            showToast('Failed to create campaign: ' + err.message, 'error');
        }
    };
}
window.showCreateCampaignModal = showCreateCampaignModal;

// ═══════════════════════════════════════════════════════════════════════════════
// Edit Campaign
// ═══════════════════════════════════════════════════════════════════════════════

async function editCampaign(campaignId) {
    // Load campaign, images, groups, and credentials in parallel
    const [campaign, images, groups, creds] = await Promise.all([
        api.apiGet(`/api/upgrades/campaigns/${campaignId}`),
        api.apiGet('/api/upgrades/images').catch(() => []),
        api.getInventoryGroups(true).catch(() => []),
        api.getCredentials().catch(() => []),
    ]);

    const currentOptions = typeof campaign.options === 'string' ? JSON.parse(campaign.options) : (campaign.options || {});
    const currentImageMap = typeof campaign.image_map === 'string' ? JSON.parse(campaign.image_map) : (campaign.image_map || {});
    const devices = campaign.devices || [];

    // Track which hosts are already in the campaign (by host_id and ip)
    const currentHostIds = new Set(devices.filter(d => d.host_id).map(d => d.host_id));
    const currentAdHocIps = devices.filter(d => !d.host_id).map(d => d.ip_address);

    // Devices that have progress (not all-pending) can't be removed
    const devicesWithProgress = devices.filter(d =>
        d.phase !== 'pending' ||
        d.prestage_status !== 'pending' ||
        d.transfer_status !== 'pending' ||
        d.activate_status !== 'pending'
    );
    const lockedIps = new Set(devicesWithProgress.map(d => d.ip_address));

    const imageOptions = images.map(img =>
        `<option value="${escapeHtml(img.filename)}" data-pattern="${escapeHtml(img.model_pattern || '')}">${escapeHtml(img.filename)} (${escapeHtml(img.model_pattern || 'no pattern')} / v${escapeHtml(img.version || '?')})</option>`
    ).join('');

    // Build image map rows from current data
    const mapEntries = Object.entries(currentImageMap);
    const imageMapRowsHtml = mapEntries.length > 0
        ? mapEntries.map(([pattern, image]) => `
            <div class="image-map-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
                <input class="form-input img-map-pattern" placeholder="Model pattern (e.g. 9200)" style="flex:1;" value="${escapeHtml(pattern)}">
                <select class="form-select img-map-image" style="flex:2;" data-selected="${escapeHtml(image)}">${imageOptions}</select>
                <button type="button" class="btn btn-sm btn-secondary" onclick="this.closest('.image-map-row').remove()">X</button>
            </div>`).join('')
        : `<div class="image-map-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
            <input class="form-input img-map-pattern" placeholder="Model pattern (e.g. 9200)" style="flex:1;">
            <select class="form-select img-map-image" style="flex:2;">${imageOptions}</select>
            <button type="button" class="btn btn-sm btn-secondary" onclick="this.closest('.image-map-row').remove()">X</button>
        </div>`;

    showModal('Edit Campaign', `
        <form id="edit-campaign-form">
            <div class="form-group">
                <label class="form-label">Campaign Name</label>
                <input id="campaign-name" class="form-input" required value="${escapeHtml(campaign.name)}">
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea id="campaign-desc" class="form-input" rows="2">${escapeHtml(campaign.description || '')}</textarea>
            </div>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Image Map</legend>
                <p style="font-size:0.85em; opacity:0.7; margin-top:0;">Map model patterns to images. 9200 switches need the "lite" image, 9300 need regular.</p>
                <div id="campaign-image-map-rows">
                    ${imageMapRowsHtml}
                </div>
                <button type="button" class="btn btn-sm btn-secondary" onclick="addImageMapRow()">+ Add Mapping</button>
            </fieldset>

            <div class="form-group">
                <label class="form-label">Credential</label>
                <select id="campaign-cred" class="form-select" required>
                    <option value="">Select credential...</option>
                    ${creds.map(c => `<option value="${c.id}" ${c.id === currentOptions.credential_id ? 'selected' : ''}>${escapeHtml(c.name || 'Credential ' + c.id)}</option>`).join('')}
                </select>
            </div>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Target Devices</legend>
                ${devicesWithProgress.length > 0 ? `<p style="font-size:0.85em; color:var(--warning-color); margin-top:0;">${devicesWithProgress.length} device(s) have upgrade progress and cannot be removed.</p>` : ''}
                <div style="max-height:250px; overflow-y:auto;">
                    ${groups.map(g => {
                        const groupHosts = g.hosts || [];
                        return `<div style="margin-bottom:0.75rem;">
                            <label style="font-weight:600; display:flex; align-items:center; gap:0.5rem;">
                                <input type="checkbox" class="campaign-group-cb" data-group-id="${g.id}"
                                    onchange="toggleCampaignGroupHosts(this, ${g.id})">
                                ${escapeHtml(g.name)} (${groupHosts.length} hosts)
                            </label>
                            <div style="margin-left:1.5rem;">
                                ${groupHosts.map(h => {
                                    const isChecked = currentHostIds.has(h.id);
                                    const isLocked = lockedIps.has(h.ip_address);
                                    return `<label style="display:flex; align-items:center; gap:0.5rem; font-size:0.9em;">
                                        <input type="checkbox" class="campaign-host-cb" data-host-id="${h.id}" data-group-id="${g.id}" value="${h.id}"
                                            ${isChecked ? 'checked' : ''} ${isLocked ? 'disabled' : ''}>
                                        ${escapeHtml(h.hostname || h.ip_address)} <span style="opacity:0.5;">${h.ip_address}</span>
                                        ${h.model ? `<code style="font-size:0.8em;">${escapeHtml(h.model)}</code>` : ''}
                                        ${isLocked ? '<span style="font-size:0.75em; opacity:0.6;">(in progress)</span>' : ''}
                                    </label>`;
                                }).join('')}
                            </div>
                        </div>`;
                    }).join('')}
                </div>
                <div class="form-group" style="margin-top:0.75rem;">
                    <label class="form-label">Ad-hoc IPs (one per line)</label>
                    <textarea id="campaign-adhoc-ips" class="form-input" rows="2" placeholder="10.0.1.1&#10;10.0.1.2">${escapeHtml(currentAdHocIps.join('\n'))}</textarea>
                </div>
            </fieldset>

            <fieldset style="border:1px solid var(--glass-border); border-radius:8px; padding:1rem; margin-bottom:1rem;">
                <legend style="font-weight:600; padding:0 0.5rem;">Options</legend>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-backup" ${currentOptions.skip_backup ? 'checked' : ''}> Skip config backup
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-md5" ${currentOptions.skip_md5 ? 'checked' : ''}> Skip MD5 verification
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-skip-health" ${currentOptions.skip_health_check ? 'checked' : ''}> Skip health check
                    </label>
                    <label style="display:flex; align-items:center; gap:0.5rem;">
                        <input type="checkbox" id="campaign-opt-verify" ${currentOptions.verify_upgrade !== false ? 'checked' : ''}> Verify upgrade after reboot
                    </label>
                </div>
                <div style="display:flex; gap:1rem; margin-top:0.75rem;">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Parallel Workers</label>
                        <input type="number" id="campaign-opt-parallel" class="form-input" value="${currentOptions.parallel || 4}" min="1" max="8">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">SSH Retries</label>
                        <input type="number" id="campaign-opt-retries" class="form-input" value="${currentOptions.retries ?? 2}" min="0" max="5">
                    </div>
                </div>
            </fieldset>

            <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Save Changes</button>
            </div>
        </form>
    `, { wide: true });

    // Set correct image selections for existing map entries
    document.querySelectorAll('.image-map-row .img-map-image').forEach(select => {
        const target = select.dataset.selected;
        if (target) {
            for (const opt of select.options) {
                if (opt.value === target) {
                    opt.selected = true;
                    break;
                }
            }
        }
    });

    // Update group checkboxes if all hosts in group are checked
    document.querySelectorAll('.campaign-group-cb').forEach(groupCb => {
        const gid = groupCb.dataset.groupId;
        const hostCbs = document.querySelectorAll(`.campaign-host-cb[data-group-id="${gid}"]`);
        if (hostCbs.length > 0 && [...hostCbs].every(cb => cb.checked)) {
            groupCb.checked = true;
        }
    });

    document.getElementById('edit-campaign-form').onsubmit = async (e) => {
        e.preventDefault();

        const imageMap = {};
        document.querySelectorAll('.image-map-row').forEach(row => {
            const pattern = row.querySelector('.img-map-pattern')?.value?.trim();
            const image = row.querySelector('.img-map-image')?.value;
            if (pattern && image) imageMap[pattern] = image;
        });

        const hostIds = [];
        document.querySelectorAll('.campaign-host-cb:checked').forEach(cb => {
            hostIds.push(parseInt(cb.value));
        });

        const adhocText = document.getElementById('campaign-adhoc-ips').value;
        const adHocIps = adhocText.split(/[\n,]+/).map(s => s.trim()).filter(s => s);

        if (!hostIds.length && !adHocIps.length) {
            showToast('Select at least one device or enter ad-hoc IPs', 'error');
            return;
        }
        if (Object.keys(imageMap).length === 0) {
            showToast('Add at least one image mapping', 'error');
            return;
        }

        try {
            const result = await api.apiPatch(`/api/upgrades/campaigns/${campaignId}`, {
                name: document.getElementById('campaign-name').value,
                description: document.getElementById('campaign-desc').value,
                image_map: imageMap,
                credential_id: parseInt(document.getElementById('campaign-cred').value),
                host_ids: hostIds,
                ad_hoc_ips: adHocIps,
                options: {
                    skip_backup: document.getElementById('campaign-opt-skip-backup').checked,
                    skip_md5: document.getElementById('campaign-opt-skip-md5').checked,
                    skip_health_check: document.getElementById('campaign-opt-skip-health').checked,
                    verify_upgrade: document.getElementById('campaign-opt-verify').checked,
                    parallel: parseInt(document.getElementById('campaign-opt-parallel').value) || 4,
                    retries: parseInt(document.getElementById('campaign-opt-retries').value) || 2,
                },
            });

            showToast(`Campaign updated — ${result.total_devices} devices (${result.devices_added} new)`, 'success');
            closeAllModals();
            loadUpgradeCampaigns();
        } catch (err) {
            showToast('Failed to update campaign: ' + err.message, 'error');
        }
    };
}
window.editCampaign = editCampaign;

function addImageMapRow() {
    const container = document.getElementById('campaign-image-map-rows');
    const selects = container.querySelectorAll('.img-map-image');
    const optionsHtml = selects.length ? selects[0].innerHTML : '<option>No images uploaded</option>';
    container.insertAdjacentHTML('beforeend', `
        <div class="image-map-row" style="display:flex; gap:0.5rem; margin-bottom:0.5rem;">
            <input class="form-input img-map-pattern" placeholder="Model pattern (e.g. 9300)" style="flex:1;">
            <select class="form-select img-map-image" style="flex:2;">${optionsHtml}</select>
            <button type="button" class="btn btn-sm btn-secondary" onclick="this.closest('.image-map-row').remove()">X</button>
        </div>
    `);
}
window.addImageMapRow = addImageMapRow;

function toggleCampaignGroupHosts(checkbox, groupId) {
    const checked = checkbox.checked;
    document.querySelectorAll(`.campaign-host-cb[data-group-id="${groupId}"]`).forEach(cb => {
        cb.checked = checked;
    });
}
window.toggleCampaignGroupHosts = toggleCampaignGroupHosts;

// ═══════════════════════════════════════════════════════════════════════════════
// Campaign Detail View
// ═══════════════════════════════════════════════════════════════════════════════

async function viewCampaign(campaignId) {
    try {
        const campaign = await api.apiGet(`/api/upgrades/campaigns/${campaignId}`);
        const devices = campaign.devices || [];
        const options = typeof campaign.options === 'string' ? JSON.parse(campaign.options) : (campaign.options || {});
        const imageMap = typeof campaign.image_map === 'string' ? JSON.parse(campaign.image_map) : (campaign.image_map || {});

        const phaseColumns = ['prestage', 'transfer', 'activate', 'verify'];

        const statusIcon = (s) => {
            if (s === 'completed') return '<span style="color:var(--success-color);">&#10003;</span>';
            if (s === 'running') return '<span style="color:var(--info-color);">&#9881;</span>';
            if (s === 'failed') return '<span style="color:var(--error-color);">&#10007;</span>';
            if (s === 'cancelled') return '<span style="opacity:0.5;">&#8709;</span>';
            return '<span style="opacity:0.3;">&#8226;</span>';
        };

        const isRunning = campaign.status?.includes('running');

        showModal(`Campaign: ${escapeHtml(campaign.name)}`, `
            <div style="margin-bottom:1rem;">
                <span class="badge ${campaign.status?.includes('failed') ? 'badge-error' : campaign.status?.includes('running') ? 'badge-info' : campaign.status?.includes('complete') ? 'badge-success' : 'badge-secondary'}">${escapeHtml(campaign.status || 'created')}</span>
                <span style="opacity:0.7; margin-left:0.5rem; font-size:0.85em;">${devices.length} devices</span>
                ${Object.entries(imageMap).map(([p, i]) => `<span class="badge badge-secondary" style="margin-left:0.25rem;">${escapeHtml(p)} &rarr; ${escapeHtml(String(i).split('/').pop() || i)}</span>`).join('')}
            </div>

            <!-- Phase Action Buttons -->
            <div style="display:flex; gap:0.5rem; margin-bottom:1rem; flex-wrap:wrap;">
                <button class="btn btn-secondary" onclick="executeCampaignPhase(${campaignId}, 'prestage')" ${isRunning ? 'disabled' : ''}>
                    Run Prestage
                </button>
                <button class="btn btn-secondary" onclick="executeCampaignPhase(${campaignId}, 'transfer')" ${isRunning ? 'disabled' : ''}>
                    Run Transfer
                </button>
                <button class="btn btn-danger" onclick="executeCampaignPhase(${campaignId}, 'activate')" ${isRunning ? 'disabled' : ''}>
                    Run Activate (Reload!)
                </button>
                <button class="btn btn-secondary" onclick="executeCampaignPhase(${campaignId}, 'verify')" ${isRunning ? 'disabled' : ''}>
                    Verify Upgrade
                </button>
                ${isRunning ? `<button class="btn btn-secondary" onclick="cancelCampaignPhase(${campaignId})">Cancel</button>` : ''}
                <button class="btn btn-sm btn-secondary" style="margin-left:auto;" onclick="editCampaign(${campaignId})" ${isRunning ? 'disabled' : ''}>Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteCampaign(${campaignId})">Delete</button>
            </div>

            <!-- Device Pipeline Grid -->
            <div style="overflow-x:auto;">
                <table class="data-table" style="width:100%; font-size:0.85em;">
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>Model</th>
                            <th>Current</th>
                            <th>Target Image</th>
                            ${phaseColumns.map(p => `<th style="text-align:center;">${p.charAt(0).toUpperCase() + p.slice(1)}</th>`).join('')}
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${devices.map(d => `<tr id="upgrade-dev-${d.id}" style="cursor:pointer;" onclick="viewDeviceUpgradeLog(${campaignId}, ${d.id}, '${escapeHtml(d.ip_address)}')">
                            <td>
                                <strong>${escapeHtml(d.hostname || d.ip_address)}</strong>
                                ${d.hostname ? `<br><span style="opacity:0.5; font-size:0.9em;">${escapeHtml(d.ip_address)}</span>` : ''}
                            </td>
                            <td><code>${escapeHtml(d.model || '-')}</code></td>
                            <td>${escapeHtml(d.current_version || '-')}</td>
                            <td style="font-size:0.85em;">${escapeHtml(d.target_image ? d.target_image.split('/').pop() : '-')}</td>
                            ${phaseColumns.map(p => `<td style="text-align:center;">${statusIcon(d[p + '_status'])}</td>`).join('')}
                            <td>
                                ${d.error_message ? `<span style="color:var(--error-color); font-size:0.85em;" title="${escapeHtml(d.error_message)}">${escapeHtml(d.error_message.substring(0, 40))}${d.error_message.length > 40 ? '...' : ''}</span>` : `<span style="opacity:0.5;">${escapeHtml(d.phase || 'pending')}</span>`}
                            </td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>

            <!-- Live Output -->
            <div style="margin-top:1rem;">
                <h4 style="margin:0 0 0.5rem;">Live Output</h4>
                <div id="upgrade-live-output" class="job-output upgrade-live-output">
                </div>
            </div>
        `, { wide: true });

        // Connect WebSocket for live updates
        connectUpgradeWebSocket(campaignId,
            (data) => {
                // Handle live device status updates (checkmarks)
                if (data.type === 'device_status' && data.device_id) {
                    const row = document.getElementById(`upgrade-dev-${data.device_id}`);
                    if (row) {
                        const phases = ['prestage', 'transfer', 'activate', 'verify'];
                        const cells = row.querySelectorAll('td');
                        // Phase columns start after Device, Model, Current, Target Image (index 4-7)
                        phases.forEach((p, i) => {
                            const statusKey = `${p}_status`;
                            if (data[statusKey]) {
                                const cell = cells[4 + i];
                                if (cell) {
                                    cell.innerHTML = data[statusKey] === 'completed'
                                        ? '<span style="color:var(--success-color);">&#10003;</span>'
                                        : data[statusKey] === 'running'
                                        ? '<span style="color:var(--info-color);">&#9881;</span>'
                                        : data[statusKey] === 'failed'
                                        ? '<span style="color:var(--error-color);">&#10007;</span>'
                                        : '<span style="opacity:0.3;">&#8226;</span>';
                                }
                            }
                        });
                        // Update error message / status column (last column)
                        const lastCell = cells[cells.length - 1];
                        if (lastCell) {
                            if (data.error_message) {
                                const short = data.error_message.length > 40
                                    ? data.error_message.substring(0, 40) + '...'
                                    : data.error_message;
                                lastCell.innerHTML = `<span style="color:var(--error-color); font-size:0.85em;" title="${escapeHtml(data.error_message)}">${escapeHtml(short)}</span>`;
                            } else if ('error_message' in data) {
                                // Explicitly cleared — show phase instead
                                const phase = data.verify_status === 'completed' ? 'verified'
                                    : data.activate_status === 'completed' ? 'completed'
                                    : '';
                                lastCell.innerHTML = `<span style="opacity:0.5;">${phase || 'ok'}</span>`;
                            }
                        }
                    }
                    return;
                }

                const output = document.getElementById('upgrade-live-output');
                if (output) {
                    const line = document.createElement('div');
                    line.className = `job-output-line ${data.level || 'info'}`;
                    const ts = data.timestamp ? data.timestamp.substring(11, 19) : '';
                    const host = data.host ? `${data.host}: ` : '';
                    line.textContent = `[${ts}] ${host}${data.message}`;
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                }
            },
            (data) => {
                // Phase complete — reload campaign detail
                showToast(`Campaign phase ${data.phase || ''} ${data.status || 'complete'}`, 'success');
                viewCampaign(campaignId);
            },
            (err) => {
                const output = document.getElementById('upgrade-live-output');
                if (output) {
                    const line = document.createElement('div');
                    line.className = 'job-output-line error';
                    line.textContent = '[WebSocket Error] Connection lost';
                    output.appendChild(line);
                }
            },
            (events) => {
                // Batch replay — build all lines in a fragment, append once
                const output = document.getElementById('upgrade-live-output');
                if (!output) return;
                const frag = document.createDocumentFragment();
                for (const data of events) {
                    if (data.type === 'device_status') continue;
                    const line = document.createElement('div');
                    line.className = `job-output-line ${data.level || 'info'}`;
                    const ts = data.timestamp ? data.timestamp.substring(11, 19) : '';
                    const host = data.host ? `${data.host}: ` : '';
                    line.textContent = `[${ts}] ${host}${data.message}`;
                    frag.appendChild(line);
                }
                output.appendChild(frag);
                output.scrollTop = output.scrollHeight;
            }
        );
    } catch (err) {
        showToast('Failed to load campaign: ' + err.message, 'error');
    }
}
window.viewCampaign = viewCampaign;

// ═══════════════════════════════════════════════════════════════════════════════
// Campaign Phase Execution
// ═══════════════════════════════════════════════════════════════════════════════

async function executeCampaignPhase(campaignId, phase) {
    const confirmMsg = phase === 'activate'
        ? 'This will reload switches and cause downtime. Are you sure?'
        : phase === 'verify'
        ? 'Connect to each switch and check the running version against the target?'
        : `Run ${phase} phase on all campaign devices?`;

    const confirmed = await showConfirm({
        title: phase === 'verify' ? 'Verify Upgrade' : `Execute ${phase.charAt(0).toUpperCase() + phase.slice(1)}`,
        message: confirmMsg,
        confirmText: phase === 'activate' ? 'Activate & Reload' : phase === 'verify' ? 'Verify' : `Run ${phase}`,
        confirmClass: phase === 'activate' ? 'btn-danger' : 'btn-primary',
    });
    if (!confirmed) return;

    try {
        await api.apiPost(`/api/upgrades/campaigns/${campaignId}/execute`, { phase });
        showToast(`${phase} phase started`, 'success');
        // Refresh the campaign view to show running state
        viewCampaign(campaignId);
    } catch (err) {
        showToast(`Failed to start ${phase}: ${err.message}`, 'error');
    }
}
window.executeCampaignPhase = executeCampaignPhase;

async function cancelCampaignPhase(campaignId) {
    try {
        await api.apiPost(`/api/upgrades/campaigns/${campaignId}/cancel`);
        showToast('Campaign cancelled', 'success');
        viewCampaign(campaignId);
    } catch (err) {
        showToast('Cancel failed: ' + err.message, 'error');
    }
}
window.cancelCampaignPhase = cancelCampaignPhase;

async function deleteCampaign(campaignId) {
    const confirmed = await showConfirm({
        title: 'Delete Campaign',
        message: 'This will permanently delete the campaign and all associated data.',
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
    });
    if (!confirmed) return;
    try {
        await api.apiDelete(`/api/upgrades/campaigns/${campaignId}`);
        showToast('Campaign deleted', 'success');
        closeAllModals();
        loadUpgradeCampaigns();
    } catch (err) {
        showToast('Delete failed: ' + err.message, 'error');
    }
}
window.deleteCampaign = deleteCampaign;

// ═══════════════════════════════════════════════════════════════════════════════
// Device Upgrade Log
// ═══════════════════════════════════════════════════════════════════════════════

async function viewDeviceUpgradeLog(campaignId, deviceId, ip) {
    try {
        const events = await api.apiGet(`/api/upgrades/campaigns/${campaignId}/events?device_id=${deviceId}`);
        showModal(`Upgrade Log: ${escapeHtml(ip)}`, `
            <div class="job-output upgrade-live-output">
                ${events.map(ev => {
                    const ts = ev.timestamp ? ev.timestamp.substring(11, 19) : '';
                    return `<div class="job-output-line ${ev.level || 'info'}">[${ts}] ${escapeHtml(ev.message)}</div>`;
                }).join('')}
                ${events.length === 0 ? '<div style="opacity:0.5;">No events yet for this device</div>' : ''}
            </div>
        `);
    } catch (err) {
        showToast('Failed to load log: ' + err.message, 'error');
    }
}
window.viewDeviceUpgradeLog = viewDeviceUpgradeLog;

// ═══════════════════════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════════════════════

export function destroyUpgrades() {
    disconnectUpgradeWebSocket();
}

/**
 * floor-plan.js — Geolocation and Floor Plan Mapping module.
 *
 * Provides:
 *   - Site list with online/offline/unknown device status summary
 *   - Floor plan viewer with drag-and-drop device pin placement
 *   - Site/floor CRUD and floor plan image upload
 *   - Device inventory sidebar for placing unplaced devices
 */
import * as api from '../api.js';
import { escapeHtml, showError, showToast } from '../app.js';

// ── Module state ──────────────────────────────────────────────────────────────
let _sites = [];
let _currentSite = null;      // { id, name, floors, … }
let _currentFloor = null;     // { id, name, image_filename, … }
let _placements = [];         // device pins on current floor
let _allHosts = [];           // inventory hosts (for placement sidebar)
let _dragState = null;        // active drag info

// ── Entry point ───────────────────────────────────────────────────────────────
export async function loadFloorPlan({ preserveContent = false } = {}) {
    const page = document.getElementById('page-floor-plan');
    if (!page) return;

    _ensureLayout(page);
    await _loadSites();
}

// ── Layout bootstrap ─────────────────────────────────────────────────────────
function _ensureLayout(page) {
    if (page.querySelector('#geo-sites-panel')) return;
    page.innerHTML = `
<div class="page-header">
    <h2>Floor Plan Mapping</h2>
    <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="geoShowAddSiteModal()">+ Add Site</button>
        <button class="btn btn-secondary" onclick="geoRefresh()">Refresh</button>
    </div>
</div>
<div id="geo-body" style="display:flex; gap:1rem; height:calc(100vh - 180px); overflow:hidden;">
    <!-- Left: site + floor tree -->
    <div id="geo-sites-panel" style="width:240px; min-width:180px; flex-shrink:0; overflow-y:auto; background:var(--card-bg); border:1px solid var(--border); border-radius:var(--radius); padding:0.5rem;">
        <div id="geo-sites-list"><div class="skeleton skeleton-card"></div></div>
    </div>
    <!-- Right: floor plan canvas -->
    <div id="geo-canvas-wrap" style="flex:1; display:flex; flex-direction:column; overflow:hidden; background:var(--card-bg); border:1px solid var(--border); border-radius:var(--radius);">
        <div id="geo-canvas-toolbar" style="display:flex; gap:0.5rem; align-items:center; padding:0.5rem 0.75rem; border-bottom:1px solid var(--border); flex-wrap:wrap;">
            <span id="geo-breadcrumb" style="font-size:0.85rem; color:var(--text-muted);">Select a site and floor</span>
            <span style="flex:1"></span>
            <button class="btn btn-sm btn-secondary" id="geo-add-floor-btn" style="display:none" onclick="geoShowAddFloorModal()">+ Add Floor</button>
            <button class="btn btn-sm btn-secondary" id="geo-upload-image-btn" style="display:none" onclick="geoShowUploadImageModal()">Upload Floor Plan</button>
            <button class="btn btn-sm btn-secondary" id="geo-edit-floor-btn" style="display:none" onclick="geoShowEditFloorModal()">Edit Floor</button>
            <button class="btn btn-sm btn-danger" id="geo-delete-floor-btn" style="display:none" onclick="geoConfirmDeleteFloor()">Delete Floor</button>
            <label id="geo-place-mode-label" style="display:none; align-items:center; gap:0.4rem; font-size:0.82rem;">
                <input type="checkbox" id="geo-place-mode-toggle" onchange="geoTogglePlaceMode()">
                Edit pins
            </label>
        </div>
        <div id="geo-canvas-area" style="flex:1; overflow:auto; position:relative; background:var(--bg);">
            <div id="geo-empty-state" style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; color:var(--text-muted); gap:0.5rem;">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6M9 12h6M9 15h4"/></svg>
                <p style="margin:0;">Select a floor to view its map.</p>
            </div>
            <div id="geo-floor-container" style="display:none; position:relative; width:fit-content;">
                <img id="geo-floor-img" src="" alt="Floor plan" style="display:block; max-width:100%; user-select:none; -webkit-user-drag:none;" draggable="false">
                <div id="geo-pins-layer" style="position:absolute; inset:0; pointer-events:none;"></div>
            </div>
        </div>
        <!-- Device sidebar (shown when place mode is on) -->
        <div id="geo-device-sidebar" style="display:none; border-top:1px solid var(--border); max-height:200px; overflow-y:auto; padding:0.5rem 0.75rem;">
            <div style="font-size:0.8rem; font-weight:600; margin-bottom:0.4rem; color:var(--text-muted);">UNPLACED DEVICES — drag onto the floor plan above</div>
            <div id="geo-unplaced-list" style="display:flex; flex-wrap:wrap; gap:0.4rem;"></div>
        </div>
    </div>
</div>
<!-- Hidden modals anchor -->
<div id="geo-modals"></div>`;

    // Expose globally for onclick handlers
    window.geoRefresh = _refresh;
    window.geoShowAddSiteModal = _showAddSiteModal;
    window.geoShowAddFloorModal = _showAddFloorModal;
    window.geoShowUploadImageModal = _showUploadImageModal;
    window.geoShowEditFloorModal = _showEditFloorModal;
    window.geoConfirmDeleteFloor = _confirmDeleteFloor;
    window.geoTogglePlaceMode = _togglePlaceMode;
}

// ── Data loading ──────────────────────────────────────────────────────────────
async function _loadSites() {
    try {
        _sites = await api.getGeoOverview();
        _renderSiteList();
    } catch (e) {
        showError('Failed to load geo sites: ' + e.message);
    }
}

async function _refresh() {
    await _loadSites();
    if (_currentFloor) {
        await _loadFloor(_currentFloor.id);
    }
}

// ── Site list ─────────────────────────────────────────────────────────────────
function _renderSiteList() {
    const el = document.getElementById('geo-sites-list');
    if (!el) return;
    if (!_sites.length) {
        el.innerHTML = `<div style="padding:0.75rem; color:var(--text-muted); font-size:0.82rem;">No sites yet.<br>Click <strong>+ Add Site</strong> to create one.</div>`;
        return;
    }
    el.innerHTML = _sites.map(s => {
        const online = parseInt(s.online_count) || 0;
        const offline = parseInt(s.offline_count) || 0;
        const unknown = parseInt(s.unknown_count) || 0;
        const placed = parseInt(s.placed_device_count) || 0;
        const floors = parseInt(s.floor_count) || 0;
        const active = _currentSite && _currentSite.id === s.id;
        return `
<div class="geo-site-item${active ? ' active' : ''}" onclick="geoSelectSite(${s.id})" style="padding:0.5rem 0.6rem; border-radius:4px; cursor:pointer; margin-bottom:2px; ${active ? 'background:var(--primary-muted);' : 'hover:background:var(--hover-bg);'}">
    <div style="font-weight:600; font-size:0.85rem;">${escapeHtml(s.name)}</div>
    ${s.address ? `<div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(s.address)}</div>` : ''}
    <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">
        ${floors} floor${floors !== 1 ? 's' : ''} · ${placed} pinned
        ${online ? `<span style="color:#4caf50;">&#9679; ${online}</span> ` : ''}
        ${offline ? `<span style="color:#f44336;">&#9679; ${offline}</span> ` : ''}
        ${unknown ? `<span style="color:#9e9e9e;">&#9679; ${unknown}</span>` : ''}
    </div>
    <div id="geo-floors-${s.id}" class="geo-floor-list" style="display:${active ? 'block' : 'none'}; margin-top:0.4rem; padding-left:0.6rem;"></div>
</div>`;
    }).join('');

    window.geoSelectSite = _selectSite;
    window.geoSelectFloor = _selectFloor;

    // Re-render active site's floor list
    if (_currentSite) {
        _renderFloorListFor(_currentSite);
    }
}

async function _selectSite(siteId) {
    if (_currentSite && _currentSite.id === siteId) return;
    try {
        _currentSite = await api.getGeoSite(siteId);
    } catch (e) {
        showError('Failed to load site: ' + e.message);
        return;
    }
    _currentFloor = null;
    _placements = [];
    _renderSiteList();
    _showEmptyState('Select a floor to view its map.');
    _updateToolbarButtons();
}

function _renderFloorListFor(site) {
    const el = document.getElementById(`geo-floors-${site.id}`);
    if (!el) return;
    const floors = site.floors || [];
    if (!floors.length) {
        el.innerHTML = `<div style="font-size:0.75rem; color:var(--text-muted);">No floors — add one above</div>`;
    } else {
        el.innerHTML = floors.map(f => {
            const active = _currentFloor && _currentFloor.id === f.id;
            return `<div class="geo-floor-item${active ? ' active' : ''}" onclick="geoSelectFloor(${f.id})" style="padding:3px 6px; border-radius:3px; cursor:pointer; font-size:0.81rem; ${active ? 'background:var(--primary-muted); font-weight:600;' : ''}">
    ${escapeHtml(f.name)}${f.placed_device_count ? ` <span style="color:var(--text-muted);">(${f.placed_device_count})</span>` : ''}
</div>`;
        }).join('');
    }
    el.style.display = 'block';
}

async function _selectFloor(floorId) {
    await _loadFloor(floorId);
}

async function _loadFloor(floorId) {
    try {
        _currentFloor = await api.getGeoFloor(floorId);
        _placements = await api.getFloorPlacements(floorId);
    } catch (e) {
        showError('Failed to load floor: ' + e.message);
        return;
    }
    _renderFloorCanvas();
    _updateToolbarButtons();
    _renderSiteList(); // refresh active states
}

// ── Toolbar helpers ───────────────────────────────────────────────────────────
function _updateToolbarButtons() {
    const hasSite = Boolean(_currentSite);
    const hasFloor = Boolean(_currentFloor);
    const crumb = document.getElementById('geo-breadcrumb');
    if (crumb) {
        crumb.textContent = hasFloor
            ? `${_currentSite.name} › ${_currentFloor.name}`
            : hasSite ? _currentSite.name : 'Select a site and floor';
    }
    _setDisplay('geo-add-floor-btn', hasSite);
    _setDisplay('geo-upload-image-btn', hasFloor);
    _setDisplay('geo-edit-floor-btn', hasFloor);
    _setDisplay('geo-delete-floor-btn', hasFloor);
    _setDisplay('geo-place-mode-label', hasFloor);
}

function _setDisplay(id, show) {
    const el = document.getElementById(id);
    if (el) el.style.display = show ? '' : 'none';
}

// ── Floor plan canvas ─────────────────────────────────────────────────────────
function _showEmptyState(msg) {
    const empty = document.getElementById('geo-empty-state');
    const container = document.getElementById('geo-floor-container');
    if (empty) { empty.style.display = 'flex'; if (msg) empty.querySelector('p').textContent = msg; }
    if (container) container.style.display = 'none';
}

function _renderFloorCanvas() {
    const empty = document.getElementById('geo-empty-state');
    const container = document.getElementById('geo-floor-container');
    if (!container) return;

    if (!_currentFloor.image_filename) {
        _showEmptyState('No floor plan image. Use "Upload Floor Plan" to add one.');
        return;
    }

    if (empty) empty.style.display = 'none';
    container.style.display = 'block';

    const img = document.getElementById('geo-floor-img');
    img.src = api.floorImageUrl(_currentFloor.id) + '?t=' + Date.now();
    img.onload = () => _renderPins();

    _renderPins();
}

function _renderPins() {
    const layer = document.getElementById('geo-pins-layer');
    const img = document.getElementById('geo-floor-img');
    if (!layer || !img) return;

    const placeModeOn = document.getElementById('geo-place-mode-toggle')?.checked;
    layer.style.pointerEvents = placeModeOn ? 'auto' : 'none';

    layer.innerHTML = _placements.map(p => {
        const statusColor = _statusColor(p.status);
        const x = (p.x_pct * 100).toFixed(2);
        const y = (p.y_pct * 100).toFixed(2);
        return `
<div class="geo-pin" data-host-id="${p.host_id}"
     style="position:absolute; left:${x}%; top:${y}%; transform:translate(-50%,-100%); cursor:${placeModeOn ? 'grab' : 'default'}; user-select:none;"
     title="${escapeHtml(p.hostname)} (${escapeHtml(p.ip_address || '')})">
    <svg width="24" height="32" viewBox="0 0 24 32" fill="${statusColor}" stroke="rgba(0,0,0,0.4)" stroke-width="1">
        <path d="M12 0C5.4 0 0 5.4 0 12c0 8.4 12 20 12 20s12-11.6 12-20C24 5.4 18.6 0 12 0z"/>
    </svg>
    <div style="position:absolute; top:1px; left:50%; transform:translateX(-50%); font-size:9px; color:#fff; font-weight:700; text-shadow:0 0 2px rgba(0,0,0,0.7); width:22px; text-align:center; overflow:hidden; white-space:nowrap;">${escapeHtml((p.hostname || '').slice(0, 3).toUpperCase())}</div>
</div>`;
    }).join('');

    if (placeModeOn) {
        layer.querySelectorAll('.geo-pin').forEach(pin => {
            pin.addEventListener('mousedown', _onPinMouseDown);
        });
        // Allow dropping onto the layer to place new devices
        layer.style.pointerEvents = 'auto';
        layer.addEventListener('dragover', e => e.preventDefault());
        layer.addEventListener('drop', _onCanvasDrop);
    }
}

function _statusColor(status) {
    if (status === 'up' || status === 'online') return '#4caf50';
    if (status === 'down' || status === 'offline') return '#f44336';
    return '#9e9e9e';
}

// ── Pin drag (existing pins) ──────────────────────────────────────────────────
function _onPinMouseDown(e) {
    const pin = e.currentTarget;
    const hostId = parseInt(pin.dataset.hostId);
    if (!hostId || isNaN(hostId)) return;
    e.preventDefault();
    const placement = _placements.find(p => p.host_id === hostId);
    if (!placement) return;

    _dragState = { hostId, pin, startX: e.clientX, startY: e.clientY };
    pin.style.cursor = 'grabbing';

    const onMove = (me) => {
        const layer = document.getElementById('geo-pins-layer');
        const img = document.getElementById('geo-floor-img');
        if (!layer || !img) return;
        const rect = img.getBoundingClientRect();
        const x = Math.max(0, Math.min(1, (me.clientX - rect.left) / rect.width));
        const y = Math.max(0, Math.min(1, (me.clientY - rect.top) / rect.height));
        pin.style.left = (x * 100).toFixed(2) + '%';
        pin.style.top = (y * 100).toFixed(2) + '%';
        _dragState.x = x;
        _dragState.y = y;
    };

    const onUp = async () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        pin.style.cursor = 'grab';
        if (_dragState && _dragState.x != null && _currentFloor) {
            try {
                await api.upsertFloorPlacement(_currentFloor.id, _dragState.hostId, _dragState.x, _dragState.y);
                // Update local state
                const p = _placements.find(pl => pl.host_id === _dragState.hostId);
                if (p) { p.x_pct = _dragState.x; p.y_pct = _dragState.y; }
            } catch (err) {
                showError('Failed to save pin position: ' + err.message);
                _renderPins(); // revert visual
            }
        }
        _dragState = null;
    };

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
}

// ── Drop new devices from sidebar ─────────────────────────────────────────────
async function _onCanvasDrop(e) {
    e.preventDefault();
    const hostId = parseInt(e.dataTransfer.getData('text/plain'));
    if (!hostId || isNaN(hostId) || !_currentFloor) return;
    const img = document.getElementById('geo-floor-img');
    if (!img) return;
    const rect = img.getBoundingClientRect();
    const x = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const y = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));
    try {
        await api.upsertFloorPlacement(_currentFloor.id, hostId, x, y);
        _placements = await api.getFloorPlacements(_currentFloor.id);
        _renderPins();
        _renderUnplacedDevices();
        showToast('Device placed', 'success');
    } catch (err) {
        showError('Failed to place device: ' + err.message);
    }
}

// ── Place mode toggle ─────────────────────────────────────────────────────────
async function _togglePlaceMode() {
    const on = document.getElementById('geo-place-mode-toggle')?.checked;
    const sidebar = document.getElementById('geo-device-sidebar');
    if (!sidebar) return;
    sidebar.style.display = on ? 'block' : 'none';

    if (on && !_allHosts.length) {
        try {
            const resp = await api.getInventoryGroups(false);
            // Get all hosts from all groups
            _allHosts = [];
            await Promise.all((resp || []).map(async g => {
                try {
                    const hosts = await api.getHostsForGroup(g.id);
                    _allHosts.push(...(hosts || []));
                } catch (_) {}
            }));
        } catch (e) { /* ignore */ }
    }

    _renderPins();
    if (on) _renderUnplacedDevices();
}

function _renderUnplacedDevices() {
    const el = document.getElementById('geo-unplaced-list');
    if (!el) return;
    const placedIds = new Set(_placements.map(p => p.host_id));
    const unplaced = _allHosts.filter(h => !placedIds.has(h.id));
    if (!unplaced.length) {
        el.innerHTML = '<span style="font-size:0.8rem; color:var(--text-muted);">All devices placed.</span>';
        return;
    }
    el.innerHTML = unplaced.map(h => `
<div class="geo-device-chip" draggable="true"
     data-host-id="${h.id}"
     style="padding:3px 8px; background:var(--card-bg); border:1px solid var(--border); border-radius:12px; font-size:0.78rem; cursor:grab; user-select:none;">
    <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${_statusColor(h.status)}; margin-right:4px;"></span>${escapeHtml(h.hostname)}
</div>`).join('');

    el.querySelectorAll('.geo-device-chip').forEach(chip => {
        chip.addEventListener('dragstart', e => {
            e.dataTransfer.setData('text/plain', chip.dataset.hostId);
            e.dataTransfer.effectAllowed = 'copy';
        });
    });
}

// ── Site / Floor CRUD modals ──────────────────────────────────────────────────
function _modal(title, bodyHtml, footerHtml) {
    const overlay = document.getElementById('modal-overlay');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');
    if (!overlay || !modalTitle || !modalBody) return;
    modalTitle.textContent = title;
    modalBody.innerHTML = bodyHtml;
    overlay.querySelector('.modal-footer')?.remove();
    if (footerHtml) {
        const footer = document.createElement('div');
        footer.className = 'modal-footer';
        footer.innerHTML = footerHtml;
        overlay.querySelector('.modal').appendChild(footer);
    }
    overlay.classList.add('active');
}

function _showAddSiteModal() {
    _modal('Add Site',
        `<div class="form-group"><label>Name *</label><input class="form-input" id="geo-site-name" placeholder="Site name" autofocus></div>
         <div class="form-group"><label>Address</label><input class="form-input" id="geo-site-address" placeholder="Street address or description"></div>
         <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
             <div class="form-group"><label>Latitude</label><input class="form-input" id="geo-site-lat" type="number" step="any" placeholder="-90 to 90"></div>
             <div class="form-group"><label>Longitude</label><input class="form-input" id="geo-site-lng" type="number" step="any" placeholder="-180 to 180"></div>
         </div>`,
        `<button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
         <button class="btn btn-primary" onclick="geoSubmitAddSite()">Create Site</button>`);
    window.geoSubmitAddSite = _submitAddSite;
}

async function _submitAddSite() {
    const name = document.getElementById('geo-site-name')?.value?.trim();
    if (!name) { showError('Site name is required'); return; }
    const address = document.getElementById('geo-site-address')?.value?.trim() || '';
    const latRaw = document.getElementById('geo-site-lat')?.value?.trim();
    const lngRaw = document.getElementById('geo-site-lng')?.value?.trim();
    const lat = latRaw ? parseFloat(latRaw) : null;
    const lng = lngRaw ? parseFloat(lngRaw) : null;
    try {
        await api.createGeoSite({ name, address, lat, lng });
        window.closeAllModals();
        showToast(`Site '${name}' created`, 'success');
        await _loadSites();
    } catch (e) {
        showError('Failed to create site: ' + e.message);
    }
}

function _showAddFloorModal() {
    if (!_currentSite) return;
    _modal('Add Floor',
        `<div class="form-group"><label>Floor Name *</label><input class="form-input" id="geo-floor-name" placeholder="e.g. Building A – Floor 2" autofocus></div>
         <div class="form-group"><label>Floor Number</label><input class="form-input" id="geo-floor-number" type="number" value="0" placeholder="0"></div>`,
        `<button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
         <button class="btn btn-primary" onclick="geoSubmitAddFloor()">Add Floor</button>`);
    window.geoSubmitAddFloor = _submitAddFloor;
}

async function _submitAddFloor() {
    const name = document.getElementById('geo-floor-name')?.value?.trim();
    if (!name) { showError('Floor name is required'); return; }
    const floorNumber = parseInt(document.getElementById('geo-floor-number')?.value || '0');
    try {
        await api.createGeoFloor(_currentSite.id, { name, floor_number: floorNumber });
        window.closeAllModals();
        showToast(`Floor '${name}' added`, 'success');
        _currentSite = await api.getGeoSite(_currentSite.id);
        _renderSiteList();
        _renderFloorListFor(_currentSite);
    } catch (e) {
        showError('Failed to add floor: ' + e.message);
    }
}

function _showEditFloorModal() {
    if (!_currentFloor) return;
    _modal('Edit Floor',
        `<div class="form-group"><label>Floor Name *</label><input class="form-input" id="geo-edit-floor-name" value="${escapeHtml(_currentFloor.name)}" autofocus></div>
         <div class="form-group"><label>Floor Number</label><input class="form-input" id="geo-edit-floor-number" type="number" value="${_currentFloor.floor_number || 0}"></div>`,
        `<button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
         <button class="btn btn-primary" onclick="geoSubmitEditFloor()">Save</button>`);
    window.geoSubmitEditFloor = _submitEditFloor;
}

async function _submitEditFloor() {
    const name = document.getElementById('geo-edit-floor-name')?.value?.trim();
    if (!name) { showError('Floor name is required'); return; }
    const floorNumber = parseInt(document.getElementById('geo-edit-floor-number')?.value || '0');
    try {
        _currentFloor = await api.updateGeoFloor(_currentFloor.id, { name, floor_number: floorNumber });
        window.closeAllModals();
        showToast('Floor updated', 'success');
        if (_currentSite) {
            _currentSite = await api.getGeoSite(_currentSite.id);
        }
        _updateToolbarButtons();
        _renderSiteList();
    } catch (e) {
        showError('Failed to update floor: ' + e.message);
    }
}

function _showUploadImageModal() {
    if (!_currentFloor) return;
    _modal('Upload Floor Plan Image',
        `<p style="font-size:0.85rem; color:var(--text-muted);">Upload a JPEG, PNG, GIF, WebP, or SVG image of the floor plan. Max 20 MB.</p>
         <div class="form-group"><label>Image file</label><input type="file" id="geo-image-file" accept="image/jpeg,image/png,image/gif,image/webp,image/svg+xml" class="form-input"></div>`,
        `<button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
         <button class="btn btn-primary" onclick="geoSubmitUploadImage()">Upload</button>`);
    window.geoSubmitUploadImage = _submitUploadImage;
}

async function _submitUploadImage() {
    const input = document.getElementById('geo-image-file');
    const file = input?.files?.[0];
    if (!file) { showError('Please select an image file'); return; }
    try {
        await api.uploadFloorImage(_currentFloor.id, file);
        window.closeAllModals();
        showToast('Floor plan uploaded', 'success');
        _currentFloor = await api.getGeoFloor(_currentFloor.id);
        _renderFloorCanvas();
    } catch (e) {
        showError('Upload failed: ' + e.message);
    }
}

async function _confirmDeleteFloor() {
    if (!_currentFloor) return;
    if (!confirm(`Delete floor "${_currentFloor.name}" and all its device pins?`)) return;
    try {
        await api.deleteGeoFloor(_currentFloor.id);
        showToast('Floor deleted', 'success');
        _currentFloor = null;
        _placements = [];
        if (_currentSite) {
            _currentSite = await api.getGeoSite(_currentSite.id);
        }
        _renderSiteList();
        _showEmptyState('Floor deleted. Select another floor.');
        _updateToolbarButtons();
    } catch (e) {
        showError('Failed to delete floor: ' + e.message);
    }
}

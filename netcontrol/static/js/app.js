/**
 * Main Application Logic
 */

import * as api from './api.js';
import { connectJobWebSocket, disconnectJobWebSocket } from './websocket.js';

// Global state
let currentPage = 'dashboard';
let dashboardData = null;
const _hostCache = {};
const _groupCache = {};
let converterSessionId = null;
let currentFeatureAccess = [];

const NAV_FEATURE_MAP = {
    dashboard: 'dashboard',
    inventory: 'inventory',
    playbooks: 'playbooks',
    jobs: 'jobs',
    templates: 'templates',
    credentials: 'credentials',
    converter: 'converter',
};

const THEME_KEY = 'plexus-theme';
const VALID_THEMES = ['forest', 'dark', 'dark-modern', 'easy', 'easy-dark', 'light'];
const DEFAULT_THEME = 'forest';

function normalizeTheme(theme) {
    return VALID_THEMES.includes(theme) ? theme : DEFAULT_THEME;
}

function applyTheme(theme) {
    const chosen = normalizeTheme(theme);
    document.documentElement.setAttribute('data-theme', chosen);
    localStorage.setItem(THEME_KEY, chosen);
    ['theme-select', 'theme-select-settings'].forEach((id) => {
        const select = document.getElementById(id);
        if (select) select.value = chosen;
    });
}

function initThemeControls() {
    const savedTheme = localStorage.getItem(THEME_KEY) || DEFAULT_THEME;
    applyTheme(savedTheme);

    ['theme-select', 'theme-select-settings'].forEach((id) => {
        const select = document.getElementById(id);
        if (select && select.dataset.themeBound !== '1') {
            select.addEventListener('change', (e) => applyTheme(e.target.value));
            select.dataset.themeBound = '1';
        }
    });
}

function canAccessFeature(feature) {
    if (currentUserData?.role === 'admin') return true;
    if (!Array.isArray(currentFeatureAccess) || currentFeatureAccess.length === 0) return true;
    return currentFeatureAccess.includes(feature);
}

function applyFeatureVisibility() {
    document.querySelectorAll('.nav-link[data-page]').forEach((link) => {
        const page = link.getAttribute('data-page');
        const feature = NAV_FEATURE_MAP[page];
        if (!feature) return;
        link.style.display = canAccessFeature(feature) ? '' : 'none';
    });

    const settingsLink = document.querySelector('.nav-link[data-page="settings"]');
    if (settingsLink) {
        settingsLink.style.display = currentUserData?.role === 'admin' ? '' : 'none';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Navigation
// ═══════════════════════════════════════════════════════════════════════════════

function initNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.getAttribute('data-page');
            navigateToPage(page);
        });
    });
}

function navigateToPage(page) {
    if (page === 'settings' && currentUserData?.role !== 'admin') {
        showError('Admin access required for Settings');
        return;
    }
    if (NAV_FEATURE_MAP[page] && !canAccessFeature(NAV_FEATURE_MAP[page])) {
        showError(`Your account does not have access to ${page}`);
        return;
    }

    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === page) {
            link.classList.add('active');
        }
    });

    // Hide all pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    // Show target page
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
        currentPage = page;
        loadPageData(page);
    }
}

async function loadPageData(page) {
    try {
        switch (page) {
            case 'dashboard':
                await loadDashboard();
                break;
            case 'inventory':
                await loadInventory();
                break;
            case 'playbooks':
                await loadPlaybooks();
                break;
            case 'jobs':
                await loadJobs();
                break;
            case 'templates':
                await loadTemplates();
                break;
            case 'credentials':
                await loadCredentials();
                break;
            case 'settings':
                await loadAdminSettings();
                break;
            case 'converter':
                await loadConverter();
                break;
        }
    } catch (error) {
        console.error(`Error loading ${page}:`, error);
        showError(`Failed to load ${page}: ${error.message}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Converter
// ═══════════════════════════════════════════════════════════════════════════════

// Firewall brand/model data
const FIREWALL_MODELS = {
    source: {
        fortinet: [
            { value: 'fortigate-60f',   label: 'FortiGate 60F' },
            { value: 'fortigate-80f',   label: 'FortiGate 80F' },
            { value: 'fortigate-100f',  label: 'FortiGate 100F' },
            { value: 'fortigate-200f',  label: 'FortiGate 200F' },
            { value: 'fortigate-300e',  label: 'FortiGate 300E' },
            { value: 'fortigate-400e',  label: 'FortiGate 400E' },
            { value: 'fortigate-500e',  label: 'FortiGate 500E' },
            { value: 'fortigate-600e',  label: 'FortiGate 600E' },
            { value: 'fortigate-1000d', label: 'FortiGate 1000D' },
            { value: 'fortigate-2000e', label: 'FortiGate 2000E' },
            { value: 'fortigate-3000d', label: 'FortiGate 3000D' },
            { value: 'fortigate-3200d', label: 'FortiGate 3200D' },
            { value: 'fortigate-3600e', label: 'FortiGate 3600E' },
            { value: 'fortigate-3980e', label: 'FortiGate 3980E' },
            { value: 'fortigate-6300f', label: 'FortiGate 6300F' },
            { value: 'fortigate-6500f', label: 'FortiGate 6500F' },
        ]
    },
    target: {
        cisco: [
            { value: 'ftd-1010', label: 'Firepower 1010' },
            { value: 'ftd-1120', label: 'Firepower 1120' },
            { value: 'ftd-1140', label: 'Firepower 1140' },
            { value: 'ftd-2110', label: 'Firepower 2110' },
            { value: 'ftd-2120', label: 'Firepower 2120' },
            { value: 'ftd-2130', label: 'Firepower 2130' },
            { value: 'ftd-2140', label: 'Firepower 2140' },
            { value: 'ftd-3105', label: 'Secure Firewall 3105' },
            { value: 'ftd-3110', label: 'Secure Firewall 3110' },
            { value: 'ftd-3120', label: 'Secure Firewall 3120' },
            { value: 'ftd-3130', label: 'Secure Firewall 3130' },
            { value: 'ftd-3140', label: 'Secure Firewall 3140' },
            { value: 'ftd-4215', label: 'Secure Firewall 4215' },
        ]
    }
};

window.updateSourceModels = function () {
    const brand = document.getElementById('source-brand').value;
    const modelSelect = document.getElementById('source-model');
    const models = FIREWALL_MODELS.source[brand] || [];
    modelSelect.innerHTML = '<option value="">-- Select Model --</option>' +
        models.map(m => `<option value="${m.value}">${m.label}</option>`).join('');
};

window.updateTargetModels = function () {
    const brand = document.getElementById('target-brand').value;
    const modelSelect = document.getElementById('target-model');
    const models = FIREWALL_MODELS.target[brand] || [];
    modelSelect.innerHTML = '<option value="">-- Select Model --</option>' +
        models.map(m => `<option value="${m.value}">${m.label}</option>`).join('');
};

async function loadConverter() {
    const convertForm   = document.getElementById('converter-form');
    const importForm    = document.getElementById('import-form');
    const statusDiv     = document.getElementById('converter-status');
    const step2         = document.getElementById('converter-step2');
    const step3         = document.getElementById('converter-step3');
    const outputWindow  = document.getElementById('converter-output-window');
    const summaryCards  = document.getElementById('converter-summary-cards');
    const importOutput  = document.getElementById('import-output-window');
    const cleanupForm   = document.getElementById('cleanup-form');
    const cleanupOutput = document.getElementById('cleanup-output-window');
    const recentSessions = document.getElementById('recent-sessions');
    const configSection = document.getElementById('session-config-preview');
    const configFileSelect = document.getElementById('session-config-file');
    const configContent = document.getElementById('session-config-content');
    const configMeta = document.getElementById('session-config-meta');
    const importSelectAll = document.getElementById('import-only-select-all');

    // Bail out if any required element is missing
    if (!convertForm || !importForm || !statusDiv || !step2 || !outputWindow || !summaryCards || !importOutput) {
        console.error('Converter: missing DOM elements', { convertForm, importForm, statusDiv, step2, outputWindow, summaryCards, importOutput });
        return;
    }

    // Reset state on page load
    convertForm.reset();
    statusDiv.textContent = '';
    step2.style.display = 'none';
    if (step3) step3.style.display = 'block';
    importOutput.style.display = 'none';

    converterSessionId = null;

    function syncImportOnlySelectAll() {
        if (!importSelectAll) return;
        const onlyFlags = [...document.querySelectorAll('.only-flag')];
        const checkedCount = onlyFlags.filter(cb => cb.checked).length;

        importSelectAll.checked = onlyFlags.length > 0 && checkedCount === onlyFlags.length;
        importSelectAll.indeterminate = checkedCount > 0 && checkedCount < onlyFlags.length;
    }

    if (importSelectAll) {
        importSelectAll.onchange = () => {
            const checkAll = importSelectAll.checked;
            document.querySelectorAll('.only-flag').forEach((cb) => {
                cb.checked = checkAll;
            });
            importSelectAll.indeterminate = false;
        };
    }

    document.querySelectorAll('.only-flag').forEach((cb) => {
        cb.onchange = syncImportOnlySelectAll;
    });

    syncImportOnlySelectAll();

    function apiErrorMessage(data, fallback) {
        return data?.error?.message || data?.detail || fallback;
    }

    function renderSummary(summary) {
        const s = summary?.conversion_summary;
        if (s) {
            summaryCards.innerHTML = `
                <div class="stat-card"><div class="stat-label">Address Objects</div><div class="stat-value">${s.address_objects ?? '-'}</div></div>
                <div class="stat-card"><div class="stat-label">Address Groups</div><div class="stat-value">${s.address_groups ?? '-'}</div></div>
                <div class="stat-card"><div class="stat-label">Service Objects</div><div class="stat-value">${s.service_objects?.total ?? '-'}</div></div>
                <div class="stat-card"><div class="stat-label">Service Groups</div><div class="stat-value">${s.service_groups ?? '-'}</div></div>
                <div class="stat-card"><div class="stat-label">Access Rules</div><div class="stat-value">${s.access_rules?.total ?? '-'}</div></div>
                <div class="stat-card"><div class="stat-label">Static Routes</div><div class="stat-value">${s.static_routes?.total ?? '-'}</div></div>
            `;
        } else {
            summaryCards.innerHTML = '';
        }
    }

    async function loadSessionState(sessionId) {
        try {
            const resp = await fetch(`/api/converter-session-state?session_id=${encodeURIComponent(sessionId)}`);
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Failed to load session state'));

            const modelLabel = data.target_model || 'unknown';
            outputWindow.textContent = `[Backend confirmed target model: ${modelLabel}]\n\n` + (data.conversion_output || '(no output captured for this session)');
            renderSummary(data.summary || {});
            if (step2) step2.style.display = 'block';
            return data;
        } catch (err) {
            outputWindow.textContent = 'Error loading conversion output: ' + err.message;
            summaryCards.innerHTML = '';
            return null;
        }
    }

    // ── Step 1: Convert ──────────────────────────────────────────────────────
    convertForm.onsubmit = async (e) => {
        e.preventDefault();
        step2.style.display = 'none';
        converterSessionId = null;

        const targetModel = document.getElementById('target-model').value;
        const sourceModel = document.getElementById('source-model').value;

        if (!targetModel) {
            statusDiv.textContent = 'Error: Please select a target firewall brand and model before converting.';
            return;
        }
        if (!sourceModel) {
            statusDiv.textContent = 'Error: Please select a source firewall brand and model before converting.';
            return;
        }

        statusDiv.textContent = `Converting for target model: ${targetModel}...`;

        const formData = new FormData(convertForm);
        // Explicitly set model values to ensure they are included regardless of FormData capture behaviour
        formData.set('target_model', targetModel);
        formData.set('source_model', sourceModel);

        // Debug: confirm what is being sent
        console.log('[Converter] Sending target_model:', formData.get('target_model'), '| source_model:', formData.get('source_model'));

        try {
            const resp = await fetch('/api/convert-only', { method: 'POST', body: formData });
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Conversion failed'));

            converterSessionId = data.session_id;

            // Show raw output, prefixed with confirmed model from backend
            outputWindow.textContent = `[Backend confirmed target model: ${data.target_model}]\n\n` + (data.conversion_output || '(no output)');

            // Build summary stat cards
            renderSummary(data.summary || {});

            step2.style.display = 'block';
            if (step3) step3.style.display = 'block';
            statusDiv.textContent = 'Conversion complete. Review below, then import.';
            await loadRecentSessions();
        } catch (err) {
            statusDiv.textContent = 'Error: ' + err.message;
        }
    };

    // ── Recent sessions list ──────────────────────────────────────────────
    async function loadRecentSessions() {
        if (!recentSessions) return;
        recentSessions.innerHTML = '<div class="loading">Loading...</div>';
        try {
            const resp = await fetch('/api/converter-sessions');
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Failed to load sessions'));
            const sessions = data.sessions || [];
            if (!sessions.length) {
                recentSessions.innerHTML = '<div class="empty-state">No recent conversions found.</div>';
                return;
            }
            recentSessions.innerHTML = sessions.map(s => {
                const when = new Date(s.created_at * 1000).toLocaleString();
                return `
                    <div class="job-item">
                        <div class="job-info">
                            <div class="job-title">Session ${s.session_id}</div>
                            <div class="job-meta">Model: ${s.target_model || 'unknown'} • Base: ${s.base} • ${when}</div>
                        </div>
                        <div style="display:flex; gap:0.5rem;">
                            <button class="btn btn-sm" onclick="viewSessionConfig('${s.session_id}')">View</button>
                            <button class="btn btn-sm btn-secondary" onclick="resumeImport('${s.session_id}')">Import</button>
                            <button class="btn btn-sm" onclick="resumeCleanup('${s.session_id}')">Cleanup</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteSession('${s.session_id}')">Delete</button>
                        </div>
                    </div>
                `;
            }).join('');
        } catch (err) {
            recentSessions.innerHTML = `<div class="empty-state">Error: ${err.message}</div>`;
        }
    }

    window.deleteSession = async function (id) {
        const confirmed = await showConfirm({
            title: 'Delete Session',
            message: `Delete session ${id}? This removes its generated files.`,
            confirmText: 'Delete',
            cancelText: 'Keep Session',
            confirmClass: 'btn-danger'
        });
        if (!confirmed) return;
        try {
            const resp = await fetch('/api/reset-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: id })
            });
            if (!resp.ok) throw new Error('Delete failed');
            if (converterSessionId === id) {
                converterSessionId = null;
                const statusDiv = document.getElementById('converter-status');
                if (statusDiv) statusDiv.textContent = 'Active session deleted.';
            }
            await loadRecentSessions();
        } catch (err) {
            alert('Error deleting session: ' + err.message);
        }
    };

    function setActiveSession(id, message) {
        converterSessionId = id;
        if (statusDiv) statusDiv.textContent = message || `Using session ${id}.`;
        if (step2) step2.style.display = 'block';
        if (step3) step3.style.display = 'block';
    }

    window.resumeImport = function (id) {
        setActiveSession(id, `Resumed session ${id}. Provide FTD credentials to re-run import.`);
        loadSessionState(id);
        if (importOutput) { importOutput.textContent = ''; importOutput.style.display = 'none'; }
        if (cleanupOutput) { cleanupOutput.textContent = ''; cleanupOutput.style.display = 'none'; }
        document.getElementById('converter-step2')?.scrollIntoView({ behavior: 'smooth' });
    };

    window.resumeCleanup = function (id) {
        setActiveSession(id, `Resumed session ${id}. Provide FTD credentials to clean up.`);
        loadSessionState(id);
        if (cleanupOutput) { cleanupOutput.textContent = 'Ready to clean up this session.'; cleanupOutput.style.display = 'block'; }
        document.getElementById('converter-step3')?.scrollIntoView({ behavior: 'smooth' });
    };

    async function loadSessionConfigFile(sessionId, filename) {
        if (!configContent) return;
        if (!filename) { configContent.textContent = 'Select a file to preview.'; return; }
        configContent.textContent = 'Loading file...';
        try {
            const resp = await fetch(`/api/converter-session-file?session_id=${encodeURIComponent(sessionId)}&filename=${encodeURIComponent(filename)}`);
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Failed to load file'));
            const raw = data.content || '';
            const trimmed = raw.trim();
            if (!trimmed) {
                configContent.textContent = '(empty file)';
                return;
            }
            // Pretty-print JSON when possible; fallback to raw text on parse errors
            if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
                try {
                    const parsed = JSON.parse(trimmed);
                    configContent.textContent = JSON.stringify(parsed, null, 2);
                    return;
                } catch (_) {
                    // fall through to raw
                }
            }
            configContent.textContent = raw;
        } catch (err) {
            configContent.textContent = 'Error: ' + err.message;
        }
    }

    window.viewSessionConfig = async function (id) {
        setActiveSession(id, `Viewing generated config for session ${id}.`);
        await loadSessionState(id);
        if (!configSection || !configContent || !configFileSelect) return;
        configSection.style.display = 'block';
        configContent.textContent = 'Loading files...';
        configFileSelect.innerHTML = '';
        if (configMeta) configMeta.textContent = '';
        try {
            const resp = await fetch(`/api/converter-session-files?session_id=${encodeURIComponent(id)}`);
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Failed to load session files'));
            const files = data.files || [];
            if (configMeta) configMeta.textContent = `Model: ${data.target_model || 'unknown'} • Base: ${data.base || ''}`;
            if (!files.length) {
                configContent.textContent = 'No generated config files found for this session.';
                return;
            }
            configFileSelect.innerHTML = files.map(f => {
                const kb = Math.max(1, Math.round(f.size / 1024));
                return `<option value="${f.name}">${f.name} (${kb} KB)</option>`;
            }).join('');
            configFileSelect.onchange = () => loadSessionConfigFile(id, configFileSelect.value);
            await loadSessionConfigFile(id, files[0].name);
            configSection.scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
            configContent.textContent = 'Error: ' + err.message;
        }
    };

    await loadRecentSessions();

    // ── Step 2: Import ───────────────────────────────────────────────────────
    importForm.onsubmit = async (e) => {
        e.preventDefault();
        if (!converterSessionId) { alert('No active conversion session. Please convert first or resume one.'); return; }
        importOutput.textContent = `Importing session ${converterSessionId} to FTD...\n`;
        importOutput.style.display = 'block';
        importOutput.scrollIntoView({ behavior: 'smooth' });

        try {
            const resp = await fetch('/api/import-fortigate-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: converterSessionId,
                    ftd_host:     document.getElementById('ftd-host').value,
                    ftd_username: document.getElementById('ftd-username').value,
                    ftd_password: document.getElementById('ftd-password').value,
                    deploy:       document.getElementById('ftd-deploy').checked,
                    debug:        document.getElementById('ftd-debug').checked,
                    only_flags:   [...document.querySelectorAll('.only-flag:checked')].map(cb => cb.value)
                })
            });

            if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                throw new Error(data.detail || `Import request failed (HTTP ${resp.status})`);
            }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                importOutput.textContent += decoder.decode(value, { stream: true });
                importOutput.scrollTop = importOutput.scrollHeight;
            }
        } catch (err) {
            importOutput.textContent += '\nError: ' + err.message;
        }
    };

    // ── Step 3: Cleanup ───────────────────────────────────────────────────────
    if (cleanupForm) {
        cleanupForm.onsubmit = async (e) => {
            e.preventDefault();
            const deleteFlags = [...document.querySelectorAll('.delete-flag:checked')].map(cb => cb.value);
            if (deleteFlags.length === 0) {
                alert('Please select at least one item to delete.');
                return;
            }
            if (cleanupOutput) {
                cleanupOutput.textContent = 'Running cleanup...';
                cleanupOutput.style.display = 'block';
                cleanupOutput.scrollIntoView({ behavior: 'smooth' });
            }
            try {
                const resp = await fetch('/api/cleanup-ftd-stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        session_id:   converterSessionId || '',
                        ftd_host:     document.getElementById('cleanup-host').value,
                        ftd_username: document.getElementById('cleanup-username').value,
                        ftd_password: document.getElementById('cleanup-password').value,
                        dry_run:      document.getElementById('cleanup-dry-run').checked,
                        deploy:       document.getElementById('cleanup-deploy').checked,
                        debug:        document.getElementById('cleanup-debug').checked,
                        delete_flags: deleteFlags
                    })
                });

                if (!resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    throw new Error(data.detail || `Cleanup request failed (HTTP ${resp.status})`);
                }

                const reader = resp.body.getReader();
                const decoder = new TextDecoder();
                while (true) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    cleanupOutput.textContent += decoder.decode(value, { stream: true });
                    cleanupOutput.scrollTop = cleanupOutput.scrollHeight;
                }
            } catch (err) {
                if (cleanupOutput) cleanupOutput.textContent = 'Error: ' + err.message;
            }
        };
    }
}

window.toggleDeleteAll = function (cb) {
    const specifics = document.querySelectorAll('.delete-specific');
    const allIfaces = document.getElementById('cleanup-delete-all-ifaces');
    specifics.forEach(f => { f.checked = cb.checked; f.disabled = cb.checked; });
    if (allIfaces) { allIfaces.checked = cb.checked; allIfaces.disabled = cb.checked; }
};

window.resetConverter = function () {
    // Fire-and-forget: clean up server-side session files
    const currentSession = converterSessionId;
    if (currentSession) {
        fetch('/api/reset-session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: currentSession })
        }).catch(() => {});
    }
    converterSessionId = null;
    const f  = document.getElementById('converter-form');
    const s  = document.getElementById('converter-status');
    const s2 = document.getElementById('converter-step2');
    const io = document.getElementById('import-output-window');
    const co = document.getElementById('cleanup-output-window');
    const cf = document.getElementById('cleanup-form');
    const sc = document.getElementById('session-config-preview');
    const scf = document.getElementById('session-config-file');
    const scc = document.getElementById('session-config-content');
    const scm = document.getElementById('session-config-meta');
    if (f)  f.reset();
    const importSelectAll = document.getElementById('import-only-select-all');
    if (importSelectAll) importSelectAll.indeterminate = false;
    if (s)  s.textContent = '';
    if (s2) s2.style.display = 'none';
    if (io) io.style.display = 'none';
    if (co) { co.style.display = 'none'; co.textContent = ''; }
    if (cf) cf.reset();
    if (sc) sc.style.display = 'none';
    if (scf) scf.innerHTML = '';
    if (scc) scc.textContent = '';
    if (scm) scm.textContent = '';
    // Clear dynamic model dropdowns
    const srcModel = document.getElementById('source-model');
    const tgtModel = document.getElementById('target-model');
    if (srcModel) srcModel.innerHTML = '<option value="">-- Select Model --</option>';
    if (tgtModel) tgtModel.innerHTML = '<option value="">-- Select Model --</option>';
};

// ═══════════════════════════════════════════════════════════════════════════════
// Dashboard
// ═══════════════════════════════════════════════════════════════════════════════

async function loadDashboard() {
    const container = document.getElementById('page-dashboard');
    container.querySelector('.loading')?.remove();

    try {
        const data = await api.getDashboard();
        dashboardData = data;

        // Update stats
        document.getElementById('stat-groups').textContent = data.stats?.total_groups || 0;
        document.getElementById('stat-hosts').textContent = data.stats?.total_hosts || 0;
        document.getElementById('stat-playbooks').textContent = data.stats?.total_playbooks || 0;
        document.getElementById('stat-jobs').textContent = data.stats?.total_jobs || 0;

        // Render recent jobs
        renderRecentJobs(data.recent_jobs || []);

        // Render groups overview
        renderGroupsOverview(data.groups || []);
    } catch (error) {
        showError('Failed to load dashboard', container);
    }
}

function renderRecentJobs(jobs) {
    const container = document.getElementById('recent-jobs');
    if (!jobs.length) {
        container.innerHTML = '<div class="empty-state">No jobs yet</div>';
        return;
    }

    container.innerHTML = jobs.map(job => `
        <div class="job-item">
            <div class="job-info">
                <div class="job-title">${escapeHtml(job.playbook_name || 'Unknown')}</div>
                <div class="job-meta">
                    Group: ${escapeHtml(job.group_name || 'Unknown')} • 
                    ${formatDate(job.started_at)} • 
                    <span class="status-badge status-${job.status}">${job.status}</span>
                </div>
            </div>
            <button class="btn btn-sm btn-secondary" onclick="viewJobOutput(${job.id})">View Output</button>
        </div>
    `).join('');
}

function renderGroupsOverview(groups) {
    const container = document.getElementById('groups-overview');
    if (!groups.length) {
        container.innerHTML = '<div class="empty-state">No inventory groups</div>';
        return;
    }

    container.innerHTML = groups.map(group => `
        <div class="card card-clickable" onclick="goToInventory()">
            <div class="card-title">${escapeHtml(group.name)}</div>
            <div class="card-description">${escapeHtml(group.description || '')}</div>
            <div class="card-description" style="margin-top: 0.5rem;">
                ${group.host_count || 0} host(s)
            </div>
        </div>
    `).join('');
}

window.goToInventory = function() {
    navigateToPage('inventory');
};

// ═══════════════════════════════════════════════════════════════════════════════
// Inventory
// ═══════════════════════════════════════════════════════════════════════════════

async function loadInventory() {
    const container = document.getElementById('inventory-groups');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const groups = await api.getInventoryGroups();
        if (!groups.length) {
            container.innerHTML = '<div class="empty-state">No inventory groups. Create one to get started!</div>';
            return;
        }

        // Load full details for each group
        const groupsWithHosts = await Promise.all(
            groups.map(async (group) => {
                const fullGroup = await api.getGroup(group.id);
                return fullGroup;
            })
        );

        renderInventoryGroups(groupsWithHosts);
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderInventoryGroups(groups) {
    const container = document.getElementById('inventory-groups');
    container.innerHTML = groups.map(group => `
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">${escapeHtml(group.name)}</div>
                    <div class="card-description">${escapeHtml(group.description || '')}</div>
                </div>
                <div style="display: flex; gap: 0.25rem;">
                    <button class="btn btn-sm btn-secondary" onclick="showEditGroupModal(${group.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteGroup(${group.id})">Delete</button>
                </div>
            </div>
            <div class="hosts-list">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong>Hosts</strong>
                    <button class="btn btn-sm btn-primary" onclick="showAddHostModal(${group.id})">+ Add Host</button>
                </div>
                ${group.hosts && group.hosts.length ? 
                    group.hosts.map(host => {
                        // Store host data for the edit modal
                        _hostCache[host.id] = { groupId: group.id, ...host };
                        return `
                        <div class="host-item">
                            <div class="host-info">
                                <span class="host-name">${escapeHtml(host.hostname)}</span>
                                <span class="host-ip">${escapeHtml(host.ip_address)}</span>
                                <span class="host-type">${escapeHtml(host.device_type || 'cisco_ios')}</span>
                            </div>
                            <div style="display: flex; gap: 0.25rem;">
                                <button class="btn btn-sm btn-secondary" onclick="showEditHostModal(${host.id})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteHost(${group.id}, ${host.id})">Delete</button>
                            </div>
                        </div>
                    `;}).join('') :
                    '<div class="empty-state" style="padding: 1rem;">No hosts</div>'
                }
            </div>
        </div>
    `).join('');

    groups.forEach(group => {
        _groupCache[group.id] = {
            id: group.id,
            name: group.name,
            description: group.description || '',
        };
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Playbooks
// ═══════════════════════════════════════════════════════════════════════════════

async function loadPlaybooks() {
    const container = document.getElementById('playbooks-list');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const playbooks = await api.getPlaybooks();
        if (!playbooks.length) {
            container.innerHTML = '<div class="empty-state">No playbooks available. <button class="btn btn-primary btn-sm" onclick="showCreatePlaybookModal()" style="margin-top: 1rem;">Create Playbook</button></div>';
            return;
        }

        container.innerHTML = playbooks.map(pb => {
            // Tags are already parsed as an array by the backend
            let tags = pb.tags;
            if (typeof tags === 'string') {
                try {
                    tags = JSON.parse(tags);
                } catch (e) {
                    tags = [];
                }
            }
            if (!Array.isArray(tags)) {
                tags = [];
            }
            
            return `
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">${escapeHtml(pb.name)}</div>
                        <div class="card-description">${escapeHtml(pb.description || '')}</div>
                        <div style="margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-muted);">
                            File: ${escapeHtml(pb.filename)}
                        </div>
                        <div style="margin-top: 0.5rem;">
                            ${tags.length > 0 ? tags.map(tag => `<span class="status-badge" style="margin-right: 0.5rem;">${escapeHtml(tag)}</span>`).join('') : ''}
                        </div>
                    </div>
                    <div>
                        <button class="btn btn-sm btn-secondary" onclick="editPlaybook(${pb.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deletePlaybook(${pb.id})">Delete</button>
                    </div>
                </div>
            </div>
        `;
        }).join('');
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Jobs
// ═══════════════════════════════════════════════════════════════════════════════

async function loadJobs() {
    const container = document.getElementById('jobs-list');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const jobs = await api.getJobs(100);
        if (!jobs.length) {
            container.innerHTML = '<div class="empty-state">No jobs yet. Launch a playbook to get started!</div>';
            return;
        }

        container.innerHTML = jobs.map(job => `
            <div class="job-item">
                <div class="job-info">
                    <div class="job-title">${escapeHtml(job.playbook_name || 'Unknown')}</div>
                    <div class="job-meta">
                        Group: ${escapeHtml(job.group_name || 'Unknown')} • 
                        Started: ${formatDate(job.started_at)} • 
                        <span class="status-badge status-${job.status}">${job.status}</span>
                        ${job.dry_run ? ' • <span style="color: var(--warning);">DRY RUN</span>' : ''}
                    </div>
                </div>
                <button class="btn btn-sm btn-secondary" onclick="viewJobOutput(${job.id})">View Output</button>
            </div>
        `).join('');
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Templates
// ═══════════════════════════════════════════════════════════════════════════════

async function loadTemplates() {
    const container = document.getElementById('templates-list');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const templates = await api.getTemplates();
        if (!templates.length) {
            container.innerHTML = '<div class="empty-state">No templates. Create one to get started!</div>';
            return;
        }

        container.innerHTML = templates.map(template => `
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">${escapeHtml(template.name)}</div>
                        <div class="card-description">${escapeHtml(template.description || '')}</div>
                    </div>
                    <div>
                        <button class="btn btn-sm btn-secondary" onclick="editTemplate(${template.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteTemplate(${template.id})">Delete</button>
                    </div>
                </div>
                <pre style="background: var(--bg); padding: 1rem; border-radius: 0.375rem; overflow-x: auto; margin-top: 1rem; font-size: 0.75rem;">${escapeHtml(template.content)}</pre>
            </div>
        `).join('');
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Credentials
// ═══════════════════════════════════════════════════════════════════════════════

async function loadCredentials() {
    const container = document.getElementById('credentials-list');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const credentials = await api.getCredentials();
        if (!credentials.length) {
            container.innerHTML = '<div class="empty-state">No credentials. Create one to get started!</div>';
            return;
        }

        container.innerHTML = credentials.map(cred => `
            <div class="credential-card" data-cred-id="${cred.id}">
                <div class="credential-fields">
                    <div class="credential-field">
                        <label class="credential-label">Name</label>
                        <input type="text" class="credential-input" data-field="name" value="${escapeHtml(cred.name)}">
                    </div>
                    <div class="credential-field">
                        <label class="credential-label">Username</label>
                        <input type="text" class="credential-input" data-field="username" value="${escapeHtml(cred.username)}">
                    </div>
                    <div class="credential-field">
                        <label class="credential-label">Password</label>
                        <input type="password" class="credential-input" data-field="password" placeholder="unchanged">
                    </div>
                    <div class="credential-field">
                        <label class="credential-label">Secret</label>
                        <input type="password" class="credential-input" data-field="secret" placeholder="unchanged">
                    </div>
                </div>
                <div class="credential-actions">
                    <button class="btn btn-primary btn-sm credential-save-btn" style="display:none;" onclick="saveCredentialInline(${cred.id})">Save</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteCredential(${cred.id})">Delete</button>
                </div>
            </div>
        `).join('');

        initCredentialChangeTracking();
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function initCredentialChangeTracking() {
    document.querySelectorAll('.credential-card').forEach(card => {
        const inputs = card.querySelectorAll('.credential-input');
        const saveBtn = card.querySelector('.credential-save-btn');
        const originals = {};
        inputs.forEach(input => {
            originals[input.dataset.field] = input.value;
        });
        card._originals = originals;

        inputs.forEach(input => {
            input.addEventListener('input', () => {
                let changed = false;
                inputs.forEach(inp => {
                    if (inp.dataset.field === 'password' || inp.dataset.field === 'secret') {
                        if (inp.value.length > 0) changed = true;
                    } else {
                        if (inp.value !== originals[inp.dataset.field]) changed = true;
                    }
                });
                saveBtn.style.display = changed ? '' : 'none';
            });
        });
    });
}

window.saveCredentialInline = async function(credentialId) {
    const card = document.querySelector(`.credential-card[data-cred-id="${credentialId}"]`);
    if (!card) return;

    const data = {};
    card.querySelectorAll('.credential-input').forEach(input => {
        const field = input.dataset.field;
        if (field === 'password' || field === 'secret') {
            if (input.value) data[field] = input.value;
        } else {
            data[field] = input.value;
        }
    });

    const saveBtn = card.querySelector('.credential-save-btn');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    try {
        await api.updateCredential(credentialId, data);
        showSuccess('Credential updated successfully');
        await loadCredentials();
    } catch (error) {
        showError(`Failed to update credential: ${error.message}`);
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
    }
};

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
        container.innerHTML = '<div class="empty-state" style="padding:1rem;">No user accounts found.</div>';
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
        container.innerHTML = '<div class="empty-state" style="padding:1rem;">No access groups defined yet.</div>';
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
    if (!form || form.dataset.bound === '1') return;
    form.dataset.bound = '1';
    form.addEventListener('submit', async (e) => {
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
    });
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
    if (!form || form.dataset.bound === '1') return;
    form.dataset.bound = '1';
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const retentionDays = Number(document.getElementById('job-retention-days').value);
            if (retentionDays < 30) {
                showError('Job retention must be at least 30 days');
                return;
            }
            const payload = {
                provider: document.getElementById('auth-provider').value,
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
            };
            adminState.authConfig = await api.updateAuthConfig(payload);
            renderAuthConfig();
            showSuccess('Authentication settings saved');
        } catch (error) {
            showError(`Failed to save authentication settings: ${error.message}`);
        }
    });

    const providerEl = document.getElementById('auth-provider');
    if (providerEl) {
        providerEl.addEventListener('change', () => {
            const radiusPanel = document.getElementById('radius-config-panel');
            if (radiusPanel) {
                radiusPanel.style.display = providerEl.value === 'radius' ? '' : 'none';
            }
        });
    }
}

function renderAuthConfig() {
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

async function loadAdminSettings() {
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
        renderLoginRules();
        renderAuthConfig();
        initThemeControls();
    } catch (error) {
        const usersContainer = document.getElementById('admin-users-list');
        if (usersContainer) {
            usersContainer.innerHTML = `<div class="error">Failed loading admin settings: ${escapeHtml(error.message)}</div>`;
        }
    }
}

window.showCreateAdminUserModal = function() {
    showModal('Create User Account', `
        <form id="admin-create-user-form">
            <div class="form-group"><label class="form-label">Username</label><input class="form-input" name="username" required minlength="3"></div>
            <div class="form-group"><label class="form-label">Display Name</label><input class="form-input" name="display_name"></div>
            <div class="form-group"><label class="form-label">Password</label><input type="password" class="form-input" name="password" required minlength="6"></div>
            <div class="form-group"><label class="form-label">Confirm Password</label><input type="password" class="form-input" name="confirm_password" required minlength="6"></div>
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
            <div class="form-group"><label class="form-label">New Password</label><input type="password" class="form-input" name="new_password" required minlength="6"></div>
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
// Modals
// ═══════════════════════════════════════════════════════════════════════════════

function showModal(title, content) {
    const modal = document.querySelector('#modal-overlay .modal');
    if (modal) {
        const isCodeEditorModal = /playbook|template/i.test(title);
        modal.classList.toggle('modal-large', isCodeEditorModal);
    }

    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal-overlay').classList.add('active');
}

function closeAllModals() {
    const modal = document.querySelector('#modal-overlay .modal');
    if (modal) {
        modal.classList.remove('modal-large');
    }

    document.getElementById('modal-overlay').classList.remove('active');
    document.getElementById('modal-body').innerHTML = '';
}

// Expose to window for inline onclick handlers
window.closeAllModals = closeAllModals;

// Themed confirmation dialog using the app modal styling (also accepts legacy signature showConfirm(title, message))
function showConfirm(optionsOrTitle = {}) {
    const defaults = {
        title: 'Confirm',
        message: 'Are you sure?',
        confirmText: 'Confirm',
        cancelText: 'Cancel',
        confirmClass: 'btn-danger'
    };

    const opts = typeof optionsOrTitle === 'string'
        ? { ...defaults, title: optionsOrTitle, message: arguments[1] || defaults.message }
        : { ...defaults, ...(optionsOrTitle || {}) };

    return new Promise((resolve) => {
        const overlay = document.getElementById('modal-overlay');
        const body = document.getElementById('modal-body');

        document.getElementById('modal-title').textContent = opts.title;
        body.innerHTML = '';

        const msg = document.createElement('p');
        msg.className = 'modal-confirm-message';
        msg.textContent = opts.message;

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.gap = '0.5rem';
        actions.style.justifyContent = 'flex-end';
        actions.style.marginTop = '1rem';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = opts.cancelText;

        const confirmBtn = document.createElement('button');
        confirmBtn.type = 'button';
        confirmBtn.className = `btn ${opts.confirmClass}`;
        confirmBtn.textContent = opts.confirmText;

        actions.appendChild(cancelBtn);
        actions.appendChild(confirmBtn);
        body.appendChild(msg);
        body.appendChild(actions);

        // Pause the overlay's default click-to-close handler so we can resolve the promise
        const previousOverlayOnClick = overlay.onclick;
        overlay.onclick = null;

        const onOverlay = (e) => {
            if (e.target === overlay) {
                e.stopPropagation();
                onCancel();
            }
        };

        const cleanup = () => {
            cancelBtn.removeEventListener('click', onCancel);
            confirmBtn.removeEventListener('click', onConfirm);
            overlay.removeEventListener('click', onOverlay);
            overlay.onclick = previousOverlayOnClick || null;
        };

        const onCancel = () => {
            cleanup();
            closeAllModals();
            resolve(false);
        };

        const onConfirm = () => {
            cleanup();
            closeAllModals();
            resolve(true);
        };

        overlay.addEventListener('click', onOverlay);
        overlay.classList.add('active');
        cancelBtn.addEventListener('click', onCancel);
        confirmBtn.addEventListener('click', onConfirm);
    });
}

window.showConfirm = showConfirm;

// Create Group Modal
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
        closeAllModals();
        await loadInventory();
        showSuccess('Host added successfully');
    } catch (error) {
        showError(`Failed to add host: ${error.message}`);
    }
};

// Launch Job Modal
window.showLaunchJobModal = async function() {
    try {
        const [playbooks, groups, credentials, templates] = await Promise.all([
            api.getPlaybooks(),
            api.getInventoryGroups(),
            api.getCredentials(),
            api.getTemplates(),
        ]);

        // Load hosts for each group
        const groupsWithHosts = await Promise.all(
            groups.map(async (group) => {
                try {
                    const groupData = await api.getGroup(group.id);
                    return { ...group, hosts: groupData.hosts || [] };
                } catch (e) {
                    return { ...group, hosts: [] };
                }
            })
        );

        showModal('Launch Job', `
            <form onsubmit="launchJob(event)">
                <div class="form-group">
                    <label class="form-label">Playbook</label>
                    <select class="form-select" name="playbook_id" id="job-playbook-select" required>
                        <option value="">Select a playbook...</option>
                        ${playbooks.map(pb => `<option value="${pb.id}">${escapeHtml(pb.name)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Select Targets</label>
                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.375rem; max-height: 400px; overflow-y: auto; border: 1px solid var(--border);">
                        ${groupsWithHosts.map(group => `
                            <div style="margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);">
                                <label style="display: flex; align-items: center; cursor: pointer; font-weight: 600; margin-bottom: 0.5rem;">
                                    <input type="checkbox" class="job-group-checkbox" data-group-id="${group.id}" 
                                           onchange="toggleJobGroup(${group.id}, this.checked)" style="margin-right: 0.5rem;">
                                    ${escapeHtml(group.name)} <span style="color: var(--text-muted); font-weight: normal; margin-left: 0.5rem;">(${group.hosts.length} hosts)</span>
                                </label>
                                <div class="job-hosts-list" data-group-id="${group.id}" style="margin-left: 1.5rem; margin-top: 0.5rem;">
                                    ${group.hosts.map(host => `
                                        <label style="display: flex; align-items: center; cursor: pointer; padding: 0.25rem 0; color: var(--text-light);">
                                            <input type="checkbox" class="job-host-checkbox" name="host_ids[]" value="${host.id}" 
                                                   data-group-id="${group.id}" style="margin-right: 0.5rem;">
                                            <span>${escapeHtml(host.hostname)}</span>
                                            <span style="color: var(--text-muted); margin-left: 0.5rem; font-size: 0.875rem;">${escapeHtml(host.ip_address)}</span>
                                            <span style="color: var(--text-muted); margin-left: 0.5rem; font-size: 0.75rem;">(${escapeHtml(host.device_type || 'cisco_ios')})</span>
                                        </label>
                                    `).join('')}
                                </div>
                            </div>
                        `).join('')}
                        ${groupsWithHosts.length === 0 ? '<div class="empty-state">No inventory groups available</div>' : ''}
                    </div>
                    <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.5rem;">
                        Select entire groups or individual hosts. At least one target must be selected.
                    </small>
                </div>
                <div class="form-group">
                    <label class="form-label">Credential (optional)</label>
                    <select class="form-select" name="credential_id">
                        <option value="">None</option>
                        ${credentials.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Template (optional)</label>
                    <select class="form-select" name="template_id">
                        <option value="">None</option>
                        ${templates.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('')}
                    </select>
                    <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">If the selected playbook expects a template (e.g., VLAN 1 remediation), choose one here.</small>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="dry_run" checked> Dry Run (simulation)
                    </label>
                </div>
                <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Launch</button>
                </div>
            </form>
        `);
        
        // Store groups data
        window._jobGroupsData = groupsWithHosts;
    } catch (error) {
        showError(`Failed to load job form: ${error.message}`);
    }
};

window.toggleJobGroup = function(groupId, checked) {
    // Toggle all hosts in this group
    const hostCheckboxes = document.querySelectorAll(`.job-host-checkbox[data-group-id="${groupId}"]`);
    hostCheckboxes.forEach(cb => {
        cb.checked = checked;
    });
};

window.updateJobGroupHosts = function(groupId) {
    // This function is no longer needed but kept for compatibility
};

window.launchJob = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    // Get selected host IDs
    const hostIds = Array.from(document.querySelectorAll('.job-host-checkbox:checked'))
        .map(cb => parseInt(cb.value))
        .filter(id => !isNaN(id)); // Filter out any invalid IDs
    
    if (hostIds.length === 0) {
        showError('Please select at least one host or group');
        return;
    }
    
    console.log('Launching job with host IDs:', hostIds);
    
    try {
        const playbookId = parseInt(formData.get('playbook_id'));
        const credentialId = formData.get('credential_id') ? parseInt(formData.get('credential_id')) : null;
        const templateId = formData.get('template_id') ? parseInt(formData.get('template_id')) : null;
        const dryRun = formData.get('dry_run') === 'on';
        
        console.log('Job parameters:', { playbookId, credentialId, templateId, dryRun, hostIds });
        
        const job = await api.launchJob(
            playbookId,
            null, // No longer using inventory_group_id
            credentialId,
            templateId,
            dryRun,
            hostIds
        );
        closeAllModals();
        await loadJobs();
        showSuccess(`Job launched successfully on ${hostIds.length} host(s)`);
        setTimeout(() => viewJobOutput(job.job_id), 500);
    } catch (error) {
        console.error('Job launch error:', error);
        showError(`Failed to launch job: ${error.message}`);
    }
};

// Edit Template Modal
window.editTemplate = async function(templateId) {
    try {
        const template = await api.getTemplate(templateId);
        showModal('Edit Template', `
            <form onsubmit="updateTemplate(event, ${templateId})">
                <div class="form-group">
                    <label class="form-label">Template Name</label>
                    <input type="text" class="form-input" name="name" value="${escapeHtml(template.name)}" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <input type="text" class="form-input" name="description" value="${escapeHtml(template.description || '')}">
                </div>
                <div class="form-group">
                    <label class="form-label">Config Content</label>
                    <textarea class="form-textarea code-editor" name="content" wrap="off" spellcheck="false" style="min-height: 320px;" required>${escapeHtml(template.content)}</textarea>
                </div>
                <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save</button>
                </div>
            </form>
        `);
    } catch (error) {
        showError(`Failed to load template: ${error.message}`);
    }
};

window.updateTemplate = async function(e, templateId) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.updateTemplate(templateId, formData.get('name'), formData.get('content'), formData.get('description'));
        closeAllModals();
        await loadTemplates();
        showSuccess('Template updated successfully');
    } catch (error) {
        showError(`Failed to update template: ${error.message}`);
    }
};

// Create Template Modal
window.showCreateTemplateModal = function() {
    showModal('Create Template', `
        <form onsubmit="createTemplate(event)">
            <div class="form-group">
                <label class="form-label">Template Name</label>
                <input type="text" class="form-input" name="name" required>
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <input type="text" class="form-input" name="description">
            </div>
            <div class="form-group">
                <label class="form-label">Config Content</label>
                <textarea class="form-textarea code-editor" name="content" wrap="off" spellcheck="false" style="min-height: 320px;" required></textarea>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    `);
};

window.createTemplate = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.createTemplate(formData.get('name'), formData.get('content'), formData.get('description'));
        closeAllModals();
        await loadTemplates();
        showSuccess('Template created successfully');
    } catch (error) {
        showError(`Failed to create template: ${error.message}`);
    }
};

// Create Credential Modal
window.showCreateCredentialModal = function() {
    showModal('Create Credential', `
        <form onsubmit="createCredential(event)">
            <div class="form-group">
                <label class="form-label">Name</label>
                <input type="text" class="form-input" name="name" required>
            </div>
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" name="username" required>
            </div>
            <div class="form-group">
                <label class="form-label">Password</label>
                <input type="password" class="form-input" name="password" required>
            </div>
            <div class="form-group">
                <label class="form-label">Secret (Enable Password)</label>
                <input type="password" class="form-input" name="secret">
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    `);
};

window.createCredential = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        await api.createCredential(formData.get('name'), formData.get('username'), formData.get('password'), formData.get('secret'));
        closeAllModals();
        await loadCredentials();
        showSuccess('Credential created successfully');
    } catch (error) {
        showError(`Failed to create credential: ${error.message}`);
    }
};

// Create Playbook Modal
window.showCreatePlaybookModal = function() {
    const defaultContent = `"""
Your playbook description here.

This playbook will be executed on all hosts in the selected inventory group.
"""

import asyncio
from typing import AsyncGenerator

from routes.runner import BasePlaybook, LogEvent, register_playbook

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoTimeoutException,
        NetmikoAuthenticationException,
    )
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False


@register_playbook
class MyPlaybook(BasePlaybook):
    filename = "my_playbook.py"
    display_name = "My Playbook"
    description = "Description of what this playbook does"
    tags = ["example"]
    requires_template = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(f"My Playbook — targeting {len(hosts)} device(s)")
        
        if dry_run:
            yield self.log_warn("*** DRY-RUN MODE — no changes will be made ***")
        
        for host_info in hosts:
            ip = host_info["ip_address"]
            hostname = host_info.get("hostname", ip)
            device_type = host_info.get("device_type", "cisco_ios")
            
            yield self.log_sep()
            yield self.log_info(f"Processing {hostname} ({ip})...", host=hostname)
            
            if NETMIKO_AVAILABLE:
                # Real device connection code here
                device = {
                    "device_type": device_type,
                    "host": ip,
                    "username": credentials["username"],
                    "password": credentials["password"],
                    "secret": credentials.get("secret", credentials["password"]),
                    "timeout": 30,
                }
                
                try:
                    conn = await asyncio.to_thread(ConnectHandler, **device)
                    try:
                        if not conn.check_enable_mode():
                            await asyncio.to_thread(conn.enable)
                        
                        # Your playbook logic here
                        yield self.log_success(f"Connected to {hostname}", host=hostname)
                        
                        # Example: Run a command
                        # output = await asyncio.to_thread(conn.send_command, "show version")
                        # yield self.log_info(f"Output: {output[:100]}...", host=hostname)
                        
                    finally:
                        conn.disconnect()
                except NetmikoTimeoutException:
                    yield self.log_error(f"Timeout connecting to {ip}", host=hostname)
                except NetmikoAuthenticationException:
                    yield self.log_error(f"Authentication failed for {ip}", host=hostname)
                except Exception as e:
                    yield self.log_error(f"Error: {e}", host=hostname)
            else:
                yield self.log_warn("Netmiko not available — running in simulation mode", host=hostname)
                await asyncio.sleep(0.5)
            
            yield self.log_success(f"Finished processing {hostname} ({ip})", host=hostname)
        
        yield self.log_sep()
        yield self.log_success("Playbook execution complete")
`;

    showModal('Create Playbook', `
        <form onsubmit="createPlaybook(event)">
            <div class="form-group">
                <label class="form-label">Playbook Name</label>
                <input type="text" class="form-input" name="name" placeholder="My Playbook" required>
            </div>
            <div class="form-group">
                <label class="form-label">Filename</label>
                <input type="text" class="form-input" name="filename" placeholder="my_playbook.py" required>
                <small style="color: var(--text-muted); font-size: 0.75rem;">Must end with .py</small>
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <input type="text" class="form-input" name="description" placeholder="What this playbook does">
            </div>
            <div class="form-group">
                <label class="form-label">Tags (comma-separated)</label>
                <input type="text" class="form-input" name="tags" placeholder="example, automation">
            </div>
            <div class="form-group">
                <label class="form-label">Python Code</label>
                <textarea class="form-textarea code-editor" name="content" wrap="off" spellcheck="false" style="min-height: 500px; font-family: 'Courier New', monospace;" required>${defaultContent}</textarea>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    `);
};

window.createPlaybook = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const tagsStr = formData.get('tags') || '';
    const tags = tagsStr.split(',').map(t => t.trim()).filter(t => t);
    
    try {
        let filename = formData.get('filename');
        if (!filename.endsWith('.py')) {
            filename += '.py';
        }
        
        await api.createPlaybook(
            formData.get('name'),
            filename,
            formData.get('description') || '',
            tags,
            formData.get('content')
        );
        closeAllModals();
        await loadPlaybooks();
        showSuccess('Playbook created successfully');
    } catch (error) {
        showError(`Failed to create playbook: ${error.message}`);
    }
};

window.editPlaybook = async function(playbookId) {
    try {
        const playbook = await api.getPlaybook(playbookId);
        console.log('Loaded playbook:', playbook);
        console.log('Content type:', typeof playbook.content);
        console.log('Content length:', playbook.content ? playbook.content.length : 'null/undefined');
        
        let tags = playbook.tags;
        if (typeof tags === 'string') {
            try {
                tags = JSON.parse(tags);
            } catch (e) {
                tags = [];
            }
        }
        if (!Array.isArray(tags)) {
            tags = [];
        }
        
        // Ensure content is a string
        const playbookContent = playbook.content || '';
        console.log('Final content to set, length:', playbookContent.length);
        
        showModal('Edit Playbook', `
            <form onsubmit="updatePlaybook(event, ${playbookId})">
                <div class="form-group">
                    <label class="form-label">Playbook Name</label>
                    <input type="text" class="form-input" name="name" value="${escapeHtml(playbook.name || '')}" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Filename</label>
                    <input type="text" class="form-input" name="filename" value="${escapeHtml(playbook.filename || '')}" required>
                    <small style="color: var(--text-muted); font-size: 0.75rem;">Must end with .py</small>
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <input type="text" class="form-input" name="description" value="${escapeHtml(playbook.description || '')}">
                </div>
                <div class="form-group">
                    <label class="form-label">Tags (comma-separated)</label>
                    <input type="text" class="form-input" name="tags" value="${escapeHtml(tags.join(', '))}">
                </div>
                <div class="form-group">
                    <label class="form-label">Python Code</label>
                    <textarea id="playbook-content-textarea" class="form-textarea code-editor" name="content" wrap="off" spellcheck="false" style="min-height: 500px; font-family: 'Courier New', monospace;" required></textarea>
                </div>
                <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save</button>
                </div>
            </form>
        `);
        
        // Set textarea content after modal DOM is updated
        // Use multiple attempts to ensure DOM is ready
        const setContent = () => {
            const textarea = document.getElementById('playbook-content-textarea');
            if (textarea) {
                textarea.value = playbookContent;
                console.log('Successfully set textarea content, length:', playbookContent.length);
                console.log('Textarea value length:', textarea.value.length);
            } else {
                console.warn('Textarea not found, retrying...');
                setTimeout(setContent, 50);
            }
        };
        
        // Try immediately, then with delays
        requestAnimationFrame(() => {
            setTimeout(setContent, 10);
        });
    } catch (error) {
        console.error('Error loading playbook:', error);
        showError(`Failed to load playbook: ${error.message}`);
    }
};

window.updatePlaybook = async function(e, playbookId) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const tagsStr = formData.get('tags') || '';
    const tags = tagsStr.split(',').map(t => t.trim()).filter(t => t);
    
    try {
        let filename = formData.get('filename');
        if (!filename.endsWith('.py')) {
            filename += '.py';
        }
        
        await api.updatePlaybook(playbookId, {
            name: formData.get('name'),
            filename: filename,
            description: formData.get('description') || '',
            tags: tags,
            content: formData.get('content')
        });
        closeAllModals();
        await loadPlaybooks();
        showSuccess('Playbook updated successfully');
    } catch (error) {
        showError(`Failed to update playbook: ${error.message}`);
    }
};

window.deletePlaybook = async function(playbookId) {
    if (!await showConfirm({
        title: 'Delete Playbook',
        message: 'Are you sure you want to delete this playbook? This action cannot be undone.',
        confirmText: 'Delete',
        cancelText: 'Cancel',
        confirmClass: 'btn-danger'
    })) {
        return;
    }
    
    try {
        await api.deletePlaybook(playbookId);
        await loadPlaybooks();
        showSuccess('Playbook deleted successfully');
    } catch (error) {
        showError(`Failed to delete playbook: ${error.message}`);
    }
};


// Delete functions
window.deleteGroup = async function(groupId) {
    if (!await showConfirm('Delete Group', 'This will remove the group and all its hosts. This action cannot be undone.')) return;
    try {
        await api.deleteGroup(groupId);
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
        await loadInventory();
        showSuccess('Host deleted successfully');
    } catch (error) {
        showError(`Failed to delete host: ${error.message}`);
    }
};

window.deleteTemplate = async function(templateId) {
    if (!await showConfirm('Delete Template', 'This will permanently remove this config template.')) return;
    try {
        await api.deleteTemplate(templateId);
        await loadTemplates();
        showSuccess('Template deleted successfully');
    } catch (error) {
        showError(`Failed to delete template: ${error.message}`);
    }
};

window.deleteCredential = async function(credentialId) {
    if (!await showConfirm('Delete Credential', 'This will permanently remove this stored credential.')) return;
    try {
        await api.deleteCredential(credentialId);
        await loadCredentials();
        showSuccess('Credential deleted successfully');
    } catch (error) {
        showError(`Failed to delete credential: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Job Output Viewer
// ═══════════════════════════════════════════════════════════════════════════════

window.viewJobOutput = async function(jobId) {
    const modal = document.getElementById('job-output-modal');
    const output = document.getElementById('job-output');
    
    output.innerHTML = '<div class="loading">Loading...</div>';
    modal.classList.add('active');

    // Load historical events
    try {
        const events = await api.getJobEvents(jobId);
        output.innerHTML = events.map(e => 
            `<div class="job-output-line ${e.level}">[${formatTime(e.timestamp)}] ${e.host ? e.host + ': ' : ''}${escapeHtml(e.message)}</div>`
        ).join('');

        // Connect WebSocket for live updates
        const job = await api.getJob(jobId);
        if (job.status === 'running' || job.status === 'pending') {
            connectJobWebSocket(
                jobId,
                (data) => {
                    const line = document.createElement('div');
                    line.className = `job-output-line ${data.level || 'info'}`;
                    line.textContent = `[${formatTime(data.timestamp || new Date().toISOString())}] ${data.host ? data.host + ': ' : ''}${data.message}`;
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                },
                (data) => {
                    const line = document.createElement('div');
                    line.className = 'job-output-line success';
                    line.textContent = `\n[Job Complete] Status: ${data.status}`;
                    output.appendChild(line);
                    output.scrollTop = output.scrollHeight;
                },
                (error) => {
                    const line = document.createElement('div');
                    line.className = 'job-output-line error';
                    line.textContent = `[Error] WebSocket connection failed`;
                    output.appendChild(line);
                }
            );
        }
    } catch (error) {
        output.innerHTML = `<div class="error">Failed to load job output: ${error.message}</div>`;
    }
};

window.closeJobOutputModal = function() {
    document.getElementById('job-output-modal').classList.remove('active');
    disconnectJobWebSocket();
};

// ═══════════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════════

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatTime(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleTimeString();
}

function showError(message, container = null) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error';
    errorDiv.textContent = message;
    if (container) {
        container.insertBefore(errorDiv, container.firstChild);
    } else {
        document.body.insertBefore(errorDiv, document.body.firstChild);
        setTimeout(() => errorDiv.remove(), 5000);
    }
}

function showSuccess(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'success';
    successDiv.textContent = message;
    document.body.insertBefore(successDiv, document.body.firstChild);
    setTimeout(() => successDiv.remove(), 3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Authentication UI
// ═══════════════════════════════════════════════════════════════════════════════

let currentUser = null;
let currentUserData = null; // {username, user_id, display_name, role}

function showLoginScreen() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('app-container').style.display = 'none';
    document.getElementById('login-error').style.display = 'none';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    showLoginForm();
    document.getElementById('login-username').focus();
}

window.showRegisterScreen = function() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
    document.getElementById('register-back').style.display = 'block';
    // Hide "Don't have an account?" link
    document.getElementById('login-form').nextElementSibling.style.display = 'none';
    document.getElementById('register-error').style.display = 'none';
    document.getElementById('register-username').focus();
};

window.showLoginForm = function() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('register-back').style.display = 'none';
    // Show "Don't have an account?" link
    const registerLink = document.getElementById('login-form').nextElementSibling;
    if (registerLink) registerLink.style.display = 'block';
    document.getElementById('login-error').style.display = 'none';
};

function showApp(userData) {
    currentUserData = userData;
    currentUser = userData.username;
    currentFeatureAccess = Array.isArray(userData.feature_access) ? userData.feature_access : [];
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-container').style.display = 'flex';
    document.getElementById('nav-user').textContent = userData.display_name || userData.username;
    initNavigation();
    applyFeatureVisibility();

    const orderedPages = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'converter'];
    const firstAllowed = orderedPages.find((page) => canAccessFeature(NAV_FEATURE_MAP[page])) || 'dashboard';
    navigateToPage(firstAllowed);
}

function initLoginForm() {
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        const errorEl = document.getElementById('login-error');
        errorEl.style.display = 'none';

        try {
            const result = await api.login(username, password);
            showApp(result);
        } catch (error) {
            errorEl.textContent = error.message || 'Invalid username or password';
            errorEl.style.display = 'block';
        }
    });

    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const displayName = document.getElementById('register-display-name').value;
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;
        const errorEl = document.getElementById('register-error');
        errorEl.style.display = 'none';

        if (password !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            errorEl.style.display = 'block';
            return;
        }

        try {
            const result = await api.register(username, password, displayName);
            showApp(result);
        } catch (error) {
            errorEl.textContent = error.message || 'Registration failed';
            errorEl.style.display = 'block';
        }
    });
}

window.showUserMenu = async function() {
    // Load fresh profile data
    try {
        const profile = await api.getProfile();
        currentUserData = profile;
        console.log('showUserMenu: Fetched profile:', profile);

        const userMenuOverlay = document.getElementById('user-menu-overlay');
        if (!userMenuOverlay) {
            console.error('Error: user-menu-overlay not found!');
            return;
        }

        const avatar = document.getElementById('user-avatar');
        if (!avatar) {
            console.error('Error: user-avatar not found BEFORE assignment!');
            return;
        }

        const displayNameEl = document.getElementById('user-menu-display-name');
        const usernameEl = document.getElementById('user-menu-username');
        const roleEl = document.getElementById('user-menu-role');

        if (!displayNameEl || !usernameEl || !roleEl) {
            console.error('Error: One or more user menu text elements not found BEFORE assignment!');
            return;
        }

        const displayName = profile.display_name || profile.username;
        console.log('showUserMenu: Attempting to set avatar textContent. Avatar element:', avatar); // NEW LOG
        avatar.textContent = displayName.charAt(0).toUpperCase();
        displayNameEl.textContent = displayName;
        usernameEl.textContent = `@${profile.username}`;
        roleEl.textContent = profile.role;
        console.log('showUserMenu: Updated user menu elements.');
    } catch (e) {
        console.error('showUserMenu: Error fetching profile, falling back to cached data:', e);
    }
    
    // Final check before activating overlay
    const finalOverlay = document.getElementById('user-menu-overlay');
    if (!finalOverlay) {
        console.error('Error: user-menu-overlay not found when trying to activate!');
        return;
    }
    finalOverlay.classList.add('active');
    console.log('showUserMenu: User menu overlay activated.');
};

window.closeUserMenu = function() {
    document.getElementById('user-menu-overlay').classList.remove('active');
};

window.doLogout = async function() {
    try {
        await api.logout();
    } catch (e) {
        // ignore
    }
    currentUser = null;
    currentUserData = null;
    closeUserMenu();
    showLoginScreen();
};

window.showEditProfileModal = function() {
    closeUserMenu();
    const displayName = currentUserData?.display_name || currentUserData?.username || '';
    showModal('Edit Profile', `
        <form id="edit-profile-form">
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" value="${escapeHtml(currentUserData?.username || '')}" disabled style="opacity: 0.6;">
                <small style="color: var(--text-muted);">Username cannot be changed</small>
            </div>
            <div class="form-group">
                <label class="form-label">Display Name</label>
                <input type="text" class="form-input" name="display_name" value="${escapeHtml(displayName)}" required>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Save</button>
            </div>
        </form>
    `);

    document.getElementById('edit-profile-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        try {
            await api.updateProfile(formData.get('display_name'));
            closeAllModals();
            // Update nav display
            const newName = formData.get('display_name');
            document.getElementById('nav-user').textContent = newName;
            if (currentUserData) currentUserData.display_name = newName;
            showSuccess('Profile updated successfully');
        } catch (error) {
            showError(`Failed to update profile: ${error.message}`);
        }
    });
};

window.showChangePasswordModal = function() {
    closeUserMenu();
    showModal('Change Password', `
        <form id="change-password-form">
            <div class="form-group">
                <label class="form-label">Current Password</label>
                <input type="password" class="form-input" name="current_password" required>
            </div>
            <div class="form-group">
                <label class="form-label">New Password</label>
                <input type="password" class="form-input" name="new_password" required minlength="6">
            </div>
            <div class="form-group">
                <label class="form-label">Confirm New Password</label>
                <input type="password" class="form-input" name="confirm_password" required minlength="6">
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Change Password</button>
            </div>
        </form>
    `);

    document.getElementById('change-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const newPass = formData.get('new_password');
        const confirmPass = formData.get('confirm_password');

        if (newPass !== confirmPass) {
            showError('New passwords do not match');
            return;
        }

        try {
            await api.changePassword(formData.get('current_password'), newPass);
            closeAllModals();
            showSuccess('Password changed successfully');
        } catch (error) {
            showError(`Failed to change password: ${error.message}`);
        }
    });
};

// ═══════════════════════════════════════════════════════════════════════════════
// Initialize
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    initThemeControls();
    initLoginForm();

    try {
        const status = await api.getAuthStatus();
        if (status.authenticated) {
            showApp(status);
        } else {
            showLoginScreen();
        }
    } catch (e) {
        showLoginScreen();
    }
});

/**
 * Main Application Logic
 */

import * as api from './api.js';
import { getCsrfToken, setCsrfToken } from './api.js';
import { connectJobWebSocket, disconnectJobWebSocket } from './websocket.js';

// Global state
let currentPage = 'dashboard';
let dashboardData = null;
const _hostCache = {};
const _groupCache = {};
let _snmpProfilesCache = [];
let _groupSnmpAssignments = {};
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
    topology: 'topology',
    'config-drift': 'config-drift',
    'config-backups': 'config-backups',
    compliance: 'compliance',
    'risk-analysis': 'risk-analysis',
    deployments: 'deployments',
    monitoring: 'monitoring',
    sla: 'monitoring',
};

const THEME_KEY = 'plexus-theme';
const VALID_THEMES = ['forest', 'dark', 'dark-modern', 'easy', 'easy-dark', 'light', 'void'];
const DEFAULT_THEME = 'forest';
const PAGE_CACHE_TTL_MS = 30 * 1000;
const CACHEABLE_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'settings', 'converter', 'topology', 'config-drift', 'config-backups'];
const pageCacheMeta = {};

// ── Utility: debounce ──────────────────────────────────────────────────────────
function debounce(fn, delay) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// ── Utility: batched streaming renderer ───────────────────────────────────────
// Buffers decoded chunks and flushes to the DOM once per animation frame,
// preventing a layout reflow on every streamed byte.
function createStreamHandler(el) {
    const decoder = new TextDecoder();
    let pending = '';
    let rafId = null;

    function flush() {
        if (pending) {
            el.textContent += pending;
            pending = '';
        }
        el.scrollTop = el.scrollHeight;
        rafId = null;
    }

    return {
        write(value) {
            pending += decoder.decode(value, { stream: true });
            if (!rafId) rafId = requestAnimationFrame(flush);
        },
        done() {
            if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
            flush();
        },
    };
}
const listViewState = {
    inventory: { items: [], query: '', sort: 'name_asc' },
    playbooks: { items: [], query: '', sort: 'name_asc' },
    jobs: { items: [], query: '', sort: 'started_desc', status: 'all', dryRun: 'all', dateRange: 'all' },
    templates: { items: [], query: '', sort: 'name_asc' },
    credentials: { items: [], query: '', sort: 'name_asc' },
    configDrift: { items: [], query: '', sort: 'detected_desc', status: 'open' },
    configBackups: { policies: [], backups: [], query: '', tab: 'policies' },
    compliance: { profiles: [], assignments: [], results: [], statusList: [], query: '', tab: 'profiles' },
    riskAnalysis: { items: [], query: '', levelFilter: '' },
    deployments: { items: [], query: '', statusFilter: '' },
    monitoring: { polls: [], alerts: [], query: '', tab: 'devices' },
    sla: { summary: null, hosts: [], query: '', tab: 'hosts' },
};

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
    // Refresh topology vis-network colors for the new theme
    if (_topologyNetwork && _topologyData && _topoNodesDS && _topoEdgesDS) {
        _getTopoThemeColors();
        _topoNodesDS.update(_topologyData.nodes.map(n => _buildVisNode(n, _topoSavedPositions)));
        _topoEdgesDS.update(_topologyData.edges.map(e => _buildVisEdge(e)));
    }
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

// ── Performance / Reduced-Motion Mode ─────────────────────────────────────────
const PERF_KEY = 'plexus_performance_mode';

function applyPerformanceMode(enabled) {
    document.body.classList.toggle('reduced-motion', enabled);
    localStorage.setItem(PERF_KEY, enabled ? '1' : '0');
    const toggle = document.getElementById('perf-mode-toggle');
    if (toggle) {
        toggle.classList.toggle('active', enabled);
        toggle.title = enabled ? 'Performance Mode ON — click to disable' : 'Performance Mode — reduce animations and blur';
    }
}

function togglePerformanceMode(e) {
    e.preventDefault();
    const isActive = document.body.classList.contains('reduced-motion');
    applyPerformanceMode(!isActive);
}
window.togglePerformanceMode = togglePerformanceMode;

function initPerformanceMode() {
    const osPrefers = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const saved = localStorage.getItem(PERF_KEY);
    const enabled = saved !== null ? saved === '1' : osPrefers;
    applyPerformanceMode(enabled);
}

// ── Modal Accessibility: Focus Trap & Focus Return ──────────────────────────
let _previouslyFocusedElement = null;
const _focusTrapStack = [];

const FOCUSABLE_SELECTOR = [
    'a[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(', ');

function trapFocus(container) {
    const handler = (e) => {
        if (e.key !== 'Tab') return;
        const focusable = Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR))
            .filter(el => el.offsetParent !== null);
        if (focusable.length === 0) { e.preventDefault(); return; }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
            if (document.activeElement === first || !container.contains(document.activeElement)) {
                e.preventDefault();
                last.focus();
            }
        } else {
            if (document.activeElement === last || !container.contains(document.activeElement)) {
                e.preventDefault();
                first.focus();
            }
        }
    };
    container.addEventListener('keydown', handler);
    return handler;
}

function activateFocusTrap(overlayId) {
    _previouslyFocusedElement = document.activeElement;
    const overlay = document.getElementById(overlayId);
    if (!overlay) return;
    const dialog = overlay.querySelector('[role="dialog"], [role="alertdialog"], .command-palette');
    const target = dialog || overlay;
    const handler = trapFocus(target);
    _focusTrapStack.push({ overlayId, handler, target, previousFocus: _previouslyFocusedElement });
    // Auto-focus first focusable element inside the dialog
    requestAnimationFrame(() => {
        const first = target.querySelector(FOCUSABLE_SELECTOR);
        if (first) first.focus();
    });
}

function deactivateFocusTrap(overlayId) {
    const idx = _focusTrapStack.findIndex(t => t.overlayId === overlayId);
    if (idx === -1) return;
    const entry = _focusTrapStack.splice(idx, 1)[0];
    entry.target.removeEventListener('keydown', entry.handler);
    // Restore focus to the element that was focused before the modal opened
    if (entry.previousFocus && typeof entry.previousFocus.focus === 'function') {
        requestAnimationFrame(() => entry.previousFocus.focus());
    }
}

function markPageCacheFresh(page) {
    pageCacheMeta[page] = Date.now();
}

function isPageCacheFresh(page) {
    const ts = pageCacheMeta[page];
    return Boolean(ts && (Date.now() - ts) < PAGE_CACHE_TTL_MS);
}

function invalidatePageCache(...pages) {
    pages.forEach((page) => {
        delete pageCacheMeta[page];
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

    // Hide nav groups when all children are hidden
    document.querySelectorAll('.nav-group').forEach(group => {
        const children = group.querySelectorAll('.nav-link[data-page]');
        const allHidden = Array.from(children).every(c => c.style.display === 'none');
        group.style.display = allHidden ? 'none' : '';
    });

    const settingsLink = document.querySelector('.nav-link[data-page="settings"]');
    if (settingsLink) {
        settingsLink.style.display = currentUserData?.role === 'admin' ? '' : 'none';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Navigation
// ═══════════════════════════════════════════════════════════════════════════════

// Map child pages to their nav-group id for auto-expand
const NAV_GROUP_CHILDREN = {
    'topology': 'network',
    'config-drift': 'network',
    'config-backups': 'network',
    'monitoring': 'network',
    'compliance': 'network',
    'risk-analysis': 'network',
    'deployments': 'network',
    'sla': 'network',
};

window.toggleNavGroup = function(groupName, e) {
    e.preventDefault();
    const group = document.getElementById(`nav-group-${groupName}`);
    if (group) group.classList.toggle('expanded');
};

function expandNavGroupForPage(page) {
    const groupName = NAV_GROUP_CHILDREN[page];
    if (groupName) {
        const group = document.getElementById(`nav-group-${groupName}`);
        if (group) group.classList.add('expanded');
    }
}

function updateNavGroupActiveState() {
    document.querySelectorAll('.nav-group').forEach(group => {
        const hasActive = group.querySelector('.nav-link.active') !== null;
        const toggle = group.querySelector('.nav-group-toggle');
        if (toggle) toggle.classList.toggle('has-active-child', hasActive);
    });
}

function initNavigation() {
    document.querySelectorAll('.nav-link[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.getAttribute('data-page');
            navigateToPage(page);
        });
    });
}

const VALID_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'converter', 'topology', 'monitoring', 'config-drift', 'config-backups', 'settings'];

function getPageFromHash() {
    const hash = window.location.hash.replace(/^#\/?/, '');
    return VALID_PAGES.includes(hash) ? hash : null;
}

function navigateToPage(page, { updateHash = true } = {}) {
    if (page === 'settings' && currentUserData?.role !== 'admin') {
        showError('Admin access required for Settings');
        return;
    }
    if (NAV_FEATURE_MAP[page] && !canAccessFeature(NAV_FEATURE_MAP[page])) {
        showError(`Your account does not have access to ${page}`);
        return;
    }

    // Update active nav link (only page-navigation links, not utility toggles)
    document.querySelectorAll('.nav-link[data-page]').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === page) {
            link.classList.add('active');
        }
    });

    // Auto-expand parent nav group and update group active styling
    expandNavGroupForPage(page);
    updateNavGroupActiveState();

    // Hide all pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    // Show target page
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
        currentPage = page;
        updateBreadcrumb(page);
        loadPageData(page);
        // Sync URL hash
        if (updateHash) {
            const newHash = `#${page}`;
            if (window.location.hash !== newHash) {
                history.pushState(null, '', newHash);
            }
        }
    }
}

const PAGE_LABELS = {
    dashboard: 'Dashboard',
    inventory: 'Inventory Management',
    playbooks: 'Playbooks',
    jobs: 'Job Execution',
    templates: 'Config Templates',
    credentials: 'Credentials',
    converter: 'Firewall Migration Tool',
    topology: 'Network Topology',
    'config-drift': 'Config Drift Detection',
    sla: 'SLA Dashboards',
    settings: 'Admin Settings',
};

function updateBreadcrumb(page) {
    const el = document.getElementById('breadcrumb-current');
    if (el) el.textContent = PAGE_LABELS[page] || page;
}

async function loadPageData(page, options = {}) {
    const { force = false } = options;
    if (!force && isPageCacheFresh(page)) {
        return;
    }
    const preserveContent = !force && Boolean(pageCacheMeta[page]);
    try {
        switch (page) {
            case 'dashboard':
                await loadDashboard({ preserveContent });
                break;
            case 'inventory':
                await loadInventory({ preserveContent });
                break;
            case 'playbooks':
                await loadPlaybooks({ preserveContent });
                break;
            case 'jobs':
                await loadJobs({ preserveContent });
                break;
            case 'templates':
                await loadTemplates({ preserveContent });
                break;
            case 'credentials':
                await loadCredentials({ preserveContent });
                break;
            case 'settings':
                await loadAdminSettings({ preserveContent });
                break;
            case 'converter':
                await loadConverter({ preserveContent });
                break;
            case 'topology':
                await loadTopology({ preserveContent });
                break;
            case 'config-drift':
                await loadConfigDrift({ preserveContent });
                break;
            case 'config-backups':
                await loadConfigBackups({ preserveContent });
                break;
            case 'compliance':
                await loadCompliance({ preserveContent });
                break;
            case 'risk-analysis':
                await loadRiskAnalysis({ preserveContent });
                break;
            case 'deployments':
                await loadDeployments({ preserveContent });
                break;
            case 'monitoring':
                await loadMonitoring({ preserveContent });
                break;
            case 'sla':
                await loadSla({ preserveContent });
                break;
        }
        markPageCacheFresh(page);
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

async function loadConverter(options = {}) {
    const { preserveContent = false } = options;
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
    if (!convertForm || !importForm || !statusDiv || !step2 || !step3 || !outputWindow || !summaryCards || !importOutput) {
        console.error('Converter: missing DOM elements', { convertForm, importForm, statusDiv, step2, step3, outputWindow, summaryCards, importOutput });
        return;
    }

    // Reset state only on first load/forced refresh so revisiting keeps context.
    if (!preserveContent) {
        const step1 = document.getElementById('converter-step1');
        if (step1) step1.style.display = '';
        convertForm.reset();
        statusDiv.textContent = '';
        step2.style.display = 'none';
        step3.style.display = 'none';
        importOutput.style.display = 'none';
        converterSessionId = null;
        updateConverterStepper(1);
    }

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
            const convertHeaders = {};
            const csrfTok1 = getCsrfToken();
            if (csrfTok1) convertHeaders['X-CSRF-Token'] = csrfTok1;
            const resp = await fetch('/api/convert-only', { method: 'POST', headers: convertHeaders, body: formData });
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Conversion failed'));

            converterSessionId = data.session_id;

            // Show raw output, prefixed with confirmed model from backend
            outputWindow.textContent = `[Backend confirmed target model: ${data.target_model}]\n\n` + (data.conversion_output || '(no output)');

            // Build summary stat cards
            renderSummary(data.summary || {});

            const step1El = document.getElementById('converter-step1');
            if (step1El) step1El.style.display = 'none';
            step2.style.display = 'block';
            step3.style.display = 'none';
            statusDiv.textContent = 'Conversion complete. Review the output, then proceed to import.';
            updateConverterStepper(2);
            step2.scrollIntoView({ behavior: 'smooth' });
            await loadRecentSessions();
        } catch (err) {
            statusDiv.textContent = 'Error: ' + err.message;
        }
    };

    // ── Recent sessions list ──────────────────────────────────────────────
    async function loadRecentSessions() {
        if (!recentSessions) return;
        recentSessions.innerHTML = skeletonCards(2);
        try {
            const resp = await fetch('/api/converter-sessions');
            const data = await resp.json();
            if (!resp.ok) throw new Error(apiErrorMessage(data, 'Failed to load sessions'));
            const sessions = data.sessions || [];
            if (!sessions.length) {
                recentSessions.innerHTML = emptyStateHTML('No recent conversions', 'converter');
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
            const delHeaders = { 'Content-Type': 'application/json' };
            const csrfTok2 = getCsrfToken();
            if (csrfTok2) delHeaders['X-CSRF-Token'] = csrfTok2;
            const resp = await fetch('/api/reset-session', {
                method: 'POST',
                headers: delHeaders,
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
            showToast('Error deleting session: ' + err.message, 'error');
        }
    };

    function setActiveSession(id, message) {
        converterSessionId = id;
        if (statusDiv) statusDiv.textContent = message || `Using session ${id}.`;
    }

    window.resumeImport = function (id) {
        const step1 = document.getElementById('converter-step1');
        if (step1) step1.style.display = 'none';
        setActiveSession(id, `Resumed session ${id}. Provide FTD credentials to import.`);
        loadSessionState(id);
        step2.style.display = 'none';
        step3.style.display = 'block';
        updateConverterStepper(3);
        if (importOutput) { importOutput.textContent = ''; importOutput.style.display = 'none'; }
        document.getElementById('converter-step3')?.scrollIntoView({ behavior: 'smooth' });
    };

    window.resumeCleanup = function (id) {
        setActiveSession(id, `Linked session ${id} for cleanup.`);
        // Open the cleanup section and scroll to it
        const cleanupSection = document.getElementById('converter-cleanup-section');
        if (cleanupSection) {
            cleanupSection.open = true;
            cleanupSection.scrollIntoView({ behavior: 'smooth' });
        }
        if (cleanupOutput) { cleanupOutput.textContent = 'Ready to clean up this session.'; cleanupOutput.style.display = 'block'; }
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

    // ── Converter job WebSocket helper ───────────────────────────────────────
    // Opens a WebSocket to /ws/converter-jobs/{jobId}, replays history, then
    // streams live lines.  Clears storageKey from localStorage when done.
    function connectConverterJobWS(jobId, outputEl, storageKey, onComplete) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/converter-jobs/${jobId}`);
        ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                if (msg.type === 'line') {
                    outputEl.textContent += msg.text;
                    outputEl.scrollTop = outputEl.scrollHeight;
                } else if (msg.type === 'job_complete') {
                    if (storageKey) localStorage.removeItem(storageKey);
                    if (onComplete) onComplete(msg.status);
                    ws.close();
                } else if (msg.type === 'error') {
                    outputEl.textContent += `\n[Error] ${msg.message}\n`;
                }
            } catch (_) {}
        };
        ws.onerror = () => { outputEl.textContent += '\n[Connection error — WebSocket failed]\n'; };
        return ws;
    }

    // ── Reconnect any active converter jobs from a previous page visit ────────
    async function tryReconnectActiveJobs() {
        const jobs = [
            { key: 'plexus_converter_import_job', outputEl: importOutput, label: 'import' },
            { key: 'plexus_converter_cleanup_job', outputEl: cleanupOutput, label: 'cleanup' },
        ];
        for (const { key, outputEl, label } of jobs) {
            if (!outputEl) continue;
            const raw = localStorage.getItem(key);
            if (!raw) continue;
            let saved;
            try { saved = JSON.parse(raw); } catch (_) { localStorage.removeItem(key); continue; }
            const { job_id, session_id } = saved;
            try {
                const resp = await fetch(`/api/converter-job/${encodeURIComponent(job_id)}`);
                if (!resp.ok) { localStorage.removeItem(key); continue; }
                const job = await resp.json();

                // Restore session + step so the UI is in the right state
                if (session_id && !converterSessionId) {
                    converterSessionId = session_id;
                    if (statusDiv) statusDiv.textContent = `Reconnected to active ${label} job for session ${session_id}.`;
                    if (step3) step3.style.display = 'block';
                    if (step2) step2.style.display = 'none';
                    updateConverterStepper(3);
                }

                outputEl.textContent = `[Reconnected — accumulated ${label} output]\n` + (job.output || '');
                outputEl.style.display = 'block';

                if (job.status === 'running') {
                    connectConverterJobWS(job_id, outputEl, key, (status) => {
                        outputEl.textContent += `\n[${label} finished: ${status}]\n`;
                    });
                    showToast(`Reconnected to running ${label} job.`, 'info');
                } else {
                    localStorage.removeItem(key);
                    outputEl.textContent += `\n[${label} finished: ${job.status}]\n`;
                }
            } catch (_) {
                localStorage.removeItem(key);
            }
        }
    }

    // ── Step 3: Import ───────────────────────────────────────────────────────
    importForm.onsubmit = async (e) => {
        e.preventDefault();
        if (!converterSessionId) { showToast('No active conversion session. Please convert first or resume one.', 'error'); return; }
        importOutput.textContent = `Importing session ${converterSessionId} to FTD...\n`;
        importOutput.style.display = 'block';
        importOutput.scrollIntoView({ behavior: 'smooth' });

        try {
            const importHeaders = { 'Content-Type': 'application/json' };
            const csrfTok3 = getCsrfToken();
            if (csrfTok3) importHeaders['X-CSRF-Token'] = csrfTok3;
            const resp = await fetch('/api/import-fortigate-bg', {
                method: 'POST',
                headers: importHeaders,
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

            const { job_id } = await resp.json();
            localStorage.setItem('plexus_converter_import_job', JSON.stringify({ job_id, session_id: converterSessionId }));
            connectConverterJobWS(job_id, importOutput, 'plexus_converter_import_job', (status) => {
                importOutput.textContent += `\n[Import finished: ${status}]\n`;
            });
        } catch (err) {
            importOutput.textContent += '\nError: ' + err.message;
        }
    };

    // ── Cleanup Utility ─────────────────────────────────────────────────────
    if (cleanupForm) {
        cleanupForm.onsubmit = async (e) => {
            e.preventDefault();
            const deleteFlags = [...document.querySelectorAll('.delete-flag:checked')].map(cb => cb.value);
            if (deleteFlags.length === 0) {
                showToast('Please select at least one item to delete.', 'error');
                return;
            }
            if (cleanupOutput) {
                cleanupOutput.textContent = 'Running cleanup...';
                cleanupOutput.style.display = 'block';
                cleanupOutput.scrollIntoView({ behavior: 'smooth' });
            }
            try {
                const headers = { 'Content-Type': 'application/json' };
                const csrfTok = getCsrfToken();
                if (csrfTok) headers['X-CSRF-Token'] = csrfTok;
                const resp = await fetch('/api/cleanup-ftd-bg', {
                    method: 'POST',
                    headers,
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

                const { job_id } = await resp.json();
                localStorage.setItem('plexus_converter_cleanup_job', JSON.stringify({ job_id, session_id: converterSessionId || '' }));
                connectConverterJobWS(job_id, cleanupOutput, 'plexus_converter_cleanup_job', (status) => {
                    cleanupOutput.textContent += `\n[Cleanup finished: ${status}]\n`;
                });
            } catch (err) {
                if (cleanupOutput) cleanupOutput.textContent = 'Error: ' + err.message;
            }
        };
    }

    await tryReconnectActiveJobs();
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
        const resetHeaders = { 'Content-Type': 'application/json' };
        const csrfTok4 = getCsrfToken();
        if (csrfTok4) resetHeaders['X-CSRF-Token'] = csrfTok4;
        fetch('/api/reset-session', {
            method: 'POST',
            headers: resetHeaders,
            body: JSON.stringify({ session_id: currentSession })
        }).catch(() => {});
    }
    converterSessionId = null;
    localStorage.removeItem('plexus_converter_import_job');
    localStorage.removeItem('plexus_converter_cleanup_job');
    const f  = document.getElementById('converter-form');
    const s  = document.getElementById('converter-status');
    const s2 = document.getElementById('converter-step2');
    const s3 = document.getElementById('converter-step3');
    const io = document.getElementById('import-output-window');
    const co = document.getElementById('cleanup-output-window');
    const cf = document.getElementById('cleanup-form');
    const sc = document.getElementById('session-config-preview');
    const scf = document.getElementById('session-config-file');
    const scc = document.getElementById('session-config-content');
    const scm = document.getElementById('session-config-meta');
    const s1 = document.getElementById('converter-step1');
    if (f)  f.reset();
    const importSelectAll = document.getElementById('import-only-select-all');
    if (importSelectAll) importSelectAll.indeterminate = false;
    if (s)  s.textContent = '';
    if (s1) s1.style.display = '';
    if (s2) s2.style.display = 'none';
    if (s3) s3.style.display = 'none';
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
    updateConverterStepper(1);
};

// ═══════════════════════════════════════════════════════════════════════════════
// Topology
// ═══════════════════════════════════════════════════════════════════════════════

let _topologyNetwork = null;
let _topologyData = null;
let _topoNodesDS = null;         // vis.DataSet for nodes (persistent)
let _topoEdgesDS = null;         // vis.DataSet for edges (persistent)
let _topoSavedPositions = {};    // { nodeId: {x, y} } loaded from server
let _topoPathMode = false;
let _topoPathSource = null;
let _topoOriginalColors = null;  // stashed node/edge colors for restore
let _topoUtilOverlay = false;    // utilization overlay toggle state
let _topoThemeColors = null;     // cached theme-aware colors for vis-network

function _getTopoThemeColors() {
    const style = getComputedStyle(document.documentElement);
    const theme = document.documentElement.getAttribute('data-theme') || 'forest';
    const isDark = !['easy', 'light'].includes(theme);
    _topoThemeColors = {
        nodeFont: style.getPropertyValue('--text').trim() || '#c8d4c8',
        nodeFontStroke: isDark ? 'rgba(0,0,0,0.6)' : 'rgba(255,255,255,0.7)',
        edgeFont: style.getPropertyValue('--text-muted').trim() || '#7a8a7a',
        edgeFontStroke: isDark ? 'rgba(0,0,0,0.5)' : 'rgba(255,255,255,0.6)',
        externalBg: isDark ? '#263238' : style.getPropertyValue('--bg-secondary').trim(),
        externalBorder: isDark ? '#546e7a' : style.getPropertyValue('--border').trim(),
        externalHighlightBg: isDark ? '#37474f' : style.getPropertyValue('--card-bg-hover').trim(),
        externalHighlightBorder: isDark ? '#90a4ae' : style.getPropertyValue('--border-light').trim(),
    };
    return _topoThemeColors;
}

const _TOPO_NODE_COLORS = {
    cisco_ios:     { background: '#0d47a1', border: '#42a5f5', highlight: { background: '#1565c0', border: '#90caf9' }, hover: { background: '#1565c0', border: '#90caf9' } },
    juniper_junos: { background: '#1b5e20', border: '#66bb6a', highlight: { background: '#2e7d32', border: '#a5d6a7' }, hover: { background: '#2e7d32', border: '#a5d6a7' } },
    arista_eos:    { background: '#e65100', border: '#ffa726', highlight: { background: '#f57c00', border: '#ffcc80' }, hover: { background: '#f57c00', border: '#ffcc80' } },
    fortinet:      { background: '#b71c1c', border: '#ef5350', highlight: { background: '#c62828', border: '#ef9a9a' }, hover: { background: '#c62828', border: '#ef9a9a' } },
    unknown:       { background: '#37474f', border: '#78909c', highlight: { background: '#455a64', border: '#b0bec5' }, hover: { background: '#455a64', border: '#b0bec5' } },
};

function _topoNodeShape(deviceType) {
    if (deviceType === 'fortinet') return 'triangle';
    if (['cisco_ios', 'juniper_junos', 'arista_eos'].includes(deviceType)) return 'diamond';
    return 'dot';
}

function _topoNodeColor(node) {
    if (!node.in_inventory) {
        const tc = _topoThemeColors || _getTopoThemeColors();
        return { background: tc.externalBg, border: tc.externalBorder, highlight: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder }, hover: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder } };
    }
    return _TOPO_NODE_COLORS[node.device_type] || _TOPO_NODE_COLORS.unknown;
}

function _topoEdgeColor(protocol) {
    if (protocol === 'lldp') return { color: '#00e676', highlight: '#69f0ae', hover: '#69f0ae', opacity: 0.8 };
    if (protocol === 'ospf') return { color: '#ffab40', highlight: '#ffd180', hover: '#ffd180', opacity: 0.8 };
    if (protocol === 'bgp')  return { color: '#e040fb', highlight: '#ea80fc', hover: '#ea80fc', opacity: 0.8 };
    return { color: '#00b0ff', highlight: '#40c4ff', hover: '#40c4ff', opacity: 0.8 };
}

// Utilization overlay color: green (0%) → yellow (50%) → red (100%)
function _utilColor(pct) {
    let r, g, b;
    if (pct <= 50) {
        // green → yellow
        const t = pct / 50;
        r = Math.round(76 + (255 - 76) * t);
        g = Math.round(175 + (235 - 175) * t);
        b = Math.round(80 + (59 - 80) * t);
    } else {
        // yellow → red
        const t = (pct - 50) / 50;
        r = Math.round(255 + (244 - 255) * t);
        g = Math.round(235 - 235 * t * 0.85);
        b = Math.round(59 + (67 - 59) * t);
    }
    const hex = `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
    return { color: hex, highlight: hex, hover: hex, opacity: 0.9 };
}

function _formatBps(bps) {
    if (!bps || bps < 0) return '0 bps';
    if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
    return bps + ' bps';
}

function _utilShadow(pct) {
    if (pct > 75) return 'rgba(244,67,54,0.4)';
    if (pct > 50) return 'rgba(255,235,59,0.3)';
    return 'rgba(76,175,80,0.3)';
}

function toggleUtilizationOverlay() {
    _topoUtilOverlay = !_topoUtilOverlay;
    const btn = document.getElementById('topology-util-btn');
    if (btn) btn.classList.toggle('active', _topoUtilOverlay);
    const utilLegend = document.getElementById('topology-legend-util');
    if (utilLegend) utilLegend.style.display = _topoUtilOverlay ? 'inline-flex' : 'none';
    // Update edges in-place without rebuilding the graph
    if (_topologyNetwork && _topologyData) {
        const edgesDS = _topologyNetwork.body.data.edges;
        const updates = _topologyData.edges.map(e => {
            const util = e.utilization;
            const hasUtil = _topoUtilOverlay && util && util.utilization_pct != null;
            const utilPct = hasUtil ? util.utilization_pct : 0;
            const utilWidth = hasUtil ? 2 + (utilPct / 100) * 6 : 2;
            const utilColor = hasUtil ? _utilColor(utilPct) : null;
            let edgeLabel = e.label || '';
            if (hasUtil) edgeLabel = `${edgeLabel ? edgeLabel + ' ' : ''}(${utilPct}%)`;
            return {
                id: e.id,
                label: edgeLabel,
                color: utilColor || _topoEdgeColor(e.protocol),
                width: utilWidth,
                shadow: {
                    enabled: true,
                    color: hasUtil ? _utilShadow(utilPct) : ({ lldp: 'rgba(0,230,118,0.3)', ospf: 'rgba(255,171,64,0.3)', bgp: 'rgba(224,64,251,0.3)' }[e.protocol] || 'rgba(0,176,255,0.3)'),
                    size: 6, x: 0, y: 0,
                },
            };
        });
        edgesDS.update(updates);
    }
}

async function loadTopology(options = {}) {
    const { preserveContent = false } = options;
    const container = document.querySelector('.topology-container');
    const legend = document.getElementById('topology-legend');
    const emptyEl = document.getElementById('topology-empty');

    // Populate group filter
    try {
        const groups = await api.getInventoryGroups(false);
        const select = document.getElementById('topology-group-filter');
        const currentVal = select.value;
        select.innerHTML = '<option value="">All Groups</option>';
        (groups || []).forEach(g => {
            const opt = document.createElement('option');
            opt.value = g.id;
            opt.textContent = g.name;
            select.appendChild(opt);
        });
        if (currentVal) select.value = currentVal;
    } catch (e) { /* ignore */ }

    // Fetch topology data and saved positions in parallel
    const groupFilter = document.getElementById('topology-group-filter').value;
    try {
        const [data, positions] = await Promise.all([
            api.getTopology(groupFilter || null),
            api.getTopologyPositions().catch(() => ({})),
        ]);
        _topologyData = data;
        _topoSavedPositions = positions || {};
        if (!data.nodes || data.nodes.length === 0) {
            container.style.display = 'none';
            legend.style.display = 'none';
            emptyEl.style.display = 'flex';
            if (_topologyNetwork) { _topologyNetwork.destroy(); _topologyNetwork = null; }
            return;
        }
        container.style.display = 'flex';
        legend.style.display = 'flex';
        emptyEl.style.display = 'none';
        renderTopologyGraph(data);
        // Update change badge
        _updateTopologyChangeBadge(data.unacknowledged_changes || 0);
    } catch (error) {
        container.style.display = 'none';
        legend.style.display = 'none';
        emptyEl.style.display = 'flex';
        showError('Failed to load topology: ' + error.message);
    }
}

function _buildVisNode(n, savedPos) {
    const colors = _topoNodeColor(n);
    const node = {
        id: n.id,
        label: n.label,
        title: `${n.label}\n${n.ip || ''}\nType: ${n.device_type}${n.group_name ? '\nGroup: ' + n.group_name : ''}${n.in_inventory ? '' : '\n(External)'}`,
        shape: _topoNodeShape(n.device_type),
        color: colors,
        size: n.in_inventory ? 25 : 18,
        borderWidth: n.in_inventory ? 2.5 : 1.5,
        borderWidthSelected: 4,
        shapeProperties: { borderDashes: n.in_inventory ? false : [5, 5] },
        shadow: { enabled: true, color: colors.border, size: n.in_inventory ? 18 : 8, x: 0, y: 0 },
        font: { color: (_topoThemeColors || _getTopoThemeColors()).nodeFont, size: 12, face: 'Inter, sans-serif', strokeWidth: 3, strokeColor: (_topoThemeColors || _getTopoThemeColors()).nodeFontStroke },
        _raw: n,
    };
    // Apply saved position — pin the node so physics won't move it
    const key = String(n.id);
    if (savedPos[key]) {
        node.x = savedPos[key].x;
        node.y = savedPos[key].y;
        node.fixed = { x: true, y: true };
        node.physics = false;
    }
    return node;
}

function _buildVisEdge(e) {
    const util = e.utilization;
    const hasUtil = _topoUtilOverlay && util && util.utilization_pct != null;
    const utilPct = hasUtil ? util.utilization_pct : 0;
    const utilWidth = hasUtil ? 2 + (utilPct / 100) * 6 : 2;
    const utilColor = hasUtil ? _utilColor(utilPct) : null;
    let edgeLabel = e.label || '';
    if (hasUtil) edgeLabel = `${edgeLabel ? edgeLabel + ' ' : ''}(${utilPct}%)`;
    return {
        id: e.id,
        from: e.from,
        to: e.to,
        label: edgeLabel,
        color: utilColor || _topoEdgeColor(e.protocol),
        dashes: e.protocol === 'lldp' ? [8, 5] : e.protocol === 'ospf' ? [12, 4, 4, 4] : e.protocol === 'bgp' ? [4, 4] : false,
        width: utilWidth,
        hoverWidth: 0.5,
        selectionWidth: 1,
        shadow: {
            enabled: true,
            color: hasUtil ? _utilShadow(utilPct) : ({ lldp: 'rgba(0,230,118,0.3)', ospf: 'rgba(255,171,64,0.3)', bgp: 'rgba(224,64,251,0.3)' }[e.protocol] || 'rgba(0,176,255,0.3)'),
            size: 6, x: 0, y: 0,
        },
        font: { size: 9, color: (_topoThemeColors || _getTopoThemeColors()).edgeFont, strokeWidth: 2, strokeColor: (_topoThemeColors || _getTopoThemeColors()).edgeFontStroke, align: 'middle' },
        smooth: { type: 'continuous', roundness: 0.4 },
        _raw: e,
    };
}

function renderTopologyGraph(data) {
    _getTopoThemeColors();
    const container = document.getElementById('topology-canvas');
    const layoutMode = document.getElementById('topology-layout').value;

    _topoNodesDS = new vis.DataSet(data.nodes.map(n => _buildVisNode(n, _topoSavedPositions)));
    _topoEdgesDS = new vis.DataSet(data.edges.map(e => _buildVisEdge(e)));

    // Decide physics: if ALL nodes have saved positions, disable physics entirely
    const allPinned = data.nodes.length > 0 && data.nodes.every(n => _topoSavedPositions[String(n.id)]);
    const usePhysics = layoutMode === 'physics' && !allPinned;

    const graphOptions = {
        physics: {
            enabled: usePhysics,
            barnesHut: {
                gravitationalConstant: -4000,
                centralGravity: 0.25,
                springLength: 180,
                springConstant: 0.035,
                damping: 0.1,
                avoidOverlap: 0.3,
            },
            stabilization: { iterations: 250, updateInterval: 20 },
        },
        interaction: {
            hover: true,
            tooltipDelay: 150,
            navigationButtons: false,
            keyboard: { enabled: true },
            zoomSpeed: 0.6,
        },
        layout: layoutMode === 'hierarchical'
            ? { hierarchical: { direction: 'UD', sortMethod: 'hubsize', nodeSpacing: 180, levelSeparation: 140 } }
            : {},
        edges: {
            smooth: { type: 'continuous', roundness: 0.4 },
        },
    };

    if (_topologyNetwork) {
        _topologyNetwork.destroy();
    }
    _topologyNetwork = new vis.Network(container, { nodes: _topoNodesDS, edges: _topoEdgesDS }, graphOptions);

    _topologyNetwork.on('click', (params) => {
        if (_topoPathMode && params.nodes.length > 0) {
            _handlePathClick(params.nodes[0], _topoNodesDS, _topoEdgesDS, data);
            return;
        }
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = _topoNodesDS.get(nodeId);
            if (node && node._raw) showTopologyNodeDetails(node._raw, data.edges);
        } else {
            closeTopologyDetails();
        }
    });

    // Save position when a node is dragged
    _topologyNetwork.on('dragEnd', (params) => {
        if (!params.nodes.length) return;
        const positions = _topologyNetwork.getPositions(params.nodes);
        const updates = {};
        for (const nid of params.nodes) {
            const pos = positions[nid];
            if (!pos) continue;
            updates[String(nid)] = { x: Math.round(pos.x), y: Math.round(pos.y) };
            _topoSavedPositions[String(nid)] = updates[String(nid)];
            // Pin the node so it stays put
            _topoNodesDS.update({ id: nid, fixed: { x: true, y: true }, physics: false });
        }
        // Persist to server (fire-and-forget)
        _saveNodePositions(updates);
    });

    // Fit after stabilization (only if physics ran)
    if (usePhysics) {
        _topologyNetwork.once('stabilizationIterationsDone', () => {
            _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        });
    } else if (allPinned) {
        // All nodes positioned — just fit to view
        setTimeout(() => _topologyNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }), 50);
    }
}

let _savePositionTimer = null;
async function _saveNodePositions(positionsMap) {
    // Debounce: batch rapid drags into one API call
    clearTimeout(_savePositionTimer);
    _savePositionTimer = setTimeout(async () => {
        try {
            await api.saveTopologyPositions(positionsMap);
        } catch (e) {
            console.warn('Failed to save topology positions:', e.message);
        }
    }, 500);
}

async function resetTopologyPositions() {
    try {
        await api.deleteTopologyPositions();
        _topoSavedPositions = {};
        showToast('Node positions reset — physics re-enabled', 'success');
        // Unpin all nodes and re-enable physics in-place instead of rebuilding
        if (_topologyNetwork && _topoNodesDS) {
            const updates = _topoNodesDS.getIds().map(id => ({
                id,
                fixed: false,
                physics: true,
            }));
            _topoNodesDS.update(updates);
            // Re-enable physics and force a new stabilization cycle
            _topologyNetwork.setOptions({ physics: { enabled: true } });
            _topologyNetwork.once('stabilizationIterationsDone', () => {
                _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
            });
            _topologyNetwork.stabilize(250);
        }
    } catch (e) {
        showError('Failed to reset positions: ' + e.message);
    }
}

function showTopologyNodeDetails(node, allEdges) {
    const panel = document.getElementById('topology-details');
    const title = document.getElementById('topology-details-title');
    const content = document.getElementById('topology-details-content');

    title.textContent = node.label || 'Unknown';
    const connectedEdges = (allEdges || []).filter(e =>
        e.from === node.id || e.to === node.id
    );

    let html = `
        <div class="topology-detail-section">
            <div class="topology-detail-row"><span class="topology-detail-label">IP Address</span><span>${node.ip || 'N/A'}</span></div>
            <div class="topology-detail-row"><span class="topology-detail-label">Device Type</span><span>${node.device_type || 'unknown'}</span></div>
            <div class="topology-detail-row"><span class="topology-detail-label">Status</span><span class="status-badge status-${node.status || 'unknown'}">${node.status || 'unknown'}</span></div>
            ${node.group_name ? `<div class="topology-detail-row"><span class="topology-detail-label">Group</span><span>${node.group_name}</span></div>` : ''}
            <div class="topology-detail-row"><span class="topology-detail-label">In Inventory</span><span>${node.in_inventory ? 'Yes' : 'No'}</span></div>
            ${node.platform ? `<div class="topology-detail-row"><span class="topology-detail-label">Platform</span><span>${node.platform}</span></div>` : ''}
        </div>
    `;

    if (connectedEdges.length > 0) {
        html += `<h4 style="margin-top:1rem; margin-bottom:0.5rem; color:var(--text-color);">Connections (${connectedEdges.length})</h4>`;
        html += '<div class="topology-detail-section">';
        for (const edge of connectedEdges) {
            const isSource = edge.from === node.id;
            const peerLabel = isSource
                ? (_topologyData?.nodes?.find(n => n.id === edge.to)?.label || edge.to)
                : (_topologyData?.nodes?.find(n => n.id === edge.from)?.label || edge.from);
            const proto = { cdp: 'CDP', lldp: 'LLDP', ospf: 'OSPF', bgp: 'BGP' }[edge.protocol] || edge.protocol?.toUpperCase() || 'L2';
            const util = edge.utilization;
            const utilHtml = util ? `<span style="font-size:0.7rem; padding:0.1rem 0.35rem; border-radius:0.2rem; background:${util.utilization_pct > 75 ? 'rgba(244,67,54,0.2)' : util.utilization_pct > 50 ? 'rgba(255,235,59,0.15)' : 'rgba(76,175,80,0.15)'}; color:${util.utilization_pct > 75 ? '#ef5350' : util.utilization_pct > 50 ? '#fdd835' : '#66bb6a'};">${util.utilization_pct}% (${_formatBps(util.in_bps)} in / ${_formatBps(util.out_bps)} out)</span>` : '';
            html += `<div class="topology-detail-row" style="flex-direction:column; align-items:flex-start; gap:0.15rem;">
                <span style="font-weight:500; color:var(--text-color);">${peerLabel}</span>
                <span style="font-size:0.75rem; color:var(--text-muted);">${edge.source_interface || ''} &harr; ${edge.target_interface || ''} &middot; ${proto}</span>
                ${utilHtml}
            </div>`;
        }
        html += '</div>';
    }

    if (!node.in_inventory && node.ip) {
        html += `<button class="btn btn-primary btn-sm" style="margin-top:1rem; width:100%;"
                         onclick="addTopologyNodeToInventory('${node.label}', '${node.ip}')">Add to Inventory</button>`;
    }

    content.innerHTML = html;
    panel.style.display = 'flex';
}

function closeTopologyDetails() {
    document.getElementById('topology-details').style.display = 'none';
}

async function addTopologyNodeToInventory(hostname, ip) {
    try {
        const groups = await api.getInventoryGroups(false);
        if (!groups || groups.length === 0) {
            showError('No inventory groups available. Create a group first.');
            return;
        }
        // Add to the first group by default
        await api.addHost(groups[0].id, hostname, ip, 'unknown');
        showToast(`Added ${hostname} (${ip}) to ${groups[0].name}`, 'success');
        invalidatePageCache('topology');
        invalidatePageCache('inventory');
        await loadTopology({ preserveContent: true });
    } catch (error) {
        showError('Failed to add host: ' + error.message);
    }
}

async function discoverTopology() {
    const btn = document.getElementById('topology-discover-btn');
    const groupFilter = document.getElementById('topology-group-filter').value;
    btn.disabled = true;
    btn.textContent = 'Discovering...';

    try {
        let result;
        if (groupFilter) {
            result = await api.discoverTopologyForGroup(groupFilter);
        } else {
            result = await api.discoverTopologyAll();
        }
        const msg = `Discovered ${result.links_discovered} links from ${result.hosts_scanned} hosts` +
            (result.errors > 0 ? ` (${result.errors} errors)` : '');
        showToast(msg, result.errors > 0 ? 'warning' : 'success');
        invalidatePageCache('topology');
        await loadTopology({ preserveContent: true });
    } catch (error) {
        showError('Discovery failed: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Discover Neighbors';
    }
}

async function refreshTopology() {
    invalidatePageCache('topology');
    // If no network exists yet, do a full load
    if (!_topologyNetwork || !_topoNodesDS || !_topoEdgesDS) {
        loadTopology({ preserveContent: false });
        return;
    }
    // Fetch fresh data + positions without rebuilding the graph
    const groupFilter = document.getElementById('topology-group-filter').value;
    try {
        const [data, positions] = await Promise.all([
            api.getTopology(groupFilter || null),
            api.getTopologyPositions().catch(() => ({})),
        ]);
        _topologyData = data;
        _topoSavedPositions = positions || {};

        const container = document.querySelector('.topology-container');
        const legend = document.getElementById('topology-legend');
        const emptyEl = document.getElementById('topology-empty');

        if (!data.nodes || data.nodes.length === 0) {
            container.style.display = 'none';
            legend.style.display = 'none';
            emptyEl.style.display = 'flex';
            _topologyNetwork.destroy(); _topologyNetwork = null;
            _topoNodesDS = null; _topoEdgesDS = null;
            return;
        }
        container.style.display = 'flex';
        legend.style.display = 'flex';
        emptyEl.style.display = 'none';

        // Capture current positions from the live network for nodes without saved positions
        const currentPositions = _topologyNetwork.getPositions();
        const mergedPos = { ..._topoSavedPositions };
        for (const [nid, pos] of Object.entries(currentPositions)) {
            if (!mergedPos[String(nid)]) {
                mergedPos[String(nid)] = { x: Math.round(pos.x), y: Math.round(pos.y) };
            }
        }

        // Update nodes in-place: add new, update existing, remove stale
        const newNodeIds = new Set(data.nodes.map(n => n.id));
        const existingNodeIds = new Set(_topoNodesDS.getIds());

        // Remove nodes no longer in data
        const toRemove = [...existingNodeIds].filter(id => !newNodeIds.has(id));
        if (toRemove.length) _topoNodesDS.remove(toRemove);

        // Add or update nodes
        const nodeUpdates = data.nodes.map(n => _buildVisNode(n, mergedPos));
        _topoNodesDS.update(nodeUpdates);

        // Update edges in-place
        const newEdgeIds = new Set(data.edges.map(e => e.id));
        const existingEdgeIds = new Set(_topoEdgesDS.getIds());
        const edgesToRemove = [...existingEdgeIds].filter(id => !newEdgeIds.has(id));
        if (edgesToRemove.length) _topoEdgesDS.remove(edgesToRemove);
        const edgeUpdates = data.edges.map(e => _buildVisEdge(e));
        _topoEdgesDS.update(edgeUpdates);

        _updateTopologyChangeBadge(data.unacknowledged_changes || 0);
        showToast('Topology refreshed', 'success');
    } catch (error) {
        showError('Failed to refresh topology: ' + error.message);
    }
}

function fitTopology() {
    if (_topologyNetwork) {
        _topologyNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
    }
}

// ── Path View ──

function togglePathMode() {
    const btn = document.getElementById('topology-path-btn');
    const bar = document.getElementById('topology-path-bar');
    if (_topoPathMode) {
        clearPathMode();
        return;
    }
    if (!_topologyNetwork || !_topologyData || !_topologyData.nodes.length) return;
    _topoPathMode = true;
    _topoPathSource = null;
    btn.classList.add('btn-active');
    bar.style.display = 'flex';
    document.getElementById('topology-path-status').textContent = 'Click a source node...';
    closeTopologyDetails();
}

function clearPathMode() {
    _topoPathMode = false;
    _topoPathSource = null;
    const btn = document.getElementById('topology-path-btn');
    const bar = document.getElementById('topology-path-bar');
    btn.classList.remove('btn-active');
    bar.style.display = 'none';
    // Restore original colors
    if (_topoOriginalColors && _topoNodesDS && _topoEdgesDS) {
        for (const [id, color] of _topoOriginalColors.nodes) {
            _topoNodesDS.update({ id, color, opacity: 1 });
        }
        for (const [id, color] of _topoOriginalColors.edges) {
            _topoEdgesDS.update({ id, color, opacity: 1 });
        }
        _topoOriginalColors = null;
    }
}

function _handlePathClick(nodeId, nodesDS, edgesDS, data) {
    if (!_topoPathSource) {
        _topoPathSource = nodeId;
        const label = nodesDS.get(nodeId)?.label || nodeId;
        document.getElementById('topology-path-status').textContent = `Source: ${label}  —  click a destination node...`;
        // Highlight source
        nodesDS.update({ id: nodeId, borderWidth: 4 });
        return;
    }

    const targetId = nodeId;
    if (targetId === _topoPathSource) return;

    // BFS shortest path
    const path = _bfsShortestPath(_topoPathSource, targetId, data);
    if (!path) {
        showToast('No path found between these nodes.', 'warning');
        clearPathMode();
        return;
    }

    _highlightPath(path, nodesDS, edgesDS, data);

    const srcLabel = nodesDS.get(_topoPathSource)?.label || _topoPathSource;
    const tgtLabel = nodesDS.get(targetId)?.label || targetId;
    document.getElementById('topology-path-status').textContent =
        `Path: ${srcLabel} → ${tgtLabel}  (${path.length - 1} hop${path.length - 1 !== 1 ? 's' : ''})`;

    _topoPathMode = false;
    document.getElementById('topology-path-btn').classList.remove('btn-active');
}

function _bfsShortestPath(startId, endId, data) {
    // Build adjacency list from edges
    const adj = new Map();
    for (const edge of data.edges) {
        if (!adj.has(edge.from)) adj.set(edge.from, []);
        if (!adj.has(edge.to)) adj.set(edge.to, []);
        adj.get(edge.from).push(edge.to);
        adj.get(edge.to).push(edge.from);
    }

    const visited = new Set();
    const queue = [[startId]];
    visited.add(startId);

    while (queue.length > 0) {
        const path = queue.shift();
        const current = path[path.length - 1];
        if (current === endId) return path;

        for (const neighbor of (adj.get(current) || [])) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push([...path, neighbor]);
            }
        }
    }
    return null;  // No path found
}

function _highlightPath(path, nodesDS, edgesDS, data) {
    const pathSet = new Set(path);

    // Find edges on the path
    const pathEdgeIds = new Set();
    for (let i = 0; i < path.length - 1; i++) {
        const a = path[i], b = path[i + 1];
        const edge = data.edges.find(e =>
            (e.from === a && e.to === b) || (e.from === b && e.to === a)
        );
        if (edge) pathEdgeIds.add(edge.id);
    }

    // Stash original colors for restore
    _topoOriginalColors = { nodes: [], edges: [] };
    const dimColor = { background: 'rgba(40,50,60,0.4)', border: 'rgba(60,70,80,0.4)' };
    const dimEdgeColor = { color: 'rgba(80,90,100,0.2)', highlight: 'rgba(80,90,100,0.3)', hover: 'rgba(80,90,100,0.3)' };

    for (const node of nodesDS.get()) {
        _topoOriginalColors.nodes.push([node.id, node.color]);
        if (!pathSet.has(node.id)) {
            nodesDS.update({ id: node.id, color: dimColor, opacity: 0.3 });
        } else {
            // Brighten path nodes
            nodesDS.update({
                id: node.id,
                borderWidth: 4,
                shadow: { enabled: true, color: '#ffffff', size: 20, x: 0, y: 0 },
            });
        }
    }

    for (const edge of edgesDS.get()) {
        _topoOriginalColors.edges.push([edge.id, edge.color]);
        if (!pathEdgeIds.has(edge.id)) {
            edgesDS.update({ id: edge.id, color: dimEdgeColor, opacity: 0.15 });
        } else {
            // Brighten path edges
            edgesDS.update({
                id: edge.id,
                width: 4,
                shadow: { enabled: true, color: '#ffffff', size: 12, x: 0, y: 0 },
            });
        }
    }
}

// ── Node Search ──

let _topoSearchDebounce = null;

function _onTopoSearchInput() {
    clearTimeout(_topoSearchDebounce);
    const input = document.getElementById('topology-search');
    const resultsEl = document.getElementById('topology-search-results');
    const query = (input?.value || '').trim().toLowerCase();
    if (!query || !_topologyData || !_topologyData.nodes.length) {
        resultsEl.style.display = 'none';
        return;
    }
    _topoSearchDebounce = setTimeout(() => {
        const matches = _topologyData.nodes.filter(n =>
            (n.label || '').toLowerCase().includes(query) ||
            (n.ip || '').includes(query)
        ).slice(0, 12);

        if (matches.length === 0) {
            resultsEl.innerHTML = '<div class="topology-search-item" style="color:rgba(180,210,240,0.4); cursor:default;">No matches</div>';
        } else {
            resultsEl.innerHTML = matches.map(n => {
                const label = (n.label || '').replace(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'), '<mark>$1</mark>');
                const ip = (n.ip || '').replace(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'), '<mark>$1</mark>');
                return `<div class="topology-search-item" data-node-id="${n.id}">${label}${n.ip ? `<span class="search-ip">${ip}</span>` : ''}</div>`;
            }).join('');
        }
        resultsEl.style.display = 'block';
    }, 150);
}

function _onTopoSearchResultClick(e) {
    const item = e.target.closest('.topology-search-item');
    if (!item || !item.dataset.nodeId) return;
    const nodeId = isNaN(item.dataset.nodeId) ? item.dataset.nodeId : Number(item.dataset.nodeId);
    _focusTopologyNode(nodeId);
    document.getElementById('topology-search').value = '';
    document.getElementById('topology-search-results').style.display = 'none';
}

function _focusTopologyNode(nodeId) {
    if (!_topologyNetwork) return;
    _topologyNetwork.focus(nodeId, {
        scale: 1.5,
        animation: { duration: 600, easingFunction: 'easeInOutQuad' },
    });
    _topologyNetwork.selectNodes([nodeId]);
    // Show details
    const node = (_topologyData?.nodes || []).find(n => n.id === nodeId);
    if (node) showTopologyNodeDetails(node, _topologyData.edges);
}

document.getElementById('topology-search')?.addEventListener('input', _onTopoSearchInput);
document.getElementById('topology-search')?.addEventListener('keydown', (e) => {
    const resultsEl = document.getElementById('topology-search-results');
    const items = resultsEl?.querySelectorAll('.topology-search-item[data-node-id]') || [];
    if (!items.length) return;
    const activeItem = resultsEl.querySelector('.topology-search-item.active');
    let idx = Array.from(items).indexOf(activeItem);
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        idx = Math.min(idx + 1, items.length - 1);
        items.forEach(i => i.classList.remove('active'));
        items[idx].classList.add('active');
        items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        idx = Math.max(idx - 1, 0);
        items.forEach(i => i.classList.remove('active'));
        items[idx].classList.add('active');
        items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
        e.preventDefault();
        if (activeItem && activeItem.dataset.nodeId) {
            const nodeId = isNaN(activeItem.dataset.nodeId) ? activeItem.dataset.nodeId : Number(activeItem.dataset.nodeId);
            _focusTopologyNode(nodeId);
            document.getElementById('topology-search').value = '';
            resultsEl.style.display = 'none';
        }
    } else if (e.key === 'Escape') {
        resultsEl.style.display = 'none';
    }
});
document.getElementById('topology-search-results')?.addEventListener('click', _onTopoSearchResultClick);
// Close search results when clicking elsewhere
document.addEventListener('click', (e) => {
    if (!e.target.closest('.topology-search-wrap')) {
        const el = document.getElementById('topology-search-results');
        if (el) el.style.display = 'none';
    }
});

// ── Export ──

function exportTopologyPNG() {
    if (!_topologyNetwork) { showToast('No topology to export', 'warning'); return; }
    const canvas = document.getElementById('topology-canvas')?.querySelector('canvas');
    if (!canvas) { showToast('Canvas not found', 'warning'); return; }
    try {
        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.png`;
        link.href = canvas.toDataURL('image/png');
        link.click();
        showToast('PNG exported', 'success');
    } catch (err) {
        showError('Failed to export PNG: ' + err.message);
    }
}

function exportTopologyJSON() {
    if (!_topologyData) { showToast('No topology to export', 'warning'); return; }
    try {
        const blob = new Blob([JSON.stringify(_topologyData, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.download = `topology-${new Date().toISOString().slice(0, 10)}.json`;
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        showToast('JSON exported', 'success');
    } catch (err) {
        showError('Failed to export JSON: ' + err.message);
    }
}

// ── Topology Change Detection UI ─────────────────────────────────────────────

function _updateTopologyChangeBadge(count) {
    const badge = document.getElementById('topology-change-badge');
    const btn = document.getElementById('topology-changes-btn');
    if (!badge || !btn) return;
    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.style.display = 'inline-flex';
        btn.classList.add('has-changes');
    } else {
        badge.style.display = 'none';
        btn.classList.remove('has-changes');
    }
}

async function showTopologyChanges() {
    try {
        const resp = await api.getTopologyChanges(false, 200);
        const changes = resp.changes || [];
        if (changes.length === 0) {
            showToast('No topology changes recorded', 'info');
            return;
        }

        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        title.textContent = 'Topology Changes';

        let html = `<div style="margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="color:var(--text-muted); font-size:0.85rem;">${changes.length} change${changes.length !== 1 ? 's' : ''} detected</span>
            <button class="btn btn-secondary btn-sm" onclick="acknowledgeTopologyChanges()">Acknowledge All</button>
        </div>`;
        html += '<div style="max-height:400px; overflow-y:auto;">';

        for (const c of changes) {
            const isAdded = c.change_type === 'added';
            const icon = isAdded ? '+' : '&minus;';
            const color = isAdded ? '#00e676' : '#ef5350';
            const bg = isAdded ? 'rgba(0,230,118,0.08)' : 'rgba(239,83,80,0.08)';
            const ackClass = c.acknowledged ? ' style="opacity:0.5;"' : '';
            const proto = { cdp: 'CDP', lldp: 'LLDP', ospf: 'OSPF', bgp: 'BGP' }[c.protocol] || c.protocol?.toUpperCase() || '';

            html += `<div class="topology-change-item"${ackClass} style="background:${bg}; border-left:3px solid ${color}; padding:0.5rem 0.75rem; margin-bottom:0.4rem; border-radius:0.25rem;">
                <div style="display:flex; justify-content:space-between; align-items:baseline;">
                    <span style="font-weight:600; color:${color}; font-size:0.9rem;">${icon} ${c.change_type.toUpperCase()}</span>
                    <span style="font-size:0.7rem; color:var(--text-muted);">${new Date(c.detected_at + 'Z').toLocaleString()}</span>
                </div>
                <div style="font-size:0.82rem; margin-top:0.2rem;">
                    <strong>${c.source_hostname || 'Host #' + c.source_host_id}</strong>
                    ${c.source_interface ? `(${c.source_interface})` : ''}
                    &harr;
                    <strong>${c.target_device_name || c.target_ip || 'unknown'}</strong>
                    ${c.target_interface ? `(${c.target_interface})` : ''}
                    ${proto ? `<span style="margin-left:0.4rem; font-size:0.7rem; padding:0.1rem 0.35rem; background:rgba(255,255,255,0.07); border-radius:0.2rem;">${proto}</span>` : ''}
                </div>
            </div>`;
        }
        html += '</div>';
        body.innerHTML = html;
        document.getElementById('modal-overlay').classList.add('active');
    } catch (err) {
        showError('Failed to load topology changes: ' + err.message);
    }
}

async function acknowledgeTopologyChanges() {
    try {
        const resp = await api.acknowledgeTopologyChanges();
        showToast(`Acknowledged ${resp.acknowledged} change${resp.acknowledged !== 1 ? 's' : ''}`, 'success');
        _updateTopologyChangeBadge(0);
        closeAllModals();
    } catch (err) {
        showError('Failed to acknowledge: ' + err.message);
    }
}

// Event listeners for topology controls
document.getElementById('topology-group-filter')?.addEventListener('change', () => {
    invalidatePageCache('topology');
    loadTopology({ preserveContent: false });
});
document.getElementById('topology-layout')?.addEventListener('change', () => {
    // Layout change requires a rebuild (hierarchical vs physics are fundamentally different)
    if (_topologyData) renderTopologyGraph(_topologyData);
});

// Expose topology functions for HTML onclick handlers
window.discoverTopology = discoverTopology;
window.refreshTopology = refreshTopology;
window.fitTopology = fitTopology;
window.closeTopologyDetails = closeTopologyDetails;
window.addTopologyNodeToInventory = addTopologyNodeToInventory;
window.togglePathMode = togglePathMode;
window.clearPathMode = clearPathMode;
window.exportTopologyPNG = exportTopologyPNG;
window.exportTopologyJSON = exportTopologyJSON;
window.toggleUtilizationOverlay = toggleUtilizationOverlay;
window.showTopologyChanges = showTopologyChanges;
window.acknowledgeTopologyChanges = acknowledgeTopologyChanges;
window.resetTopologyPositions = resetTopologyPositions;

// ═══════════════════════════════════════════════════════════════════════════════
// Dashboard
// ═══════════════════════════════════════════════════════════════════════════════

async function loadDashboard(_options = {}) {
    const container = document.getElementById('page-dashboard');
    container.querySelector('.loading')?.remove();

    try {
        const data = await api.getDashboard();
        dashboardData = data;

        const groups = data.stats?.total_groups || 0;
        const hosts = data.stats?.total_hosts || 0;
        const playbooks = data.stats?.total_playbooks || 0;
        const jobs = data.stats?.total_jobs || 0;

        // Animate stats
        animateCounter('stat-groups', groups);
        animateCounter('stat-hosts', hosts);
        animateCounter('stat-playbooks', playbooks);
        animateCounter('stat-jobs', jobs);

        // Animate ring charts — use a sensible max so partial rings look meaningful
        const ringMax = Math.max(groups, hosts, playbooks, jobs, 1);
        animateRing('ring-groups', groups, ringMax);
        animateRing('ring-hosts', hosts, ringMax);
        animateRing('ring-playbooks', playbooks, ringMax);
        animateRing('ring-jobs', jobs, ringMax);

        // Render recent jobs
        renderRecentJobs(data.recent_jobs || []);

        // Render activity timeline
        renderActivityTimeline(data.recent_jobs || []);

        // Render groups overview
        renderGroupsOverview(data.groups || []);
    } catch (error) {
        showError('Failed to load dashboard', container);
    }
}

function isReducedMotion() {
    return document.body.classList.contains('reduced-motion');
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const num = parseInt(target, 10) || 0;
    if (num === 0) { el.textContent = '0'; return; }
    if (isReducedMotion()) { el.textContent = num; return; }
    const duration = 600;
    const start = performance.now();
    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(eased * num);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function skeletonCards(count = 3) {
    return Array.from({length: count}, () =>
        '<div class="skeleton skeleton-card" style="margin-bottom: 0.75rem;"></div>'
    ).join('');
}

function renderRecentJobs(jobs) {
    const container = document.getElementById('recent-jobs');
    if (!jobs.length) {
        container.innerHTML = emptyStateHTML('No recent jobs', 'jobs');
        return;
    }

    container.innerHTML = jobs.map((job, i) => `
        <div class="job-item animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s">
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
        container.innerHTML = emptyStateHTML('No inventory groups', 'inventory');
        return;
    }

    container.innerHTML = groups.map((group, i) => `
        <div class="card card-clickable animate-in" style="animation-delay: ${i * 0.06}s" onclick="goToInventory()">
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

function textMatch(value, query) {
    if (!query) return true;
    return String(value || '').toLowerCase().includes(query);
}

function byNameAsc(a, b) {
    return String(a.name || '').localeCompare(String(b.name || ''));
}

function byNameDesc(a, b) {
    return String(b.name || '').localeCompare(String(a.name || ''));
}

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

function applyPlaybookFilters() {
    const state = listViewState.playbooks;
    const query = state.query.trim().toLowerCase();
    const filtered = state.items.filter((pb) => {
        const tags = Array.isArray(pb.tags) ? pb.tags.join(' ') : (typeof pb.tags === 'string' ? pb.tags : '');
        return !query || textMatch(pb.name, query) || textMatch(pb.description, query) || textMatch(pb.filename, query) || textMatch(tags, query);
    });
    if (state.sort === 'updated_desc') filtered.sort((a, b) => String(b.updated_at || b.created_at || '').localeCompare(String(a.updated_at || a.created_at || '')));
    else if (state.sort === 'updated_asc') filtered.sort((a, b) => String(a.updated_at || a.created_at || '').localeCompare(String(b.updated_at || b.created_at || '')));
    else if (state.sort === 'name_desc') filtered.sort(byNameDesc);
    else filtered.sort(byNameAsc);
    return filtered;
}

function applyJobFilters() {
    const state = listViewState.jobs;
    const query = state.query.trim().toLowerCase();
    const now = new Date();
    const filtered = state.items.filter((job) => {
        const matchesText = !query || textMatch(job.playbook_name, query) || textMatch(job.group_name, query) || textMatch(job.status, query);
        const matchesStatus = state.status === 'all' || String(job.status || '').toLowerCase() === state.status;
        const isDry = Boolean(job.dry_run);
        const matchesDryRun = state.dryRun === 'all' || (state.dryRun === 'yes' && isDry) || (state.dryRun === 'no' && !isDry);
        let matchesDate = true;
        const jobDateStr = job.started_at || job.queued_at;
        if (state.dateRange !== 'all' && jobDateStr) {
            const jobDate = new Date(jobDateStr);
            const diffMs = now - jobDate;
            const diffDays = diffMs / (1000 * 60 * 60 * 24);
            if (state.dateRange === 'today') matchesDate = diffDays < 1;
            else if (state.dateRange === '7d') matchesDate = diffDays <= 7;
            else if (state.dateRange === '30d') matchesDate = diffDays <= 30;
        }
        return matchesText && matchesStatus && matchesDryRun && matchesDate;
    });
    const sortKey = (j) => j.started_at || j.queued_at || '';
    if (state.sort === 'started_asc') filtered.sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
    else filtered.sort((a, b) => sortKey(b).localeCompare(sortKey(a)));
    return filtered;
}

function applyTemplateFilters() {
    const state = listViewState.templates;
    const query = state.query.trim().toLowerCase();
    const filtered = state.items.filter((tpl) =>
        !query || textMatch(tpl.name, query) || textMatch(tpl.description, query) || textMatch(tpl.content, query)
    );
    if (state.sort === 'updated_desc') filtered.sort((a, b) => String(b.updated_at || b.created_at || '').localeCompare(String(a.updated_at || a.created_at || '')));
    else if (state.sort === 'updated_asc') filtered.sort((a, b) => String(a.updated_at || a.created_at || '').localeCompare(String(b.updated_at || b.created_at || '')));
    else if (state.sort === 'name_desc') filtered.sort(byNameDesc);
    else filtered.sort(byNameAsc);
    return filtered;
}

function applyCredentialFilters() {
    const state = listViewState.credentials;
    const query = state.query.trim().toLowerCase();
    const filtered = state.items.filter((cred) =>
        !query || textMatch(cred.name, query) || textMatch(cred.username, query)
    );
    if (state.sort === 'created_desc') filtered.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
    else if (state.sort === 'created_asc') filtered.sort((a, b) => String(a.created_at || '').localeCompare(String(b.created_at || '')));
    else if (state.sort === 'name_desc') filtered.sort(byNameDesc);
    else filtered.sort(byNameAsc);
    return filtered;
}

function bindListControl(id, handler) {
    const el = document.getElementById(id);
    if (!el || el.dataset.bound === '1') return;
    el.dataset.bound = '1';
    el.addEventListener('input', handler);
    el.addEventListener('change', handler);
}

function initListPageControls() {
    // Search inputs: debounced to avoid re-rendering on every keystroke
    bindListControl('inventory-search', debounce((e) => {
        listViewState.inventory.query = e.target.value;
        renderInventoryGroups(applyInventoryFilters());
    }, 300));
    // Sort/filter dropdowns: instant response
    bindListControl('inventory-sort', (e) => {
        listViewState.inventory.sort = e.target.value;
        renderInventoryGroups(applyInventoryFilters());
    });
    bindListControl('playbooks-search', debounce((e) => {
        listViewState.playbooks.query = e.target.value;
        renderPlaybooksList(applyPlaybookFilters());
    }, 300));
    bindListControl('playbooks-sort', (e) => {
        listViewState.playbooks.sort = e.target.value;
        renderPlaybooksList(applyPlaybookFilters());
    });
    bindListControl('jobs-search', debounce((e) => {
        listViewState.jobs.query = e.target.value;
        renderJobsList(applyJobFilters());
    }, 300));
    bindListControl('jobs-sort', (e) => {
        listViewState.jobs.sort = e.target.value;
        renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-status-filter', (e) => {
        listViewState.jobs.status = e.target.value;
        renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-dryrun-filter', (e) => {
        listViewState.jobs.dryRun = e.target.value;
        renderJobsList(applyJobFilters());
    });
    bindListControl('jobs-date-filter', (e) => {
        listViewState.jobs.dateRange = e.target.value;
        renderJobsList(applyJobFilters());
    });
    bindListControl('templates-search', debounce((e) => {
        listViewState.templates.query = e.target.value;
        renderTemplatesList(applyTemplateFilters());
    }, 300));
    bindListControl('templates-sort', (e) => {
        listViewState.templates.sort = e.target.value;
        renderTemplatesList(applyTemplateFilters());
    });
    bindListControl('credentials-search', debounce((e) => {
        listViewState.credentials.query = e.target.value;
        renderCredentialsList(applyCredentialFilters());
    }, 300));
    bindListControl('credentials-sort', (e) => {
        listViewState.credentials.sort = e.target.value;
        renderCredentialsList(applyCredentialFilters());
    });
    bindListControl('drift-search', debounce((e) => {
        listViewState.configDrift.query = e.target.value;
        renderDriftEventsList(applyDriftFilters());
    }, 300));
    bindListControl('drift-status-filter', (e) => {
        listViewState.configDrift.status = e.target.value;
        renderDriftEventsList(applyDriftFilters());
    });
    bindListControl('drift-sort', (e) => {
        listViewState.configDrift.sort = e.target.value;
        renderDriftEventsList(applyDriftFilters());
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Inventory
// ═══════════════════════════════════════════════════════════════════════════════

async function loadInventory(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('inventory-groups');
    if (!preserveContent) {
        container.innerHTML = skeletonCards(4);
    }

    try {
        const [groups, profiles] = await Promise.all([
            api.getInventoryGroups(true),
            api.listSnmpProfiles().catch(() => []),
        ]);
        _snmpProfilesCache = profiles || [];
        listViewState.inventory.items = groups || [];
        if (!groups.length) {
            container.innerHTML = emptyStateHTML('No inventory groups', 'inventory', '<button class="btn btn-primary btn-sm" onclick="showCreateGroupModal()">+ New Group</button>');
            return;
        }
        renderInventoryGroups(applyInventoryFilters());
        // Load SNMP profile assignments for each group and populate selects
        await _populateSnmpProfileSelects(groups);
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderInventoryGroups(groups) {
    const container = document.getElementById('inventory-groups');
    const query = (listViewState.inventory.query || '').trim().toLowerCase();
    const hostMatchesQuery = (host) => query && (
        textMatch(host.hostname, query) || textMatch(host.ip_address, query) || textMatch(host.device_type, query)
    );
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
                ${sortedHosts.length ?
                    sortedHosts.map(host => {
                        // Store host data for the edit modal
                        _hostCache[host.id] = { groupId: group.id, ...host };
                        const isMatch = hostMatchesQuery(host);
                        return `
                        <div class="host-item"${isMatch ? ' style="background: var(--highlight-bg, rgba(59,130,246,0.08)); border-radius: 4px;"' : ''}>
                            <div class="host-info" style="display:flex; align-items:center; gap:0.5rem;">
                                <input type="checkbox" class="host-select" data-host-id="${host.id}" data-group-id="${group.id}" onchange="onHostSelectChange(${group.id})">
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
        </div>`;
    }).join('');

    groups.forEach(group => {
        _groupCache[group.id] = {
            id: group.id,
            name: group.name,
            description: group.description || '',
        };
    });
}

async function _populateSnmpProfileSelects(groups) {
    // Fetch all assignments in parallel
    const assignments = await Promise.all(
        groups.map(g => api.getGroupSnmpAssignment(g.id).catch(() => ({ group_id: g.id, snmp_profile_id: '' })))
    );
    _groupSnmpAssignments = {};
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

window.showGlobalDiscoveryModal = function() {
    const groups = Object.values(_groupCache);
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

    // Elapsed timer
    const scanStart = Date.now();
    const elapsedInterval = setInterval(() => {
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
                        entry.textContent = `\u2713 ${event.host.ip_address} — ${event.host.hostname || 'unknown'} (${event.host.device_type || 'unknown'})`;
                        feedEl.appendChild(entry);
                        feedEl.scrollTop = feedEl.scrollHeight;
                    }
                }
            } else if (event.type === 'done') {
                finalResult = event;
            }
        });

        clearInterval(elapsedInterval);

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
        clearInterval(elapsedInterval);
        closeAllModals();
        showError(`Discovery scan failed: ${error.message}`);
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
    showModal(title, `
        <form onsubmit="runInventoryDiscovery(event, ${groupId}, '${isSync ? 'sync' : 'scan'}')">
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

    if (!cidrs.length) {
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
        _snmpProfilesCache = profiles || [];
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
                <input type="password" class="form-input" name="v3_auth_password" value="${escapeHtml(v3.auth_password || '')}">
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
            <input type="password" class="form-input" name="v3_priv_password" value="${escapeHtml(v3.priv_password || '')}">
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
    if (!confirm('Delete this SNMP profile? Any groups using it will be unassigned.')) return;
    try {
        await api.deleteSnmpProfile(profileId);
        showSuccess('SNMP profile deleted.');
        showSnmpProfilesModal();
    } catch (error) {
        showError(`Failed to delete SNMP profile: ${error.message}`);
    }
};


// ═══════════════════════════════════════════════════════════════════════════════
// Playbooks
// ═══════════════════════════════════════════════════════════════════════════════

async function loadPlaybooks(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('playbooks-list');
    if (!preserveContent) {
        container.innerHTML = skeletonCards(3);
    }

    try {
        const playbooks = await api.getPlaybooks();
        listViewState.playbooks.items = playbooks || [];
        if (!playbooks.length) {
            container.innerHTML = emptyStateHTML('No playbooks available', 'playbooks', '<button class="btn btn-primary btn-sm" onclick="showCreatePlaybookModal()">Create Playbook</button>');
            return;
        }
        renderPlaybooksList(applyPlaybookFilters());
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderPlaybooksList(playbooks) {
    const container = document.getElementById('playbooks-list');
    if (!playbooks.length) {
        container.innerHTML = emptyStateHTML('No matching playbooks', 'playbooks');
        return;
    }

    container.innerHTML = playbooks.map((pb, i) => {
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

        const pbType = pb.type || 'python';
        const typeBadge = pbType === 'ansible'
            ? '<span class="status-badge" style="background: var(--info); color: #fff; margin-right: 0.5rem;">Ansible</span>'
            : '<span class="status-badge" style="background: var(--primary); color: #fff; margin-right: 0.5rem;">Python</span>';

        return `
            <div class="card animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s">
                <div class="card-header">
                    <div>
                        <div class="card-title">${typeBadge}${escapeHtml(pb.name)}</div>
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
}

// ═══════════════════════════════════════════════════════════════════════════════
// Jobs
// ═══════════════════════════════════════════════════════════════════════════════

const JOB_PRIORITY_LABELS = { 0: 'Low', 1: 'Below Normal', 2: 'Normal', 3: 'High', 4: 'Critical' };
const JOB_PRIORITY_COLORS = { 0: 'text-muted', 1: 'text-muted', 2: 'primary', 3: 'warning', 4: 'danger' };

async function loadJobs(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('jobs-list');
    if (!preserveContent) {
        container.innerHTML = skeletonCards(5);
    }

    try {
        const [jobs, queueData] = await Promise.all([
            api.getJobs(100),
            api.getJobQueue(),
        ]);
        listViewState.jobs.items = jobs || [];
        renderJobsQueuePanel(queueData);
        if (!jobs.length) {
            container.innerHTML = emptyStateHTML('No jobs yet', 'jobs', '<button class="btn btn-primary btn-sm" onclick="showLaunchJobModal()">Launch Job</button>');
            return;
        }
        renderJobsList(applyJobFilters());
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderJobsQueuePanel(q) {
    const panel = document.getElementById('jobs-queue-panel');
    if (!panel || !q) return;
    const hasActivity = q.running > 0 || q.queued > 0;
    panel.style.display = hasActivity ? '' : 'none';

    const setT = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setT('jobs-q-running', q.running);
    setT('jobs-q-max', q.max_concurrent);
    setT('jobs-q-queued', q.queued);

    const items = document.getElementById('jobs-q-items');
    if (items) {
        items.innerHTML = (q.jobs || []).map(j => {
            const isRunning = j.status === 'running';
            const pColor = JOB_PRIORITY_COLORS[j.priority] || 'text-muted';
            return `<span class="job-queue-chip ${isRunning ? 'job-queue-chip-running' : ''}" title="${escapeHtml(j.playbook_name || '')} — ${JOB_PRIORITY_LABELS[j.priority] || 'Normal'}">
                <span class="job-queue-chip-dot" style="background:var(--${isRunning ? 'success' : pColor});"></span>
                ${escapeHtml((j.playbook_name || 'Job').substring(0, 20))}
                ${!isRunning ? `<span class="job-queue-chip-pri">${JOB_PRIORITY_LABELS[j.priority] || 'Normal'}</span>` : ''}
            </span>`;
        }).join('');
    }
}

function renderJobsList(jobs) {
    const container = document.getElementById('jobs-list');
    if (!jobs.length) {
        container.innerHTML = emptyStateHTML('No matching jobs', 'jobs');
        return;
    }
    container.innerHTML = jobs.map((job, i) => {
        const priLabel = JOB_PRIORITY_LABELS[job.priority] || 'Normal';
        const priColor = JOB_PRIORITY_COLORS[job.priority] || 'text-muted';
        const showPri = job.priority != null && job.priority !== 2;
        const deps = (() => { try { return JSON.parse(job.depends_on || '[]'); } catch { return []; } })();
        const hasDeps = deps.length > 0;
        const timeLabel = job.started_at ? `Started: ${formatDate(job.started_at)}` :
                          job.queued_at ? `Queued: ${formatDate(job.queued_at)}` : '';

        const actions = [];
        if (job.status === 'running' || job.status === 'queued') {
            actions.push(`<button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); cancelJobFromList(${job.id})">Cancel</button>`);
        }
        if (job.status === 'failed' || job.status === 'cancelled') {
            actions.push(`<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); retryJobFromList(${job.id})">Retry</button>`);
        }
        actions.push(`<button class="btn btn-sm btn-secondary" onclick="viewJobOutput(${job.id})">View Output</button>`);

        return `<div class="job-item animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s">
            <div class="job-info">
                <div class="job-title">
                    ${escapeHtml(job.playbook_name || 'Unknown')}
                    ${showPri ? `<span class="job-priority-badge job-priority-${priColor}" title="Priority: ${priLabel}">${priLabel}</span>` : ''}
                    ${hasDeps ? `<span class="job-dep-badge" title="Depends on job(s): ${deps.join(', ')}">deps: ${deps.join(', ')}</span>` : ''}
                </div>
                <div class="job-meta">
                    Group: ${escapeHtml(job.group_name || 'Unknown')} •
                    ${timeLabel} •
                    <span class="status-badge status-${job.status}">${job.status}</span>
                    ${job.dry_run ? ' • <span style="color: var(--warning);">DRY RUN</span>' : ''}
                    ${job.launched_by ? ` • <span style="color:var(--text-muted);">by ${escapeHtml(job.launched_by)}</span>` : ''}
                </div>
            </div>
            <div style="display:flex; gap:0.4rem;">${actions.join('')}</div>
        </div>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════════════════════
// Templates
// ═══════════════════════════════════════════════════════════════════════════════

async function loadTemplates(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('templates-list');
    if (!preserveContent) {
        container.innerHTML = skeletonCards(3);
    }

    try {
        const templates = await api.getTemplates();
        listViewState.templates.items = templates || [];
        if (!templates.length) {
            container.innerHTML = emptyStateHTML('No templates', 'templates', '<button class="btn btn-primary btn-sm" onclick="showCreateTemplateModal()">+ New Template</button>');
            return;
        }
        renderTemplatesList(applyTemplateFilters());
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderTemplatesList(templates) {
    const container = document.getElementById('templates-list');
    if (!templates.length) {
        container.innerHTML = emptyStateHTML('No matching templates', 'templates');
        return;
    }

    container.innerHTML = templates.map((template, i) => {
        const content = escapeHtml(template.content);
        const lines = content.split('\n');
        const isLong = lines.length > 3;
        const preview = lines.slice(0, 3).join('\n');
        return `
        <div class="card animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s">
            <div class="card-header">
                <div>
                    <div class="card-title">${escapeHtml(template.name)}</div>
                    <div class="card-description">${escapeHtml(template.description || '')}</div>
                </div>
                <div>
                    ${isLong ? `<button class="btn btn-sm btn-ghost template-expand-btn" onclick="toggleTemplateContent(this)" data-expanded="false">Expand</button>` : ''}
                    <button class="btn btn-sm btn-secondary" onclick="editTemplate(${template.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteTemplate(${template.id})">Delete</button>
                </div>
            </div>
            <div class="template-content-wrap${isLong ? ' template-content-collapsed' : ''}">
                <pre class="template-content-pre">${isLong ? preview : content}</pre>
                ${isLong ? `<pre class="template-content-full" style="display:none;">${content}</pre>` : ''}
                ${isLong ? '<div class="template-fade"></div>' : ''}
            </div>
        </div>`;
    }).join('');
}

function toggleTemplateContent(btn) {
    const card = btn.closest('.card');
    const wrap = card.querySelector('.template-content-wrap');
    const preview = wrap.querySelector('.template-content-pre');
    const full = wrap.querySelector('.template-content-full');
    const fade = wrap.querySelector('.template-fade');
    const expanded = btn.dataset.expanded === 'true';

    if (expanded) {
        preview.style.display = '';
        full.style.display = 'none';
        if (fade) fade.style.display = '';
        wrap.classList.add('template-content-collapsed');
        btn.textContent = 'Expand';
        btn.dataset.expanded = 'false';
    } else {
        preview.style.display = 'none';
        full.style.display = '';
        if (fade) fade.style.display = 'none';
        wrap.classList.remove('template-content-collapsed');
        btn.textContent = 'Collapse';
        btn.dataset.expanded = 'true';
    }
}
window.toggleTemplateContent = toggleTemplateContent;

// ═══════════════════════════════════════════════════════════════════════════════
// Credentials
// ═══════════════════════════════════════════════════════════════════════════════

async function loadCredentials(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('credentials-list');
    if (!preserveContent) {
        container.innerHTML = skeletonCards(3);
    }

    try {
        const credentials = await api.getCredentials();
        listViewState.credentials.items = credentials || [];
        if (!credentials.length) {
            container.innerHTML = emptyStateHTML('No credentials', 'credentials', '<button class="btn btn-primary btn-sm" onclick="showCreateCredentialModal()">+ New Credential</button>');
            return;
        }
        renderCredentialsList(applyCredentialFilters());
        initCredentialChangeTracking();
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderCredentialsList(credentials) {
    const container = document.getElementById('credentials-list');
    if (!credentials.length) {
        container.innerHTML = emptyStateHTML('No matching credentials', 'credentials');
        return;
    }
    container.innerHTML = credentials.map((cred, i) => `
        <div class="credential-card animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s" data-cred-id="${cred.id}">
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
}

function initCredentialChangeTracking() {
    document.querySelectorAll('.credential-card').forEach(card => {
        const inputs = card.querySelectorAll('.credential-input');
        const saveBtn = card.querySelector('.credential-save-btn');
        const originals = {};
        // Track which fields are dirty without iterating all inputs on each keystroke
        const dirtyFields = new Set();

        inputs.forEach(input => {
            originals[input.dataset.field] = input.value;
        });
        card._originals = originals;

        inputs.forEach(input => {
            input.addEventListener('input', () => {
                const field = input.dataset.field;
                const isPasswordField = field === 'password' || field === 'secret';
                if (isPasswordField ? input.value.length > 0 : input.value !== originals[field]) {
                    dirtyFields.add(field);
                } else {
                    dirtyFields.delete(field);
                }
                saveBtn.style.display = dirtyFields.size > 0 ? '' : 'none';
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
    // Populate default credential dropdown
    const credSelect = document.getElementById('default-credential-id');
    if (credSelect) {
        try {
            const creds = await api.getCredentials();
            credSelect.innerHTML = '<option value="">-- None --</option>' +
                creds.map(c => `<option value="${c.id}">${c.name} (${c.username})</option>`).join('');
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
        renderLoginRules();
        renderAuthConfig();
        loadTopologyDiscoveryConfig();
        initThemeControls();
    } catch (error) {
        const usersContainer = document.getElementById('admin-users-list');
        if (usersContainer) {
            usersContainer.innerHTML = `<div class="error">Failed loading admin settings: ${escapeHtml(error.message)}</div>`;
        }
    }
}

// ── Topology Discovery Schedule ──

async function loadTopologyDiscoveryConfig() {
    try {
        const cfg = await api.getTopologyDiscoveryConfig();
        document.getElementById('topo-disc-enabled').checked = !!cfg.enabled;
        document.getElementById('topo-disc-interval').value = cfg.interval_seconds || 3600;
    } catch { /* not admin or feature unavailable */ }
}

function bindTopologyDiscoveryForm() {
    const form = document.getElementById('admin-topology-discovery-form');
    if (!form || form._bound) return;
    form._bound = true;
    form.addEventListener('submit', async (e) => {
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
    });
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
    activateFocusTrap('modal-overlay');
}

function closeAllModals() {
    const modal = document.querySelector('#modal-overlay .modal');
    if (modal) {
        modal.classList.remove('modal-large');
    }

    document.getElementById('modal-overlay').classList.remove('active');
    document.getElementById('modal-body').innerHTML = '';
    deactivateFocusTrap('modal-overlay');
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
        activateFocusTrap('modal-overlay');
        cancelBtn.addEventListener('click', onCancel);
        confirmBtn.addEventListener('click', onConfirm);
        // Focus the cancel button by default for safety
        requestAnimationFrame(() => cancelBtn.focus());
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
            api.getInventoryGroups(true),
            api.getCredentials(),
            api.getTemplates(),
        ]);
        const groupsWithHosts = groups.map((group) => ({ ...group, hosts: group.hosts || [] }));

        showModal('Launch Job', `
            <form onsubmit="launchJob(event)">
                <div class="form-group">
                    <label class="form-label">Playbook</label>
                    <select class="form-select" name="playbook_id" id="job-playbook-select" required onchange="window._onJobPlaybookChange(this.value)">
                        <option value="">Select a playbook...</option>
                        ${playbooks.map(pb => {
                            const typeTag = pb.type === 'ansible' ? ' [Ansible]' : '';
                            return `<option value="${pb.id}" data-type="${pb.type || 'python'}">${escapeHtml(pb.name)}${typeTag}</option>`;
                        }).join('')}
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
                <div class="form-group" id="job-template-group">
                    <label class="form-label">Template (optional)</label>
                    <select class="form-select" name="template_id">
                        <option value="">None</option>
                        ${templates.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('')}
                    </select>
                    <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">If the selected playbook expects a template (e.g., VLAN 1 remediation), choose one here.</small>
                </div>
                <div style="display:flex; gap:0.75rem; flex-wrap:wrap;">
                    <div class="form-group" style="flex:1; min-width:140px;">
                        <label class="form-label">Priority</label>
                        <select class="form-select" name="priority">
                            <option value="0">Low</option>
                            <option value="1">Below Normal</option>
                            <option value="2" selected>Normal</option>
                            <option value="3">High</option>
                            <option value="4">Critical</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex:1; min-width:140px;">
                        <label class="form-label">Depends On (Job IDs)</label>
                        <input type="text" class="form-input" name="depends_on" placeholder="e.g. 12, 15" title="Comma-separated job IDs that must complete first">
                    </div>
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

window._onJobPlaybookChange = function(playbookId) {
    const select = document.getElementById('job-playbook-select');
    const templateGroup = document.getElementById('job-template-group');
    if (!select || !templateGroup) return;
    const option = select.querySelector(`option[value="${playbookId}"]`);
    const pbType = option ? option.getAttribute('data-type') : 'python';
    templateGroup.style.display = pbType === 'ansible' ? 'none' : '';
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
        const priority = parseInt(formData.get('priority') || '2');
        const depsStr = (formData.get('depends_on') || '').trim();
        const dependsOn = depsStr ? depsStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : null;

        const job = await api.launchJob(
            playbookId,
            null, // No longer using inventory_group_id
            credentialId,
            templateId,
            dryRun,
            hostIds,
            priority,
            dependsOn
        );
        closeAllModals();
        await loadJobs();
        showSuccess(`Job queued successfully on ${hostIds.length} host(s)`);
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
    const pythonDefault = `"""
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
                        yield self.log_success(f"Connected to {hostname}", host=hostname)
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

    const ansibleDefault = `---
- name: My Ansible Playbook
  hosts: all
  gather_facts: false
  connection: ansible.netcommon.network_cli

  tasks:
    - name: Gather device facts
      cisco.ios.ios_facts:
        gather_subset: min
      register: facts

    - name: Show version
      cisco.ios.ios_command:
        commands:
          - show version
      register: result

    - name: Display output
      debug:
        var: result.stdout_lines
`;

    showModal('Create Playbook', `
        <form onsubmit="createPlaybook(event)">
            <div class="form-group">
                <label class="form-label">Type</label>
                <select class="form-select" name="type" id="create-pb-type" onchange="window._toggleCreatePbType(this.value)">
                    <option value="python">Python (Netmiko)</option>
                    <option value="ansible">Ansible (YAML)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Playbook Name</label>
                <input type="text" class="form-input" name="name" placeholder="My Playbook" required>
            </div>
            <div class="form-group">
                <label class="form-label">Filename</label>
                <input type="text" class="form-input" name="filename" id="create-pb-filename" placeholder="my_playbook.py" required>
                <small id="create-pb-ext-hint" style="color: var(--text-muted); font-size: 0.75rem;">Must end with .py</small>
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
                <label class="form-label" id="create-pb-code-label">Python Code</label>
                <textarea class="form-textarea code-editor" name="content" id="create-pb-content" wrap="off" spellcheck="false" style="min-height: 500px; font-family: 'Courier New', monospace;" required>${pythonDefault}</textarea>
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem;">
                <button type="button" class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create</button>
            </div>
        </form>
    `);

    // Store defaults for toggling
    window._pbDefaults = { python: pythonDefault, ansible: ansibleDefault };
    window._pbContentModified = false;
    const contentEl = document.getElementById('create-pb-content');
    if (contentEl) {
        contentEl.addEventListener('input', () => { window._pbContentModified = true; }, { once: true });
    }
};

window._toggleCreatePbType = function(type) {
    const filenameInput = document.getElementById('create-pb-filename');
    const extHint = document.getElementById('create-pb-ext-hint');
    const codeLabel = document.getElementById('create-pb-code-label');
    const contentEl = document.getElementById('create-pb-content');

    if (type === 'ansible') {
        if (filenameInput) filenameInput.placeholder = 'my_playbook.yml';
        if (extHint) extHint.textContent = 'Must end with .yml or .yaml';
        if (codeLabel) codeLabel.textContent = 'Ansible YAML';
        if (contentEl && !window._pbContentModified) contentEl.value = window._pbDefaults.ansible;
    } else {
        if (filenameInput) filenameInput.placeholder = 'my_playbook.py';
        if (extHint) extHint.textContent = 'Must end with .py';
        if (codeLabel) codeLabel.textContent = 'Python Code';
        if (contentEl && !window._pbContentModified) contentEl.value = window._pbDefaults.python;
    }
};

window.createPlaybook = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const tagsStr = formData.get('tags') || '';
    const tags = tagsStr.split(',').map(t => t.trim()).filter(t => t);
    const pbType = formData.get('type') || 'python';

    try {
        let filename = formData.get('filename');
        if (pbType === 'ansible') {
            if (!filename.endsWith('.yml') && !filename.endsWith('.yaml')) {
                filename += '.yml';
            }
        } else {
            if (!filename.endsWith('.py')) {
                filename += '.py';
            }
        }

        await api.createPlaybook(
            formData.get('name'),
            filename,
            formData.get('description') || '',
            tags,
            formData.get('content'),
            pbType
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
        
        const pbType = playbook.type || 'python';
        const isAnsible = pbType === 'ansible';
        const extHint = isAnsible ? 'Must end with .yml or .yaml' : 'Must end with .py';
        const codeLabel = isAnsible ? 'Ansible YAML' : 'Python Code';

        showModal('Edit Playbook', `
            <form onsubmit="updatePlaybook(event, ${playbookId})">
                <input type="hidden" name="type" value="${pbType}">
                <div class="form-group">
                    <label class="form-label">Type</label>
                    <div style="padding: 0.5rem 0;">
                        <span class="status-badge" style="background: var(${isAnsible ? '--info' : '--primary'}); color: #fff;">${isAnsible ? 'Ansible' : 'Python'}</span>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Playbook Name</label>
                    <input type="text" class="form-input" name="name" value="${escapeHtml(playbook.name || '')}" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Filename</label>
                    <input type="text" class="form-input" name="filename" value="${escapeHtml(playbook.filename || '')}" required>
                    <small style="color: var(--text-muted); font-size: 0.75rem;">${extHint}</small>
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
                    <label class="form-label">${codeLabel}</label>
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
    const pbType = formData.get('type') || 'python';

    try {
        let filename = formData.get('filename');
        if (pbType === 'ansible') {
            if (!filename.endsWith('.yml') && !filename.endsWith('.yaml')) {
                filename += '.yml';
            }
        } else {
            if (!filename.endsWith('.py')) {
                filename += '.py';
            }
        }

        await api.updatePlaybook(playbookId, {
            name: formData.get('name'),
            filename: filename,
            description: formData.get('description') || '',
            tags: tags,
            content: formData.get('content'),
            type: pbType,
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

let _currentViewJobId = null;

window.viewJobOutput = async function(jobId) {
    _currentViewJobId = jobId;
    const modal = document.getElementById('job-output-modal');
    const output = document.getElementById('job-output');

    output.innerHTML = '<div class="loading">Loading...</div>';
    modal.classList.add('active');
    activateFocusTrap('job-output-modal');

    // Hide action buttons initially
    const cancelBtn = document.getElementById('job-output-cancel-btn');
    const retryBtn = document.getElementById('job-output-retry-btn');
    const statusBadge = document.getElementById('job-output-status');
    const priBadge = document.getElementById('job-output-priority');
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (retryBtn) retryBtn.style.display = 'none';
    if (statusBadge) statusBadge.style.display = 'none';
    if (priBadge) priBadge.style.display = 'none';

    // Load historical events
    try {
        const [events, job] = await Promise.all([
            api.getJobEvents(jobId),
            api.getJob(jobId),
        ]);
        output.innerHTML = events.map(e =>
            `<div class="job-output-line ${e.level}">[${formatTime(e.timestamp)}] ${e.host ? e.host + ': ' : ''}${escapeHtml(e.message)}</div>`
        ).join('');

        // Update modal controls based on job state
        if (statusBadge) {
            statusBadge.textContent = job.status;
            statusBadge.className = `status-badge status-${job.status}`;
            statusBadge.style.display = '';
        }
        if (priBadge && job.priority != null && job.priority !== 2) {
            priBadge.textContent = JOB_PRIORITY_LABELS[job.priority] || 'Normal';
            priBadge.className = `job-priority-badge job-priority-${JOB_PRIORITY_COLORS[job.priority] || 'text-muted'}`;
            priBadge.style.display = '';
        }
        if (cancelBtn) cancelBtn.style.display = (job.status === 'running' || job.status === 'queued') ? '' : 'none';
        if (retryBtn) retryBtn.style.display = (job.status === 'failed' || job.status === 'cancelled') ? '' : 'none';

        // Connect WebSocket for live updates
        if (job.status === 'running' || job.status === 'queued') {
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
                    // Update buttons
                    if (cancelBtn) cancelBtn.style.display = 'none';
                    if (retryBtn) retryBtn.style.display = '';
                    if (statusBadge) { statusBadge.textContent = data.status; statusBadge.className = `status-badge status-${data.status}`; }
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
    deactivateFocusTrap('job-output-modal');
    _currentViewJobId = null;
};

window.cancelCurrentJob = async function() {
    if (!_currentViewJobId) return;
    if (!confirm('Cancel this job?')) return;
    try {
        await api.cancelJob(_currentViewJobId);
        showSuccess('Job cancelled');
        closeJobOutputModal();
        loadJobs();
    } catch (error) {
        showError('Failed to cancel: ' + error.message);
    }
};

window.retryCurrentJob = async function() {
    if (!_currentViewJobId) return;
    try {
        const result = await api.retryJob(_currentViewJobId);
        showSuccess(`Job retried as #${result.job_id}`);
        closeJobOutputModal();
        await loadJobs();
        setTimeout(() => viewJobOutput(result.job_id), 500);
    } catch (error) {
        showError('Failed to retry: ' + error.message);
    }
};

window.cancelJobFromList = async function(jobId) {
    if (!confirm('Cancel this job?')) return;
    try {
        await api.cancelJob(jobId);
        showSuccess('Job cancelled');
        loadJobs();
    } catch (error) {
        showError('Failed to cancel: ' + error.message);
    }
};

window.retryJobFromList = async function(jobId) {
    try {
        const result = await api.retryJob(jobId);
        showSuccess(`Job retried as #${result.job_id}`);
        loadJobs();
    } catch (error) {
        showError('Failed to retry: ' + error.message);
    }
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

function getToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    return container;
}

function showToast(message, type = 'info', duration = 4000) {
    const container = getToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const icons = {
        success: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        error: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        info: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" aria-label="Close">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => dismissToast(toast));
    container.appendChild(toast);
    // Trigger entrance animation on next frame
    requestAnimationFrame(() => toast.classList.add('toast-visible'));

    const timer = setTimeout(() => dismissToast(toast), duration);
    toast._timer = timer;
}

function dismissToast(toast) {
    if (toast._dismissed) return;
    toast._dismissed = true;
    clearTimeout(toast._timer);
    toast.classList.remove('toast-visible');
    toast.classList.add('toast-exit');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
    // Fallback removal
    setTimeout(() => toast.remove(), 500);
}

function showError(message, container = null) {
    if (container) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error';
        errorDiv.textContent = message;
        container.insertBefore(errorDiv, container.firstChild);
    } else {
        showToast(message, 'error', 5000);
    }
}

function showSuccess(message) {
    showToast(message, 'success', 3000);
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
    invalidatePageCache(...CACHEABLE_PAGES);
    // Store CSRF token from login/register response
    if (userData.csrf_token) {
        setCsrfToken(userData.csrf_token);
    }
    currentUserData = userData;
    currentUser = userData.username;
    currentFeatureAccess = Array.isArray(userData.feature_access) ? userData.feature_access : [];
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-container').style.display = 'flex';
    const navUserLabel = document.querySelector('#nav-user .nav-user-label');
    if (navUserLabel) navUserLabel.textContent = userData.display_name || userData.username;
    initNavigation();
    applyFeatureVisibility();

    // Enforce first-login password reset before allowing any navigation
    if (userData.must_change_password) {
        showForcePasswordChange();
        return;
    }

    const orderedPages = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'converter'];
    const firstAllowed = orderedPages.find((page) => canAccessFeature(NAV_FEATURE_MAP[page])) || 'dashboard';
    // Restore page from URL hash if present, otherwise go to first allowed page
    const hashPage = getPageFromHash();
    const startPage = hashPage && canAccessFeature(NAV_FEATURE_MAP[hashPage] || hashPage) ? hashPage : firstAllowed;
    navigateToPage(startPage);
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
    activateFocusTrap('user-menu-overlay');
    console.log('showUserMenu: User menu overlay activated.');
};

window.closeUserMenu = function() {
    document.getElementById('user-menu-overlay').classList.remove('active');
    deactivateFocusTrap('user-menu-overlay');
};

window.doLogout = async function() {
    try {
        await api.logout();
    } catch (e) {
        // ignore
    }
    currentUser = null;
    currentUserData = null;
    invalidatePageCache(...CACHEABLE_PAGES);
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
            const navLabel = document.querySelector('#nav-user .nav-user-label');
            if (navLabel) navLabel.textContent = newName;
            if (currentUserData) currentUserData.display_name = newName;
            showSuccess('Profile updated successfully');
        } catch (error) {
            showError(`Failed to update profile: ${error.message}`);
        }
    });
};

function showForcePasswordChange() {
    showModal('Password Change Required', `
        <p style="color: var(--text-muted); margin-bottom: 1.25rem;">
            You must change the default password before continuing.
        </p>
        <form id="force-password-form">
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
                <button type="submit" class="btn btn-primary">Change Password</button>
            </div>
        </form>
    `);

    // Prevent closing the modal without changing password
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.setAttribute('onclick', '');
    const closeBtn = overlay?.querySelector('.modal-close');
    if (closeBtn) closeBtn.style.display = 'none';

    document.getElementById('force-password-form').addEventListener('submit', async (e) => {
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
            // Restore modal close behavior
            if (overlay) overlay.setAttribute('onclick', 'closeAllModals()');
            if (closeBtn) closeBtn.style.display = '';
            closeAllModals();
            currentUserData.must_change_password = false;
            showSuccess('Password changed successfully. Welcome!');
            const orderedPages = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'converter'];
            const firstAllowed = orderedPages.find((page) => canAccessFeature(NAV_FEATURE_MAP[page])) || 'dashboard';
            navigateToPage(firstAllowed);
        } catch (error) {
            showError(`Failed to change password: ${error.message}`);
        }
    });
}

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

function initLoginParticles() {
    const canvas = document.getElementById('login-particles');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    const particles = [];
    const PARTICLE_COUNT = 50;

    let cachedColor = '#7fa07f';
    function updateColor() {
        const style = getComputedStyle(document.documentElement);
        cachedColor = style.getPropertyValue('--primary-light').trim() || '#7fa07f';
    }

    function resize() {
        canvas.width = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
        updateColor();
    }
    resize();
    window.addEventListener('resize', resize);
    
    // Also observe theme changes if attributes change on html
    const themeObserver = new MutationObserver(updateColor);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            r: Math.random() * 2 + 0.5,
            dx: (Math.random() - 0.5) * 0.4,
            dy: (Math.random() - 0.5) * 0.4,
            opacity: Math.random() * 0.5 + 0.15,
        });
    }

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        const color = cachedColor;
        // Draw connecting lines for nearby particles
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.strokeStyle = color;
                    ctx.globalAlpha = (1 - dist / 120) * 0.12;
                    ctx.lineWidth = 0.5;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        // Draw particles
        for (const p of particles) {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            p.x += p.dx;
            p.y += p.dy;
            if (p.x < 0 || p.x > canvas.width) p.dx *= -1;
            if (p.y < 0 || p.y > canvas.height) p.dy *= -1;
        }
        ctx.globalAlpha = 1;
        if (!isReducedMotion()) animId = requestAnimationFrame(draw);
    }

    if (!isReducedMotion()) draw();

    // Stop animation once user logs in (login-screen hidden)
    const observer = new MutationObserver(() => {
        const screen = document.getElementById('login-screen');
        if (screen && screen.style.display === 'none') {
            cancelAnimationFrame(animId);
            observer.disconnect();
        }
    });
    observer.observe(document.getElementById('login-screen'), { attributes: true, attributeFilter: ['style'] });
}

function initAppParticles() {
    const canvas = document.getElementById('app-particles');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    const particles = [];
    const PARTICLE_COUNT = 35; // slightly fewer for the app to not clutter

    let cachedColor = '#7fa07f';
    function updateColor() {
        const style = getComputedStyle(document.documentElement);
        cachedColor = style.getPropertyValue('--primary-light').trim() || '#7fa07f';
    }

    function resize() {
        canvas.width = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
        updateColor();
    }
    resize();
    window.addEventListener('resize', resize);
    
    const themeObserver = new MutationObserver(updateColor);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push({
            x: Math.random() * (canvas.width || window.innerWidth),
            y: Math.random() * (canvas.height || window.innerHeight),
            r: Math.random() * 2 + 0.5,
            dx: (Math.random() - 0.5) * 0.3,
            dy: (Math.random() - 0.5) * 0.3,
            opacity: Math.random() * 0.4 + 0.1,
        });
    }

    let isRunning = false;

    function draw() {
        if (!isRunning) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        const color = cachedColor;
        
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.strokeStyle = color;
                    ctx.globalAlpha = (1 - dist / 150) * 0.08;
                    ctx.lineWidth = 0.5;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        
        for (const p of particles) {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.globalAlpha = p.opacity;
            ctx.fill();
            p.x += p.dx;
            p.y += p.dy;
            if (p.x < 0 || p.x > canvas.width) p.dx *= -1;
            if (p.y < 0 || p.y > canvas.height) p.dy *= -1;
        }
        ctx.globalAlpha = 1;
        if (!isReducedMotion()) animId = requestAnimationFrame(draw);
    }

    // Only run when app is visible
    const observer = new MutationObserver(() => {
        const screen = document.getElementById('app-container');
        const isVisible = screen && screen.style.display !== 'none';
        if (isVisible && !isRunning) {
            isRunning = true;
            resize(); // Ensure canvas has dimensions once shown
            if (!isReducedMotion()) draw();
        } else if (!isVisible && isRunning) {
            isRunning = false;
            cancelAnimationFrame(animId);
        }
    });
    observer.observe(document.getElementById('app-container'), { attributes: true, attributeFilter: ['style'] });
}

function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebar-toggle');
    if (!sidebar || !toggle) return;
    const COLLAPSED_KEY = 'plexus-sidebar-collapsed';
    if (localStorage.getItem(COLLAPSED_KEY) === '1') {
        sidebar.classList.add('collapsed');
    }
    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem(COLLAPSED_KEY, sidebar.classList.contains('collapsed') ? '1' : '0');
    });

    // Mobile hamburger + backdrop
    const hamburger = document.getElementById('hamburger-btn');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (hamburger) {
        hamburger.addEventListener('click', () => toggleMobileSidebar());
    }
    if (backdrop) {
        backdrop.addEventListener('click', () => closeMobileSidebar());
    }
    // Close mobile sidebar on nav link click
    sidebar.querySelectorAll('.nav-link[data-page]').forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= 768) closeMobileSidebar();
        });
    });
}

function toggleMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (!sidebar) return;
    const opening = !sidebar.classList.contains('mobile-open');
    sidebar.classList.toggle('mobile-open', opening);
    if (backdrop) backdrop.classList.toggle('visible', opening);
}

function closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.remove('mobile-open');
    if (backdrop) backdrop.classList.remove('visible');
}

// ═══════════════════════════════════════════════════════════════════════════════
// Converter Stepper
// ═══════════════════════════════════════════════════════════════════════════════

function updateConverterStepper(activeStep) {
    const steps = document.querySelectorAll('.stepper-step');
    const fill1 = document.getElementById('stepper-fill-1');
    const fill2 = document.getElementById('stepper-fill-2');
    if (!steps.length) return;

    steps.forEach((step) => {
        const stepNum = parseInt(step.dataset.step, 10);
        step.classList.remove('active', 'completed');
        if (stepNum < activeStep) {
            step.classList.add('completed');
            // Replace number with checkmark
            const numEl = step.querySelector('.stepper-number');
            if (numEl) numEl.innerHTML = '&#10003;';
        } else if (stepNum === activeStep) {
            step.classList.add('active');
            const numEl = step.querySelector('.stepper-number');
            if (numEl) numEl.textContent = stepNum;
        } else {
            const numEl = step.querySelector('.stepper-number');
            if (numEl) numEl.textContent = stepNum;
        }
    });

    if (fill1) fill1.style.width = activeStep > 1 ? '100%' : '0%';
    if (fill2) fill2.style.width = activeStep > 2 ? '100%' : '0%';
}

window.jumpToConverterStep = function (step) {
    const step1 = document.getElementById('converter-step1');
    const step2 = document.getElementById('converter-step2');
    const step3 = document.getElementById('converter-step3');
    const statusDiv = document.getElementById('converter-status');
    const importOutput = document.getElementById('import-output-window');

    if (step === 1) {
        // Show upload form, hide review/import
        if (step1) step1.style.display = '';
        if (step2) step2.style.display = 'none';
        if (step3) step3.style.display = 'none';
        updateConverterStepper(1);
        if (statusDiv) statusDiv.textContent = '';
        step1?.scrollIntoView({ behavior: 'smooth' });
    } else if (step === 2) {
        // Show review section
        if (step1) step1.style.display = 'none';
        if (step2) step2.style.display = 'block';
        if (step3) step3.style.display = 'none';
        updateConverterStepper(2);
        if (statusDiv) statusDiv.textContent = converterSessionId
            ? `Reviewing session ${converterSessionId}.`
            : 'No conversion session active — go back to Step 1 to convert, or select a recent session.';
        step2?.scrollIntoView({ behavior: 'smooth' });
    } else if (step === 3) {
        // Show import section
        if (step1) step1.style.display = 'none';
        if (step2) step2.style.display = 'none';
        if (step3) step3.style.display = 'block';
        updateConverterStepper(3);
        if (statusDiv) statusDiv.textContent = converterSessionId
            ? `Using session ${converterSessionId}. Provide FTD credentials to import.`
            : 'No conversion session active — go back to Step 1 to convert, or select a recent session.';
        if (importOutput) { importOutput.textContent = ''; importOutput.style.display = 'none'; }
        step3?.scrollIntoView({ behavior: 'smooth' });
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Dashboard Ring Charts
// ═══════════════════════════════════════════════════════════════════════════════

function animateRing(elementId, value, maxValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const circumference = 2 * Math.PI * 34; // r=34
    const clamped = Math.min(value, maxValue);
    const ratio = maxValue > 0 ? clamped / maxValue : 0;
    const offset = circumference * (1 - ratio);
    // Start fully hidden, then animate
    el.style.strokeDasharray = circumference;
    el.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => {
        el.style.strokeDashoffset = offset;
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dashboard Activity Timeline
// ═══════════════════════════════════════════════════════════════════════════════

function renderActivityTimeline(jobs) {
    const container = document.getElementById('activity-timeline');
    if (!container) return;

    if (!jobs || !jobs.length) {
        container.innerHTML = emptyStateHTML('No recent activity', 'jobs');
        return;
    }

    container.innerHTML = jobs.map((job, i) => {
        const statusClass = job.status === 'running' ? 'timeline-running'
            : job.status === 'failed' ? 'timeline-failure'
            : job.status === 'completed' ? 'timeline-success'
            : '';
        const pulseDot = job.status === 'running' ? '<span class="pulse-dot"></span>' : '';
        return `
            <div class="timeline-item ${statusClass} animate-in" style="animation-delay: ${i * 0.08}s">
                <div class="timeline-title">${escapeHtml(job.playbook_name || 'Unknown')}</div>
                <div class="timeline-meta">
                    ${pulseDot}
                    <span class="status-badge status-${job.status}">${job.status}</span>
                    <span>${escapeHtml(job.group_name || '')}</span>
                </div>
                <div class="timeline-time">${formatDate(job.started_at)}</div>
            </div>
        `;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Drift Detection
// ═══════════════════════════════════════════════════════════════════════════════

let _driftEventsCache = {};

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

function renderDriftEventsList(events) {
    const container = document.getElementById('drift-events-list');
    if (!container) return;
    if (!events.length) {
        container.innerHTML = '<div class="card" style="text-align:center;color:var(--text-muted);padding:2rem;">No matching drift events.</div>';
        return;
    }
    container.innerHTML = events.map((ev, i) => {
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
                <button class="btn btn-sm btn-secondary" onclick="showHostDriftHistory(${ev.host_id})">History</button>
                ${ev.status === 'open' ? `
                    <button class="btn btn-sm btn-primary" onclick="acceptDriftEvent(${ev.id})">Accept</button>
                    <button class="btn btn-sm btn-danger" onclick="showRevertDriftModal(${ev.id})">Revert</button>
                    <button class="btn btn-sm btn-secondary" onclick="resolveDriftEvent(${ev.id})">Resolve</button>
                ` : ''}
            </div>
        </div>`;
    }).join('');
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
            <div class="drift-diff-viewer">${diffHtml}</div>
            <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1rem">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                ${ev.status === 'open' ? `
                    <button class="btn btn-primary" onclick="acceptDriftEvent(${eventId});closeAllModals()">Accept</button>
                    <button class="btn btn-danger" onclick="closeAllModals();showRevertDriftModal(${eventId})">Revert</button>
                    <button class="btn btn-secondary" onclick="resolveDriftEvent(${eventId});closeAllModals()">Resolve</button>
                ` : ''}
            </div>
        `);
    } catch (err) {
        showError('Failed to load drift details: ' + err.message);
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
        invalidatePageCache('config-drift');
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
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/config-capture/${jobId}`);

        ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                if (msg.type === 'line') {
                    const line = document.createElement('div');
                    line.className = 'job-output-line';
                    // Color code success/failure lines
                    if (msg.text.includes('✓')) line.className += ' success';
                    else if (msg.text.includes('✗') || msg.text.includes('FAILED')) line.className += ' error';
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
                    invalidatePageCache('config-drift');
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
        invalidatePageCache('config-drift');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Failed to accept: ' + err.message);
    }
};

window.resolveDriftEvent = async function(eventId) {
    try {
        await api.updateConfigDriftEventStatus(eventId, 'resolved');
        showSuccess('Drift event resolved');
        invalidatePageCache('config-drift');
        await loadConfigDrift({ preserveContent: false });
    } catch (err) {
        showError('Failed to resolve: ' + err.message);
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
            const ws = new WebSocket(`${protocol}//${window.location.host}/ws/config-revert/${jobId}`);
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
                    invalidatePageCache('config-drift');
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
            <div class="drift-diff-viewer">${escapeHtml(snap.config_text || '')}</div>
            <div style="display:flex;justify-content:flex-end;margin-top:1rem">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
    } catch (err) {
        showError('Failed to load snapshot: ' + err.message);
    }
};

window.refreshConfigDrift = async function() {
    invalidatePageCache('config-drift');
    await loadConfigDrift({ preserveContent: false });
};


// ═══════════════════════════════════════════════════════════════════════════════
// Keyboard Shortcuts & Command Palette
// ═══════════════════════════════════════════════════════════════════════════════

const COMMAND_PALETTE_PAGES = [
    { page: 'dashboard',   label: 'Dashboard',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>' },
    { page: 'inventory',   label: 'Inventory',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>' },
    { page: 'playbooks',   label: 'Playbooks',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>' },
    { page: 'jobs',        label: 'Jobs',         icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>' },
    { page: 'templates',   label: 'Templates',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>' },
    { page: 'credentials', label: 'Credentials',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>' },
    { page: 'converter',   label: 'Converter',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/></svg>' },
    { page: 'monitoring',   label: 'Monitoring',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' },
    { page: 'config-drift', label: 'Config Drift', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' },
    { page: 'deployments', label: 'Deployments',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>' },
    { page: 'sla',         label: 'SLA Dashboards', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg>' },
    { page: 'settings',    label: 'Settings',     icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
];

let commandPaletteSelectedIndex = 0;
let commandPaletteFilteredItems = [];

function openCommandPalette() {
    const overlay = document.getElementById('command-palette-overlay');
    const input = document.getElementById('command-palette-input');
    if (!overlay || !input) return;
    overlay.classList.add('visible');
    input.value = '';
    commandPaletteSelectedIndex = 0;
    renderCommandPaletteResults('');
    activateFocusTrap('command-palette-overlay');
    setTimeout(() => input.focus(), 50);
}

window.closeCommandPalette = function () {
    const overlay = document.getElementById('command-palette-overlay');
    if (overlay) overlay.classList.remove('visible');
    deactivateFocusTrap('command-palette-overlay');
};

function renderCommandPaletteResults(query) {
    const container = document.getElementById('command-palette-results');
    if (!container) return;

    const q = query.toLowerCase().trim();
    commandPaletteFilteredItems = COMMAND_PALETTE_PAGES.filter((item) => {
        // Filter by access
        if (item.page === 'settings' && currentUserData?.role !== 'admin') return false;
        const feature = NAV_FEATURE_MAP[item.page];
        if (feature && !canAccessFeature(feature)) return false;
        // Filter by search
        if (!q) return true;
        return item.label.toLowerCase().includes(q) || item.page.toLowerCase().includes(q);
    });

    if (!commandPaletteFilteredItems.length) {
        container.innerHTML = '<div class="command-palette-empty">No results found</div>';
        return;
    }

    if (commandPaletteSelectedIndex >= commandPaletteFilteredItems.length) {
        commandPaletteSelectedIndex = 0;
    }

    container.innerHTML = commandPaletteFilteredItems.map((item, i) => `
        <div class="command-palette-item ${i === commandPaletteSelectedIndex ? 'selected' : ''}" data-page="${item.page}">
            <div class="command-palette-item-icon">${item.icon}</div>
            <div class="command-palette-item-label">${escapeHtml(item.label)}</div>
        </div>
    `).join('');

    container.querySelectorAll('.command-palette-item').forEach((el) => {
        el.addEventListener('click', () => {
            navigateToPage(el.dataset.page);
            closeCommandPalette();
        });
    });
}

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        const overlay = document.getElementById('command-palette-overlay');
        const paletteOpen = overlay?.classList.contains('visible');

        // Ctrl+K / Cmd+K: open command palette
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (paletteOpen) {
                closeCommandPalette();
            } else {
                // Only open when logged in
                if (document.getElementById('app-container')?.style.display !== 'none') {
                    openCommandPalette();
                }
            }
            return;
        }

        // Esc: close modals / command palette
        if (e.key === 'Escape') {
            if (paletteOpen) {
                e.preventDefault();
                closeCommandPalette();
                return;
            }
            // Close any open modal (but not the forced password change modal)
            if (currentUserData?.must_change_password) return;
            const modalClosers = {
                'modal-overlay': closeAllModals,
                'job-output-modal': closeJobOutputModal,
                'user-menu-overlay': closeUserMenu,
                'confirm-overlay': closeAllModals,
            };
            for (const [id, closeFn] of Object.entries(modalClosers)) {
                const el = document.getElementById(id);
                if (el && (el.classList.contains('active') || el.classList.contains('visible'))) {
                    e.preventDefault();
                    closeFn();
                    return;
                }
            }
        }

        // / to focus search (only when not in an input)
        if (e.key === '/' && !paletteOpen) {
            const tag = document.activeElement?.tagName.toLowerCase();
            if (tag !== 'input' && tag !== 'textarea' && tag !== 'select' && !document.activeElement?.isContentEditable) {
                e.preventDefault();
                if (document.getElementById('app-container')?.style.display !== 'none') {
                    openCommandPalette();
                }
            }
        }

        // Command palette navigation
        if (paletteOpen) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                commandPaletteSelectedIndex = (commandPaletteSelectedIndex + 1) % (commandPaletteFilteredItems.length || 1);
                renderCommandPaletteResults(document.getElementById('command-palette-input')?.value || '');
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                commandPaletteSelectedIndex = (commandPaletteSelectedIndex - 1 + (commandPaletteFilteredItems.length || 1)) % (commandPaletteFilteredItems.length || 1);
                renderCommandPaletteResults(document.getElementById('command-palette-input')?.value || '');
            } else if (e.key === 'Enter') {
                e.preventDefault();
                const item = commandPaletteFilteredItems[commandPaletteSelectedIndex];
                if (item) {
                    navigateToPage(item.page);
                    closeCommandPalette();
                }
            }
        }
    });

    // Input filtering for command palette
    const paletteInput = document.getElementById('command-palette-input');
    if (paletteInput) {
        paletteInput.addEventListener('input', (e) => {
            commandPaletteSelectedIndex = 0;
            renderCommandPaletteResults(e.target.value);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3D Perspective Card Tilt
// ═══════════════════════════════════════════════════════════════════════════════

function initCardTilt() {
    const MAX_TILT = 6; // degrees
    document.addEventListener('mousemove', (e) => {
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (!card || isReducedMotion()) return;
        const rect = card.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width;
        const y = (e.clientY - rect.top) / rect.height;
        const rotateY = (x - 0.5) * MAX_TILT * 2;
        const rotateX = (0.5 - y) * MAX_TILT * 2;
        card.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-3px)`;
    });
    document.addEventListener('mouseleave', (e) => {
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (card) card.style.transform = '';
    }, true);
    document.addEventListener('mouseout', (e) => {
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (!card) return;
        if (!card.contains(e.relatedTarget)) {
            card.style.transform = '';
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Empty State SVG Illustrations
// ═══════════════════════════════════════════════════════════════════════════════

const EMPTY_ILLUSTRATIONS = {
    inventory: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="20" y="30" width="80" height="60" rx="6" opacity="0.3"/>
        <rect x="30" y="42" width="25" height="4" rx="2" opacity="0.5"/>
        <rect x="30" y="52" width="40" height="4" rx="2" opacity="0.4"/>
        <rect x="30" y="62" width="20" height="4" rx="2" opacity="0.3"/>
        <line x1="75" y1="45" x2="85" y2="45" opacity="0.4"/>
        <line x1="75" y1="55" x2="85" y2="55" opacity="0.3"/>
        <circle cx="80" cy="75" r="12" opacity="0.2" fill="currentColor"/>
        <line x1="75" y1="75" x2="85" y2="75" opacity="0.6"/>
        <line x1="80" y1="70" x2="80" y2="80" opacity="0.6"/>
    </svg>`,
    playbooks: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M35 25h50a5 5 0 015 5v60a5 5 0 01-5 5H35a5 5 0 01-5-5V30a5 5 0 015-5z" opacity="0.3"/>
        <path d="M30 30h5v60h-5" opacity="0.2" fill="currentColor"/>
        <rect x="42" y="40" width="35" height="3" rx="1.5" opacity="0.5"/>
        <rect x="42" y="50" width="25" height="3" rx="1.5" opacity="0.4"/>
        <rect x="42" y="60" width="30" height="3" rx="1.5" opacity="0.3"/>
        <rect x="42" y="70" width="20" height="3" rx="1.5" opacity="0.25"/>
        <circle cx="80" cy="80" r="12" opacity="0.2" fill="currentColor"/>
        <line x1="75" y1="80" x2="85" y2="80" opacity="0.6"/>
        <line x1="80" y1="75" x2="80" y2="85" opacity="0.6"/>
    </svg>`,
    jobs: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="60,20 95,40 95,80 60,100 25,80 25,40" opacity="0.2"/>
        <polygon points="60,20 95,40 60,60 25,40" opacity="0.15" fill="currentColor"/>
        <line x1="60" y1="60" x2="60" y2="100" opacity="0.3"/>
        <line x1="25" y1="40" x2="60" y2="60" opacity="0.3"/>
        <line x1="95" y1="40" x2="60" y2="60" opacity="0.3"/>
        <circle cx="60" cy="58" r="10" opacity="0.3"/>
        <polyline points="55,58 59,62 66,54" opacity="0.5"/>
    </svg>`,
    templates: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="25" y="25" width="70" height="70" rx="6" opacity="0.2"/>
        <line x1="25" y1="45" x2="95" y2="45" opacity="0.2"/>
        <line x1="55" y1="45" x2="55" y2="95" opacity="0.2"/>
        <rect x="30" y="30" width="20" height="4" rx="2" opacity="0.4"/>
        <rect x="35" y="55" width="12" height="8" rx="2" opacity="0.15" fill="currentColor"/>
        <rect x="65" y="55" width="20" height="8" rx="2" opacity="0.15" fill="currentColor"/>
        <rect x="35" y="72" width="12" height="8" rx="2" opacity="0.1" fill="currentColor"/>
        <rect x="65" y="72" width="20" height="8" rx="2" opacity="0.1" fill="currentColor"/>
    </svg>`,
    credentials: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="25" y="45" width="70" height="40" rx="6" opacity="0.3"/>
        <path d="M60 45V35a12 12 0 0124 0v10" opacity="0.3"/>
        <circle cx="60" cy="62" r="5" opacity="0.4"/>
        <line x1="60" y1="67" x2="60" y2="75" opacity="0.4"/>
    </svg>`,
    default: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="60" cy="50" r="25" opacity="0.2"/>
        <line x1="60" y1="40" x2="60" y2="55" opacity="0.4"/>
        <circle cx="60" cy="62" r="2" opacity="0.4" fill="currentColor"/>
        <rect x="35" y="85" width="50" height="4" rx="2" opacity="0.15"/>
        <rect x="42" y="93" width="36" height="4" rx="2" opacity="0.1"/>
    </svg>`,
    converter: `<svg viewBox="0 0 120 120" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <rect x="15" y="35" width="35" height="50" rx="4" opacity="0.25"/>
        <rect x="70" y="35" width="35" height="50" rx="4" opacity="0.25"/>
        <polyline points="55,52 63,60 55,68" opacity="0.5"/>
        <line x1="42" y1="60" x2="63" y2="60" opacity="0.4"/>
        <rect x="22" y="45" width="18" height="3" rx="1.5" opacity="0.35"/>
        <rect x="22" y="53" width="12" height="3" rx="1.5" opacity="0.25"/>
        <rect x="77" y="45" width="18" height="3" rx="1.5" opacity="0.35"/>
        <rect x="77" y="53" width="12" height="3" rx="1.5" opacity="0.25"/>
    </svg>`,
};

function getEmptyIllustration(type) {
    return EMPTY_ILLUSTRATIONS[type] || EMPTY_ILLUSTRATIONS.default;
}

function emptyStateHTML(message, type, actionBtn) {
    return `<div class="empty-state">
        <div class="empty-state-illustration">${getEmptyIllustration(type)}</div>
        <div class="empty-state-title">${message}</div>
        <div class="empty-state-text">Get started by creating your first ${type === 'converter' ? 'conversion' : type.replace(/s$/, '')}.</div>
        ${actionBtn || ''}
    </div>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Backups
// ═══════════════════════════════════════════════════════════════════════════════

let _backupCurrentTab = 'policies';

async function loadConfigBackups(options = {}) {
    const { preserveContent = false } = options;
    const policiesContainer = document.getElementById('backup-policies-list');
    const historyContainer = document.getElementById('backup-history-list');
    if (!preserveContent && policiesContainer) policiesContainer.innerHTML = skeletonCards(2);
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
    }
}
window.loadConfigBackups = loadConfigBackups;

function renderBackupSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('backup-stat-policies', summary.total_policies ?? '-');
    set('backup-stat-backups', summary.total_backups ?? '-');
    set('backup-stat-hosts', summary.hosts_backed_up ?? '-');
    set('backup-stat-last', summary.last_backup_at ? new Date(summary.last_backup_at + 'Z').toLocaleString() : 'Never');
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
                    <button class="btn btn-sm btn-secondary" onclick="runBackupPolicyNow(${p.id})">Run Now</button>
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

function formatInterval(seconds) {
    if (seconds >= 86400) return `${Math.round(seconds / 86400)}d`;
    if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`;
    return `${Math.round(seconds / 60)}m`;
}

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
    if (!confirm(`Delete backup policy "${name}"?`)) return;
    try {
        await api.deleteConfigBackupPolicy(id);
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
}
window.confirmDeleteBackupPolicy = confirmDeleteBackupPolicy;

async function runBackupPolicyNow(id) {
    try {
        const result = await api.runConfigBackupPolicy(id);
        alert(`Backup complete: ${result.backed_up} succeeded, ${result.errors} errors`);
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
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
            <pre class="code-block" style="max-height:400px; overflow:auto; font-size:0.8em; white-space:pre-wrap;">${escapeHtml(backup.config_text || '(empty)')}</pre>
        `);
    } catch (e) { alert('Error: ' + e.message); }
}
window.viewBackupDetail = viewBackupDetail;

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
    if (!confirm('Delete this backup?')) return;
    try {
        await api.deleteConfigBackup(id);
        loadConfigBackups();
    } catch (e) { alert('Error: ' + e.message); }
}
window.confirmDeleteBackup = confirmDeleteBackup;

// Search handler for config backups
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('backup-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            listViewState.configBackups.query = searchInput.value;
            renderBackupPolicies(listViewState.configBackups.policies);
            renderBackupHistory(listViewState.configBackups.backups);
        }, 200));
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
// Compliance Profiles & Scans
// ═══════════════════════════════════════════════════════════════════════════════

let _complianceCurrentTab = 'profiles';

async function loadCompliance(options = {}) {
    const { preserveContent = false } = options;
    const profilesContainer = document.getElementById('compliance-profiles-list');
    if (!preserveContent && profilesContainer) profilesContainer.innerHTML = skeletonCards(2);
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
        if (btn) btn.className = t === tab ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
        if (list) list.style.display = t === tab ? '' : 'none';
    });
}
window.switchComplianceTab = switchComplianceTab;

function refreshCompliance() { loadCompliance(); }
window.refreshCompliance = refreshCompliance;

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
    let groups = [], creds = [];
    try {
        [groups, creds] = await Promise.all([api.getInventoryGroups(), api.getCredentials()]);
    } catch (e) { /* ignore */ }
    const groupOpts = (groups || []).map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    showModal('Assign Profile to Group', `
        <label class="form-label">Inventory Group</label>
        <select id="ca-group" class="form-select">${groupOpts}</select>
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
    const groupId = parseInt(document.getElementById('ca-group')?.value);
    const credId = parseInt(document.getElementById('ca-cred')?.value);
    const hours = parseInt(document.getElementById('ca-interval')?.value) || 24;
    if (!groupId || !credId) { showError('Group and credential are required'); return; }
    try {
        await api.createComplianceAssignment({
            profile_id: profileId,
            group_id: groupId,
            credential_id: credId,
            interval_seconds: hours * 3600,
        });
        closeAllModals();
        showSuccess('Profile assigned to group');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.submitAssignComplianceProfile = submitAssignComplianceProfile;

async function confirmDeleteComplianceProfile(profileId) {
    if (!confirm('Delete this compliance profile and all its assignments and scan results?')) return;
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
    if (!confirm('Delete this compliance assignment?')) return;
    try {
        await api.deleteComplianceAssignment(assignmentId);
        showSuccess('Assignment deleted');
        loadCompliance();
    } catch (e) { showError(e.message); }
}
window.confirmDeleteComplianceAssignment = confirmDeleteComplianceAssignment;

async function showComplianceFindings(resultId) {
    let result;
    try { result = await api.getComplianceScanResult(resultId); } catch (e) { showError(e.message); return; }
    let findings = [];
    try { findings = JSON.parse(result.findings || '[]'); } catch (e) { /* ignore */ }
    const rows = findings.map(f => {
        const color = f.passed ? 'success' : 'danger';
        return `<tr>
            <td style="color:var(--${color})">${f.passed ? 'PASS' : 'FAIL'}</td>
            <td>${escapeHtml(f.name || '-')}</td>
            <td><code>${escapeHtml(f.type || '-')}</code></td>
            <td style="font-size:0.85em">${escapeHtml(f.detail || '-')}</td>
        </tr>`;
    }).join('');
    showModal(`Compliance Findings — ${escapeHtml(result.hostname || '?')}`, `
        <div style="margin-bottom:1rem;">
            <strong>Profile:</strong> ${escapeHtml(result.profile_name || '?')} ·
            <strong>Status:</strong> ${escapeHtml(result.status)} ·
            <strong>Score:</strong> ${result.passed_rules}/${result.total_rules} passed
        </div>
        <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:0.9em;">
                <thead><tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:0.5rem;">Result</th>
                    <th style="text-align:left; padding:0.5rem;">Rule</th>
                    <th style="text-align:left; padding:0.5rem;">Type</th>
                    <th style="text-align:left; padding:0.5rem;">Detail</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `);
}
window.showComplianceFindings = showComplianceFindings;

// Search handler for compliance
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('compliance-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            listViewState.compliance.query = searchInput.value;
            renderComplianceProfiles(listViewState.compliance.profiles);
            renderComplianceAssignments(listViewState.compliance.assignments);
            renderComplianceResults(listViewState.compliance.results);
            renderComplianceStatus(listViewState.compliance.statusList);
        }, 200));
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
// Risk Analysis
// ═══════════════════════════════════════════════════════════════════════════════

async function loadRiskAnalysis(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('risk-analyses-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const [summary, analyses] = await Promise.all([
            api.getRiskAnalysisSummary(),
            api.getRiskAnalyses({ limit: 200 }),
        ]);
        renderRiskSummary(summary);
        listViewState.riskAnalysis.items = analyses || [];
        renderRiskAnalyses(analyses || []);
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading risk analyses: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadRiskAnalysis = loadRiskAnalysis;

function renderRiskSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('risk-stat-total', summary.total ?? '-');
    set('risk-stat-high', summary.high_risk ?? '-');
    set('risk-stat-approved', summary.approved ?? '-');
    set('risk-stat-pending', summary.pending ?? '-');
    set('risk-stat-last', summary.last_analysis_at ? new Date(summary.last_analysis_at + 'Z').toLocaleString() : 'Never');
}

function renderRiskAnalyses(analyses) {
    const container = document.getElementById('risk-analyses-list');
    if (!container) return;
    const query = (listViewState.riskAnalysis.query || '').toLowerCase();
    const levelFilter = listViewState.riskAnalysis.levelFilter || '';
    const filtered = analyses.filter(a => {
        if (levelFilter && a.risk_level !== levelFilter) return false;
        if (query && !(a.hostname || '').toLowerCase().includes(query)
            && !(a.group_name || '').toLowerCase().includes(query)
            && !(a.change_type || '').toLowerCase().includes(query)) return false;
        return true;
    });
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No risk analyses', 'risk-analysis',
            '<button class="btn btn-primary btn-sm" onclick="showNewRiskAnalysisModal()">Run an Analysis</button>');
        return;
    }
    container.innerHTML = filtered.map(a => {
        const levelColors = { low: 'success', medium: 'warning', high: 'warning', critical: 'danger', unknown: 'text-muted' };
        const levelColor = levelColors[a.risk_level] || 'text-muted';
        const scorePercent = Math.round((a.risk_score || 0) * 100);
        const created = a.created_at ? new Date(a.created_at + 'Z').toLocaleString() : '-';
        const approved = a.approved ? '<span style="color:var(--success)">Approved</span>' : '<span style="color:var(--text-muted)">Pending</span>';
        let affectedAreas = [];
        try { affectedAreas = JSON.parse(a.affected_areas || '[]'); } catch (e) { /* ignore */ }
        const target = a.hostname ? `${escapeHtml(a.hostname)} (${escapeHtml(a.ip_address || '')})` : (a.group_name ? `Group: ${escapeHtml(a.group_name)}` : 'N/A');

        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <span class="badge" style="background:var(--${levelColor}); color:white; font-size:0.8em; padding:3px 10px; border-radius:4px; text-transform:uppercase; font-weight:600;">${escapeHtml(a.risk_level)}</span>
                    <span style="margin-left:0.5rem; font-size:0.9em; color:var(--text-muted)">Score: ${scorePercent}%</span>
                    <strong style="margin-left:0.75rem;">${target}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">Type: ${escapeHtml(a.change_type || '?')}</span>
                </div>
                <div style="display:flex; gap:0.4rem; align-items:center;">
                    ${approved}
                    <button class="btn btn-sm btn-secondary" onclick="showRiskAnalysisDetail(${a.id})">Details</button>
                    ${!a.approved ? `<button class="btn btn-sm btn-primary" onclick="approveRiskAnalysis(${a.id})">Approve</button>` : ''}
                    <button class="btn btn-sm" style="color:var(--danger)" onclick="confirmDeleteRiskAnalysis(${a.id})">Delete</button>
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                ${affectedAreas.length > 0 ? `Areas: ${affectedAreas.map(a => escapeHtml(a)).join(', ')} · ` : ''}${created}${a.created_by ? ` by ${escapeHtml(a.created_by)}` : ''}
            </div>
            <!-- Risk score bar -->
            <div style="margin-top:0.5rem; background:var(--bg-secondary); border-radius:4px; height:6px; overflow:hidden;">
                <div style="width:${scorePercent}%; height:100%; background:var(--${levelColor}); border-radius:4px; transition:width 0.3s;"></div>
            </div>
        </div>`;
    }).join('');
}

function filterRiskAnalyses() {
    listViewState.riskAnalysis.levelFilter = document.getElementById('risk-filter-level')?.value || '';
    renderRiskAnalyses(listViewState.riskAnalysis.items);
}
window.filterRiskAnalyses = filterRiskAnalyses;

function refreshRiskAnalysis() { loadRiskAnalysis(); }
window.refreshRiskAnalysis = refreshRiskAnalysis;

async function showNewRiskAnalysisModal() {
    let groups = [], creds = [], templates = [];
    try {
        [groups, creds, templates] = await Promise.all([
            api.getInventoryGroups(), api.getCredentials(), api.getTemplates(),
        ]);
    } catch (e) { /* ignore */ }
    const groupOpts = (groups || []).map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    const tplOpts = `<option value="">-- Enter commands manually --</option>` +
        (templates || []).map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
    showModal('Pre-Change Risk Analysis', `
        <label class="form-label">Change Type</label>
        <select id="ra-type" class="form-select">
            <option value="template">Template</option>
            <option value="policy">Policy / ACL</option>
            <option value="route">Route</option>
            <option value="nat">NAT</option>
            <option value="manual">Manual</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Target Group</label>
        <select id="ra-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Credential</label>
        <select id="ra-cred" class="form-select">${credOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Source</label>
        <select id="ra-template" class="form-select" onchange="toggleRiskCommands()">${tplOpts}</select>
        <div id="ra-commands-section">
            <label class="form-label" style="margin-top:0.75rem;">Proposed Commands (one per line)</label>
            <textarea id="ra-commands" class="form-input" rows="8" placeholder="ip route 10.0.0.0 255.0.0.0 192.168.1.1
access-list 101 permit ip any 10.0.0.0 0.255.255.255
ip nat inside source list 1 interface GigabitEthernet0/1 overload"></textarea>
        </div>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitRiskAnalysis()">Analyze Risk</button>
        </div>
    `);
}
window.showNewRiskAnalysisModal = showNewRiskAnalysisModal;

function toggleRiskCommands() {
    const tplSelect = document.getElementById('ra-template');
    const cmdSection = document.getElementById('ra-commands-section');
    if (cmdSection) cmdSection.style.display = tplSelect?.value ? 'none' : '';
}
window.toggleRiskCommands = toggleRiskCommands;

async function submitRiskAnalysis() {
    const group_id = parseInt(document.getElementById('ra-group')?.value);
    const credential_id = parseInt(document.getElementById('ra-cred')?.value);
    const template_id = document.getElementById('ra-template')?.value ? parseInt(document.getElementById('ra-template').value) : null;
    const change_type = document.getElementById('ra-type')?.value || 'template';

    if (!credential_id) { showError('Credential is required'); return; }

    let proposed_commands = [];
    if (!template_id) {
        const cmdText = document.getElementById('ra-commands')?.value?.trim() || '';
        if (!cmdText) { showError('Enter proposed commands or select a template'); return; }
        proposed_commands = cmdText.split('\n').filter(l => l.trim());
    }

    closeAllModals();
    showSuccess('Running risk analysis...');

    try {
        const result = await api.runRiskAnalysis({
            change_type,
            group_id: group_id || undefined,
            credential_id,
            template_id: template_id || undefined,
            proposed_commands,
        });
        loadRiskAnalysis();
        // Show result summary
        const levelColors = { low: 'success', medium: 'warning', high: 'warning', critical: 'danger' };
        const color = levelColors[result.risk_level] || 'text-muted';
        showModal('Risk Analysis Complete', `
            <div style="text-align:center; margin-bottom:1rem;">
                <div style="font-size:2em; font-weight:700; color:var(--${color}); text-transform:uppercase;">${escapeHtml(result.risk_level)}</div>
                <div style="font-size:1.2em; color:var(--text-muted);">Score: ${Math.round((result.risk_score || 0) * 100)}%</div>
            </div>
            <div style="margin-bottom:0.75rem;">
                <strong>Hosts analyzed:</strong> ${result.hosts_analyzed || 0}<br>
                <strong>Compliance violations:</strong> ${result.total_compliance_violations || 0}<br>
                <strong>Affected areas:</strong> ${(result.affected_areas || []).join(', ') || 'None'}
            </div>
            ${result.host_results && result.host_results.length > 0 ? `
                <div style="margin-top:1rem;">
                    <strong>Per-host results:</strong>
                    ${result.host_results.map(hr => {
                        const hcolor = levelColors[hr.risk_level] || 'text-muted';
                        return `<div style="margin-top:0.5rem; padding:0.5rem; background:var(--bg-secondary); border-radius:6px;">
                            <span style="color:var(--${hcolor}); font-weight:600; text-transform:uppercase;">${escapeHtml(hr.risk_level || '?')}</span>
                            <strong style="margin-left:0.5rem;">${escapeHtml(hr.hostname || '?')}</strong>
                            <span style="font-size:0.85em; color:var(--text-muted); margin-left:0.5rem;">Score: ${Math.round((hr.risk_score || 0) * 100)}%</span>
                            ${hr.affected_areas && hr.affected_areas.length ? `<div style="font-size:0.8em; color:var(--text-muted); margin-top:0.25rem;">Areas: ${hr.affected_areas.join(', ')}</div>` : ''}
                        </div>`;
                    }).join('')}
                </div>
            ` : ''}
            <div style="margin-top:1rem; text-align:right;">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
                <button class="btn btn-primary" onclick="closeAllModals(); showRiskAnalysisDetail(${result.id})">View Full Details</button>
            </div>
        `);
    } catch (e) { showError('Risk analysis failed: ' + e.message); }
}
window.submitRiskAnalysis = submitRiskAnalysis;

async function showOfflineRiskAnalysisModal() {
    showModal('Offline Risk Analysis', `
        <p style="font-size:0.9em; color:var(--text-muted); margin-bottom:1rem;">
            Analyze risk without connecting to devices. Paste the current config and proposed commands.
        </p>
        <label class="form-label">Change Type</label>
        <select id="ora-type" class="form-select">
            <option value="policy">Policy / ACL</option>
            <option value="route">Route</option>
            <option value="nat">NAT</option>
            <option value="manual">Manual</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Current Running Config</label>
        <textarea id="ora-config" class="form-input" rows="8" placeholder="Paste current running-config here..."></textarea>
        <label class="form-label" style="margin-top:0.75rem;">Proposed Commands (one per line)</label>
        <textarea id="ora-commands" class="form-input" rows="6" placeholder="ip route 10.0.0.0 255.0.0.0 192.168.1.1
no ip route 172.16.0.0 255.240.0.0 192.168.1.254"></textarea>
        <div style="margin-top:1rem; text-align:right;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" onclick="submitOfflineRiskAnalysis()">Analyze</button>
        </div>
    `);
}
window.showOfflineRiskAnalysisModal = showOfflineRiskAnalysisModal;

async function submitOfflineRiskAnalysis() {
    const config = document.getElementById('ora-config')?.value?.trim() || '';
    const cmdText = document.getElementById('ora-commands')?.value?.trim() || '';
    const changeType = document.getElementById('ora-type')?.value || 'manual';
    if (!config) { showError('Current config is required'); return; }
    if (!cmdText) { showError('Proposed commands are required'); return; }
    const commands = cmdText.split('\n').filter(l => l.trim());
    closeAllModals();
    showSuccess('Running offline analysis...');
    try {
        const result = await api.runOfflineRiskAnalysis({
            change_type: changeType,
            current_config: config,
            proposed_commands: commands,
        });
        loadRiskAnalysis();
        const levelColors = { low: 'success', medium: 'warning', high: 'warning', critical: 'danger' };
        const color = levelColors[result.risk_level] || 'text-muted';
        showModal('Offline Analysis Complete', `
            <div style="text-align:center; margin-bottom:1rem;">
                <div style="font-size:2em; font-weight:700; color:var(--${color}); text-transform:uppercase;">${escapeHtml(result.risk_level)}</div>
                <div style="font-size:1.2em; color:var(--text-muted);">Score: ${Math.round((result.risk_score || 0) * 100)}%</div>
            </div>
            <div><strong>Affected areas:</strong> ${(result.affected_areas || []).join(', ') || 'None'}</div>
            ${result.analysis?.risk_factors?.length ? `<div style="margin-top:0.5rem;"><strong>Risk factors:</strong><ul style="margin:0.25rem 0 0 1.5rem;">${result.analysis.risk_factors.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul></div>` : ''}
            ${result.proposed_diff ? `<div style="margin-top:1rem;"><strong>Predicted diff:</strong><pre style="background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:300px; overflow:auto; white-space:pre-wrap;">${escapeHtml(result.proposed_diff)}</pre></div>` : ''}
            <div style="margin-top:1rem; text-align:right;">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
    } catch (e) { showError('Offline analysis failed: ' + e.message); }
}
window.submitOfflineRiskAnalysis = submitOfflineRiskAnalysis;

async function showRiskAnalysisDetail(analysisId) {
    let analysis;
    try { analysis = await api.getRiskAnalysis(analysisId); } catch (e) { showError(e.message); return; }

    const levelColors = { low: 'success', medium: 'warning', high: 'warning', critical: 'danger' };
    const color = levelColors[analysis.risk_level] || 'text-muted';
    const scorePercent = Math.round((analysis.risk_score || 0) * 100);

    let analysisObj = {};
    try { analysisObj = JSON.parse(analysis.analysis || '{}'); } catch (e) { /* ignore */ }
    let complianceImpact = [];
    try { complianceImpact = JSON.parse(analysis.compliance_impact || '[]'); } catch (e) { /* ignore */ }
    let affectedAreas = [];
    try { affectedAreas = JSON.parse(analysis.affected_areas || '[]'); } catch (e) { /* ignore */ }

    const riskFactors = analysisObj.risk_factors || [];
    const changeVolume = analysisObj.change_volume || {};

    showModal('Risk Analysis Details', `
        <div style="display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1rem;">
            <div style="text-align:center;">
                <div style="font-size:2em; font-weight:700; color:var(--${color}); text-transform:uppercase;">${escapeHtml(analysis.risk_level)}</div>
                <div style="font-size:1.1em; color:var(--text-muted);">Risk Score: ${scorePercent}%</div>
                <div style="margin-top:0.5rem; width:120px; background:var(--bg-secondary); border-radius:4px; height:8px; overflow:hidden;">
                    <div style="width:${scorePercent}%; height:100%; background:var(--${color}); border-radius:4px;"></div>
                </div>
            </div>
            <div style="flex:1; min-width:200px;">
                <div><strong>Target:</strong> ${analysis.hostname ? `${escapeHtml(analysis.hostname)} (${escapeHtml(analysis.ip_address || '')})` : (analysis.group_name ? `Group: ${escapeHtml(analysis.group_name)}` : 'N/A')}</div>
                <div><strong>Change type:</strong> ${escapeHtml(analysis.change_type || '?')}</div>
                <div><strong>Status:</strong> ${analysis.approved ? `<span style="color:var(--success)">Approved</span> by ${escapeHtml(analysis.approved_by || '?')}` : '<span style="color:var(--text-muted)">Pending approval</span>'}</div>
                <div><strong>Created:</strong> ${analysis.created_at ? new Date(analysis.created_at + 'Z').toLocaleString() : '-'}${analysis.created_by ? ` by ${escapeHtml(analysis.created_by)}` : ''}</div>
            </div>
        </div>

        ${affectedAreas.length ? `<div style="margin-bottom:1rem;"><strong>Affected Areas:</strong> ${affectedAreas.map(a => `<span class="badge" style="background:var(--bg-secondary); padding:2px 8px; border-radius:4px; margin-right:0.25rem; font-size:0.85em;">${escapeHtml(a)}</span>`).join('')}</div>` : ''}

        ${riskFactors.length ? `<div style="margin-bottom:1rem;"><strong>Risk Factors:</strong><ul style="margin:0.25rem 0 0 1.5rem;">${riskFactors.map(f => `<li style="margin-bottom:0.25rem;">${escapeHtml(f)}</li>`).join('')}</ul></div>` : ''}

        ${changeVolume.total_commands ? `<div style="margin-bottom:1rem;"><strong>Change Volume:</strong> ${changeVolume.total_commands} commands, +${changeVolume.diff_lines_added || 0} / -${changeVolume.diff_lines_removed || 0} lines</div>` : ''}

        ${complianceImpact.length ? `
            <div style="margin-bottom:1rem;">
                <strong>Compliance Impact:</strong>
                ${complianceImpact.map(ci => `
                    <div style="margin-top:0.5rem; padding:0.5rem; background:var(--bg-secondary); border-radius:6px;">
                        <strong>${escapeHtml(ci.profile_name || '?')}</strong>
                        <span style="margin-left:0.5rem; font-size:0.85em;">
                            ${ci.new_violations > 0 ? `<span style="color:var(--danger)">+${ci.new_violations} violation(s)</span>` : ''}
                            ${ci.improvements > 0 ? `<span style="color:var(--success); margin-left:0.5rem;">+${ci.improvements} improvement(s)</span>` : ''}
                        </span>
                        ${ci.changed_rules ? `<div style="margin-top:0.25rem; font-size:0.8em;">${ci.changed_rules.map(r => `<div style="margin-left:1rem;"><span style="color:var(--${r.impact === 'regression' ? 'danger' : 'success'})">${r.impact === 'regression' ? 'REGRESS' : 'IMPROVE'}</span> ${escapeHtml(r.name)}: ${r.before} → ${r.after}</div>`).join('')}</div>` : ''}
                    </div>
                `).join('')}
            </div>
        ` : ''}

        ${analysis.proposed_commands ? `
            <details style="margin-bottom:1rem;">
                <summary style="cursor:pointer; font-weight:600;">Proposed Commands</summary>
                <pre style="background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:200px; overflow:auto; margin-top:0.5rem; white-space:pre-wrap;">${escapeHtml(analysis.proposed_commands)}</pre>
            </details>
        ` : ''}

        ${analysis.proposed_diff ? `
            <details style="margin-bottom:1rem;">
                <summary style="cursor:pointer; font-weight:600;">Predicted Config Diff</summary>
                <pre style="background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:300px; overflow:auto; margin-top:0.5rem; white-space:pre-wrap;">${escapeHtml(analysis.proposed_diff)}</pre>
            </details>
        ` : ''}

        <div style="margin-top:1rem; text-align:right;">
            ${!analysis.approved ? `<button class="btn btn-primary" onclick="approveRiskAnalysis(${analysis.id}); closeAllModals();">Approve Change</button>` : ''}
            <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
        </div>
    `);
}
window.showRiskAnalysisDetail = showRiskAnalysisDetail;

async function approveRiskAnalysis(analysisId) {
    try {
        await api.approveRiskAnalysis(analysisId);
        showSuccess('Risk analysis approved');
        loadRiskAnalysis();
    } catch (e) { showError(e.message); }
}
window.approveRiskAnalysis = approveRiskAnalysis;

async function confirmDeleteRiskAnalysis(analysisId) {
    if (!confirm('Delete this risk analysis?')) return;
    try {
        await api.deleteRiskAnalysis(analysisId);
        showSuccess('Risk analysis deleted');
        loadRiskAnalysis();
    } catch (e) { showError(e.message); }
}
window.confirmDeleteRiskAnalysis = confirmDeleteRiskAnalysis;

// Search handler for risk analysis
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('risk-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            listViewState.riskAnalysis.query = searchInput.value;
            renderRiskAnalyses(listViewState.riskAnalysis.items);
        }, 200));
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
// Real-Time Monitoring
// ═══════════════════════════════════════════════════════════════════════════════

async function loadMonitoring(options = {}) {
    const { preserveContent = false } = options;
    const devContainer = document.getElementById('monitoring-devices-list');
    if (!preserveContent && devContainer) devContainer.innerHTML = skeletonCards(2);
    try {
        const [summary, polls, alerts] = await Promise.all([
            api.getMonitoringSummary(),
            api.getMonitoringPolls(),
            api.getMonitoringAlerts({ acknowledged: false, limit: 200 }),
        ]);
        renderMonitoringSummary(summary);
        listViewState.monitoring.polls = polls || [];
        listViewState.monitoring.alerts = alerts || [];
        renderMonitoringDevices(polls || []);
        renderMonitoringAlerts(alerts || []);
    } catch (error) {
        if (devContainer) devContainer.innerHTML = `<div class="card" style="color:var(--danger)">Error loading monitoring: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadMonitoring = loadMonitoring;

function renderMonitoringSummary(s) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('mon-stat-hosts', s.monitored_hosts ?? '-');
    set('mon-stat-cpu', s.avg_cpu != null ? s.avg_cpu + '%' : '-');
    set('mon-stat-mem', s.avg_memory != null ? s.avg_memory + '%' : '-');
    set('mon-stat-if-up', s.interfaces_up ?? '-');
    set('mon-stat-if-down', s.interfaces_down ?? '-');
    set('mon-stat-vpn-up', s.vpn_tunnels_up ?? '-');
    set('mon-stat-vpn-down', s.vpn_tunnels_down ?? '-');
    set('mon-stat-routes', s.total_routes ?? '-');
    set('mon-stat-alerts', s.open_alerts ?? '-');

    // Highlight problem stats
    const cpuEl = document.getElementById('mon-stat-cpu');
    if (cpuEl) cpuEl.style.color = (s.avg_cpu != null && s.avg_cpu >= 80) ? 'var(--danger)' : '';
    const memEl = document.getElementById('mon-stat-mem');
    if (memEl) memEl.style.color = (s.avg_memory != null && s.avg_memory >= 80) ? 'var(--danger)' : '';
    const ifDownEl = document.getElementById('mon-stat-if-down');
    if (ifDownEl) ifDownEl.style.color = (s.interfaces_down > 0) ? 'var(--warning)' : '';
    const vpnDownEl = document.getElementById('mon-stat-vpn-down');
    if (vpnDownEl) vpnDownEl.style.color = (s.vpn_tunnels_down > 0) ? 'var(--warning)' : '';
    const alertsEl = document.getElementById('mon-stat-alerts');
    if (alertsEl) alertsEl.style.color = (s.open_alerts > 0) ? 'var(--danger)' : '';
}

function renderMonitoringDevices(polls) {
    const container = document.getElementById('monitoring-devices-list');
    if (!container) return;
    const query = (listViewState.monitoring.query || '').toLowerCase();
    const filtered = polls.filter(p => {
        if (query && !(p.hostname || '').toLowerCase().includes(query)
            && !(p.ip_address || '').toLowerCase().includes(query)) return false;
        return true;
    });
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No monitoring data', 'monitoring',
            '<button class="btn btn-primary btn-sm" onclick="runMonitoringPollNow()">Run First Poll</button>');
        return;
    }
    container.innerHTML = filtered.map(p => {
        const cpuColor = p.cpu_percent == null ? 'text-muted' : (p.cpu_percent >= 90 ? 'danger' : (p.cpu_percent >= 70 ? 'warning' : 'success'));
        const memColor = p.memory_percent == null ? 'text-muted' : (p.memory_percent >= 90 ? 'danger' : (p.memory_percent >= 70 ? 'warning' : 'success'));
        const cpuVal = p.cpu_percent != null ? p.cpu_percent + '%' : 'N/A';
        const memVal = p.memory_percent != null ? p.memory_percent + '%' : 'N/A';
        const polled = p.polled_at ? new Date(p.polled_at + 'Z').toLocaleString() : '-';
        const statusDot = p.poll_status === 'error' ? 'danger' : 'success';
        const uptime = p.uptime_seconds != null ? formatUptime(p.uptime_seconds) : 'N/A';

        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div style="display:flex; align-items:center; gap:0.5rem;">
                    <span style="width:8px; height:8px; border-radius:50%; background:var(--${statusDot}); display:inline-block;"></span>
                    <strong>${escapeHtml(p.hostname || 'Unknown')}</strong>
                    <span style="color:var(--text-muted); font-size:0.85em;">${escapeHtml(p.ip_address || '')}</span>
                    <span style="color:var(--text-muted); font-size:0.8em;">${escapeHtml(p.device_type || '')}</span>
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-secondary" onclick="showMonitoringHostDetail(${p.host_id})">Details</button>
                    <button class="btn btn-sm btn-secondary" onclick="showMonitoringHostHistory(${p.host_id}, '${escapeHtml(p.hostname || '')}')">History</button>
                </div>
            </div>
            <div style="display:flex; gap:1.5rem; margin-top:0.75rem; flex-wrap:wrap; font-size:0.9em;">
                <div><span style="color:var(--text-muted);">CPU:</span> <span style="color:var(--${cpuColor}); font-weight:600;">${cpuVal}</span></div>
                <div><span style="color:var(--text-muted);">Memory:</span> <span style="color:var(--${memColor}); font-weight:600;">${memVal}</span>${p.memory_used_mb != null && p.memory_total_mb != null ? ` <span style="font-size:0.8em; color:var(--text-muted);">(${p.memory_used_mb}/${p.memory_total_mb} MB)</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">Interfaces:</span> <span style="color:var(--success);">${p.if_up_count} up</span>${p.if_down_count > 0 ? ` / <span style="color:var(--danger);">${p.if_down_count} down</span>` : ''}${p.if_admin_down > 0 ? ` / <span style="color:var(--text-muted);">${p.if_admin_down} admin-down</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">VPN:</span> <span style="color:var(--success);">${p.vpn_tunnels_up} up</span>${p.vpn_tunnels_down > 0 ? ` / <span style="color:var(--danger);">${p.vpn_tunnels_down} down</span>` : ''}</div>
                <div><span style="color:var(--text-muted);">Routes:</span> ${p.route_count}</div>
                <div><span style="color:var(--text-muted);">Uptime:</span> ${uptime}</div>
            </div>
            ${p.cpu_percent != null ? `<div style="display:flex; gap:0.5rem; margin-top:0.5rem;">
                <div style="flex:1; background:var(--bg-secondary); border-radius:4px; height:6px; overflow:hidden;" title="CPU ${cpuVal}">
                    <div style="width:${Math.min(p.cpu_percent, 100)}%; height:100%; background:var(--${cpuColor}); border-radius:4px; transition:width 0.3s;"></div>
                </div>
                <div style="flex:1; background:var(--bg-secondary); border-radius:4px; height:6px; overflow:hidden;" title="Memory ${memVal}">
                    <div style="width:${Math.min(p.memory_percent || 0, 100)}%; height:100%; background:var(--${memColor}); border-radius:4px; transition:width 0.3s;"></div>
                </div>
            </div>` : ''}
            <div style="margin-top:0.4rem; font-size:0.8em; color:var(--text-muted);">Last poll: ${polled}</div>
        </div>`;
    }).join('');
}

function formatUptime(seconds) {
    if (seconds == null) return 'N/A';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function renderMonitoringAlerts(alerts) {
    const container = document.getElementById('monitoring-alerts-list');
    if (!container) return;
    const query = (listViewState.monitoring.query || '').toLowerCase();
    const sevFilter = document.getElementById('mon-alert-filter-severity')?.value || '';
    const ackFilter = document.getElementById('mon-alert-filter-ack')?.value;

    let filtered = alerts;
    if (sevFilter) filtered = filtered.filter(a => a.severity === sevFilter);
    if (ackFilter === 'true') filtered = filtered.filter(a => a.acknowledged);
    else if (ackFilter === 'false') filtered = filtered.filter(a => !a.acknowledged);
    if (query) filtered = filtered.filter(a =>
        (a.hostname || '').toLowerCase().includes(query) ||
        (a.message || '').toLowerCase().includes(query) ||
        (a.metric || '').toLowerCase().includes(query));

    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No alerts', 'monitoring', '');
        return;
    }

    // Bulk acknowledge button for unacknowledged alerts
    const unackedIds = filtered.filter(a => !a.acknowledged).map(a => a.id);
    const bulkBtn = unackedIds.length > 1
        ? `<div style="margin-bottom:0.5rem;"><button class="btn btn-sm btn-secondary" onclick="bulkAcknowledgeAlerts([${unackedIds.join(',')}])">Acknowledge All (${unackedIds.length})</button></div>`
        : '';

    container.innerHTML = bulkBtn + filtered.map(a => {
        const sevColors = { critical: 'danger', warning: 'warning', info: 'primary' };
        const sevColor = sevColors[a.severity] || 'text-muted';
        const created = a.created_at ? new Date(a.created_at + 'Z').toLocaleString() : '-';
        const lastSeen = a.last_seen_at ? new Date(a.last_seen_at + 'Z').toLocaleString() : created;
        const ackBadge = a.acknowledged
            ? `<span style="color:var(--success); font-size:0.8em;">Acknowledged${a.acknowledged_by ? ` by ${escapeHtml(a.acknowledged_by)}` : ''}</span>`
            : `<button class="btn btn-sm btn-secondary" onclick="acknowledgeMonitoringAlert(${a.id})">Acknowledge</button>`;

        // Dedup badge
        const occurrences = (a.occurrence_count || 1);
        const dedupBadge = occurrences > 1
            ? `<span style="background:var(--bg-secondary); color:var(--text-muted); font-size:0.75em; padding:2px 6px; border-radius:3px; margin-left:0.3rem;" title="Deduplicated: seen ${occurrences} times">${occurrences}x</span>`
            : '';

        // Escalation badge
        const escalationBadge = a.escalated
            ? `<span style="background:var(--danger); color:white; font-size:0.7em; padding:2px 6px; border-radius:3px; margin-left:0.3rem;" title="Escalated from ${escapeHtml(a.original_severity || '')}">ESCALATED</span>`
            : '';

        return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; border-left:3px solid var(--${sevColor});">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                <div>
                    <span class="badge" style="background:var(--${sevColor}); color:white; font-size:0.75em; padding:2px 8px; border-radius:3px; text-transform:uppercase;">${escapeHtml(a.severity)}</span>
                    ${escalationBadge}${dedupBadge}
                    <strong style="margin-left:0.4rem;">${escapeHtml(a.hostname || '')}</strong>
                    <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.4rem;">${escapeHtml(a.metric || '')}</span>
                </div>
                <div style="display:flex; gap:0.4rem; align-items:center;">
                    ${ackBadge}
                </div>
            </div>
            <div style="margin-top:0.3rem; font-size:0.9em;">${escapeHtml(a.message)}</div>
            <div style="margin-top:0.2rem; font-size:0.8em; color:var(--text-muted);">
                Created: ${created}${occurrences > 1 ? ` · Last seen: ${lastSeen}` : ''}${a.rule_id ? ` · Rule #${a.rule_id}` : ''}
            </div>
        </div>`;
    }).join('');
}

window.bulkAcknowledgeAlerts = async function(alertIds) {
    try {
        const result = await api.bulkAcknowledgeAlerts(alertIds);
        showSuccess(`${result.acknowledged} alert(s) acknowledged`);
        loadMonitoring();
    } catch (e) {
        showError(e.message);
    }
};

window.switchMonitoringTab = function(tab) {
    listViewState.monitoring.tab = tab;
    document.querySelectorAll('.mon-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-mon-tab') === tab));
    document.querySelectorAll('.monitoring-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`monitoring-tab-${tab}`);
    if (target) target.style.display = '';

    if (tab === 'routes' && !document.getElementById('monitoring-routes-list')?.dataset.loaded) {
        loadMonitoringRouteChurn();
    }
    if (tab === 'rules') loadMonitoringRules();
    if (tab === 'suppressions') loadMonitoringSuppressions();
};

async function loadMonitoringRouteChurn() {
    const container = document.getElementById('monitoring-routes-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        // Get latest polls that have route data
        const polls = listViewState.monitoring.polls.filter(p => p.route_count > 0);
        if (!polls.length) {
            container.innerHTML = emptyStateHTML('No route data collected', 'monitoring', '');
            container.dataset.loaded = '1';
            return;
        }
        // For each host with routes, get the last 2 route snapshots
        const routeAlerts = (listViewState.monitoring.alerts || []).filter(a => a.metric === 'route_churn');
        if (!routeAlerts.length) {
            container.innerHTML = `<div class="card" style="padding:1rem;">
                <p style="color:var(--text-muted);">No route churn events detected. Routes are stable across ${polls.length} monitored device(s).</p>
                <p style="color:var(--text-muted); font-size:0.85em;">Route churn alerts are generated when the route table changes between polling cycles.</p>
            </div>`;
        } else {
            container.innerHTML = routeAlerts.map(a => {
                const created = a.created_at ? new Date(a.created_at + 'Z').toLocaleString() : '-';
                return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; border-left:3px solid var(--warning);">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <strong>${escapeHtml(a.hostname || '')}</strong>
                            <span style="color:var(--text-muted); margin-left:0.5rem; font-size:0.85em;">${escapeHtml(a.ip_address || '')}</span>
                        </div>
                        <button class="btn btn-sm btn-secondary" onclick="showRouteSnapshotHistory(${a.host_id}, '${escapeHtml(a.hostname || '')}')">View History</button>
                    </div>
                    <div style="margin-top:0.3rem; font-size:0.9em;">${escapeHtml(a.message)}</div>
                    <div style="margin-top:0.2rem; font-size:0.8em; color:var(--text-muted);">${created}</div>
                </div>`;
            }).join('');
        }
        container.dataset.loaded = '1';
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.acknowledgeMonitoringAlert = async function(alertId) {
    try {
        await api.acknowledgeMonitoringAlert(alertId);
        showSuccess('Alert acknowledged');
        loadMonitoring();
    } catch (e) {
        showError(e.message);
    }
};

window.runMonitoringPollNow = async function() {
    try {
        showSuccess('Starting monitoring poll...');
        const result = await api.runMonitoringPollNow();
        showSuccess(`Poll complete: ${result.hosts_polled} hosts, ${result.alerts_created} alerts`);
        loadMonitoring();
    } catch (e) {
        showError(e.message);
    }
};

window.refreshMonitoring = function() { loadMonitoring(); };

window.filterMonitoringAlerts = function() {
    renderMonitoringAlerts(listViewState.monitoring.alerts);
};

window.showMonitoringHostDetail = async function(hostId) {
    try {
        const polls = listViewState.monitoring.polls;
        const poll = polls.find(p => p.host_id === hostId);
        if (!poll) { showError('No poll data for this host'); return; }

        let ifDetails = [];
        try { ifDetails = JSON.parse(poll.if_details || '[]'); } catch (e) { /* ignore */ }
        let vpnDetails = [];
        try { vpnDetails = JSON.parse(poll.vpn_details || '[]'); } catch (e) { /* ignore */ }

        const ifTable = ifDetails.length ? `
            <h4 style="margin-top:1rem;">Interfaces (${ifDetails.length})</h4>
            <div style="max-height:300px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Name</th>
                    <th style="text-align:left; padding:4px 8px;">Status</th>
                    <th style="text-align:right; padding:4px 8px;">Speed</th>
                    <th style="text-align:right; padding:4px 8px;">In Octets</th>
                    <th style="text-align:right; padding:4px 8px;">Out Octets</th>
                </tr>
                ${ifDetails.map(i => {
                    const sColor = i.status === 'up' ? 'success' : (i.status === 'admin_down' ? 'text-muted' : 'danger');
                    return `<tr style="border-bottom:1px solid var(--border-color);">
                        <td style="padding:4px 8px;">${escapeHtml(i.name)}</td>
                        <td style="padding:4px 8px; color:var(--${sColor});">${i.status}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.speed_mbps ? i.speed_mbps + ' Mbps' : '-'}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.in_octets?.toLocaleString() || '0'}</td>
                        <td style="padding:4px 8px; text-align:right;">${i.out_octets?.toLocaleString() || '0'}</td>
                    </tr>`;
                }).join('')}
            </table>
            </div>` : '<p style="color:var(--text-muted);">No interface data available.</p>';

        const vpnTable = vpnDetails.length ? `
            <h4 style="margin-top:1rem;">VPN Tunnels (${vpnDetails.length})</h4>
            <div style="max-height:200px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:1px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Peer</th>
                    <th style="text-align:left; padding:4px 8px;">Status</th>
                </tr>
                ${vpnDetails.map(v => {
                    const vColor = v.status === 'up' ? 'success' : 'danger';
                    return `<tr style="border-bottom:1px solid var(--border-color);">
                        <td style="padding:4px 8px;">${escapeHtml(v.peer || '')}</td>
                        <td style="padding:4px 8px; color:var(--${vColor});">${v.status}</td>
                    </tr>`;
                }).join('')}
            </table>
            </div>` : '<p style="color:var(--text-muted);">No VPN data available.</p>';

        const uptime = poll.uptime_seconds != null ? formatUptime(poll.uptime_seconds) : 'N/A';
        const polled = poll.polled_at ? new Date(poll.polled_at + 'Z').toLocaleString() : '-';

        showModal(`${escapeHtml(poll.hostname || 'Device')} - Monitoring Detail`, `
            <div style="display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1rem;">
                <div><strong>CPU:</strong> ${poll.cpu_percent != null ? poll.cpu_percent + '%' : 'N/A'}</div>
                <div><strong>Memory:</strong> ${poll.memory_percent != null ? poll.memory_percent + '%' : 'N/A'}${poll.memory_used_mb != null ? ` (${poll.memory_used_mb}/${poll.memory_total_mb} MB)` : ''}</div>
                <div><strong>Uptime:</strong> ${uptime}</div>
                <div><strong>Routes:</strong> ${poll.route_count}</div>
                <div><strong>Last Poll:</strong> ${polled}</div>
            </div>
            ${poll.poll_status === 'error' ? `<div style="color:var(--danger); margin-bottom:0.5rem;">Poll Error: ${escapeHtml(poll.poll_error || '')}</div>` : ''}
            ${ifTable}
            ${vpnTable}
        `);
    } catch (e) {
        showError(e.message);
    }
};

window.showMonitoringHostHistory = async function(hostId, hostname) {
    try {
        const history = await api.getMonitoringPollHistory(hostId, 50);
        if (!history.length) { showError('No history available'); return; }

        const rows = history.map(p => {
            const ts = p.polled_at ? new Date(p.polled_at + 'Z').toLocaleString() : '-';
            return `<tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:4px 8px; font-size:0.85em;">${ts}</td>
                <td style="padding:4px 8px; text-align:right;">${p.cpu_percent != null ? p.cpu_percent + '%' : '-'}</td>
                <td style="padding:4px 8px; text-align:right;">${p.memory_percent != null ? p.memory_percent + '%' : '-'}</td>
                <td style="padding:4px 8px; text-align:center;">${p.if_up_count}/${p.if_down_count}</td>
                <td style="padding:4px 8px; text-align:center;">${p.vpn_tunnels_up}/${p.vpn_tunnels_down}</td>
                <td style="padding:4px 8px; text-align:right;">${p.route_count}</td>
                <td style="padding:4px 8px; text-align:center;">${p.poll_status === 'error' ? '<span style="color:var(--danger);">err</span>' : '<span style="color:var(--success);">ok</span>'}</td>
            </tr>`;
        }).join('');

        showModal(`${escapeHtml(hostname)} - Poll History`, `
            <div style="max-height:400px; overflow:auto;">
            <table style="width:100%; font-size:0.85em; border-collapse:collapse;">
                <tr style="border-bottom:2px solid var(--border-color);">
                    <th style="text-align:left; padding:4px 8px;">Time</th>
                    <th style="text-align:right; padding:4px 8px;">CPU</th>
                    <th style="text-align:right; padding:4px 8px;">Memory</th>
                    <th style="text-align:center; padding:4px 8px;">IF Up/Down</th>
                    <th style="text-align:center; padding:4px 8px;">VPN Up/Down</th>
                    <th style="text-align:right; padding:4px 8px;">Routes</th>
                    <th style="text-align:center; padding:4px 8px;">Status</th>
                </tr>
                ${rows}
            </table>
            </div>
        `);
    } catch (e) {
        showError(e.message);
    }
};

window.showRouteSnapshotHistory = async function(hostId, hostname) {
    try {
        const snapshots = await api.getMonitoringRouteSnapshots(hostId, 10);
        if (!snapshots.length) { showError('No route snapshots available'); return; }

        const items = snapshots.map((s, i) => {
            const ts = s.captured_at ? new Date(s.captured_at + 'Z').toLocaleString() : '-';
            const prev = snapshots[i + 1];
            const delta = prev ? s.route_count - prev.route_count : 0;
            const deltaStr = delta > 0 ? `<span style="color:var(--success);">+${delta}</span>` : (delta < 0 ? `<span style="color:var(--danger);">${delta}</span>` : '<span style="color:var(--text-muted);">0</span>');
            return `<div class="card" style="margin-bottom:0.5rem; padding:0.5rem 0.75rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span style="font-size:0.85em; color:var(--text-muted);">${ts}</span>
                        <span style="margin-left:0.75rem;">Routes: <strong>${s.route_count}</strong></span>
                        <span style="margin-left:0.5rem; font-size:0.85em;">Delta: ${deltaStr}</span>
                    </div>
                    <button class="btn btn-sm btn-secondary" onclick="showRouteSnapshotDetail('${escapeHtml(s.routes_text || '').replace(/'/g, "\\'")}', '${ts}')">View</button>
                </div>
            </div>`;
        }).join('');

        showModal(`${escapeHtml(hostname)} - Route Snapshots`, `<div style="max-height:400px; overflow:auto;">${items}</div>`);
    } catch (e) {
        showError(e.message);
    }
};

window.showRouteSnapshotDetail = function(routesText, timestamp) {
    showModal(`Route Table - ${timestamp}`, `<pre style="max-height:400px; overflow:auto; font-size:0.8em; white-space:pre-wrap;">${escapeHtml(routesText)}</pre>`);
};

// ── Alert Rules Management ──────────────────────────────────────────────────

async function loadMonitoringRules() {
    const container = document.getElementById('monitoring-rules-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        const rules = await api.getAlertRules();
        if (!rules.length) {
            container.innerHTML = emptyStateHTML('No alert rules defined', 'monitoring',
                '<button class="btn btn-primary btn-sm" onclick="showCreateAlertRuleModal()">Create First Rule</button>');
            return;
        }
        container.innerHTML = rules.map(r => {
            const sevColors = { critical: 'danger', warning: 'warning', info: 'primary' };
            const sevColor = sevColors[r.severity] || 'text-muted';
            const scope = r.hostname ? `Host: ${escapeHtml(r.hostname)}` : (r.group_name ? `Group: ${escapeHtml(r.group_name)}` : 'All hosts');
            const escalation = r.escalate_after_minutes > 0
                ? `<span style="font-size:0.8em; color:var(--text-muted);">Escalate to ${escapeHtml(r.escalate_to)} after ${r.escalate_after_minutes}m</span>`
                : '';
            return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; opacity:${r.enabled ? 1 : 0.5};">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                    <div>
                        <span class="badge" style="background:var(--${sevColor}); color:white; font-size:0.75em; padding:2px 8px; border-radius:3px; text-transform:uppercase;">${escapeHtml(r.severity)}</span>
                        <strong style="margin-left:0.4rem;">${escapeHtml(r.name || 'Unnamed')}</strong>
                        <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.5rem;">${escapeHtml(r.metric)} ${escapeHtml(r.operator)} ${r.value}</span>
                        ${!r.enabled ? '<span style="color:var(--text-muted); font-size:0.75em; margin-left:0.3rem;">(disabled)</span>' : ''}
                    </div>
                    <div style="display:flex; gap:0.4rem;">
                        <button class="btn btn-sm btn-secondary" onclick="toggleAlertRule(${r.id}, ${r.enabled ? 0 : 1})">${r.enabled ? 'Disable' : 'Enable'}</button>
                        <button class="btn btn-sm" style="color:var(--danger);" onclick="confirmDeleteAlertRule(${r.id}, '${escapeHtml(r.name || '')}')">Delete</button>
                    </div>
                </div>
                <div style="margin-top:0.3rem; font-size:0.85em; color:var(--text-muted);">
                    ${scope} · Cooldown: ${r.cooldown_minutes}m ${escalation ? '· ' + escalation : ''}
                    ${r.description ? `<br>${escapeHtml(r.description)}` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.showCreateAlertRuleModal = async function() {
    let groups = [], hosts = [];
    try {
        const inv = await api.getInventoryGroups(true);
        groups = inv || [];
        hosts = groups.flatMap(g => (g.hosts || []).map(h => ({ ...h, group_name: g.name })));
    } catch (e) { /* ignore */ }

    const groupOpts = `<option value="">All Groups</option>` + groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const hostOpts = `<option value="">All Hosts</option>` + hosts.map(h => `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`).join('');

    showModal('Create Alert Rule', `
        <label class="form-label">Rule Name</label>
        <input type="text" class="form-input" id="ar-name" placeholder="e.g. High CPU Warning" required>
        <label class="form-label" style="margin-top:0.75rem;">Metric</label>
        <select id="ar-metric" class="form-select">
            <option value="cpu">CPU %</option>
            <option value="memory">Memory %</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Tunnels Down</option>
            <option value="route_count">Route Count</option>
            <option value="uptime">Uptime (seconds)</option>
        </select>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Operator</label>
                <select id="ar-operator" class="form-select">
                    <option value=">=">>= (greater or equal)</option>
                    <option value=">">  > (greater)</option>
                    <option value="<="><= (less or equal)</option>
                    <option value="<">  < (less)</option>
                </select>
            </div>
            <div style="flex:1;">
                <label class="form-label">Value</label>
                <input type="number" class="form-input" id="ar-value" value="90" step="0.1">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Severity</label>
        <select id="ar-severity" class="form-select">
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
        </select>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Cooldown (minutes)</label>
                <input type="number" class="form-input" id="ar-cooldown" value="15" min="1" max="1440">
            </div>
            <div style="flex:1;">
                <label class="form-label">Escalate After (min, 0=off)</label>
                <input type="number" class="form-input" id="ar-escalate-after" value="0" min="0" max="1440">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Scope: Group</label>
        <select id="ar-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.5rem;">Scope: Host (overrides group)</label>
        <select id="ar-host" class="form-select">${hostOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Description</label>
        <textarea class="form-input" id="ar-description" rows="2" placeholder="Optional description..."></textarea>
        <button class="btn btn-primary" style="margin-top:1rem; width:100%;" onclick="submitCreateAlertRule()">Create Rule</button>
    `);
};

window.submitCreateAlertRule = async function() {
    try {
        const data = {
            name: document.getElementById('ar-name').value,
            metric: document.getElementById('ar-metric').value,
            operator: document.getElementById('ar-operator').value,
            value: parseFloat(document.getElementById('ar-value').value) || 0,
            severity: document.getElementById('ar-severity').value,
            cooldown_minutes: parseInt(document.getElementById('ar-cooldown').value) || 15,
            escalate_after_minutes: parseInt(document.getElementById('ar-escalate-after').value) || 0,
            escalate_to: 'critical',
            description: document.getElementById('ar-description').value,
        };
        const hostId = document.getElementById('ar-host').value;
        const groupId = document.getElementById('ar-group').value;
        if (hostId) data.host_id = parseInt(hostId);
        else if (groupId) data.group_id = parseInt(groupId);

        await api.createAlertRule(data);
        closeModal();
        showSuccess('Alert rule created');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

window.toggleAlertRule = async function(ruleId, enabled) {
    try {
        await api.updateAlertRule(ruleId, { enabled });
        showSuccess(enabled ? 'Rule enabled' : 'Rule disabled');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

window.confirmDeleteAlertRule = function(ruleId, name) {
    showModal('Delete Rule', `
        <p>Delete rule <strong>${escapeHtml(name)}</strong>?</p>
        <div style="display:flex; gap:0.5rem; margin-top:1rem;">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn" style="background:var(--danger); color:white;" onclick="deleteAlertRuleConfirmed(${ruleId})">Delete</button>
        </div>
    `);
};

window.deleteAlertRuleConfirmed = async function(ruleId) {
    try {
        await api.deleteAlertRule(ruleId);
        closeModal();
        showSuccess('Rule deleted');
        loadMonitoringRules();
    } catch (e) {
        showError(e.message);
    }
};

// ── Alert Suppressions Management ───────────────────────────────────────────

async function loadMonitoringSuppressions() {
    const container = document.getElementById('monitoring-suppressions-list');
    if (!container) return;
    container.innerHTML = skeletonCards(2);
    try {
        const suppressions = await api.getAlertSuppressions();
        if (!suppressions.length) {
            container.innerHTML = emptyStateHTML('No suppressions', 'monitoring',
                '<button class="btn btn-primary btn-sm" onclick="showCreateSuppressionModal()">Create Suppression</button>');
            return;
        }
        const now = new Date();
        container.innerHTML = suppressions.map(s => {
            const ends = new Date(s.ends_at + 'Z');
            const isActive = ends > now && new Date(s.starts_at + 'Z') <= now;
            const statusColor = isActive ? 'success' : 'text-muted';
            const statusLabel = isActive ? 'Active' : (ends <= now ? 'Expired' : 'Scheduled');
            const scope = s.hostname ? `Host: ${escapeHtml(s.hostname)}` : (s.group_name ? `Group: ${escapeHtml(s.group_name)}` : 'Global');
            const metricLabel = s.metric ? `Metric: ${escapeHtml(s.metric)}` : 'All metrics';
            const startsStr = s.starts_at ? new Date(s.starts_at + 'Z').toLocaleString() : '-';
            const endsStr = s.ends_at ? new Date(s.ends_at + 'Z').toLocaleString() : '-';

            return `<div class="card" style="margin-bottom:0.5rem; padding:0.75rem 1rem; opacity:${isActive ? 1 : 0.5};">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
                    <div>
                        <span style="color:var(--${statusColor}); font-size:0.8em; font-weight:600; text-transform:uppercase;">${statusLabel}</span>
                        <strong style="margin-left:0.4rem;">${escapeHtml(s.name || 'Unnamed')}</strong>
                        <span style="color:var(--text-muted); font-size:0.85em; margin-left:0.5rem;">${scope} · ${metricLabel}</span>
                    </div>
                    <button class="btn btn-sm" style="color:var(--danger);" onclick="confirmDeleteSuppression(${s.id}, '${escapeHtml(s.name || '')}')">Delete</button>
                </div>
                <div style="margin-top:0.3rem; font-size:0.85em; color:var(--text-muted);">
                    ${startsStr} — ${endsStr}${s.reason ? ` · Reason: ${escapeHtml(s.reason)}` : ''}${s.created_by ? ` · By ${escapeHtml(s.created_by)}` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        container.innerHTML = `<div class="card" style="color:var(--danger);">Error: ${escapeHtml(e.message)}</div>`;
    }
}

window.showCreateSuppressionModal = async function() {
    let groups = [], hosts = [];
    try {
        const inv = await api.getInventoryGroups(true);
        groups = inv || [];
        hosts = groups.flatMap(g => (g.hosts || []).map(h => ({ ...h, group_name: g.name })));
    } catch (e) { /* ignore */ }

    const groupOpts = `<option value="">All Groups</option>` + groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const hostOpts = `<option value="">All Hosts</option>` + hosts.map(h => `<option value="${h.id}">${escapeHtml(h.hostname)} (${escapeHtml(h.ip_address)})</option>`).join('');

    // Default: 2 hours from now
    const now = new Date();
    const endsDefault = new Date(now.getTime() + 2 * 3600000);
    const toLocal = d => d.toISOString().slice(0, 16);

    showModal('Create Alert Suppression', `
        <label class="form-label">Name</label>
        <input type="text" class="form-input" id="sup-name" placeholder="e.g. Maintenance Window - Switch Upgrade" required>
        <div style="display:flex; gap:0.5rem; margin-top:0.75rem;">
            <div style="flex:1;">
                <label class="form-label">Starts At</label>
                <input type="datetime-local" class="form-input" id="sup-starts" value="${toLocal(now)}">
            </div>
            <div style="flex:1;">
                <label class="form-label">Ends At</label>
                <input type="datetime-local" class="form-input" id="sup-ends" value="${toLocal(endsDefault)}">
            </div>
        </div>
        <label class="form-label" style="margin-top:0.75rem;">Scope: Group</label>
        <select id="sup-group" class="form-select">${groupOpts}</select>
        <label class="form-label" style="margin-top:0.5rem;">Scope: Host (overrides group)</label>
        <select id="sup-host" class="form-select">${hostOpts}</select>
        <label class="form-label" style="margin-top:0.75rem;">Metric (blank = all metrics)</label>
        <select id="sup-metric" class="form-select">
            <option value="">All Metrics</option>
            <option value="cpu">CPU</option>
            <option value="memory">Memory</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Down</option>
            <option value="route_churn">Route Churn</option>
        </select>
        <label class="form-label" style="margin-top:0.75rem;">Reason</label>
        <textarea class="form-input" id="sup-reason" rows="2" placeholder="Optional reason..."></textarea>
        <button class="btn btn-primary" style="margin-top:1rem; width:100%;" onclick="submitCreateSuppression()">Create Suppression</button>
    `);
};

window.submitCreateSuppression = async function() {
    try {
        const startsVal = document.getElementById('sup-starts').value;
        const endsVal = document.getElementById('sup-ends').value;
        if (!endsVal) { showError('End time is required'); return; }

        const data = {
            name: document.getElementById('sup-name').value,
            starts_at: startsVal ? new Date(startsVal).toISOString().replace('T', ' ').slice(0, 19) : '',
            ends_at: new Date(endsVal).toISOString().replace('T', ' ').slice(0, 19),
            metric: document.getElementById('sup-metric').value,
            reason: document.getElementById('sup-reason').value,
        };
        const hostId = document.getElementById('sup-host').value;
        const groupId = document.getElementById('sup-group').value;
        if (hostId) data.host_id = parseInt(hostId);
        else if (groupId) data.group_id = parseInt(groupId);

        await api.createAlertSuppression(data);
        closeModal();
        showSuccess('Suppression created');
        loadMonitoringSuppressions();
    } catch (e) {
        showError(e.message);
    }
};

window.confirmDeleteSuppression = function(supId, name) {
    showModal('Delete Suppression', `
        <p>Delete suppression <strong>${escapeHtml(name)}</strong>?</p>
        <div style="display:flex; gap:0.5rem; margin-top:1rem;">
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn" style="background:var(--danger); color:white;" onclick="deleteSuppressionConfirmed(${supId})">Delete</button>
        </div>
    `);
};

window.deleteSuppressionConfirmed = async function(supId) {
    try {
        await api.deleteAlertSuppression(supId);
        closeModal();
        showSuccess('Suppression deleted');
        loadMonitoringSuppressions();
    } catch (e) {
        showError(e.message);
    }
};

// Wire up monitoring search
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('monitoring-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            listViewState.monitoring.query = searchInput.value;
            const tab = listViewState.monitoring.tab;
            if (tab === 'devices') renderMonitoringDevices(listViewState.monitoring.polls);
            else if (tab === 'alerts') renderMonitoringAlerts(listViewState.monitoring.alerts);
        });
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
// SLA Dashboards
// ═══════════════════════════════════════════════════════════════════════════════

async function loadSla(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('sla-hosts-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const [summary, targets] = await Promise.all([
            api.getSlaSummary(null, days),
            api.getSlaTargets(),
        ]);
        listViewState.sla.summary = summary;
        listViewState.sla.targets = targets || [];
        renderSlaSummary(summary);
        renderSlaHosts(summary.hosts || [], targets || []);
        renderSlaIncidents(summary);
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading SLA data: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadSla = loadSla;

function renderSlaSummary(s) {
    const CIRC = 2 * Math.PI * 52; // ~326.73

    // Uptime gauge
    const uptimeVal = s.avg_uptime_pct != null ? s.avg_uptime_pct : 0;
    const uptimeFill = document.getElementById('sla-gauge-uptime-fill');
    if (uptimeFill) {
        const pct = Math.min(uptimeVal, 100) / 100;
        uptimeFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
        uptimeFill.classList.remove('sla-gauge-warn', 'sla-gauge-danger');
        if (uptimeVal < 99) uptimeFill.classList.add('sla-gauge-danger');
        else if (uptimeVal < 99.9) uptimeFill.classList.add('sla-gauge-warn');
    }
    const uptimeEl = document.getElementById('sla-val-uptime');
    if (uptimeEl) uptimeEl.textContent = s.avg_uptime_pct != null ? s.avg_uptime_pct.toFixed(2) + '%' : '-';

    // Latency gauge (scale: 0-500ms maps to full circle)
    const latVal = s.avg_latency_ms != null ? s.avg_latency_ms : 0;
    const latFill = document.getElementById('sla-gauge-latency-fill');
    if (latFill) {
        const pct = Math.min(latVal / 500, 1);
        latFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const latEl = document.getElementById('sla-val-latency');
    if (latEl) latEl.textContent = s.avg_latency_ms != null ? s.avg_latency_ms.toFixed(1) + 'ms' : '-';

    // Jitter gauge (scale: 0-100ms)
    const jitVal = s.avg_jitter_ms != null ? s.avg_jitter_ms : 0;
    const jitFill = document.getElementById('sla-gauge-jitter-fill');
    if (jitFill) {
        const pct = Math.min(jitVal / 100, 1);
        jitFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const jitEl = document.getElementById('sla-val-jitter');
    if (jitEl) jitEl.textContent = s.avg_jitter_ms != null ? s.avg_jitter_ms.toFixed(1) + 'ms' : '-';

    // Packet loss gauge (scale: 0-100%)
    const pktVal = s.avg_packet_loss_pct != null ? s.avg_packet_loss_pct : 0;
    const pktFill = document.getElementById('sla-gauge-pktloss-fill');
    if (pktFill) {
        const pct = Math.min(pktVal / 100, 1);
        pktFill.setAttribute('stroke-dasharray', `${pct * CIRC} ${CIRC}`);
    }
    const pktEl = document.getElementById('sla-val-pktloss');
    if (pktEl) pktEl.textContent = s.avg_packet_loss_pct != null ? s.avg_packet_loss_pct.toFixed(2) + '%' : '-';

    // MTTR / MTTD
    const mttrEl = document.getElementById('sla-val-mttr');
    if (mttrEl) mttrEl.textContent = s.mttr_minutes != null ? formatMinutes(s.mttr_minutes) : '-';
    const mttdEl = document.getElementById('sla-val-mttd');
    if (mttdEl) mttdEl.textContent = s.mttd_minutes != null ? formatMinutes(s.mttd_minutes) : '-';
}

function formatMinutes(m) {
    if (m == null) return '-';
    if (m < 1) return '<1m';
    if (m < 60) return Math.round(m) + 'm';
    const h = Math.floor(m / 60);
    const rem = Math.round(m % 60);
    return rem > 0 ? `${h}h ${rem}m` : `${h}h`;
}

function getHostSlaCompliance(host, targets) {
    // Find applicable targets for this host
    const applicable = targets.filter(t =>
        t.enabled && (
            (!t.host_id && !t.group_id) ||
            (t.host_id && t.host_id === host.host_id) ||
            (t.group_id && t.group_id === host.group_id)
        )
    );
    if (!applicable.length) return { status: 'none', worst: null };

    let worst = 'met';
    for (const t of applicable) {
        let actual = null;
        if (t.metric === 'uptime') actual = host.uptime_pct;
        else if (t.metric === 'latency') actual = host.avg_latency_ms;
        else if (t.metric === 'jitter') actual = host.jitter_ms;
        else if (t.metric === 'packet_loss') actual = host.avg_packet_loss_pct;
        if (actual == null) continue;

        // For uptime: higher is better; for latency/jitter/packet_loss: lower is better
        const higherIsBetter = t.metric === 'uptime';
        if (higherIsBetter) {
            if (actual < t.target_value) worst = 'breach';
            else if (actual < t.warning_value && worst !== 'breach') worst = 'warn';
        } else {
            if (actual > t.target_value) worst = 'breach';
            else if (actual > t.warning_value && worst !== 'breach') worst = 'warn';
        }
    }
    return { status: worst };
}

function renderSlaHosts(hosts, targets) {
    const container = document.getElementById('sla-hosts-list');
    if (!container) return;
    const query = (listViewState.sla.query || '').toLowerCase();
    const filtered = hosts.filter(h => {
        if (query && !(h.hostname || '').toLowerCase().includes(query)
            && !(h.ip_address || '').toLowerCase().includes(query)) return false;
        return true;
    });

    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No SLA data available', 'sla',
            '<p style="color:var(--text-muted); font-size:0.9em;">SLA metrics are computed from monitoring polls. Enable monitoring and run polls to see data.</p>');
        return;
    }

    const header = `<div class="card" style="padding:0; overflow:hidden;">
        <div class="sla-host-row sla-host-header">
            <div>Host</div>
            <div>Uptime</div>
            <div>Latency</div>
            <div>Jitter</div>
            <div>Pkt Loss</div>
            <div>Status</div>
        </div>`;

    const rows = filtered.map(h => {
        const compliance = getHostSlaCompliance(h, targets);
        const uptimeColor = h.uptime_pct >= 99.9 ? 'success' : h.uptime_pct >= 99 ? 'warning' : 'danger';
        const badgeClass = compliance.status === 'met' ? 'met' : compliance.status === 'warn' ? 'warn' : compliance.status === 'breach' ? 'breach' : 'met';
        const badgeLabel = compliance.status === 'none' ? 'No Target' : compliance.status === 'met' ? 'Met' : compliance.status === 'warn' ? 'Warning' : 'Breach';

        return `<div class="sla-host-row" onclick="showSlaHostDetail(${h.host_id})">
            <div>
                <strong>${escapeHtml(h.hostname || 'Unknown')}</strong>
                <span style="color:var(--text-muted); font-size:0.8em; margin-left:0.4rem;">${escapeHtml(h.ip_address || '')}</span>
            </div>
            <div style="color:var(--${uptimeColor}); font-weight:600;">${h.uptime_pct != null ? h.uptime_pct.toFixed(2) + '%' : '-'}</div>
            <div>${h.avg_latency_ms != null ? h.avg_latency_ms.toFixed(1) + 'ms' : '-'}</div>
            <div>${h.jitter_ms != null ? h.jitter_ms.toFixed(1) + 'ms' : '-'}</div>
            <div>${h.avg_packet_loss_pct != null ? h.avg_packet_loss_pct.toFixed(2) + '%' : '-'}</div>
            <div><span class="sla-compliance-badge ${badgeClass}">${badgeLabel}</span></div>
        </div>`;
    }).join('');

    container.innerHTML = header + rows + '</div>';
}

function renderSlaIncidents(summary) {
    const container = document.getElementById('sla-incidents-list');
    if (!container) return;

    const alerts_info = {
        total: summary.total_alerts || 0,
        resolved: summary.resolved_alerts || 0,
        mttr: summary.mttr_minutes,
        mttd: summary.mttd_minutes,
    };

    // Show incident stats
    const open = alerts_info.total - alerts_info.resolved;
    container.innerHTML = `<div class="card" style="padding:1rem;">
        <div style="display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1rem;">
            <div><span style="color:var(--text-muted);">Total Alerts:</span> <strong>${alerts_info.total}</strong></div>
            <div><span style="color:var(--text-muted);">Resolved:</span> <strong style="color:var(--success);">${alerts_info.resolved}</strong></div>
            <div><span style="color:var(--text-muted);">Open:</span> <strong style="color:${open > 0 ? 'var(--danger)' : 'var(--success)'};">${open}</strong></div>
            <div><span style="color:var(--text-muted);">Avg MTTR:</span> <strong>${alerts_info.mttr != null ? formatMinutes(alerts_info.mttr) : '-'}</strong></div>
            <div><span style="color:var(--text-muted);">Avg MTTD:</span> <strong>${alerts_info.mttd != null ? formatMinutes(alerts_info.mttd) : '-'}</strong></div>
        </div>
        <div style="font-size:0.85em; color:var(--text-muted);">
            <p><strong>MTTR</strong> (Mean Time To Repair): Average time from alert creation to acknowledgement.</p>
            <p><strong>MTTD</strong> (Mean Time To Detect): Average time from first failure to alert creation.</p>
        </div>
    </div>`;
}

function switchSlaTab(tab) {
    listViewState.sla.tab = tab;
    document.querySelectorAll('.sla-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-sla-tab') === tab));
    document.querySelectorAll('.sla-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`sla-tab-${tab}`);
    if (target) target.style.display = '';

    if (tab === 'trends') loadSlaTrends();
    if (tab === 'targets') loadSlaTargets();
}
window.switchSlaTab = switchSlaTab;

// ── SLA Trends (SVG charts) ────────────────────────────────────────────────

async function loadSlaTrends() {
    const container = document.getElementById('sla-trends-container');
    if (!container) return;
    container.innerHTML = '<div class="skeleton skeleton-card" style="height:300px;"></div>';

    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const summary = listViewState.sla.summary;
        if (!summary || !summary.hosts || !summary.hosts.length) {
            container.innerHTML = '<div class="card" style="padding:1rem; color:var(--text-muted);">No trend data available. Run monitoring polls to collect SLA metrics.</div>';
            return;
        }

        // Get detailed daily data for first host (or aggregate)
        // Use first host with data for detailed trend
        const hostId = summary.hosts[0].host_id;
        const detail = await api.getSlaHostDetail(hostId, days);

        let html = '';
        if (detail.daily && detail.daily.length) {
            html += renderSlaChart(detail.daily, 'uptime_pct', 'Uptime %', 'var(--success)', 95, 100);
            html += renderSlaChart(detail.daily, 'avg_latency_ms', 'Latency (ms)', 'var(--primary)', 0, null);
            html += renderSlaChart(detail.daily, 'jitter_ms', 'Jitter (ms)', 'var(--warning)', 0, null);
            html += renderSlaChart(detail.daily, 'avg_packet_loss_pct', 'Packet Loss %', 'var(--danger)', 0, null);
        }
        html += `<div style="font-size:0.8em; color:var(--text-muted); margin-top:0.5rem;">
            Showing trends for <strong>${escapeHtml(detail.hostname || 'Host #' + hostId)}</strong>.
            Click a host in the Host SLAs tab to view its specific trends.
        </div>`;
        container.innerHTML = html;
    } catch (error) {
        container.innerHTML = `<div class="card" style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}

function renderSlaChart(daily, field, label, color, minY, maxY) {
    if (!daily || !daily.length) return '';

    const values = daily.map(d => d[field]).filter(v => v != null);
    if (!values.length) return `<div class="card" style="padding:1rem;"><div class="sla-chart-label">${escapeHtml(label)}</div><div style="color:var(--text-muted); font-size:0.9em;">No data</div></div>`;

    const W = 700, H = 200, PAD_L = 55, PAD_R = 20, PAD_T = 30, PAD_B = 35;
    const chartW = W - PAD_L - PAD_R;
    const chartH = H - PAD_T - PAD_B;

    const dataMin = Math.min(...values);
    const dataMax = Math.max(...values);
    const yMin = minY != null ? Math.min(minY, dataMin) : dataMin - (dataMax - dataMin) * 0.1;
    const yMax = maxY != null ? Math.max(maxY, dataMax) : dataMax + (dataMax - dataMin) * 0.1 || 1;
    const yRange = yMax - yMin || 1;

    const points = daily.map((d, i) => {
        const v = d[field];
        if (v == null) return null;
        const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
        const y = PAD_T + chartH - ((v - yMin) / yRange) * chartH;
        return { x, y, v, day: d.day };
    }).filter(Boolean);

    if (!points.length) return '';

    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaPath = linePath + ` L${points[points.length - 1].x.toFixed(1)},${PAD_T + chartH} L${points[0].x.toFixed(1)},${PAD_T + chartH} Z`;

    // Grid lines (4 horizontal)
    let gridLines = '';
    for (let i = 0; i <= 4; i++) {
        const y = PAD_T + (i / 4) * chartH;
        const val = yMax - (i / 4) * yRange;
        gridLines += `<line x1="${PAD_L}" y1="${y}" x2="${W - PAD_R}" y2="${y}" class="sla-chart-grid-line"/>`;
        gridLines += `<text x="${PAD_L - 8}" y="${y + 3}" text-anchor="end" class="sla-chart-axis-label">${val.toFixed(val < 10 ? 1 : 0)}</text>`;
    }

    // X-axis labels (show ~5 labels)
    let xLabels = '';
    const step = Math.max(1, Math.floor(daily.length / 5));
    for (let i = 0; i < daily.length; i += step) {
        const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
        const d = daily[i].day || '';
        const short = d.slice(5); // MM-DD
        xLabels += `<text x="${x}" y="${H - 5}" text-anchor="middle" class="sla-chart-axis-label">${short}</text>`;
    }

    const dots = points.map(p =>
        `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" class="sla-chart-dot" stroke="${color}">
            <title>${p.day}: ${p.v.toFixed(2)}</title>
        </circle>`
    ).join('');

    return `<div class="card" style="padding:1rem; margin-bottom:1rem;">
        <div class="sla-chart-label">${escapeHtml(label)}</div>
        <div class="sla-chart-container">
            <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
                ${gridLines}
                ${xLabels}
                <path d="${areaPath}" class="sla-chart-area" fill="${color}"/>
                <path d="${linePath}" class="sla-chart-line" stroke="${color}"/>
                ${dots}
            </svg>
        </div>
    </div>`;
}

// ── SLA Host Detail Modal ────────────────────────────────────────────────────

async function showSlaHostDetail(hostId) {
    const modal = document.getElementById('sla-host-detail-modal');
    const body = document.getElementById('sla-host-detail-body');
    const title = document.getElementById('sla-host-detail-title');
    if (!modal || !body) return;
    modal.style.display = 'block';
    body.innerHTML = '<div class="skeleton skeleton-card" style="height:200px;"></div>';

    try {
        const days = parseInt(document.getElementById('sla-period-select')?.value || '30', 10);
        const detail = await api.getSlaHostDetail(hostId, days);
        if (title) title.textContent = `SLA Detail: ${detail.hostname || 'Host #' + hostId}`;

        let html = `<div style="display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1rem; font-size:0.9em;">
            <div><span style="color:var(--text-muted);">Host:</span> <strong>${escapeHtml(detail.hostname)}</strong></div>
            <div><span style="color:var(--text-muted);">IP:</span> ${escapeHtml(detail.ip_address)}</div>
            <div><span style="color:var(--text-muted);">Type:</span> ${escapeHtml(detail.device_type || '-')}</div>
            <div><span style="color:var(--text-muted);">Period:</span> ${detail.period_days} days</div>
            <div><span style="color:var(--text-muted);">Alerts:</span> ${detail.total_alerts} (${detail.resolved_alerts} resolved)</div>
            <div><span style="color:var(--text-muted);">MTTR:</span> ${detail.mttr_minutes != null ? formatMinutes(detail.mttr_minutes) : '-'}</div>
        </div>`;

        if (detail.daily && detail.daily.length) {
            html += renderSlaChart(detail.daily, 'uptime_pct', 'Daily Uptime %', 'var(--success)', 95, 100);
            html += renderSlaChart(detail.daily, 'avg_latency_ms', 'Daily Latency (ms)', 'var(--primary)', 0, null);
            html += renderSlaChart(detail.daily, 'jitter_ms', 'Daily Jitter (ms)', 'var(--warning)', 0, null);
            html += renderSlaChart(detail.daily, 'avg_packet_loss_pct', 'Daily Packet Loss %', 'var(--danger)', 0, null);
        } else {
            html += '<div style="color:var(--text-muted);">No daily trend data available.</div>';
        }

        body.innerHTML = html;
    } catch (error) {
        body.innerHTML = `<div style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}
window.showSlaHostDetail = showSlaHostDetail;

function closeSlaHostDetailModal() {
    const modal = document.getElementById('sla-host-detail-modal');
    if (modal) modal.style.display = 'none';
}
window.closeSlaHostDetailModal = closeSlaHostDetailModal;

// ── SLA Targets CRUD ─────────────────────────────────────────────────────────

async function loadSlaTargets() {
    const container = document.getElementById('sla-targets-list');
    if (!container) return;
    container.innerHTML = skeletonCards(1);
    try {
        const targets = await api.getSlaTargets();
        listViewState.sla.targets = targets || [];
        renderSlaTargets(targets || []);
    } catch (error) {
        container.innerHTML = `<div class="card" style="color:var(--danger)">Error: ${escapeHtml(error.message)}</div>`;
    }
}

function renderSlaTargets(targets) {
    const container = document.getElementById('sla-targets-list');
    if (!container) return;
    if (!targets.length) {
        container.innerHTML = emptyStateHTML('No SLA targets defined', 'sla',
            '<button class="btn btn-primary btn-sm" onclick="showCreateSlaTargetModal()">Create First Target</button>');
        return;
    }

    const metricLabels = { uptime: 'Uptime %', latency: 'Latency (ms)', jitter: 'Jitter (ms)', packet_loss: 'Packet Loss %' };

    container.innerHTML = targets.map(t => {
        const scope = t.host_name ? `Host: ${escapeHtml(t.host_name)}` :
                       t.group_name ? `Group: ${escapeHtml(t.group_name)}` : 'Global';
        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <strong>${escapeHtml(t.name)}</strong>
                    ${!t.enabled ? '<span style="color:var(--text-muted); font-size:0.8em; margin-left:0.5rem;">(disabled)</span>' : ''}
                </div>
                <div style="display:flex; gap:0.4rem;">
                    <button class="btn btn-sm btn-secondary" onclick="editSlaTarget(${t.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSlaTarget(${t.id})">Delete</button>
                </div>
            </div>
            <div style="display:flex; gap:1.5rem; margin-top:0.5rem; font-size:0.9em; flex-wrap:wrap;">
                <div><span style="color:var(--text-muted);">Metric:</span> ${metricLabels[t.metric] || t.metric}</div>
                <div><span style="color:var(--text-muted);">Target:</span> <strong style="color:var(--success);">${t.target_value}</strong></div>
                <div><span style="color:var(--text-muted);">Warning:</span> <strong style="color:var(--warning);">${t.warning_value}</strong></div>
                <div><span style="color:var(--text-muted);">Scope:</span> ${scope}</div>
            </div>
        </div>`;
    }).join('');
}

async function showCreateSlaTargetModal(editTarget = null) {
    const modal = document.getElementById('sla-target-modal');
    const titleEl = document.getElementById('sla-target-modal-title');
    if (!modal) return;

    // Reset form
    document.getElementById('sla-target-edit-id').value = editTarget ? editTarget.id : '';
    document.getElementById('sla-target-name').value = editTarget ? editTarget.name : '';
    document.getElementById('sla-target-metric').value = editTarget ? editTarget.metric : 'uptime';
    document.getElementById('sla-target-value').value = editTarget ? editTarget.target_value : 99.9;
    document.getElementById('sla-target-warning').value = editTarget ? editTarget.warning_value : 99.0;

    // Scope
    const scopeSelect = document.getElementById('sla-target-scope');
    if (editTarget?.host_id) scopeSelect.value = 'host';
    else if (editTarget?.group_id) scopeSelect.value = 'group';
    else scopeSelect.value = 'global';
    toggleSlaTargetScope();

    // Populate group/host selects
    try {
        const groups = await api.getGroups();
        const groupSelect = document.getElementById('sla-target-group-id');
        groupSelect.innerHTML = groups.map(g => `<option value="${g.id}" ${editTarget?.group_id === g.id ? 'selected' : ''}>${escapeHtml(g.name)}</option>`).join('');

        // For hosts, flatten from groups
        const hostSelect = document.getElementById('sla-target-host-id');
        let hostOptions = '';
        for (const g of groups) {
            const hosts = g.hosts || [];
            for (const h of hosts) {
                hostOptions += `<option value="${h.id}" ${editTarget?.host_id === h.id ? 'selected' : ''}>${escapeHtml(h.hostname || h.ip_address)} (${escapeHtml(g.name)})</option>`;
            }
        }
        hostSelect.innerHTML = hostOptions || '<option value="">No hosts</option>';
    } catch { /* ignore populate errors */ }

    if (titleEl) titleEl.textContent = editTarget ? 'Edit SLA Target' : 'New SLA Target';
    modal.style.display = 'block';
}
window.showCreateSlaTargetModal = showCreateSlaTargetModal;

function toggleSlaTargetScope() {
    const scope = document.getElementById('sla-target-scope')?.value || 'global';
    document.getElementById('sla-target-scope-group').style.display = scope === 'group' ? '' : 'none';
    document.getElementById('sla-target-scope-host').style.display = scope === 'host' ? '' : 'none';
}
window.toggleSlaTargetScope = toggleSlaTargetScope;

function closeSlaTargetModal() {
    const modal = document.getElementById('sla-target-modal');
    if (modal) modal.style.display = 'none';
}
window.closeSlaTargetModal = closeSlaTargetModal;

async function saveSlaTarget() {
    const editId = document.getElementById('sla-target-edit-id')?.value;
    const name = document.getElementById('sla-target-name')?.value?.trim();
    const metric = document.getElementById('sla-target-metric')?.value;
    const targetValue = parseFloat(document.getElementById('sla-target-value')?.value);
    const warningValue = parseFloat(document.getElementById('sla-target-warning')?.value);
    const scope = document.getElementById('sla-target-scope')?.value || 'global';

    if (!name) { showError('Name is required'); return; }

    const data = {
        name,
        metric,
        target_value: targetValue,
        warning_value: warningValue,
        host_id: scope === 'host' ? parseInt(document.getElementById('sla-target-host-id')?.value) || null : null,
        group_id: scope === 'group' ? parseInt(document.getElementById('sla-target-group-id')?.value) || null : null,
    };

    try {
        if (editId) {
            await api.updateSlaTarget(parseInt(editId), data);
            showSuccess('SLA target updated');
        } else {
            await api.createSlaTarget(data);
            showSuccess('SLA target created');
        }
        closeSlaTargetModal();
        loadSlaTargets();
    } catch (error) {
        showError('Failed to save target: ' + error.message);
    }
}
window.saveSlaTarget = saveSlaTarget;

async function editSlaTarget(id) {
    const targets = listViewState.sla.targets || [];
    const target = targets.find(t => t.id === id);
    if (target) {
        showCreateSlaTargetModal(target);
    }
}
window.editSlaTarget = editSlaTarget;

async function deleteSlaTarget(id) {
    if (!confirm('Delete this SLA target?')) return;
    try {
        await api.deleteSlaTarget(id);
        showSuccess('SLA target deleted');
        loadSlaTargets();
    } catch (error) {
        showError('Failed to delete: ' + error.message);
    }
}
window.deleteSlaTarget = deleteSlaTarget;

// Wire up SLA search
document.addEventListener('DOMContentLoaded', () => {
    const slaSearch = document.getElementById('sla-search');
    if (slaSearch) {
        slaSearch.addEventListener('input', () => {
            listViewState.sla.query = slaSearch.value;
            const summary = listViewState.sla.summary;
            if (summary && summary.hosts) {
                renderSlaHosts(summary.hosts, listViewState.sla.targets || []);
            }
        });
    }
});


// ═══════════════════════════════════════════════════════════════════════════════
// Deployments / Rollback Orchestration
// ═══════════════════════════════════════════════════════════════════════════════

async function loadDeployments(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('deployments-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const [summary, deployments] = await Promise.all([
            api.getDeploymentSummary(),
            api.getDeployments({ limit: 200 }),
        ]);
        renderDeploymentSummary(summary);
        listViewState.deployments.items = deployments || [];
        renderDeployments(deployments || []);
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading deployments: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadDeployments = loadDeployments;

function renderDeploymentSummary(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('deploy-stat-total', summary.total ?? '-');
    set('deploy-stat-completed', summary.completed ?? '-');
    set('deploy-stat-active', summary.active ?? '-');
    set('deploy-stat-rolled-back', summary.rolled_back ?? '-');
    set('deploy-stat-failed', summary.failed ?? '-');
}

function renderDeployments(deployments) {
    const container = document.getElementById('deployments-list');
    if (!container) return;
    const query = (listViewState.deployments.query || '').toLowerCase();
    const statusFilter = listViewState.deployments.statusFilter || '';
    const filtered = deployments.filter(d => {
        if (statusFilter && d.status !== statusFilter) return false;
        if (query && !(d.name || '').toLowerCase().includes(query)
            && !(d.group_name || '').toLowerCase().includes(query)
            && !(d.description || '').toLowerCase().includes(query)) return false;
        return true;
    });
    if (!filtered.length) {
        container.innerHTML = emptyStateHTML('No deployments', 'deployments',
            '<button class="btn btn-primary btn-sm" onclick="showNewDeploymentModal()">Create Deployment</button>');
        return;
    }
    container.innerHTML = filtered.map(d => {
        const statusColors = {
            planning: 'text-muted', 'pre-check': 'warning', executing: 'warning',
            'post-check': 'warning', completed: 'success', failed: 'danger',
            'rolled-back': 'warning', 'rolling-back': 'warning',
        };
        const statusColor = statusColors[d.status] || 'text-muted';
        const created = d.created_at ? new Date(d.created_at + 'Z').toLocaleString() : '-';
        const finished = d.finished_at ? new Date(d.finished_at + 'Z').toLocaleString() : '';

        let actions = `<button class="btn btn-sm btn-secondary" onclick="showDeploymentDetail(${d.id})">Details</button>`;
        if (d.status === 'planning' || d.status === 'failed') {
            actions += ` <button class="btn btn-sm btn-primary" onclick="executeDeploymentAction(${d.id})">Execute</button>`;
        }
        if (d.status === 'completed' || d.status === 'failed') {
            actions += ` <button class="btn btn-sm" style="color:var(--warning);border:1px solid var(--warning);" onclick="rollbackDeploymentAction(${d.id})">Rollback</button>`;
        }
        if (['planning', 'completed', 'failed', 'rolled-back'].includes(d.status)) {
            actions += ` <button class="btn btn-sm" style="color:var(--danger)" onclick="confirmDeleteDeployment(${d.id})">Delete</button>`;
        }

        const rollbackBadge = d.rollback_status ? ` <span style="font-size:0.75em; color:var(--${d.rollback_status === 'completed' ? 'success' : d.rollback_status === 'failed' ? 'danger' : 'warning'});">(rollback: ${escapeHtml(d.rollback_status)})</span>` : '';

        return `<div class="card" style="margin-bottom:0.75rem; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                <div>
                    <span class="badge" style="background:var(--${statusColor}); color:white; font-size:0.8em; padding:3px 10px; border-radius:4px; text-transform:uppercase; font-weight:600;">${escapeHtml(d.status)}</span>${rollbackBadge}
                    <strong style="margin-left:0.75rem;">${escapeHtml(d.name)}</strong>
                    <span style="margin-left:0.5rem; font-size:0.85em; color:var(--text-muted)">Group: ${escapeHtml(d.group_name || 'N/A')}</span>
                </div>
                <div style="display:flex; gap:0.4rem; align-items:center;">
                    ${actions}
                </div>
            </div>
            <div style="margin-top:0.5rem; font-size:0.85em; color:var(--text-muted);">
                ${d.description ? escapeHtml(d.description) + ' · ' : ''}Type: ${escapeHtml(d.change_type || '?')} · ${created}${d.created_by ? ` by ${escapeHtml(d.created_by)}` : ''}${finished ? ` · Finished: ${finished}` : ''}
            </div>
        </div>`;
    }).join('');
}

function filterDeployments() {
    listViewState.deployments.statusFilter = document.getElementById('deploy-filter-status')?.value || '';
    renderDeployments(listViewState.deployments.items);
}
window.filterDeployments = filterDeployments;

function refreshDeployments() { loadDeployments(); }
window.refreshDeployments = refreshDeployments;

async function showNewDeploymentModal() {
    let groups = [], creds = [], templates = [], riskAnalyses = [];
    try {
        [groups, creds, templates, riskAnalyses] = await Promise.all([
            api.getInventoryGroups(), api.getCredentials(), api.getTemplates(),
            api.getRiskAnalyses({ limit: 50 }),
        ]);
    } catch (e) { /* ignore */ }
    const groupOpts = (groups || []).map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('');
    const credOpts = (creds || []).map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    const tplOpts = '<option value="">— None (manual commands) —</option>' +
        (templates || []).map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
    const raOpts = '<option value="">— None —</option>' +
        (riskAnalyses || []).filter(r => r.approved).map(r => `<option value="${r.id}">#${r.id} ${escapeHtml(r.risk_level)} — ${escapeHtml(r.hostname || r.group_name || '')}</option>`).join('');

    showModal('New Deployment', `
        <div style="display:flex; flex-direction:column; gap:0.75rem;">
            <div><label class="form-label">Name</label>
                <input id="deploy-name" class="form-input" placeholder="e.g. ACL Update Production" /></div>
            <div><label class="form-label">Description</label>
                <input id="deploy-desc" class="form-input" placeholder="Optional description" /></div>
            <div><label class="form-label">Inventory Group</label>
                <select id="deploy-group" class="form-select">${groupOpts}</select></div>
            <div><label class="form-label">Credential</label>
                <select id="deploy-cred" class="form-select">${credOpts}</select></div>
            <div><label class="form-label">Change Type</label>
                <select id="deploy-change-type" class="form-select">
                    <option value="template">Template</option><option value="manual">Manual</option>
                    <option value="policy">Policy</option><option value="route">Route</option>
                    <option value="nat">NAT</option>
                </select></div>
            <div><label class="form-label">Template (optional)</label>
                <select id="deploy-template" class="form-select">${tplOpts}</select></div>
            <div><label class="form-label">Linked Risk Analysis (optional)</label>
                <select id="deploy-risk-analysis" class="form-select">${raOpts}</select></div>
            <div><label class="form-label">Proposed Commands (one per line, or leave empty if using template)</label>
                <textarea id="deploy-commands" class="form-input" rows="5" style="font-family:var(--font-mono); font-size:0.85rem;" placeholder="interface GigabitEthernet0/1\n no shutdown"></textarea></div>
            <button class="btn btn-primary" onclick="submitNewDeployment()">Create Deployment</button>
        </div>
    `);
}
window.showNewDeploymentModal = showNewDeploymentModal;

async function submitNewDeployment() {
    const name = document.getElementById('deploy-name')?.value?.trim();
    if (!name) { showError('Deployment name is required'); return; }
    const data = {
        name,
        description: document.getElementById('deploy-desc')?.value?.trim() || '',
        group_id: parseInt(document.getElementById('deploy-group')?.value),
        credential_id: parseInt(document.getElementById('deploy-cred')?.value),
        change_type: document.getElementById('deploy-change-type')?.value || 'template',
        proposed_commands: (document.getElementById('deploy-commands')?.value || '').split('\n').filter(l => l.trim()),
        template_id: parseInt(document.getElementById('deploy-template')?.value) || null,
        risk_analysis_id: parseInt(document.getElementById('deploy-risk-analysis')?.value) || null,
    };
    try {
        const result = await api.createDeployment(data);
        closeModal();
        showSuccess(`Deployment #${result.id} created`);
        loadDeployments();
    } catch (e) { showError(e.message); }
}
window.submitNewDeployment = submitNewDeployment;

async function executeDeploymentAction(deploymentId) {
    if (!confirm('Execute this deployment? Pre-deployment snapshots will be captured before pushing config changes.')) return;
    try {
        const result = await api.executeDeployment(deploymentId);
        showDeploymentJobStream(result.job_id, deploymentId, 'Executing Deployment');
    } catch (e) { showError(e.message); }
}
window.executeDeploymentAction = executeDeploymentAction;

async function rollbackDeploymentAction(deploymentId) {
    if (!confirm('Roll back this deployment? Pre-deployment config snapshots will be restored to all hosts.')) return;
    try {
        const result = await api.rollbackDeployment(deploymentId);
        showDeploymentJobStream(result.job_id, deploymentId, 'Rolling Back Deployment');
    } catch (e) { showError(e.message); }
}
window.rollbackDeploymentAction = rollbackDeploymentAction;

function showDeploymentJobStream(jobId, deploymentId, title) {
    showModal(title, `
        <div style="display:flex; flex-direction:column; gap:0.75rem;">
            <div style="font-size:0.85em; color:var(--text-muted);">Deployment #${deploymentId} · Job: ${escapeHtml(jobId)}</div>
            <pre id="deploy-job-output" style="background:var(--bg-secondary); padding:1rem; border-radius:8px; max-height:400px; overflow-y:auto; font-family:var(--font-mono); font-size:0.82rem; white-space:pre-wrap; line-height:1.5;"></pre>
            <div id="deploy-job-status" style="text-align:center; color:var(--text-muted);">Connecting...</div>
        </div>
    `);

    const output = document.getElementById('deploy-job-output');
    const statusEl = document.getElementById('deploy-job-status');

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/ws/deployment/${jobId}`);

    ws.onopen = () => { if (statusEl) statusEl.textContent = 'Connected — streaming output...'; };
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'line' && output) {
                output.textContent += msg.data;
                output.scrollTop = output.scrollHeight;
            } else if (msg.type === 'job_complete') {
                if (statusEl) {
                    const color = msg.status === 'completed' ? 'var(--success)' : 'var(--danger)';
                    statusEl.innerHTML = `<span style="color:${color}; font-weight:600;">${msg.status === 'completed' ? 'Completed' : 'Failed'}</span>`;
                }
                ws.close();
                loadDeployments();
            }
        } catch (e) { /* ignore */ }
    };
    ws.onerror = () => { if (statusEl) statusEl.textContent = 'WebSocket error'; };
    ws.onclose = () => { if (statusEl && statusEl.textContent === 'Connected — streaming output...') statusEl.textContent = 'Disconnected'; };
}

async function showDeploymentDetail(deploymentId) {
    let dep;
    try { dep = await api.getDeployment(deploymentId); } catch (e) { showError(e.message); return; }

    const statusColors = {
        planning: 'text-muted', 'pre-check': 'warning', executing: 'warning',
        'post-check': 'warning', completed: 'success', failed: 'danger',
        'rolled-back': 'warning', 'rolling-back': 'warning',
    };
    const statusColor = statusColors[dep.status] || 'text-muted';
    const created = dep.created_at ? new Date(dep.created_at + 'Z').toLocaleString() : '-';
    const started = dep.started_at ? new Date(dep.started_at + 'Z').toLocaleString() : '-';
    const finished = dep.finished_at ? new Date(dep.finished_at + 'Z').toLocaleString() : '-';

    const checkpoints = dep.checkpoints || [];
    const snapshots = dep.snapshots || [];

    // Group checkpoints by phase
    const preChecks = checkpoints.filter(c => c.phase === 'pre');
    const postChecks = checkpoints.filter(c => c.phase === 'post');
    const rollbackChecks = checkpoints.filter(c => c.phase === 'rollback');

    function renderCheckpointTable(checks, label) {
        if (!checks.length) return `<div style="color:var(--text-muted); font-size:0.85em;">No ${label} checkpoints.</div>`;
        return `<table style="width:100%; font-size:0.85em; border-collapse:collapse;">
            <thead><tr style="text-align:left; border-bottom:1px solid var(--border);">
                <th style="padding:4px 8px;">Host</th><th style="padding:4px 8px;">Check</th>
                <th style="padding:4px 8px;">Status</th><th style="padding:4px 8px;">Time</th>
            </tr></thead>
            <tbody>${checks.map(c => {
                const cpColor = c.status === 'passed' ? 'success' : c.status === 'failed' ? 'danger' : 'text-muted';
                const cpTime = c.executed_at ? new Date(c.executed_at + 'Z').toLocaleTimeString() : '-';
                return `<tr style="border-bottom:1px solid var(--border);">
                    <td style="padding:4px 8px;">${escapeHtml(c.hostname || c.ip_address || '-')}</td>
                    <td style="padding:4px 8px;">${escapeHtml(c.check_type)}</td>
                    <td style="padding:4px 8px;"><span style="color:var(--${cpColor}); font-weight:600; text-transform:uppercase;">${escapeHtml(c.status)}</span></td>
                    <td style="padding:4px 8px;">${cpTime}</td>
                </tr>`;
            }).join('')}</tbody>
        </table>`;
    }

    const preSnaps = snapshots.filter(s => s.phase === 'pre');
    const postSnaps = snapshots.filter(s => s.phase === 'post');

    let actions = '';
    if (dep.status === 'planning' || dep.status === 'failed') {
        actions += `<button class="btn btn-primary" onclick="closeModal(); executeDeploymentAction(${dep.id})">Execute</button> `;
    }
    if (dep.status === 'completed' || dep.status === 'failed') {
        actions += `<button class="btn btn-secondary" style="border:1px solid var(--warning); color:var(--warning);" onclick="closeModal(); rollbackDeploymentAction(${dep.id})">Rollback</button> `;
    }

    showModal(`Deployment #${dep.id} — ${escapeHtml(dep.name)}`, `
        <div style="display:flex; flex-direction:column; gap:1rem;">
            <div style="display:flex; gap:1rem; flex-wrap:wrap;">
                <div><strong>Status:</strong> <span style="color:var(--${statusColor}); font-weight:600; text-transform:uppercase;">${escapeHtml(dep.status)}</span></div>
                <div><strong>Group:</strong> ${escapeHtml(dep.group_name || 'N/A')}</div>
                <div><strong>Type:</strong> ${escapeHtml(dep.change_type)}</div>
                ${dep.rollback_status ? `<div><strong>Rollback:</strong> ${escapeHtml(dep.rollback_status)}</div>` : ''}
            </div>
            <div style="display:flex; gap:1rem; flex-wrap:wrap; font-size:0.85em; color:var(--text-muted);">
                <span>Created: ${created}</span>
                <span>Started: ${started}</span>
                <span>Finished: ${finished}</span>
                ${dep.created_by ? `<span>By: ${escapeHtml(dep.created_by)}</span>` : ''}
            </div>
            ${dep.description ? `<div style="font-size:0.9em;">${escapeHtml(dep.description)}</div>` : ''}

            <details>
                <summary style="cursor:pointer; font-weight:600;">Proposed Commands (${(dep.proposed_commands || '').split('\\n').filter(l => l.trim()).length})</summary>
                <pre style="background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.82rem; max-height:200px; overflow-y:auto; margin-top:0.5rem;">${escapeHtml(dep.proposed_commands || '')}</pre>
            </details>

            <div>
                <h4 style="margin:0 0 0.5rem;">Pre-Deployment Checkpoints</h4>
                ${renderCheckpointTable(preChecks, 'pre-deployment')}
            </div>
            <div>
                <h4 style="margin:0 0 0.5rem;">Post-Deployment Checkpoints</h4>
                ${renderCheckpointTable(postChecks, 'post-deployment')}
            </div>
            ${rollbackChecks.length > 0 ? `<div>
                <h4 style="margin:0 0 0.5rem;">Rollback Checkpoints</h4>
                ${renderCheckpointTable(rollbackChecks, 'rollback')}
            </div>` : ''}

            <div style="display:flex; gap:0.75rem; font-size:0.85em; color:var(--text-muted);">
                <span>Pre-snapshots: ${preSnaps.length}</span>
                <span>Post-snapshots: ${postSnaps.length}</span>
            </div>

            ${actions ? `<div style="display:flex; gap:0.5rem; margin-top:0.5rem;">${actions}</div>` : ''}
        </div>
    `);
}
window.showDeploymentDetail = showDeploymentDetail;

async function confirmDeleteDeployment(deploymentId) {
    if (!confirm('Delete this deployment and all its checkpoints/snapshots?')) return;
    try {
        await api.deleteDeployment(deploymentId);
        showSuccess('Deployment deleted');
        loadDeployments();
    } catch (e) { showError(e.message); }
}
window.confirmDeleteDeployment = confirmDeleteDeployment;

// Search handler for deployments
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('deploy-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            listViewState.deployments.query = searchInput.value;
            renderDeployments(listViewState.deployments.items);
        }, 200));
    }
});


// ── Hash-based routing: back/forward button support ─────────────────────────
window.addEventListener('popstate', () => {
    const page = getPageFromHash();
    if (page && page !== currentPage && document.getElementById('app-container')?.style.display !== 'none') {
        navigateToPage(page, { updateHash: false });
    }
});

document.addEventListener('DOMContentLoaded', async () => {
    initThemeControls();
    initPerformanceMode();
    initSidebar();
    initLoginParticles();
    initAppParticles();
    initLoginForm();
    initListPageControls();
    initKeyboardShortcuts();
    // Card tilt disabled — it interfered with clicking on inventory items

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

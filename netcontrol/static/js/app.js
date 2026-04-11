/**
 * Main Application Logic
 */

import * as api from './api.js';
import { getCsrfToken, setCsrfToken } from './api.js';
import { connectJobWebSocket, disconnectJobWebSocket, connectUpgradeWebSocket, disconnectUpgradeWebSocket } from './websocket.js';
import { ensurePageDOM, ensureModalDOM, templateOidProfileModal, templateSlaHostDetailModal, templateSlaTargetModal } from './page-templates.js';

// Global state
let currentPage = 'dashboard';
let dashboardData = null;
export const _hostCache = {};
export const _groupCache = {};
export let _snmpProfilesCache = [];
export let _groupSnmpAssignments = {};
let currentFeatureAccess = [];

const NAV_FEATURE_MAP = {
    dashboard: 'dashboard',
    inventory: 'inventory',
    playbooks: 'playbooks',
    jobs: 'jobs',
    templates: 'templates',
    credentials: 'credentials',
    topology: 'topology',
    configuration: 'config-drift',
    compliance: 'compliance',
    'change-management': 'risk-analysis',
    monitoring: 'monitoring',
    reports: 'reports',
    'graph-templates': 'graph-templates',
    'mac-tracking': 'mac-tracking',
    'traffic-analysis': 'traffic-analysis',
    'upgrades': 'upgrades',
};

const THEME_KEY = 'plexus-theme';
const VALID_THEMES = ['forest', 'dark-modern', 'astral', 'light', 'void', 'coral', 'sandstone'];
const DEFAULT_THEME = 'sandstone';
const PAGE_CACHE_TTL_MS = 30 * 1000;
const CACHEABLE_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'settings', 'topology', 'configuration', 'graph-templates', 'mac-tracking', 'traffic-analysis', 'upgrades'];
const pageCacheMeta = {};

// ── Space Depth Experience Controls ──────────────────────────────────────────
const SPACE_INTENSITY_KEY = 'plexus_space_intensity';
const SPACE_PARALLAX_KEY = 'plexus_space_parallax';
const SPACE_INTENSITY_MAP = Object.freeze({ off: 0, low: 0.45, medium: 0.8, high: 1.0 });
const DEFAULT_SPACE_INTENSITY = 'medium';

const _spaceFxState = {
    intensity: DEFAULT_SPACE_INTENSITY,
    parallax: true,
    baseIntensity: 1,
    targetX: 0,
    targetY: 0,
    currentX: 0,
    currentY: 0,
    rafId: null,
    initialized: false,
};

function normalizeSpaceIntensity(value) {
    return Object.prototype.hasOwnProperty.call(SPACE_INTENSITY_MAP, value)
        ? value
        : DEFAULT_SPACE_INTENSITY;
}

function refreshSpaceBaseIntensity() {
    const raw = getComputedStyle(document.documentElement).getPropertyValue('--space-intensity-base').trim();
    const parsed = Number.parseFloat(raw);
    _spaceFxState.baseIntensity = Number.isFinite(parsed) ? parsed : 1;
}

function getSpaceIntensityScalar() {
    const userScalar = SPACE_INTENSITY_MAP[normalizeSpaceIntensity(_spaceFxState.intensity)] ?? SPACE_INTENSITY_MAP[DEFAULT_SPACE_INTENSITY];
    return userScalar * (_spaceFxState.baseIntensity || 1);
}

function _resetSpaceParallax() {
    _spaceFxState.targetX = 0;
    _spaceFxState.targetY = 0;
    _spaceFxState.currentX = 0;
    _spaceFxState.currentY = 0;
    document.documentElement.style.setProperty('--space-parallax-x', '0px');
    document.documentElement.style.setProperty('--space-parallax-y', '0px');
}

function updateSpaceFxForMotionPreference() {
    const canAnimateParallax = _spaceFxState.parallax && !isReducedMotion() && getSpaceIntensityScalar() > 0;
    document.body.classList.toggle('space-parallax-disabled', !canAnimateParallax);
    if (!canAnimateParallax) _resetSpaceParallax();
}

function applySpaceSettings(intensity, parallaxEnabled) {
    const normalizedIntensity = normalizeSpaceIntensity(intensity);
    const normalizedParallax = Boolean(parallaxEnabled);

    _spaceFxState.intensity = normalizedIntensity;
    _spaceFxState.parallax = normalizedParallax;

    localStorage.setItem(SPACE_INTENSITY_KEY, normalizedIntensity);
    localStorage.setItem(SPACE_PARALLAX_KEY, normalizedParallax ? '1' : '0');

    const userScalar = SPACE_INTENSITY_MAP[normalizedIntensity] ?? SPACE_INTENSITY_MAP[DEFAULT_SPACE_INTENSITY];
    document.documentElement.style.setProperty('--space-intensity-user', String(userScalar));

    const intensitySelect = document.getElementById('space-intensity-settings');
    if (intensitySelect) intensitySelect.value = normalizedIntensity;

    const parallaxToggle = document.getElementById('space-parallax-settings');
    if (parallaxToggle) parallaxToggle.checked = normalizedParallax;

    updateSpaceFxForMotionPreference();
}

function initSpaceParallax() {
    if (_spaceFxState.initialized) return;
    _spaceFxState.initialized = true;

    const MAX_SHIFT = 18;

    window.addEventListener('mousemove', (e) => {
        if (!_spaceFxState.parallax || isReducedMotion()) return;
        const w = window.innerWidth || 1;
        const h = window.innerHeight || 1;
        const nx = (e.clientX / w) * 2 - 1;
        const ny = (e.clientY / h) * 2 - 1;
        _spaceFxState.targetX = nx * MAX_SHIFT;
        _spaceFxState.targetY = ny * MAX_SHIFT;
        ensureParallaxRunning();
    }, { passive: true });

    window.addEventListener('mouseleave', () => {
        _spaceFxState.targetX = 0;
        _spaceFxState.targetY = 0;
        ensureParallaxRunning();
    }, { passive: true });

    const SETTLE_THRESHOLD = 0.05;

    const tick = () => {
        const canAnimateParallax = _spaceFxState.parallax && !isReducedMotion() && getSpaceIntensityScalar() > 0;
        if (canAnimateParallax) {
            _spaceFxState.currentX += (_spaceFxState.targetX - _spaceFxState.currentX) * 0.07;
            _spaceFxState.currentY += (_spaceFxState.targetY - _spaceFxState.currentY) * 0.07;
            document.documentElement.style.setProperty('--space-parallax-x', `${_spaceFxState.currentX.toFixed(3)}px`);
            document.documentElement.style.setProperty('--space-parallax-y', `${_spaceFxState.currentY.toFixed(3)}px`);

            // Stop looping once values have settled to save CPU
            const dx = Math.abs(_spaceFxState.targetX - _spaceFxState.currentX);
            const dy = Math.abs(_spaceFxState.targetY - _spaceFxState.currentY);
            if (dx < SETTLE_THRESHOLD && dy < SETTLE_THRESHOLD) {
                _spaceFxState.currentX = _spaceFxState.targetX;
                _spaceFxState.currentY = _spaceFxState.targetY;
                _spaceFxState.rafId = null;
                return;
            }
        } else {
            _resetSpaceParallax();
            _spaceFxState.rafId = null;
            return;
        }
        _spaceFxState.rafId = requestAnimationFrame(tick);
    };

    // Helper to kick the loop if it's not already running
    function ensureParallaxRunning() {
        if (!_spaceFxState.rafId && !document.hidden) {
            _spaceFxState.rafId = requestAnimationFrame(tick);
        }
    }

    // Pause the RAF loop when the tab is hidden to save CPU
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            if (_spaceFxState.rafId) {
                cancelAnimationFrame(_spaceFxState.rafId);
                _spaceFxState.rafId = null;
            }
        }
        // When visible again, the next mousemove will restart the loop via ensureParallaxRunning
    });
}

export function initSpaceControls() {
    refreshSpaceBaseIntensity();
    const savedIntensity = localStorage.getItem(SPACE_INTENSITY_KEY) || DEFAULT_SPACE_INTENSITY;
    const savedParallax = localStorage.getItem(SPACE_PARALLAX_KEY);
    const parallaxEnabled = savedParallax === null ? true : savedParallax === '1';

    applySpaceSettings(savedIntensity, parallaxEnabled);
    initSpaceParallax();

    const intensitySelect = document.getElementById('space-intensity-settings');
    if (intensitySelect && intensitySelect.dataset.bound !== '1') {
        intensitySelect.dataset.bound = '1';
        intensitySelect.addEventListener('change', (e) => {
            applySpaceSettings(e.target.value, _spaceFxState.parallax);
        });
    }

    const parallaxToggle = document.getElementById('space-parallax-settings');
    if (parallaxToggle && parallaxToggle.dataset.bound !== '1') {
        parallaxToggle.dataset.bound = '1';
        parallaxToggle.addEventListener('change', (e) => {
            applySpaceSettings(_spaceFxState.intensity, e.target.checked);
        });
    }
}

// ── Utility: debounce ──────────────────────────────────────────────────────────
export function debounce(fn, delay) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// ── Utility: generic tab switcher ─────────────────────────────────────────────
// Handles the common DOM work shared by many switch*Tab() functions:
//   btnClass   – CSS class on tab buttons (e.g. 'sla-tab-btn')
//   dataAttr   – data-* attribute name on buttons (e.g. 'data-sla-tab')
//   panelClass – CSS class on tab panels (e.g. 'sla-tab')
//   panelId    – ID of the panel to show (e.g. 'sla-tab-trends')
function _switchTabDOM(btnClass, dataAttr, panelClass, panelId, tab) {
    document.querySelectorAll('.' + btnClass).forEach(b =>
        b.classList.toggle('active', b.getAttribute(dataAttr) === tab)
    );
    document.querySelectorAll('.' + panelClass).forEach(t => t.style.display = 'none');
    const target = document.getElementById(panelId);
    if (target) target.style.display = '';
}

// ── Utility: batched streaming renderer ───────────────────────────────────────
// Buffers decoded chunks and flushes to the DOM once per animation frame,
// preventing a layout reflow on every streamed byte.
export function createStreamHandler(el) {
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
export const listViewState = {
    inventory: { items: [], query: '', sort: 'name_asc' },
    playbooks: { items: [], query: '', sort: 'name_asc' },
    jobs: { items: [], query: '', sort: 'started_desc', status: 'all', dryRun: 'all', dateRange: 'all' },
    templates: { items: [], query: '', sort: 'name_asc' },
    credentials: { items: [], query: '', sort: 'name_asc' },
    configDrift: { items: [], query: '', sort: 'detected_desc', status: 'open' },
    configBackups: { policies: [], backups: [], query: '', tab: 'policies' },
    configuration: { tab: 'drift' },
    compliance: { profiles: [], assignments: [], results: [], statusList: [], query: '', tab: 'profiles' },
    riskAnalysis: { items: [], query: '', levelFilter: '' },
    deployments: { items: [], query: '', statusFilter: '' },
    changeManagement: { tab: 'risk' },
    monitoring: { polls: [], alerts: [], query: '', tab: 'devices' },
    sla: { summary: null, hosts: [], query: '', tab: 'hosts' },
    deviceDetail: { hostId: null, tab: 'overview' },
    customDashboards: { items: [], currentId: null, editMode: false },
    graphTemplates: { items: [], hostTemplates: [], graphTrees: [], query: '', tab: 'graph-templates', category: '' },
};

function normalizeTheme(theme) {
    return VALID_THEMES.includes(theme) ? theme : DEFAULT_THEME;
}

function applyTheme(theme) {
    const chosen = normalizeTheme(theme);
    document.documentElement.setAttribute('data-theme', chosen);
    localStorage.setItem(THEME_KEY, chosen);
    refreshSpaceBaseIntensity();
    updateSpaceFxForMotionPreference();
    ['theme-select', 'theme-select-settings'].forEach((id) => {
        const select = document.getElementById(id);
        if (select) select.value = chosen;
    });
    // Defer chart/topology retheme to next frame so CSS theme applies first
    requestAnimationFrame(() => {
        PlexusChart.rethemeAll();
        // Refresh topology vis-network colors for the new theme (lazy — only if module already loaded)
        if (_moduleCache['topology']) {
            const topo = _moduleCache['topology'];
            if (topo._topologyNetwork && topo._topologyData && topo._topoNodesDS && topo._topoEdgesDS) {
                topo._getTopoThemeColors();
                topo._topoNodesDS.update(topo._topologyData.nodes.map(n => topo._buildVisNode(n, topo._topoSavedPositions)));
                topo._topoEdgesDS.update(topo._topologyData.edges.map(e => topo._buildVisEdge(e)));
            }
        }
    });
}

export function initThemeControls() {
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
    updateSpaceFxForMotionPreference();
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

// ═══════════════════════════════════════════════════════════════════════════════
// Global Time Range Selector
// ═══════════════════════════════════════════════════════════════════════════════

const METRIC_PAGES = ['monitoring', 'device-detail', 'dashboard'];

const globalTimeRange = {
    range: '6h',
    customStart: null,
    customEnd: null,
    listeners: [],
};

function setGlobalTimeRange(range, customStart = null, customEnd = null) {
    globalTimeRange.range = range;
    globalTimeRange.customStart = customStart;
    globalTimeRange.customEnd = customEnd;
    // Update button active states
    document.querySelectorAll('.time-range-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.range === range);
    });
    const customEl = document.getElementById('time-range-custom');
    if (customEl) customEl.style.display = range === 'custom' ? 'flex' : 'none';
    // Notify listeners
    globalTimeRange.listeners.forEach(cb => {
        try { cb(getTimeRangeParams()); } catch (e) { console.error('Time range listener error:', e); }
    });
}

export function onTimeRangeChange(callback) {
    globalTimeRange.listeners.push(callback);
}

export function offTimeRangeChange(callback) {
    globalTimeRange.listeners = globalTimeRange.listeners.filter(cb => cb !== callback);
}

export function getTimeRangeParams() {
    if (globalTimeRange.range === 'custom' && globalTimeRange.customStart && globalTimeRange.customEnd) {
        return { range: 'custom', start: globalTimeRange.customStart, end: globalTimeRange.customEnd };
    }
    return { range: globalTimeRange.range };
}

function updateTimeRangeBarVisibility(page) {
    const bar = document.getElementById('time-range-bar');
    if (bar) bar.style.display = METRIC_PAGES.includes(page) ? 'flex' : 'none';
}

function initTimeRangeBar() {
    document.querySelectorAll('.time-range-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const range = btn.dataset.range;
            if (range === 'custom') {
                setGlobalTimeRange('custom', globalTimeRange.customStart, globalTimeRange.customEnd);
            } else {
                setGlobalTimeRange(range);
            }
        });
    });
}

function applyCustomTimeRange() {
    const start = document.getElementById('time-range-start')?.value;
    const end = document.getElementById('time-range-end')?.value;
    if (start && end) {
        setGlobalTimeRange('custom', start, end);
    } else {
        showError('Please select both start and end times');
    }
}
window.applyCustomTimeRange = applyCustomTimeRange;

function refreshCurrentMetricView() {
    if (currentPage === 'device-detail') loadDeviceDetail({ force: true });
    else if (currentPage === 'dashboard' && listViewState.customDashboards.currentId) refreshDashboardPanels();
    else loadPageData(currentPage, { force: true });
}
window.refreshCurrentMetricView = refreshCurrentMetricView;

// ═══════════════════════════════════════════════════════════════════════════════
// PlexusChart — ECharts Abstraction Layer
// ═══════════════════════════════════════════════════════════════════════════════

export const PlexusChart = {
    instances: new Map(),
    options: new Map(),

    getThemeColors() {
        const cs = getComputedStyle(document.documentElement);
        const get = (v) => cs.getPropertyValue(v).trim();
        return {
            bg: get('--card-bg') || get('--bg-secondary') || '#1a1a2e',
            text: get('--text') || '#e0e0e0',
            textMuted: get('--text-muted') || '#888',
            primary: get('--primary') || '#4ade80',
            primaryLight: get('--primary-light') || '#86efac',
            border: get('--border') || '#333',
            success: get('--success') || '#22c55e',
            warning: get('--warning') || '#f59e0b',
            danger: get('--danger') || '#ef4444',
            gridLine: get('--border') || '#333',
        };
    },

    getBaseOption(colors) {
        return {
            backgroundColor: 'transparent',
            textStyle: { color: colors.text, fontFamily: 'Inter, system-ui, sans-serif' },
            grid: { left: 50, right: 20, top: 30, bottom: 35, containLabel: false },
            tooltip: {
                trigger: 'axis',
                backgroundColor: colors.bg,
                borderColor: colors.border,
                textStyle: { color: colors.text, fontSize: 12 },
            },
        };
    },

    create(containerId) {
        this.destroy(containerId);
        const container = document.getElementById(containerId);
        if (!container) return null;
        if (!container.offsetHeight) container.style.height = '280px';
        const chart = echarts.init(container, null, { renderer: 'canvas' });
        this.instances.set(containerId, chart);
        // Resize observer
        const ro = new ResizeObserver(() => chart.resize());
        ro.observe(container);
        chart._plexusRO = ro;
        return chart;
    },

    destroy(containerId) {
        const chart = this.instances.get(containerId);
        if (chart) {
            try {
                if (chart._plexusRO) { chart._plexusRO.disconnect(); chart._plexusRO = null; }
                if (!chart.isDisposed()) chart.dispose();
            } catch (e) { console.warn(`Chart destroy failed for ${containerId}:`, e); }
            this.instances.delete(containerId);
            this.options.delete(containerId);
        }
    },

    destroyAll() {
        this.instances.forEach((chart, id) => {
            try {
                if (chart._plexusRO) { chart._plexusRO.disconnect(); chart._plexusRO = null; }
                if (!chart.isDisposed()) chart.dispose();
            } catch (e) { console.warn(`Chart destroy failed for ${id}:`, e); }
        });
        this.instances.clear();
        this.options.clear();
    },

    rethemeAll() {
        const colors = this.getThemeColors();
        this.options.forEach((opt, id) => {
            const chart = this.instances.get(id);
            if (chart && !chart.isDisposed()) {
                const base = this.getBaseOption(colors);
                chart.setOption({ ...base, textStyle: base.textStyle, tooltip: base.tooltip });
            }
        });
    },

    timeSeries(containerId, seriesData, options = {}) {
        const chart = this.create(containerId);
        if (!chart) return null;
        const colors = this.getThemeColors();
        const base = this.getBaseOption(colors);
        const palette = [colors.primary, colors.warning, colors.danger, colors.primaryLight, '#8b5cf6', '#06b6d4', '#f97316', '#ec4899'];

        const series = seriesData.map((s, i) => ({
            name: s.name || `Series ${i + 1}`,
            type: 'line',
            smooth: true,
            symbol: 'none',
            lineStyle: { width: 2 },
            areaStyle: options.area ? { opacity: 0.08 } : undefined,
            data: s.data.map(d => [new Date(d.time).getTime(), d.value]),
            color: s.color || palette[i % palette.length],
            markLine: undefined,
        }));

        const opt = {
            ...base,
            xAxis: {
                type: 'time',
                axisLine: { lineStyle: { color: colors.border } },
                axisLabel: { color: colors.textMuted, fontSize: 11 },
                splitLine: { show: false },
            },
            yAxis: {
                type: 'value',
                name: options.yAxisName || '',
                nameTextStyle: { color: colors.textMuted, fontSize: 11 },
                min: options.yMin ?? undefined,
                max: options.yMax ?? undefined,
                axisLine: { show: false },
                axisLabel: { color: colors.textMuted, fontSize: 11 },
                splitLine: { lineStyle: { color: colors.gridLine, opacity: 0.3 } },
            },
            legend: series.length > 1 ? {
                data: series.map(s => s.name),
                textStyle: { color: colors.textMuted, fontSize: 11 },
                top: 0,
            } : undefined,
            series,
            dataZoom: options.zoom ? [{ type: 'inside' }] : undefined,
        };

        chart.setOption(opt);
        this.options.set(containerId, opt);
        return chart;
    },

    gauge(containerId, value, options = {}) {
        const chart = this.create(containerId);
        if (!chart) return null;
        const colors = this.getThemeColors();
        const max = options.max || 100;
        const opt = {
            backgroundColor: 'transparent',
            series: [{
                type: 'gauge',
                min: 0, max,
                progress: { show: true, width: 14 },
                axisLine: { lineStyle: { width: 14, color: [[0.6, colors.success], [0.8, colors.warning], [1, colors.danger]] } },
                axisTick: { show: false },
                splitLine: { show: false },
                axisLabel: { show: false },
                pointer: { show: false },
                anchor: { show: false },
                title: { show: true, offsetCenter: [0, '70%'], fontSize: 12, color: colors.textMuted },
                detail: {
                    valueAnimation: true, fontSize: 24, fontWeight: 700, color: colors.text,
                    offsetCenter: [0, '0%'], formatter: options.formatter || '{value}%',
                },
                data: [{ value: Math.round(value * 10) / 10, name: options.title || '' }],
            }],
        };
        chart.setOption(opt);
        this.options.set(containerId, opt);
        return chart;
    },

    bar(containerId, categories, values, options = {}) {
        const chart = this.create(containerId);
        if (!chart) return null;
        const colors = this.getThemeColors();
        const base = this.getBaseOption(colors);
        const opt = {
            ...base,
            xAxis: {
                type: options.horizontal ? 'value' : 'category',
                data: options.horizontal ? undefined : categories,
                axisLine: { lineStyle: { color: colors.border } },
                axisLabel: { color: colors.textMuted, fontSize: 11, rotate: options.rotateLabels || 0 },
            },
            yAxis: {
                type: options.horizontal ? 'category' : 'value',
                data: options.horizontal ? categories : undefined,
                axisLine: { show: false },
                axisLabel: { color: colors.textMuted, fontSize: 11 },
                splitLine: { lineStyle: { color: colors.gridLine, opacity: 0.3 } },
            },
            series: [{
                type: 'bar',
                data: values,
                itemStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: colors.primary },
                        { offset: 1, color: colors.primaryLight },
                    ]),
                    borderRadius: [4, 4, 0, 0],
                },
                barMaxWidth: 40,
            }],
        };
        chart.setOption(opt);
        this.options.set(containerId, opt);
        return chart;
    },

    heatmap(containerId, xLabels, yLabels, data, options = {}) {
        const chart = this.create(containerId);
        if (!chart) return null;
        const colors = this.getThemeColors();
        const base = this.getBaseOption(colors);
        const opt = {
            ...base,
            grid: { ...base.grid, bottom: 60 },
            xAxis: {
                type: 'category', data: xLabels,
                axisLabel: { color: colors.textMuted, fontSize: 10, rotate: 45 },
                splitArea: { show: true },
            },
            yAxis: {
                type: 'category', data: yLabels,
                axisLabel: { color: colors.textMuted, fontSize: 11 },
                splitArea: { show: true },
            },
            visualMap: {
                min: options.min || 0, max: options.max || 100,
                calculable: true, orient: 'horizontal', left: 'center', bottom: 0,
                inRange: { color: [colors.success, colors.warning, colors.danger] },
                textStyle: { color: colors.textMuted },
            },
            series: [{
                type: 'heatmap', data,
                label: { show: data.length < 200, color: colors.text, fontSize: 10 },
                emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,0,0,0.5)' } },
            }],
        };
        chart.setOption(opt);
        this.options.set(containerId, opt);
        return chart;
    },

    table(containerId, columns, rows) {
        // Render as HTML table since ECharts tables aren't great
        const container = document.getElementById(containerId);
        if (!container) return;
        const escH = (s) => escapeHtml(String(s ?? ''));
        container.style.height = 'auto';
        container.innerHTML = `
            <table class="chart-table">
                <thead><tr>${columns.map(c => `<th>${escH(c.label || c.key)}</th>`).join('')}</tr></thead>
                <tbody>${rows.map(row => `<tr>${columns.map(c => `<td>${escH(row[c.key])}</td>`).join('')}</tr>`).join('')}</tbody>
            </table>`;
    },

    addAnnotations(containerId, events) {
        const chart = this.instances.get(containerId);
        if (!chart || !events?.length) return;
        const categoryColors = { deployment: '#3b82f6', config: '#f59e0b', alert: '#ef4444', default: '#8b5cf6' };
        const markLines = events.map(e => ({
            xAxis: new Date(e.timestamp).getTime(),
            label: {
                formatter: e.title || e.action || '',
                position: 'start', fontSize: 9, color: categoryColors[e.category] || categoryColors.default,
            },
            lineStyle: { color: categoryColors[e.category] || categoryColors.default, type: 'dashed', width: 1 },
        }));
        const opt = chart.getOption();
        if (opt.series?.length) {
            opt.series[0].markLine = {
                silent: true, symbol: 'none',
                data: markLines,
            };
            chart.setOption(opt);
        }
    },
};

// ═══════════════════════════════════════════════════════════════════════════════
// Device Detail Page
// ═══════════════════════════════════════════════════════════════════════════════

let _deviceDetailTimeListener = null;

export function navigateToDeviceDetail(hostId) {
    listViewState.deviceDetail.hostId = hostId;
    listViewState.deviceDetail.tab = 'overview';
    navigateToPage('device-detail');
}
window.navigateToDeviceDetail = navigateToDeviceDetail;

function switchDeviceTab(tab) {
    listViewState.deviceDetail.tab = tab;
    _switchTabDOM('dev-tab-btn', 'data-dev-tab', 'device-tab', `device-tab-${tab}`, tab);
}
window.switchDeviceTab = switchDeviceTab;

async function loadDeviceDetail({ preserveContent, force } = {}) {
    const hostId = listViewState.deviceDetail.hostId;
    if (!hostId) { navigateToPage('monitoring'); return; }

    // Register time-range listener
    if (_deviceDetailTimeListener) offTimeRangeChange(_deviceDetailTimeListener);
    _deviceDetailTimeListener = () => loadDeviceDetail({ force: true });
    onTimeRangeChange(_deviceDetailTimeListener);

    const trp = getTimeRangeParams();
    const range = trp.range === 'custom' ? '24h' : trp.range;

    try {
        // Fetch data in parallel
        const [cpuData, memData, rtData, plData, ifData, alertsRes, pollHistory] = await Promise.allSettled([
            api.queryMetrics('cpu_percent', String(hostId), range),
            api.queryMetrics('memory_percent', String(hostId), range),
            api.queryMetrics('response_time_ms', String(hostId), range),
            api.queryMetrics('packet_loss_pct', String(hostId), range),
            api.getInterfaceTimeSeries(hostId, range),
            api.getMonitoringAlerts({ hostId, limit: 50 }),
            api.getMonitoringPollHistory(hostId, 1),
        ]);

        // Info bar
        const latestPoll = pollHistory.status === 'fulfilled' ? (pollHistory.value?.polls || pollHistory.value || [])[0] : null;
        renderDeviceInfoBar(hostId, latestPoll);

        // Title
        const title = document.getElementById('device-detail-title');
        if (title) title.textContent = latestPoll?.hostname || `Device #${hostId}`;

        // Batch all metric chart creation into a single animation frame
        // to avoid layout thrashing (each PlexusChart.timeSeries reads element dimensions)
        const cpuSeries = extractMetricSeries(cpuData, 'CPU %');
        const memSeries = extractMetricSeries(memData, 'Memory %');
        const rtSeries = extractMetricSeries(rtData, 'Response Time');
        const plSeries = extractMetricSeries(plData, 'Packet Loss');
        requestAnimationFrame(() => {
            PlexusChart.timeSeries('device-chart-cpu', cpuSeries, { area: true, yAxisName: '%', yMin: 0, yMax: 100 });
            PlexusChart.timeSeries('device-chart-memory', memSeries, { area: true, yAxisName: '%', yMin: 0, yMax: 100 });
            PlexusChart.timeSeries('device-chart-response', rtSeries, { area: true, yAxisName: 'ms' });
            PlexusChart.timeSeries('device-chart-pktloss', plSeries, { area: true, yAxisName: '%', yMin: 0 });
        });

        // Interface summary bar chart + detail table
        if (ifData.status === 'fulfilled') {
            renderInterfaceSummaryChart(ifData.value);
            renderInterfaceDetailCharts(ifData.value, latestPoll);
        } else {
            // Even without time-series, render interface table from poll data
            renderInterfaceDetailCharts(null, latestPoll);
        }

        // Alert history
        if (alertsRes.status === 'fulfilled') {
            renderDeviceAlertHistory(alertsRes.value?.alerts || alertsRes.value || []);
        }

        // Compliance tab
        renderDeviceComplianceTab(hostId);

        // Syslog tab
        renderDeviceSyslogTab(hostId);

        // Overlay deployment/config/alert annotations on metric charts
        try {
            const endISO = new Date().toISOString();
            const startISO = new Date(Date.now() - _rangeToMs(range)).toISOString();
            const annRes = await api.getAnnotations({ hostId, start: startISO, end: endISO, categories: 'deployment,config,alert' });
            const events = annRes?.annotations || [];
            if (events.length) {
                for (const chartId of ['device-chart-cpu', 'device-chart-memory', 'device-chart-response', 'device-chart-pktloss']) {
                    PlexusChart.addAnnotations(chartId, events);
                }
            }
        } catch { /* annotations are non-critical */ }
    } catch (e) {
        console.error('Device detail load error:', e);
        showError(`Failed to load device detail: ${e.message}`);
    }
}

function refreshDeviceDetail() {
    loadDeviceDetail({ force: true });
}
window.refreshDeviceDetail = refreshDeviceDetail;

function _rangeToMs(range) {
    const units = { h: 3600000, d: 86400000 };
    const m = /^(\d+)([hd])$/.exec(range);
    return m ? parseInt(m[1]) * units[m[2]] : 86400000;
}

function extractMetricSeries(result, name) {
    if (result.status !== 'fulfilled') return [{ name, data: [] }];
    const raw = result.value?.data || [];
    return [{
        name,
        data: raw.map(d => ({
            time: d.sampled_at || d.period_start || d.timestamp,
            value: d.val_avg ?? d.value ?? 0,
        })),
    }];
}

function renderDeviceInfoBar(hostId, poll) {
    const el = document.getElementById('device-detail-info');
    if (!el) return;
    if (!poll) { el.innerHTML = '<span class="text-muted">No poll data available</span>'; return; }
    const uptimeStr = poll.uptime_seconds ? formatUptime(poll.uptime_seconds) : 'N/A';
    const polledAt = poll.polled_at ? new Date(poll.polled_at).toLocaleString() : 'N/A';
    const ifTotal = (poll.if_up_count || 0) + (poll.if_down_count || 0) + (poll.if_admin_down || 0);
    const ifSummary = ifTotal > 0
        ? `<span class="badge badge-success">${poll.if_up_count || 0}</span>/<span class="badge badge-danger">${poll.if_down_count || 0}</span>/<span class="badge badge-secondary">${poll.if_admin_down || 0}</span>`
        : 'N/A';
    el.innerHTML = `
        <div class="device-info-item"><span class="device-info-label">Hostname</span><span>${escapeHtml(poll.hostname || 'Unknown')}</span></div>
        <div class="device-info-item"><span class="device-info-label">IP</span><span>${escapeHtml(poll.ip_address || 'N/A')}</span></div>
        <div class="device-info-item"><span class="device-info-label">Type</span><span>${escapeHtml(poll.device_type || 'N/A')}</span></div>
        <div class="device-info-item"><span class="device-info-label">CPU</span><span>${poll.cpu_percent != null ? poll.cpu_percent.toFixed(1) + '%' : 'N/A'}</span></div>
        <div class="device-info-item"><span class="device-info-label">Memory</span><span>${poll.memory_percent != null ? poll.memory_percent.toFixed(1) + '%' : 'N/A'}</span></div>
        <div class="device-info-item"><span class="device-info-label">Interfaces</span><span>${ifSummary}</span></div>
        <div class="device-info-item"><span class="device-info-label">Uptime</span><span>${uptimeStr}</span></div>
        <div class="device-info-item"><span class="device-info-label">Last Poll</span><span>${polledAt}</span></div>`;
}

function renderInterfaceSummaryChart(ifData) {
    const interfaces = ifData?.data || ifData?.interfaces || ifData || [];
    if (!interfaces.length) return;
    // Group by interface name, take latest utilization
    const ifMap = new Map();
    interfaces.forEach(d => {
        const key = d.if_name || `idx-${d.if_index}`;
        if (!ifMap.has(key) || new Date(d.sampled_at) > new Date(ifMap.get(key).sampled_at)) {
            ifMap.set(key, d);
        }
    });
    const sorted = [...ifMap.values()].sort((a, b) => (b.utilization_pct || 0) - (a.utilization_pct || 0)).slice(0, 20);
    PlexusChart.bar('device-chart-if-summary', sorted.map(d => d.if_name || `idx-${d.if_index}`), sorted.map(d => Math.round((d.utilization_pct || 0) * 10) / 10), { rotateLabels: 45 });
}

function renderInterfaceDetailCharts(ifData, latestPoll) {
    const container = document.getElementById('device-interface-charts');
    if (!container) return;

    // ── Interface Status Table from latest poll ──
    let pollInterfaces = [];
    if (latestPoll) {
        try {
            const raw = typeof latestPoll.if_details === 'string'
                ? JSON.parse(latestPoll.if_details || '[]')
                : (latestPoll.if_details || []);
            pollInterfaces = raw;
        } catch { pollInterfaces = []; }
    }

    // ── Time-series data for traffic charts ──
    const tsInterfaces = ifData?.data || ifData?.interfaces || ifData || [];

    // Build a merged map: keyed by if_index, combining poll status + latest TS rates
    const ifMap = new Map();
    pollInterfaces.forEach(iface => {
        const idx = String(iface.if_index);
        ifMap.set(idx, {
            if_index: iface.if_index,
            name: iface.name || `ifIndex-${iface.if_index}`,
            status: iface.status || 'unknown',
            speed_mbps: iface.speed_mbps || 0,
            in_octets: iface.in_octets || 0,
            out_octets: iface.out_octets || 0,
            in_rate_bps: null,
            out_rate_bps: null,
            utilization_pct: null,
        });
    });

    // Overlay latest TS rate data
    const latestByIf = {};
    tsInterfaces.forEach(d => {
        const idx = String(d.if_index);
        if (!latestByIf[idx] || new Date(d.sampled_at) > new Date(latestByIf[idx].sampled_at)) {
            latestByIf[idx] = d;
        }
    });
    Object.entries(latestByIf).forEach(([idx, d]) => {
        const existing = ifMap.get(idx) || { if_index: parseInt(idx), name: d.if_name || `ifIndex-${idx}`, status: 'unknown', speed_mbps: d.if_speed_mbps || 0 };
        existing.in_rate_bps = d.in_rate_bps;
        existing.out_rate_bps = d.out_rate_bps;
        existing.utilization_pct = d.utilization_pct;
        if (d.if_name) existing.name = d.if_name;
        ifMap.set(idx, existing);
    });

    const allIfaces = [...ifMap.values()].sort((a, b) => a.if_index - b.if_index);

    if (!allIfaces.length && !tsInterfaces.length) {
        container.innerHTML = '<p class="text-muted">No interface data available. Ensure SNMP is configured and at least one poll has completed.</p>';
        return;
    }

    // ── Classify interfaces: Physical/Logical vs VLANs vs Loopback/Management ──
    const isVlan = (n) => /^(Vl|Vlan|vlan|BDI|irb\.|vlan\.)\s*[\d]/i.test(n) || /vlan/i.test(n);
    const isLoopback = (n) => /^(Lo|Loopback|lo[\d])/i.test(n);
    const isMgmt = (n) => /^(Mgmt|Management|mgmt|ma[\d]|FastEthernet0$|GigabitEthernet0$)/i.test(n) || /^(Null|Embedded-Service|NV|Async|Voice|Cellular)/i.test(n);
    const isPortChannel = (n) => /^(Po|Port-channel|port-channel|ae[\d]|Bundle-Ether)/i.test(n);
    const isTunnel = (n) => /^(Tu|Tunnel|tunnel[\d])/i.test(n);

    const physicals = [];
    const vlans = [];
    const portChannels = [];
    const tunnels = [];
    const other = []; // loopbacks, mgmt, virtual, etc.

    allIfaces.forEach(i => {
        const n = i.name;
        if (isVlan(n)) vlans.push(i);
        else if (isPortChannel(n)) portChannels.push(i);
        else if (isTunnel(n)) tunnels.push(i);
        else if (isLoopback(n) || isMgmt(n)) other.push(i);
        else physicals.push(i);
    });

    // Format helpers
    const fmtRate = (bps) => {
        if (bps == null) return '<span class="text-muted">-</span>';
        if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
        if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
        if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
        return Math.round(bps) + ' bps';
    };
    const statusBadge = (s) => {
        if (s === 'up') return '<span class="badge badge-success">Up</span>';
        if (s === 'admin_down') return '<span class="badge badge-secondary">Admin Down</span>';
        return '<span class="badge badge-danger">Down</span>';
    };
    const utilBar = (pct) => {
        if (pct == null) return '<span class="text-muted">-</span>';
        const color = pct > 80 ? 'var(--danger)' : pct > 50 ? 'var(--warning)' : 'var(--success)';
        return `<div style="display:flex;align-items:center;gap:0.5rem;"><div style="flex:1;max-width:80px;height:6px;background:var(--border-color);border-radius:3px;overflow:hidden;"><div style="width:${Math.min(pct, 100)}%;height:100%;background:${color};border-radius:3px;"></div></div><span>${pct.toFixed(1)}%</span></div>`;
    };
    const fmtSpeed = (mbps) => {
        if (!mbps) return '<span class="text-muted">-</span>';
        return mbps >= 1000 ? (mbps / 1000) + ' Gbps' : mbps + ' Mbps';
    };

    // Count stats across all
    const upCount = allIfaces.filter(i => i.status === 'up').length;
    const downCount = allIfaces.filter(i => i.status === 'down').length;
    const adminDownCount = allIfaces.filter(i => i.status === 'admin_down').length;

    // ── Build a full-detail table for a set of interfaces ──
    const buildFullTable = (ifaces) => {
        if (!ifaces.length) return '<p class="text-muted" style="padding:0.5rem;">None</p>';
        return `<div style="overflow-x:auto;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>Name</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th><th>Util</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td>${fmtSpeed(i.speed_mbps)}</td>
                <td>${fmtRate(i.in_rate_bps)}</td>
                <td>${fmtRate(i.out_rate_bps)}</td>
                <td>${utilBar(i.utilization_pct)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // ── Build a compact table for VLANs (status + name, no traffic columns) ──
    const buildVlanTable = (ifaces) => {
        if (!ifaces.length) return '<p class="text-muted" style="padding:0.5rem;">No VLANs detected</p>';
        const vlanUp = ifaces.filter(i => i.status === 'up').length;
        const vlanDown = ifaces.filter(i => i.status !== 'up').length;
        return `<div style="margin-bottom:0.5rem; font-size:0.8rem; display:flex; gap:0.5rem;">
                <span class="badge badge-success">${vlanUp} up</span>
                ${vlanDown > 0 ? `<span class="badge badge-danger">${vlanDown} down</span>` : ''}
            </div>
            <div style="overflow-y:auto; max-height:400px;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>VLAN</th><th>Status</th><th>In</th><th>Out</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td style="font-size:0.78rem;">${fmtRate(i.in_rate_bps)}</td>
                <td style="font-size:0.78rem;">${fmtRate(i.out_rate_bps)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // ── Build a compact table for Port-Channels / Tunnels / Other ──
    const buildCompactTable = (ifaces) => {
        if (!ifaces.length) return '';
        return `<div style="overflow-x:auto;"><table class="chart-table" style="width:100%; font-size:0.82rem;">
            <thead><tr><th>Name</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th></tr></thead>
            <tbody>${ifaces.map(i => `<tr>
                <td><strong>${escapeHtml(i.name)}</strong></td>
                <td>${statusBadge(i.status)}</td>
                <td>${fmtSpeed(i.speed_mbps)}</td>
                <td>${fmtRate(i.in_rate_bps)}</td>
                <td>${fmtRate(i.out_rate_bps)}</td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    };

    // ── Summary bar ──
    let html = `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap; gap:0.5rem;">
        <h4 style="margin:0;">${allIfaces.length} Interfaces</h4>
        <div style="display:flex; gap:0.5rem; font-size:0.85rem; flex-wrap:wrap;">
            <span class="badge badge-success">${upCount} Up</span>
            ${downCount > 0 ? `<span class="badge badge-danger">${downCount} Down</span>` : ''}
            ${adminDownCount > 0 ? `<span class="badge badge-secondary">${adminDownCount} Admin Down</span>` : ''}
            <span style="color:var(--text-secondary);">|</span>
            <span style="color:var(--text-secondary);">${physicals.length} Physical</span>
            ${portChannels.length ? `<span style="color:var(--text-secondary);">${portChannels.length} Port-Channel</span>` : ''}
            <span style="color:var(--text-secondary);">${vlans.length} VLAN</span>
            ${tunnels.length ? `<span style="color:var(--text-secondary);">${tunnels.length} Tunnel</span>` : ''}
            ${other.length ? `<span style="color:var(--text-secondary);">${other.length} Other</span>` : ''}
        </div>
    </div>`;

    // ── Two-column layout: Physical interfaces (left) + VLANs (right) ──
    html += `<div class="if-split-grid">`;

    // Left column: Physical interfaces
    html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
        <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">Physical Interfaces (${physicals.length})</h4>
        ${buildFullTable(physicals)}
    </div></div>`;

    // Right column: VLANs
    html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
        <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">VLANs (${vlans.length})</h4>
        ${buildVlanTable(vlans)}
    </div></div>`;

    html += `</div>`; // close grid

    // ── Port-Channels, Tunnels, Other in a row below ──
    const extraSections = [];
    if (portChannels.length) extraSections.push({ title: `Port-Channels (${portChannels.length})`, items: portChannels });
    if (tunnels.length) extraSections.push({ title: `Tunnels (${tunnels.length})`, items: tunnels });
    if (other.length) extraSections.push({ title: `Loopback / Management / Other (${other.length})`, items: other });

    if (extraSections.length) {
        const cols = Math.min(extraSections.length, 3);
        html += `<div class="if-extra-grid" style="grid-template-columns:repeat(${cols}, 1fr);">`;
        extraSections.forEach(sec => {
            html += `<div class="card"><div class="card-body" style="padding:0.75rem;">
                <h4 style="margin:0 0 0.5rem; font-size:0.95rem;">${escapeHtml(sec.title)}</h4>
                ${buildCompactTable(sec.items)}
            </div></div>`;
        });
        html += `</div>`;
    }

    // ── Per-interface traffic charts (from time-series data) ──
    if (tsInterfaces.length) {
        const grouped = {};
        tsInterfaces.forEach(d => {
            const key = d.if_name || `idx-${d.if_index}`;
            if (!grouped[key]) grouped[key] = [];
            grouped[key].push(d);
        });
        // Sort by most traffic, show up to 12, skip VLANs/loopbacks (focus on physical + port-channels)
        const ifNames = Object.keys(grouped).sort((a, b) => {
            const aMax = Math.max(...grouped[a].map(d => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
            const bMax = Math.max(...grouped[b].map(d => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
            return bMax - aMax;
        }).slice(0, 12);

        if (ifNames.length) {
            html += '<h4 style="margin:1.25rem 0 0.5rem;">Traffic Charts (Top 12 by Activity)</h4>';
            html += '<div class="if-chart-grid">';
            html += ifNames.map(name => `
                <div class="card" style="margin-bottom:0;">
                    <div class="card-title" style="font-size:0.85rem; padding:0.5rem 0.75rem;">${escapeHtml(name)}</div>
                    <div id="if-chart-${name.replace(/[^a-zA-Z0-9]/g, '_')}" class="chart-container" style="height:180px;"></div>
                </div>`).join('');
            html += '</div>';
        }

        container.innerHTML = html;

        // Defer chart creation to next frame — let the browser complete layout
        // from the innerHTML assignment before ECharts queries element dimensions
        requestAnimationFrame(() => {
        ifNames.forEach(name => {
            const data = grouped[name].sort((a, b) => new Date(a.sampled_at) - new Date(b.sampled_at));
            const chartId = `if-chart-${name.replace(/[^a-zA-Z0-9]/g, '_')}`;
            PlexusChart.timeSeries(chartId, [
                { name: 'In (bps)', data: data.map(d => ({ time: d.sampled_at, value: d.in_rate_bps || 0 })), color: '#3b82f6' },
                { name: 'Out (bps)', data: data.map(d => ({ time: d.sampled_at, value: d.out_rate_bps || 0 })), color: '#f59e0b' },
            ], { area: true, yAxisName: 'bps' });
        });
        }); // end requestAnimationFrame
    } else {
        html += '<p class="text-muted" style="margin-top:1rem;">Traffic charts will appear after two or more polling cycles collect rate data.</p>';
        container.innerHTML = html;
    }
}

function renderDeviceAlertHistory(alerts) {
    const container = document.getElementById('device-alert-history');
    if (!container) return;
    if (!alerts.length) { container.innerHTML = '<p class="text-muted">No alerts for this device</p>'; return; }
    const sevClass = s => s === 'critical' ? 'danger' : s === 'warning' ? 'warning' : 'info';
    container.innerHTML = `
        <table class="chart-table">
            <thead><tr><th>Time</th><th>Severity</th><th>Metric</th><th>Message</th><th>Status</th><th></th></tr></thead>
            <tbody>${alerts.map(a => `<tr>
                <td>${new Date(a.created_at).toLocaleString()}</td>
                <td><span class="badge badge-${sevClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td>${escapeHtml(a.metric || '')}</td>
                <td>${escapeHtml(a.message || '')}</td>
                <td>${a.acknowledged ? 'Ack' : 'Open'}</td>
                <td><button class="btn btn-sm btn-secondary" onclick="showAlertCorrelation(${a.id})" title="View correlated events" style="padding:2px 6px; font-size:0.75em;">Correlate</button></td>
            </tr>`).join('')}</tbody>
        </table>`;
}

async function renderDeviceComplianceTab(hostId) {
    const container = document.getElementById('device-compliance-status');
    if (!container) return;
    try {
        const results = await api.getComplianceScanResults({ hostId, limit: 20 });
        const items = results?.results || results || [];
        if (!items.length) { container.innerHTML = '<p class="text-muted">No compliance data for this device</p>'; return; }
        container.innerHTML = `
            <table class="chart-table">
                <thead><tr><th>Profile</th><th>Status</th><th>Score</th><th>Scanned</th></tr></thead>
                <tbody>${items.map(r => `<tr>
                    <td>${escapeHtml(r.profile_name || '')}</td>
                    <td><span class="badge badge-${r.status === 'pass' ? 'success' : r.status === 'fail' ? 'danger' : 'warning'}">${escapeHtml(r.status || '')}</span></td>
                    <td>${r.score != null ? r.score + '%' : 'N/A'}</td>
                    <td>${r.scanned_at ? new Date(r.scanned_at).toLocaleString() : 'N/A'}</td>
                </tr>`).join('')}</tbody>
            </table>`;
    } catch (e) {
        container.innerHTML = '<p class="text-muted">Could not load compliance data</p>';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Custom Dashboards Page
// ═══════════════════════════════════════════════════════════════════════════════

let _dashboardTimeListener = null;

function setDashboardDefaultContentVisible(visible) {
    // Hide/show the default dashboard sections (stats, jobs, timeline, groups) when viewing a custom dashboard
    const container = document.getElementById('page-dashboard');
    if (!container) return;
    const marker = document.getElementById('dashboard-default-content-end');
    if (!marker) return;
    let el = container.firstElementChild;
    while (el && el !== marker) {
        el.style.display = visible ? '' : 'none';
        el = el.nextElementSibling;
    }
    if (marker) marker.style.display = 'none'; // always hide the marker itself
}

async function loadCustomDashboards({ preserveContent } = {}) {
    const listView = document.getElementById('dashboards-list-view');
    const viewer = document.getElementById('dashboard-viewer');
    // If we have a current dashboard, show viewer
    if (listViewState.customDashboards.currentId) {
        setDashboardDefaultContentVisible(false);
        if (listView) listView.style.display = 'none';
        if (viewer) viewer.style.display = '';
        await viewDashboard(listViewState.customDashboards.currentId);
        return;
    }
    // Show default dashboard content + dashboards list
    setDashboardDefaultContentVisible(true);
    if (listView) listView.style.display = '';
    if (viewer) viewer.style.display = 'none';
    try {
        const data = await api.getCustomDashboards();
        const dashboards = data?.dashboards || data || [];
        listViewState.customDashboards.items = dashboards;
        renderDashboardsList(dashboards);
    } catch (e) {
        showError('Failed to load dashboards: ' + e.message);
    }
}

function renderDashboardsList(dashboards) {
    const list = document.getElementById('dashboards-list');
    const empty = document.getElementById('dashboards-empty');
    if (!list) return;
    if (!dashboards.length) {
        list.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';
    list.innerHTML = dashboards.map(d => `
        <div class="card dashboard-card" onclick="openDashboard(${d.id})">
            <div class="card-title">${escapeHtml(d.name)}</div>
            <p class="text-muted" style="font-size:0.85rem; margin:0.25rem 0;">${escapeHtml(d.description || 'No description')}</p>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.5rem;">
                <span class="text-muted" style="font-size:0.75rem;">${d.updated_at ? new Date(d.updated_at).toLocaleDateString() : ''}</span>
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); confirmDeleteDashboardById(${d.id})" title="Delete">&times;</button>
            </div>
        </div>`).join('');
}

function openDashboard(id) {
    listViewState.customDashboards.currentId = id;
    loadCustomDashboards({});
}
window.openDashboard = openDashboard;

function backToDashboardsList() {
    listViewState.customDashboards.currentId = null;
    listViewState.customDashboards.editMode = false;
    if (_dashboardTimeListener) { offTimeRangeChange(_dashboardTimeListener); _dashboardTimeListener = null; }
    PlexusChart.destroyAll();
    loadCustomDashboards({});
}
window.backToDashboardsList = backToDashboardsList;

async function viewDashboard(id) {
    try {
        const data = await api.getCustomDashboard(id);
        const dashboard = data?.dashboard || data;
        const panels = dashboard?.panels || data?.panels || [];

        document.getElementById('dashboard-viewer-title').textContent = dashboard.name || 'Dashboard';

        // Register time-range listener
        if (_dashboardTimeListener) offTimeRangeChange(_dashboardTimeListener);
        _dashboardTimeListener = () => renderAllDashboardPanels(panels);
        onTimeRangeChange(_dashboardTimeListener);

        // Render variable dropdowns
        renderDashboardVariables(dashboard.variables_json ? JSON.parse(dashboard.variables_json) : []);

        // Render panels
        renderDashboardGrid(panels);
        await renderAllDashboardPanels(panels);

        // Edit mode controls
        updateDashboardEditControls();
    } catch (e) {
        showError('Failed to load dashboard: ' + e.message);
    }
}

function renderDashboardGrid(panels) {
    const grid = document.getElementById('dashboard-grid');
    if (!grid) return;
    if (!panels.length) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1; padding:3rem 1rem;"><svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.3;"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg><h3>No Panels Yet</h3><p style="color:var(--text-muted); margin-bottom:1rem;">Click <strong>Edit</strong> then <strong>+ Add Panel</strong> to get started.</p></div>';
        return;
    }
    grid.innerHTML = panels.map(p => `
        <div class="dashboard-panel" style="grid-column: span ${p.grid_w || 6}; grid-row: span ${p.grid_h || 4};" data-panel-id="${p.id}">
            <div class="panel-header">
                <span class="panel-title">${escapeHtml(p.title || 'Untitled')}</span>
                <div class="panel-actions" style="display:none;">
                    <button class="btn btn-sm btn-secondary" onclick="editPanelModal(${p.id})" title="Edit">&#9998;</button>
                    <button class="btn btn-sm btn-danger" onclick="confirmDeletePanel(${p.id})" title="Remove">&times;</button>
                </div>
            </div>
            <div id="panel-chart-${p.id}" class="panel-chart-container"></div>
        </div>`).join('');
}

async function renderAllDashboardPanels(panels) {
    const variables = getCurrentDashboardVariables();
    const trp = getTimeRangeParams();
    const range = trp.range === 'custom' ? '24h' : trp.range;

    await Promise.allSettled(panels.map(async (panel) => {
        const query = panel.metric_query_json ? JSON.parse(panel.metric_query_json) : {};
        const resolvedQuery = resolveVariables(query, variables);
        const chartId = `panel-chart-${panel.id}`;
        const chartType = panel.chart_type || 'line';

        try {
            const host = resolvedQuery.host || '*';
            const metric = resolvedQuery.metric || 'cpu_percent';
            const data = await api.queryMetrics(metric, host, range, 'auto', resolvedQuery.group || null);
            const items = data?.data || [];

            if (chartType === 'gauge') {
                const avg = items.length ? items.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0) / items.length : 0;
                PlexusChart.gauge(chartId, avg, { title: metric });
            } else if (chartType === 'bar') {
                const byHost = groupByHost(items);
                const labels = Object.keys(byHost);
                const values = labels.map(h => {
                    const arr = byHost[h];
                    return arr.length ? arr.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0) / arr.length : 0;
                });
                PlexusChart.bar(chartId, labels, values.map(v => Math.round(v * 10) / 10));
            } else if (chartType === 'heatmap') {
                renderHeatmapPanel(chartId, items);
            } else if (chartType === 'table') {
                renderTablePanel(chartId, items, metric);
            } else {
                // Default: line chart
                const byHost = groupByHost(items);
                const series = Object.entries(byHost).map(([hostname, pts]) => ({
                    name: hostname,
                    data: pts.map(d => ({ time: d.sampled_at || d.period_start, value: d.val_avg ?? d.value ?? 0 })),
                }));
                PlexusChart.timeSeries(chartId, series.length ? series : [{ name: metric, data: [] }], { area: true });

                // Overlay annotations on line charts
                try {
                    const endISO = new Date().toISOString();
                    const startISO = new Date(Date.now() - _rangeToMs(range)).toISOString();
                    const hostParam = host !== '*' ? host : undefined;
                    const annRes = await api.getAnnotations({ hostId: hostParam, start: startISO, end: endISO, categories: 'deployment,config,alert' });
                    const events = annRes?.annotations || [];
                    if (events.length) PlexusChart.addAnnotations(chartId, events);
                } catch { /* annotations are non-critical */ }
            }
        } catch (e) {
            const container = document.getElementById(chartId);
            if (container) container.innerHTML = `<p class="text-muted" style="padding:1rem;">Error: ${escapeHtml(e.message)}</p>`;
        }
    }));
}

function groupByHost(items) {
    const map = {};
    items.forEach(d => {
        const key = d.hostname || `host-${d.host_id}`;
        if (!map[key]) map[key] = [];
        map[key].push(d);
    });
    return map;
}

function renderHeatmapPanel(chartId, items) {
    if (!items.length) { PlexusChart.timeSeries(chartId, [{ name: 'No data', data: [] }]); return; }
    const byHost = groupByHost(items);
    const hostNames = Object.keys(byHost);
    const timeSet = new Set();
    items.forEach(d => timeSet.add(d.sampled_at || d.period_start));
    const times = [...timeSet].sort();
    const data = [];
    times.forEach((t, ti) => {
        hostNames.forEach((h, hi) => {
            const pt = byHost[h].find(d => (d.sampled_at || d.period_start) === t);
            data.push([ti, hi, pt ? Math.round((pt.val_avg ?? pt.value ?? 0) * 10) / 10 : 0]);
        });
    });
    PlexusChart.heatmap(chartId, times.map(t => new Date(t).toLocaleTimeString()), hostNames, data);
}

function renderTablePanel(chartId, items, metric) {
    const columns = [
        { key: 'hostname', label: 'Host' },
        { key: 'time', label: 'Time' },
        { key: 'value', label: metric },
    ];
    const rows = items.map(d => ({
        hostname: d.hostname || `host-${d.host_id}`,
        time: new Date(d.sampled_at || d.period_start).toLocaleString(),
        value: (d.val_avg ?? d.value ?? 0).toFixed(2),
    }));
    PlexusChart.table(chartId, columns, rows);
}

function refreshDashboardPanels() {
    const id = listViewState.customDashboards.currentId;
    if (id) viewDashboard(id);
}
window.refreshDashboardPanels = refreshDashboardPanels;

// Dashboard variables
function renderDashboardVariables(variables) {
    const container = document.getElementById('dashboard-variables');
    if (!container) return;
    if (!variables?.length) { container.innerHTML = ''; return; }
    container.innerHTML = variables.map(v => {
        if (v.type === 'group') {
            return `<select id="dashvar-${v.name}" class="form-select form-select-sm" onchange="onDashboardVariableChange()">
                <option value="*">All Groups</option>
            </select>`;
        }
        if (v.type === 'host') {
            return `<select id="dashvar-${v.name}" class="form-select form-select-sm" onchange="onDashboardVariableChange()">
                <option value="*">All Hosts</option>
            </select>`;
        }
        return '';
    }).join('');
    // Populate selects
    populateDashboardVariableOptions(variables);
}

async function populateDashboardVariableOptions(variables) {
    try {
        const groups = await api.getInventoryGroups(true);
        const allGroups = groups?.groups || groups || [];
        variables.forEach(v => {
            const sel = document.getElementById(`dashvar-${v.name}`);
            if (!sel) return;
            if (v.type === 'group') {
                allGroups.forEach(g => {
                    const opt = document.createElement('option');
                    opt.value = g.id;
                    opt.textContent = g.name;
                    sel.appendChild(opt);
                });
            } else if (v.type === 'host') {
                allGroups.forEach(g => {
                    (g.hosts || []).forEach(h => {
                        const opt = document.createElement('option');
                        opt.value = h.id;
                        opt.textContent = `${h.hostname} (${g.name})`;
                        sel.appendChild(opt);
                    });
                });
            }
        });
    } catch (e) {
        console.error('Error populating dashboard variables:', e);
    }
}

function getCurrentDashboardVariables() {
    const vars = {};
    document.querySelectorAll('#dashboard-variables select').forEach(sel => {
        const name = sel.id.replace('dashvar-', '');
        vars[name] = sel.value;
    });
    return vars;
}

function onDashboardVariableChange() {
    refreshDashboardPanels();
}
window.onDashboardVariableChange = onDashboardVariableChange;

function resolveVariables(queryObj, variables) {
    let queryStr = JSON.stringify(queryObj);
    for (const [name, value] of Object.entries(variables)) {
        queryStr = queryStr.replace(new RegExp(`\\$${name}`, 'g'), value);
    }
    return JSON.parse(queryStr);
}

// Dashboard CRUD
function showCreateDashboardModal() {
    const html = `
        <div class="form-group"><label class="form-label">Name</label><input type="text" class="form-input" id="new-dash-name" required></div>
        <div class="form-group"><label class="form-label">Description</label><input type="text" class="form-input" id="new-dash-desc"></div>
        <div class="form-group">
            <label class="form-label">Template Variables</label>
            <div style="display:flex; gap:0.5rem;">
                <label><input type="checkbox" id="new-dash-var-group"> $group</label>
                <label><input type="checkbox" id="new-dash-var-host"> $host</label>
            </div>
        </div>`;
    showFormModal('Create Dashboard', html, async () => {
        const name = document.getElementById('new-dash-name').value.trim();
        if (!name) { showError('Name is required'); return; }
        const vars = [];
        if (document.getElementById('new-dash-var-group')?.checked) vars.push({ name: 'group', type: 'group', default: '*' });
        if (document.getElementById('new-dash-var-host')?.checked) vars.push({ name: 'host', type: 'host', default: '*' });
        try {
            await api.createCustomDashboard({
                name,
                description: document.getElementById('new-dash-desc').value.trim(),
                variables_json: JSON.stringify(vars),
            });
            showSuccess('Dashboard created');
            loadCustomDashboards({ preserveContent: false });
        } catch (e) { showError('Failed to create dashboard: ' + e.message); }
    });
}
window.showCreateDashboardModal = showCreateDashboardModal;

function showAddPanelModal() {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    const html = `
        <div class="form-group"><label class="form-label">Panel Title</label><input type="text" class="form-input" id="new-panel-title"></div>
        <div class="form-group">
            <label class="form-label">Chart Type</label>
            <select class="form-select" id="new-panel-type">
                <option value="line">Line</option>
                <option value="bar">Bar</option>
                <option value="gauge">Gauge</option>
                <option value="heatmap">Heatmap</option>
                <option value="table">Table</option>
            </select>
        </div>
        <div class="form-group"><label class="form-label">Metric</label><input type="text" class="form-input" id="new-panel-metric" value="cpu_percent" placeholder="e.g. cpu_percent"></div>
        <div class="form-group"><label class="form-label">Host (ID, "*", or "$host")</label><input type="text" class="form-input" id="new-panel-host" value="*"></div>
        <div class="form-group" style="display:flex; gap:1rem;">
            <div><label class="form-label">Width (1-12)</label><input type="number" class="form-input" id="new-panel-w" value="6" min="1" max="12"></div>
            <div><label class="form-label">Height (rows)</label><input type="number" class="form-input" id="new-panel-h" value="4" min="1" max="12"></div>
        </div>`;
    showFormModal('Add Panel', html, async () => {
        const title = document.getElementById('new-panel-title')?.value.trim() || 'Untitled';
        const chartType = document.getElementById('new-panel-type')?.value || 'line';
        const metric = document.getElementById('new-panel-metric')?.value.trim() || 'cpu_percent';
        const host = document.getElementById('new-panel-host')?.value.trim() || '*';
        const gridW = parseInt(document.getElementById('new-panel-w')?.value) || 6;
        const gridH = parseInt(document.getElementById('new-panel-h')?.value) || 4;
        try {
            await api.createDashboardPanel(dashId, {
                title, chart_type: chartType,
                metric_query_json: JSON.stringify({ metric, host }),
                grid_w: gridW, grid_h: gridH, grid_x: 0, grid_y: 0,
            });
            showSuccess('Panel added');
            viewDashboard(dashId);
        } catch (e) { showError('Failed to add panel: ' + e.message); }
    });
}
window.showAddPanelModal = showAddPanelModal;

function editPanelModal(panelId) {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    // Find panel in current DOM
    const panelEl = document.querySelector(`[data-panel-id="${panelId}"]`);
    const titleEl = panelEl?.querySelector('.panel-title');
    const currentTitle = titleEl?.textContent || '';
    const html = `
        <div class="form-group"><label class="form-label">Panel Title</label><input type="text" class="form-input" id="edit-panel-title" value="${escapeHtml(currentTitle)}"></div>
        <div class="form-group">
            <label class="form-label">Chart Type</label>
            <select class="form-select" id="edit-panel-type">
                <option value="line">Line</option><option value="bar">Bar</option><option value="gauge">Gauge</option><option value="heatmap">Heatmap</option><option value="table">Table</option>
            </select>
        </div>
        <div class="form-group"><label class="form-label">Metric</label><input type="text" class="form-input" id="edit-panel-metric" placeholder="cpu_percent"></div>
        <div class="form-group"><label class="form-label">Host</label><input type="text" class="form-input" id="edit-panel-host" value="*"></div>
        <div class="form-group" style="display:flex; gap:1rem;">
            <div><label class="form-label">Width (1-12)</label><input type="number" class="form-input" id="edit-panel-w" value="6" min="1" max="12"></div>
            <div><label class="form-label">Height (rows)</label><input type="number" class="form-input" id="edit-panel-h" value="4" min="1" max="12"></div>
        </div>`;
    showFormModal('Edit Panel', html, async () => {
        const title = document.getElementById('edit-panel-title')?.value.trim() || 'Untitled';
        const chartType = document.getElementById('edit-panel-type')?.value || 'line';
        const metric = document.getElementById('edit-panel-metric')?.value.trim() || 'cpu_percent';
        const host = document.getElementById('edit-panel-host')?.value.trim() || '*';
        const gridW = parseInt(document.getElementById('edit-panel-w')?.value) || 6;
        const gridH = parseInt(document.getElementById('edit-panel-h')?.value) || 4;
        try {
            await api.updateDashboardPanel(dashId, panelId, {
                title, chart_type: chartType,
                metric_query_json: JSON.stringify({ metric, host }),
                grid_w: gridW, grid_h: gridH,
            });
            showSuccess('Panel updated');
            viewDashboard(dashId);
        } catch (e) { showError('Failed to update panel: ' + e.message); }
    });
}
window.editPanelModal = editPanelModal;

async function confirmDeletePanel(panelId) {
    const dashId = listViewState.customDashboards.currentId;
    if (!dashId) return;
    const ok = await showConfirm('Delete this panel?', 'This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteDashboardPanel(dashId, panelId);
        showSuccess('Panel deleted');
        viewDashboard(dashId);
    } catch (e) { showError('Failed to delete panel: ' + e.message); }
}
window.confirmDeletePanel = confirmDeletePanel;

function toggleDashboardEditMode() {
    listViewState.customDashboards.editMode = !listViewState.customDashboards.editMode;
    updateDashboardEditControls();
}
window.toggleDashboardEditMode = toggleDashboardEditMode;

function updateDashboardEditControls() {
    const editing = listViewState.customDashboards.editMode;
    const editBtn = document.getElementById('dashboard-edit-toggle');
    const addBtn = document.getElementById('dashboard-add-panel-btn');
    const delBtn = document.getElementById('dashboard-delete-btn');
    if (editBtn) { editBtn.textContent = editing ? 'Done' : 'Edit'; editBtn.classList.toggle('btn-primary', editing); editBtn.classList.toggle('btn-secondary', !editing); }
    if (addBtn) addBtn.style.display = editing ? '' : 'none';
    if (delBtn) delBtn.style.display = editing ? '' : 'none';
    document.querySelectorAll('.panel-actions').forEach(el => el.style.display = editing ? 'flex' : 'none');
    document.querySelectorAll('.dashboard-panel').forEach(el => el.classList.toggle('editing', editing));
}

async function confirmDeleteDashboard() {
    const id = listViewState.customDashboards.currentId;
    if (!id) return;
    const ok = await showConfirm('Delete this dashboard?', 'All panels will be removed. This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteCustomDashboard(id);
        showSuccess('Dashboard deleted');
        backToDashboardsList();
    } catch (e) { showError('Failed to delete dashboard: ' + e.message); }
}
window.confirmDeleteDashboard = confirmDeleteDashboard;

async function confirmDeleteDashboardById(id) {
    const ok = await showConfirm('Delete this dashboard?', 'All panels will be removed. This action cannot be undone.');
    if (!ok) return;
    try {
        await api.deleteCustomDashboard(id);
        showSuccess('Dashboard deleted');
        loadCustomDashboards({});
    } catch (e) { showError('Failed to delete dashboard: ' + e.message); }
}
window.confirmDeleteDashboardById = confirmDeleteDashboardById;

// Helper: generic form modal using the main modal overlay
export function showFormModal(title, bodyHtml, onSubmit) {
    const overlay = document.getElementById('modal-overlay');
    const titleEl = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');
    if (!overlay || !body) return;

    if (titleEl) titleEl.textContent = title;
    body.innerHTML = `
        <div>${bodyHtml}</div>
        <div style="display:flex; gap:0.5rem; justify-content:flex-end; margin-top:1rem;">
            <button class="btn btn-secondary" onclick="closeAllModals()">Cancel</button>
            <button class="btn btn-primary" id="form-modal-save">Save</button>
        </div>`;
    overlay.classList.add('active');

    const saveBtn = document.getElementById('form-modal-save');
    if (saveBtn) {
        saveBtn.onclick = async () => {
            await onSubmit();
            overlay.classList.remove('active');
        };
    }
}

// ── Hash routing for device-detail ──────────────────────────────────────────
function getPageFromHashExtended() {
    const hash = window.location.hash.replace(/^#\/?/, '');
    if (hash.startsWith('device-detail/')) {
        const hostId = parseInt(hash.split('/')[1]);
        if (!isNaN(hostId)) {
            listViewState.deviceDetail.hostId = hostId;
            return 'device-detail';
        }
    }
    return null;
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

export function activateFocusTrap(overlayId) {
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

export function deactivateFocusTrap(overlayId) {
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

export function invalidatePageCache(...pages) {
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
    'monitoring': 'network',
    'configuration': 'network',
    'compliance': 'network',
    'change-management': 'network',
    'reports': 'network',
    'graph-templates': 'network',
    'mac-tracking': 'network',
    'traffic-analysis': 'network',
    'upgrades': 'network',
};

window.toggleNavGroup = function(groupName, e) {
    e.preventDefault();
    const group = document.getElementById(`nav-group-${groupName}`);
    if (group) {
        group.classList.toggle('expanded');
        const toggle = group.querySelector('.nav-group-toggle');
        if (toggle) toggle.setAttribute('aria-expanded', group.classList.contains('expanded'));
    }
};

function expandNavGroupForPage(page) {
    const groupName = NAV_GROUP_CHILDREN[page];
    if (groupName) {
        const group = document.getElementById(`nav-group-${groupName}`);
        if (group) {
            group.classList.add('expanded');
            const toggle = group.querySelector('.nav-group-toggle');
            if (toggle) toggle.setAttribute('aria-expanded', 'true');
        }
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

const VALID_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'topology', 'monitoring', 'configuration', 'settings', 'device-detail', 'compliance', 'change-management', 'reports', 'graph-templates', 'mac-tracking', 'traffic-analysis'];

function getPageFromHash() {
    const hash = window.location.hash.replace(/^#\/?/, '');
    // Support device-detail/123 deep links
    if (hash.startsWith('device-detail/')) {
        const hostId = parseInt(hash.split('/')[1]);
        if (!isNaN(hostId)) {
            listViewState.deviceDetail.hostId = hostId;
            return 'device-detail';
        }
    }
    return VALID_PAGES.includes(hash) ? hash : null;
}

export function navigateToPage(page, { updateHash = true } = {}) {
    if (page === 'settings' && currentUserData?.role !== 'admin') {
        showError('Admin access required for Settings');
        return;
    }
    if (NAV_FEATURE_MAP[page] && !canAccessFeature(NAV_FEATURE_MAP[page])) {
        showError(`Your account does not have access to ${page}`);
        return;
    }

    // Update active nav link — targeted swap instead of iterating all links
    const prevNavLink = document.querySelector('.nav-link.active[data-page]');
    if (prevNavLink) {
        prevNavLink.classList.remove('active');
        prevNavLink.removeAttribute('aria-current');
    }
    const nextNavLink = document.querySelector(`.nav-link[data-page="${page}"]`);
    if (nextNavLink) {
        nextNavLink.classList.add('active');
        nextNavLink.setAttribute('aria-current', 'page');
    }

    // Auto-expand parent nav group and update group active styling
    expandNavGroupForPage(page);
    updateNavGroupActiveState();

    // Close any open modals before switching pages
    // Fast path: dismiss the shared modal overlay (most common case)
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.classList.remove('active');
    // Catch any additional overlay-based modals (rare — ensureModalDOM creates extras)
    document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));

    // Hide current page (targeted instead of sweeping all .page elements)
    const currentPageEl = document.getElementById(`page-${currentPage}`);
    if (currentPageEl) currentPageEl.classList.remove('active');

    // Abort any in-flight API requests from the page being left
    api.abortPendingRequests();

    // Call the current page module's destroy() to clean up event listeners, timers, etc.
    _destroyCurrentPage(currentPage);

    // Defer chart destruction so it doesn't block the page transition paint.
    // Charts are recreated asynchronously by loadPageData, so this is safe.
    requestAnimationFrame(() => PlexusChart.destroyAll());

    // Force fresh reload when re-navigating to the same page (e.g. clicking nav or breadcrumb)
    if (page === currentPage) {
        invalidatePageCache(page);
    }

    // Reset custom dashboard viewer state when leaving or re-navigating to dashboard
    if (currentPage === 'dashboard' && listViewState.customDashboards.currentId) {
        listViewState.customDashboards.currentId = null;
        listViewState.customDashboards.editMode = false;
        if (_dashboardTimeListener) { offTimeRangeChange(_dashboardTimeListener); _dashboardTimeListener = null; }
        setDashboardDefaultContentVisible(true);
        const listView = document.getElementById('dashboards-list-view');
        const viewer = document.getElementById('dashboard-viewer');
        if (listView) listView.style.display = '';
        if (viewer) viewer.style.display = 'none';
    }

    // Reset device detail state when leaving or re-navigating away
    if (currentPage === 'device-detail' && page !== 'device-detail') {
        listViewState.deviceDetail.hostId = null;
        listViewState.deviceDetail.tab = 'overview';
        if (_deviceDetailTimeListener) { offTimeRangeChange(_deviceDetailTimeListener); _deviceDetailTimeListener = null; }
    }

    // Ensure lazy DOM is populated for target page; bind controls only when new DOM is created
    if (ensurePageDOM(page)) {
        initListPageControls();
    }

    // Show target page
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
        currentPage = page;
        updateBreadcrumb(page);
        renderPageHelp(page);
        updateTimeRangeBarVisibility(page);
        loadPageData(page);
        // Sync URL hash
        if (updateHash) {
            let newHash = `#${page}`;
            if (page === 'device-detail' && listViewState.deviceDetail.hostId) {
                newHash = `#device-detail/${listViewState.deviceDetail.hostId}`;
            }
            if (window.location.hash !== newHash) {
                history.pushState(null, '', newHash);
            }
        }
    }
}
window.navigateToPage = navigateToPage;

const PAGE_LABELS = {
    dashboard: 'Dashboard',
    inventory: 'Inventory Management',
    playbooks: 'Playbooks',
    jobs: 'Job Execution',
    templates: 'Config Templates',
    credentials: 'Credentials',
    topology: 'Network Topology',
    configuration: 'Configuration',
    compliance: 'Compliance',
    'change-management': 'Change Management',
    monitoring: 'Monitoring',
    reports: 'Reports & Export',
    'device-detail': 'Device Detail',
    'graph-templates': 'Graph Templates',
    'mac-tracking': 'MAC/ARP Tracking',
    'traffic-analysis': 'Traffic Analysis',
    settings: 'Admin Settings',
    upgrades: 'Upgrades',
};

// Parent page for breadcrumb trail. Pages not listed here are top-level (parent = dashboard).
const PAGE_PARENTS = {
    'device-detail': 'monitoring',
    topology: 'dashboard',
    monitoring: 'dashboard',
    configuration: 'dashboard',
    compliance: 'dashboard',
    'change-management': 'dashboard',
    reports: 'dashboard',
    'graph-templates': 'dashboard',
    'mac-tracking': 'dashboard',
    'traffic-analysis': 'dashboard',
    upgrades: 'dashboard',
};

const PAGE_HELP = {
    dashboard: {
        title: 'Your Network at a Glance',
        text: 'View device status, recent alerts, backup summaries, and quick stats. Scroll down to manage custom dashboards with your own metric panels.'
    },
    inventory: {
        title: 'Manage Your Devices',
        text: 'Add, edit, and organize network devices into groups. Devices added here are used across monitoring, backups, compliance, and automation features.'
    },
    playbooks: {
        title: 'Automation Playbooks',
        text: 'Create reusable automation scripts that run commands on your network devices. Playbooks can be launched as jobs from the Job Execution page.'
    },
    jobs: {
        title: 'Run & Track Jobs',
        text: 'Launch playbooks against selected devices and monitor their progress in real time. View output logs, status, and history for each job run.'
    },
    templates: {
        title: 'Configuration Templates',
        text: 'Build reusable Jinja2 config templates with variables. Render templates for specific devices and deploy consistent configurations across your network.'
    },
    credentials: {
        title: 'Credential Management',
        text: 'Securely store SSH, SNMP, and API credentials used to connect to network devices. Assign credentials to devices in the Inventory page.'
    },
    topology: {
        title: 'Interactive Network Map',
        text: 'Visualize your network as an interactive graph. Drag nodes to rearrange, zoom in/out, and click devices to view details. Connections are discovered from device data.'
    },
    configuration: {
        title: 'Configuration Management',
        text: 'Manage device configurations in one place. Detect drift against baselines, schedule automatic backups, browse backup history, and restore previous configurations.'
    },
    compliance: {
        title: 'Policy Compliance Auditing',
        text: 'Define compliance rules and run audits against your devices. Check configurations against security policies, best practices, and industry standards.'
    },
    'change-management': {
        title: 'Plan, Analyze & Deploy Changes',
        text: 'Assess risk before pushing changes, deploy with staged rollouts, and roll back if needed. The full change lifecycle in one place.'
    },
    monitoring: {
        title: 'Real-Time Device Monitoring',
        text: 'Track CPU, memory, response time, packet loss, and interface status. Includes SLA tracking, availability history, and capacity planning trends.'
    },
    reports: {
        title: 'Reports, Event Log & OID Profiles',
        text: 'Generate and export availability, compliance, and utilization reports. View syslog events and SNMP traps. Manage custom OID profiles for monitoring.'
    },
    'graph-templates': {
        title: 'Graph Templates & Auto-Graphing',
        text: 'Manage reusable graph definitions that auto-apply to devices. Create host templates to map device types to graphs, and organize with graph trees for hierarchical navigation.'
    },
    settings: {
        title: 'Application Settings',
        text: 'Configure polling intervals, feature toggles, default credentials, and other application-wide settings. Admin access required.'
    },
};

// Cache help-dismissed state in memory — only read localStorage once
let _helpDismissedCache = null;
function _getHelpDismissed() {
    if (!_helpDismissedCache) {
        _helpDismissedCache = JSON.parse(localStorage.getItem('plexus_help_dismissed') || '{}');
    }
    return _helpDismissedCache;
}

function renderPageHelp(page) {
    const help = PAGE_HELP[page];
    if (!help) return;
    const pageEl = document.getElementById(`page-${page}`);
    if (!pageEl) return;

    // Reuse existing banner if already created for this page
    const existing = pageEl.querySelector('.page-help');
    if (existing) return;

    const dismissed = _getHelpDismissed();
    const isHidden = !!dismissed[page];

    const banner = document.createElement('div');
    banner.className = 'page-help' + (isHidden ? ' page-help-collapsed' : '');
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'page-help-toggle';
    toggleBtn.title = isHidden ? 'Show help' : 'Hide help';
    toggleBtn.innerHTML = isHidden ? '?' : '&times;';

    banner.innerHTML = `<div class="page-help-content"><svg class="page-help-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg><div><strong>${escapeHtml(help.title)}</strong><span class="page-help-text"> &mdash; ${escapeHtml(help.text)}</span></div></div>`;
    banner.appendChild(toggleBtn);

    toggleBtn.addEventListener('click', () => {
        const d = _getHelpDismissed();
        if (banner.classList.contains('page-help-collapsed')) {
            delete d[page];
            banner.classList.remove('page-help-collapsed');
            toggleBtn.innerHTML = '&times;';
            toggleBtn.title = 'Hide help';
        } else {
            d[page] = true;
            banner.classList.add('page-help-collapsed');
            toggleBtn.innerHTML = '?';
            toggleBtn.title = 'Show help';
        }
        _helpDismissedCache = d;
        localStorage.setItem('plexus_help_dismissed', JSON.stringify(d));
    });

    // Insert after the page-header (or as first child if no header)
    const header = pageEl.querySelector('.page-header') || pageEl.querySelector('h2');
    if (header) {
        header.after(banner);
    } else {
        pageEl.prepend(banner);
    }
}

let _lastBreadcrumbPage = null;
function updateBreadcrumb(page) {
    // Skip DOM write if breadcrumb is already showing this page
    if (page === _lastBreadcrumbPage) return;
    _lastBreadcrumbPage = page;

    const trail = document.getElementById('breadcrumb-trail');
    if (!trail) return;

    // Build the chain from current page up to dashboard
    const chain = [];
    let p = page;
    while (p && p !== 'dashboard') {
        chain.unshift(p);
        p = PAGE_PARENTS[p] || null;
    }

    // Always start with Home → Dashboard
    let html = '<a class="breadcrumb-home" onclick="navigateToPage(\'dashboard\')">Home</a>';

    if (chain.length === 0) {
        // We're on the dashboard itself
        html += '<span class="breadcrumb-sep">/</span>';
        html += '<span class="breadcrumb-current">Dashboard</span>';
    } else {
        // Render intermediate pages as clickable links, last one as current
        for (let i = 0; i < chain.length; i++) {
            html += '<span class="breadcrumb-sep">/</span>';
            const label = PAGE_LABELS[chain[i]] || chain[i];
            if (i < chain.length - 1) {
                html += `<a class="breadcrumb-link" onclick="navigateToPage('${chain[i]}')">${label}</a>`;
            } else {
                html += `<span class="breadcrumb-current">${label}</span>`;
            }
        }
    }

    trail.innerHTML = html;
}

// ── Module cache for lazy-loaded page modules ──
const _moduleCache = {};

// Destroy map: page name → destroy function name in the module
const _destroyMap = {
    'dashboard': 'destroyDashboard',
    'inventory': 'destroyInventory',
    'playbooks': 'destroyJobs',
    'jobs': 'destroyJobs',
    'templates': 'destroyJobs',
    'credentials': 'destroyJobs',
    'settings': 'destroySettings',
    'topology': 'destroyTopology',
    'configuration': 'destroyConfiguration',
    'compliance': 'destroyCompliance',
    'change-management': 'destroyChangeManagement',
    'monitoring': 'destroyMonitoring',
    'reports': 'destroyReports',
    'device-detail': 'destroyDeviceDetail',
    'graph-templates': 'destroyReports',
    'mac-tracking': 'destroyNetworkTools',
    'traffic-analysis': 'destroyNetworkTools',
    'upgrades': 'destroyUpgrades',
};

function _destroyCurrentPage(page) {
    const mod = _moduleCache[page];
    if (!mod) return;
    const fnName = _destroyMap[page];
    if (fnName && typeof mod[fnName] === 'function') {
        try { mod[fnName](); } catch (e) { console.warn(`Destroy error for ${page}:`, e); }
    }
}

async function _loadModule(page) {
    if (_moduleCache[page]) return _moduleCache[page];
    const moduleMap = {
        'dashboard':        () => import('./modules/dashboard.js'),
        'inventory':        () => import('./modules/inventory.js'),
        'playbooks':        () => import('./modules/jobs.js'),
        'jobs':             () => import('./modules/jobs.js'),
        'templates':        () => import('./modules/jobs.js'),
        'credentials':      () => import('./modules/jobs.js'),
        'settings':         () => import('./modules/settings.js'),
        'topology':         () => import('./modules/topology.js'),
        'configuration':    () => import('./modules/configuration.js'),
        'compliance':       () => import('./modules/compliance.js'),
        'change-management': () => import('./modules/change-management.js'),
        'monitoring':       () => import('./modules/monitoring.js'),
        'reports':          () => import('./modules/reports.js'),
        'device-detail':    () => import('./modules/device-detail.js'),
        'graph-templates':  () => import('./modules/reports.js'),
        'mac-tracking':     () => import('./modules/network-tools.js'),
        'traffic-analysis': () => import('./modules/network-tools.js'),
        'upgrades':         () => import('./modules/upgrades.js'),
    };
    const loader = moduleMap[page];
    if (!loader) return null;
    const mod = await loader();
    _moduleCache[page] = mod;
    return mod;
}

async function loadPageData(page, options = {}) {
    const { force = false } = options;
    if (!force && isPageCacheFresh(page)) {
        return;
    }
    const preserveContent = !force && Boolean(pageCacheMeta[page]);
    try {
        const mod = await _loadModule(page);
        if (!mod) return;
        switch (page) {
            case 'dashboard':
                await mod.loadDashboard({ preserveContent });
                break;
            case 'inventory':
                await mod.loadInventory({ preserveContent });
                break;
            case 'playbooks':
                await mod.loadPlaybooks({ preserveContent });
                break;
            case 'jobs':
                await mod.loadJobs({ preserveContent });
                break;
            case 'templates':
                await mod.loadTemplates({ preserveContent });
                break;
            case 'credentials':
                await mod.loadCredentials({ preserveContent });
                break;
            case 'settings':
                await mod.loadAdminSettings({ preserveContent });
                break;
            case 'topology':
                await mod.loadTopology({ preserveContent });
                break;
            case 'configuration':
                await mod.loadConfigDrift({ preserveContent });
                await mod.loadConfigBackups({ preserveContent });
                break;
            case 'compliance':
                await mod.loadCompliance({ preserveContent });
                break;
            case 'change-management':
                await mod.loadRiskAnalysis({ preserveContent });
                await mod.loadDeployments({ preserveContent });
                break;
            case 'monitoring':
                await mod.loadMonitoring({ preserveContent });
                break;
            case 'reports':
                await mod.loadReports({ preserveContent });
                break;
            case 'device-detail':
                await mod.loadDeviceDetail({ preserveContent });
                break;
            case 'graph-templates':
                await mod.loadGraphTemplates({ preserveContent });
                break;
            case 'mac-tracking':
                await mod.loadMacTrackingPage({ preserveContent });
                break;
            case 'traffic-analysis':
                await mod.loadTrafficAnalysis({ preserveContent });
                break;
            case 'upgrades':
                await mod.loadUpgradesPage({ preserveContent });
                break;
        }
        markPageCacheFresh(page);
    } catch (error) {
        if (error.name === 'AbortError') return; // navigated away — silently cancel
        console.error(`Error loading ${page}:`, error);
        showError(`Failed to load ${page}: ${error.message}`);
    }
}

// Topology — migrated to modules/topology.js
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

        // Render groups overview
        renderGroupsOverview(data.groups || []);
    } catch (error) {
        showError('Failed to load dashboard', container);
    }

    // Also load custom dashboards section
    await loadCustomDashboards(_options);
}

export function isReducedMotion() {
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

export function skeletonCards(count = 3) {
    return Array.from({length: count}, () =>
        '<div class="skeleton skeleton-card" style="margin-bottom: 0.75rem;"></div>'
    ).join('');
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

export function textMatch(value, query) {
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
    // Remaining search bindings migrated to their respective modules
}

// ═══════════════════════════════════════════════════════════════════════════════
// Inventory
// ═══════════════════════════════════════════════════════════════════════════════

async function loadInventory(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('inventory-groups');
    _lastInventoryFingerprint = null;
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

let _lastInventoryFingerprint = null;
function renderInventoryGroups(groups) {
    const container = document.getElementById('inventory-groups');
    const query = (listViewState.inventory.query || '').trim().toLowerCase();
    const hostMatchesQuery = (host) => query && (
        textMatch(host.hostname, query) || textMatch(host.ip_address, query) || textMatch(host.device_type, query)
    );

    // Skip render if data hasn't changed (prevents DOM thrash on redundant search/sort)
    const fingerprint = JSON.stringify(groups.map(g => g.id)) + '|' + query + '|' + (listViewState.inventory.sort || '');
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
                            <span class="host-col-model">${escapeHtml(host.model || '—')}</span>
                            <span class="host-col-sw">${escapeHtml(host.software_version || '—')}</span>
                            <span class="host-col-actions">
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
        clearInterval(elapsedInterval);
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
        submitBtn.textContent = mode === 'sync' ? 'Syncing…' : 'Scanning…';
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
        container.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}</div>`;
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
        container.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}</div>`;
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
        container.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}</div>`;
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
                    <button class="btn btn-sm btn-ghost" onclick="copyTemplateContent(this)" title="Copy template">${COPY_ICON_SVG}Copy</button>
                    ${isLong ? `<button class="btn btn-sm btn-ghost template-expand-btn" onclick="toggleTemplateContent(this)" data-expanded="false">Expand</button>` : ''}
                    <button class="btn btn-sm btn-secondary" onclick="editTemplate(${template.id})">Edit</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteTemplate(${template.id})">Delete</button>
                </div>
            </div>
            <div class="template-content-wrap${isLong ? ' template-content-collapsed' : ''}">
                <pre class="template-content-pre copyable-content" tabindex="0" style="user-select:text; cursor:text;">${isLong ? preview : content}</pre>
                ${isLong ? `<pre class="template-content-full copyable-content" tabindex="0" style="display:none; user-select:text; cursor:text;">${content}</pre>` : ''}
                ${isLong ? '<div class="template-fade"></div>' : ''}
            </div>
        </div>`;
    }).join('');
    initCopyableBlocks();
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

function copyTemplateContent(btn) {
    const card = btn.closest('.card');
    const full = card.querySelector('.template-content-full');
    const pre = full || card.querySelector('.template-content-pre');
    const text = pre ? pre.textContent : '';
    navigator.clipboard.writeText(text).then(() => {
        const prev = btn.innerHTML;
        btn.innerHTML = '&#10003; Copied';
        setTimeout(() => { btn.innerHTML = prev; }, 2000);
    }).catch(() => {
        const card = btn.closest('.card');
        const pre = card.querySelector('.template-content-full') || card.querySelector('.template-content-pre');
        if (pre) {
            const range = document.createRange();
            range.selectNodeContents(pre);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
        }
        showToast('Press Ctrl+C to copy the selected text', 'info');
    });
}
window.copyTemplateContent = copyTemplateContent;

// ═══════════════════════════════════════════════════════════════════════════════
// Credentials
// ═══════════════════════════════════════════════════════════════════════════════

async function loadCredentials(options = {}) {
    const { preserveContent = false } = options;

    // Load the active tab
    if (_credentialCurrentTab === 'secrets') {
        await loadSecretVariables();
        return;
    }

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
        container.innerHTML = `<div class="error">Error: ${escapeHtml(error.message)}</div>`;
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
// Secret Variables (encrypted template variables)
// ═══════════════════════════════════════════════════════════════════════════════

let _credentialCurrentTab = 'credentials';

function switchCredentialTab(tab) {
    _credentialCurrentTab = tab;
    document.querySelectorAll('.cred-tab-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-cred-tab') === tab);
    });
    document.getElementById('cred-tab-credentials').style.display = tab === 'credentials' ? '' : 'none';
    document.getElementById('cred-tab-secrets').style.display = tab === 'secrets' ? '' : 'none';
    if (tab === 'secrets') loadSecretVariables();
}
window.switchCredentialTab = switchCredentialTab;

async function loadSecretVariables() {
    const container = document.getElementById('secret-variables-list');
    if (!container) return;
    try {
        const vars = await api.getSecretVariables();
        if (!vars.length) {
            container.innerHTML = `<div class="empty-state">
                <p>No secret variables yet</p>
                <p style="opacity:0.7; font-size:0.85em;">Use <code>{{secret.NAME}}</code> in config templates to reference encrypted values.</p>
                <button class="btn btn-primary" onclick="showCreateSecretVarModal()">Create First Secret</button>
            </div>`;
            return;
        }
        container.innerHTML = vars.map((v, i) => `
            <div class="card animate-in" style="animation-delay: ${Math.min(i * 0.06, 0.3)}s; margin-bottom:0.75rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-weight:600;"><code>{{secret.${escapeHtml(v.name)}}}</code></div>
                        <div style="font-size:0.85em; opacity:0.7; margin-top:0.15rem;">${escapeHtml(v.description || '')}</div>
                        <div style="font-size:0.8em; opacity:0.5; margin-top:0.15rem;">Created by ${escapeHtml(v.created_by || 'system')} &bull; ${v.created_at?.replace('T', ' ').substring(0, 16) || ''}</div>
                    </div>
                    <div style="display:flex; gap:0.5rem;">
                        <button class="btn btn-sm btn-secondary" onclick="showEditSecretVarModal(${v.id}, '${escapeHtml(v.name)}', '${escapeHtml(v.description || '')}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteSecretVar(${v.id}, '${escapeHtml(v.name)}')">Delete</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<div class="error">Error: ${escapeHtml(err.message)}</div>`;
    }
}

function showCreateSecretVarModal() {
    showModal('Create Secret Variable', `
        <form id="create-secret-var-form">
            <div class="form-group">
                <label class="form-label">Name</label>
                <input type="text" class="form-input" id="secret-var-name" required
                       pattern="[A-Za-z_][A-Za-z0-9_-]*" maxlength="64"
                       placeholder="e.g. snmp_community_ro">
                <div style="font-size:0.8em; opacity:0.5; margin-top:0.25rem;">Letters, numbers, underscore, hyphen. Referenced as <code>{{secret.name}}</code></div>
            </div>
            <div class="form-group">
                <label class="form-label">Value</label>
                <input type="password" class="form-input" id="secret-var-value" required
                       placeholder="Secret value (encrypted at rest)">
            </div>
            <div class="form-group">
                <label class="form-label">Description (optional)</label>
                <input type="text" class="form-input" id="secret-var-description"
                       placeholder="What this secret is used for">
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Create Secret</button>
        </form>
    `);
    document.getElementById('create-secret-var-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('secret-var-name').value.trim();
        const value = document.getElementById('secret-var-value').value;
        const description = document.getElementById('secret-var-description').value.trim();
        try {
            await api.createSecretVariable(name, value, description);
            closeModal();
            showSuccess(`Secret variable '${name}' created`);
            loadSecretVariables();
        } catch (err) {
            showError(err.message);
        }
    });
}
window.showCreateSecretVarModal = showCreateSecretVarModal;

function showEditSecretVarModal(varId, name, description) {
    showModal(`Edit Secret: ${escapeHtml(name)}`, `
        <form id="edit-secret-var-form">
            <div class="form-group">
                <label class="form-label">Name</label>
                <input type="text" class="form-input" value="${escapeHtml(name)}" disabled>
            </div>
            <div class="form-group">
                <label class="form-label">New Value (leave blank to keep current)</label>
                <input type="password" class="form-input" id="edit-secret-var-value"
                       placeholder="New secret value">
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <input type="text" class="form-input" id="edit-secret-var-description"
                       value="${escapeHtml(description)}">
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Update Secret</button>
        </form>
    `);
    document.getElementById('edit-secret-var-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const value = document.getElementById('edit-secret-var-value').value;
        const desc = document.getElementById('edit-secret-var-description').value.trim();
        const data = {};
        if (value) data.value = value;
        data.description = desc;
        try {
            await api.updateSecretVariable(varId, data);
            closeModal();
            showSuccess(`Secret variable '${name}' updated`);
            loadSecretVariables();
        } catch (err) {
            showError(err.message);
        }
    });
}
window.showEditSecretVarModal = showEditSecretVarModal;

async function deleteSecretVar(varId, name) {
    const confirmed = await showConfirm(
        `Delete secret variable '${escapeHtml(name)}'?`,
        'Any templates referencing {{secret.' + escapeHtml(name) + '}} will fail at execution time.'
    );
    if (!confirmed) return;
    try {
        await api.deleteSecretVariable(varId);
        showSuccess(`Secret variable '${name}' deleted`);
        loadSecretVariables();
    } catch (err) {
        showError(err.message);
    }
}
window.deleteSecretVar = deleteSecretVar;

// Admin Settings -- migrated to modules/settings.js

// ═══════════════════════════════════════════════════════════════════════════════
// Modals
// ═══════════════════════════════════════════════════════════════════════════════

export function showModal(title, content, options = {}) {
    const modal = document.querySelector('#modal-overlay .modal');
    if (modal) {
        const isCodeEditorModal = /playbook|template/i.test(title);
        modal.classList.toggle('modal-large', isCodeEditorModal || options.wide);
    }

    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal-overlay').classList.add('active');
    activateFocusTrap('modal-overlay');
}

export function closeAllModals() {
    const modal = document.querySelector('#modal-overlay .modal');
    if (modal) {
        modal.classList.remove('modal-large');
    }

    document.getElementById('modal-overlay').classList.remove('active');
    document.getElementById('modal-body').innerHTML = '';
    deactivateFocusTrap('modal-overlay');
}

// Expose to window for inline onclick handlers
export const closeModal = closeAllModals;
window.closeAllModals = closeAllModals;
window.closeModal = closeModal;

// ── Copyable Code Block Utilities ────────────────────────────────────────────
export const COPY_ICON_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px; margin-right:4px;"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
let _copyableId = 0;

/**
 * Returns HTML for a <pre> code block with a Copy button.
 * @param {string} text - Raw text (will be escaped)
 * @param {object} [options] - { style, label }
 */
export function copyableCodeBlock(text, options = {}) {
    const id = 'copyable-' + (++_copyableId);
    const style = options.style || 'max-height:400px; overflow:auto; font-size:0.8em; white-space:pre-wrap;';
    const label = options.label || '';
    return `<div class="copyable-block" data-copyable-id="${id}">
        <div style="display:flex; align-items:center; justify-content:${label ? 'space-between' : 'flex-end'}; margin-bottom:0.25rem;">
            ${label ? `<span style="font-weight:600;">${label}</span>` : ''}
            <button class="btn btn-sm btn-secondary copyable-copy-btn" data-copyable-target="${id}" title="Copy to clipboard">${COPY_ICON_SVG}Copy</button>
        </div>
        <pre class="code-block copyable-content" id="${id}" tabindex="0" style="${style}; user-select:text; cursor:text;">${escapeHtml(text)}</pre>
    </div>`;
}

/**
 * Returns HTML wrapping existing rendered content (e.g. a diff) with a Copy button.
 * The raw text is stored in a hidden element for clipboard use.
 * @param {string} innerHtml - Already-rendered HTML to display
 * @param {string} rawText - Plain text to copy to clipboard
 * @param {object} [options] - { style, className }
 */
export function copyableHtmlBlock(innerHtml, rawText, options = {}) {
    const id = 'copyable-' + (++_copyableId);
    const className = options.className || '';
    return `<div class="copyable-block" data-copyable-id="${id}">
        <div style="display:flex; justify-content:flex-end; margin-bottom:0.25rem;">
            <button class="btn btn-sm btn-secondary copyable-copy-btn" data-copyable-target="${id}" title="Copy to clipboard">${COPY_ICON_SVG}Copy</button>
        </div>
        <div class="${className} copyable-content" id="${id}" tabindex="0" style="user-select:text; cursor:text;">${innerHtml}</div>
        <textarea class="copyable-raw" id="${id}-raw" style="display:none;">${escapeHtml(rawText)}</textarea>
    </div>`;
}

/**
 * Wire up all copyable blocks in the DOM (copy buttons + Ctrl+A scoping).
 * Safe to call multiple times — skips already-bound elements.
 */
export function initCopyableBlocks() {
    document.querySelectorAll('.copyable-copy-btn:not([data-copy-bound])').forEach(btn => {
        btn.setAttribute('data-copy-bound', '1');
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-copyable-target');
            // Prefer hidden raw textarea if present (for HTML-rendered blocks)
            const rawEl = document.getElementById(targetId + '-raw');
            const pre = document.getElementById(targetId);
            const text = rawEl ? rawEl.value : (pre ? pre.textContent : '');
            navigator.clipboard.writeText(text).then(() => {
                btn.innerHTML = '&#10003; Copied';
                setTimeout(() => { btn.innerHTML = COPY_ICON_SVG + 'Copy'; }, 2000);
            }).catch(() => {
                if (pre) {
                    const range = document.createRange();
                    range.selectNodeContents(pre);
                    const sel = window.getSelection();
                    sel.removeAllRanges();
                    sel.addRange(range);
                }
                showToast('Press Ctrl+C to copy the selected text', 'info');
            });
        });
    });
    document.querySelectorAll('.copyable-content:not([data-copy-bound])').forEach(el => {
        el.setAttribute('data-copy-bound', '1');
        el.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
                e.preventDefault();
                const range = document.createRange();
                range.selectNodeContents(el);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
            }
        });
    });
}

// Themed confirmation dialog using the app modal styling (also accepts legacy signature showConfirm(title, message))
export function showConfirm(optionsOrTitle = {}) {
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
                        Select entire groups or individual hosts, and/or enter ad-hoc IPs below.
                    </small>
                </div>
                <div class="form-group">
                    <label class="form-label">Ad-Hoc IP Addresses</label>
                    <textarea class="form-input" name="ad_hoc_ips" id="job-adhoc-ips" rows="3"
                        placeholder="Enter IP addresses (one per line or comma-separated)&#10;e.g. 10.0.1.50, 192.168.1.100"
                        style="font-family: monospace; font-size: 0.875rem; resize: vertical;"></textarea>
                    <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                        Target devices not in inventory. These will run as cisco_ios by default.
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
        .filter(id => !isNaN(id));

    // Get ad-hoc IPs from textarea
    const adHocRaw = (formData.get('ad_hoc_ips') || '').trim();
    const adHocIps = adHocRaw
        ? adHocRaw.split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0)
        : [];

    if (hostIds.length === 0 && adHocIps.length === 0) {
        showError('Please select at least one host or enter an IP address');
        return;
    }

    const totalTargets = hostIds.length + adHocIps.length;

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
            null,
            credentialId,
            templateId,
            dryRun,
            hostIds.length > 0 ? hostIds : null,
            priority,
            dependsOn,
            adHocIps.length > 0 ? adHocIps : null
        );
        closeAllModals();
        await loadJobs();
        showSuccess(`Job queued successfully on ${totalTargets} target(s)`);
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
let _configWebSocket = null; // Tracks config-capture/revert WebSockets for cleanup

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
    const runLiveBtn = document.getElementById('job-output-runlive-btn');
    const statusBadge = document.getElementById('job-output-status');
    const priBadge = document.getElementById('job-output-priority');
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (retryBtn) retryBtn.style.display = 'none';
    if (runLiveBtn) runLiveBtn.style.display = 'none';
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
        const isDry = Boolean(job.dry_run);
        const dryrunBadge = document.getElementById('job-output-dryrun');
        if (dryrunBadge) {
            dryrunBadge.textContent = isDry ? 'DRY RUN' : 'LIVE';
            dryrunBadge.style.cssText = isDry
                ? 'background: var(--warning); color: #000; font-weight: 600;'
                : 'background: var(--danger, #dc3545); color: #fff; font-weight: 600;';
            dryrunBadge.style.display = '';
        }
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
        const isFinished = !['running', 'queued'].includes(job.status);
        if (cancelBtn) cancelBtn.style.display = !isFinished ? '' : 'none';
        if (retryBtn) retryBtn.style.display = (job.status === 'failed' || job.status === 'cancelled') ? '' : 'none';
        if (runLiveBtn) runLiveBtn.style.display = (isFinished && isDry) ? '' : 'none';

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
                    if (retryBtn) retryBtn.style.display = (data.status === 'failed' || data.status === 'cancelled') ? '' : 'none';
                    if (runLiveBtn) runLiveBtn.style.display = isDry ? '' : 'none';
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
    if (_configWebSocket) {
        _configWebSocket.close();
        _configWebSocket = null;
    }
    deactivateFocusTrap('job-output-modal');
    _currentViewJobId = null;
};

window.copyJobOutput = function() {
    const output = document.getElementById('job-output');
    if (!output) return;
    const text = output.innerText || '';
    const btn = document.getElementById('job-output-copy-btn');
    navigator.clipboard.writeText(text).then(() => {
        if (btn) { const prev = btn.innerHTML; btn.innerHTML = '&#10003; Copied'; setTimeout(() => { btn.innerHTML = prev; }, 2000); }
    }).catch(() => {
        const range = document.createRange();
        range.selectNodeContents(output);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        showToast('Press Ctrl+C to copy the selected text', 'info');
    });
};

window.cancelCurrentJob = async function() {
    if (!_currentViewJobId) return;
    if (!await showConfirm({ title: 'Cancel Job', message: 'Cancel this job?', confirmText: 'Cancel Job', confirmClass: 'btn-danger' })) return;
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

window.rerunCurrentJobLive = async function() {
    if (!_currentViewJobId) return;
    if (!await showConfirm({
        title: 'Run Live',
        message: 'This will re-run the same job with dry run disabled. Changes will be applied to devices. Continue?',
        confirmText: 'Run Live',
        confirmClass: 'btn-danger',
    })) return;
    const btn = document.getElementById('job-output-runlive-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Launching…'; }
    try {
        const result = await api.rerunJobLive(_currentViewJobId);
        showSuccess(`Live job launched as #${result.job_id}`);
        disconnectJobWebSocket();
        loadJobs();
        viewJobOutput(result.job_id);
    } catch (error) {
        if (btn) { btn.disabled = false; btn.textContent = 'Run Live'; }
        showError('Failed to launch live job: ' + error.message);
    }
};

window.cancelJobFromList = async function(jobId) {
    if (!await showConfirm({ title: 'Cancel Job', message: 'Cancel this job?', confirmText: 'Cancel Job', confirmClass: 'btn-danger' })) return;
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

const _escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const _escapeRe = /[&<>"']/g;
export function escapeHtml(text) {
    if (text == null) return '';
    return String(text).replace(_escapeRe, ch => _escapeMap[ch]);
}

export function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

export function formatTime(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleTimeString();
}

export function formatRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return 'Just now';
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    if (diffDay < 30) return `${diffDay}d ago`;
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
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

export function showToast(message, type = 'info', duration = 4000) {
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

export function showError(message, container = null) {
    if (container) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error';
        errorDiv.textContent = message;
        container.insertBefore(errorDiv, container.firstChild);
    } else {
        showToast(message, 'error', 5000);
    }
}

export function showSuccess(message) {
    showToast(message, 'success', 3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Authentication UI
// ═══════════════════════════════════════════════════════════════════════════════

let currentUser = null;
export let currentUserData = null; // {username, user_id, display_name, role}

function showLoginScreen() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
    document.getElementById('login-error').classList.add('hidden');
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    showLoginForm();
    document.getElementById('login-username').focus();
}

window.showRegisterScreen = function() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
    document.getElementById('register-back').classList.remove('hidden');
    // Hide "Don't have an account?" link
    document.getElementById('login-form').nextElementSibling.classList.add('hidden');
    document.getElementById('register-error').classList.add('hidden');
    document.getElementById('register-username').focus();
};

window.showLoginForm = function() {
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('register-back').classList.add('hidden');
    // Show "Don't have an account?" link
    const registerLink = document.getElementById('login-form').nextElementSibling;
    if (registerLink) registerLink.classList.remove('hidden');
    document.getElementById('login-error').classList.add('hidden');
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
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    const navUserLabel = document.querySelector('#nav-user .nav-user-label');
    if (navUserLabel) navUserLabel.textContent = userData.display_name || userData.username;
    initNavigation();
    applyFeatureVisibility();

    // Enforce first-login password reset before allowing any navigation
    if (userData.must_change_password) {
        showForcePasswordChange();
        return;
    }

    const orderedPages = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials'];
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
        errorEl.classList.add('hidden');

        try {
            const result = await api.login(username, password);
            showApp(result);
        } catch (error) {
            errorEl.textContent = error.message || 'Invalid username or password';
            errorEl.classList.remove('hidden');
        }
    });

    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const displayName = document.getElementById('register-display-name').value;
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;
        const errorEl = document.getElementById('register-error');
        errorEl.classList.add('hidden');

        if (password !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            errorEl.classList.remove('hidden');
            return;
        }

        try {
            const result = await api.register(username, password, displayName);
            showApp(result);
        } catch (error) {
            errorEl.textContent = error.message || 'Registration failed';
            errorEl.classList.remove('hidden');
        }
    });
}

window.showUserMenu = async function() {
    // Load fresh profile data
    try {
        const profile = await api.getProfile();
        currentUserData = profile;

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
        avatar.textContent = displayName.charAt(0).toUpperCase();
        displayNameEl.textContent = displayName;
        usernameEl.textContent = `@${profile.username}`;
        roleEl.textContent = profile.role;
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
        const currentPass = formData.get('current_password');
        const newPass = formData.get('new_password');
        const confirmPass = formData.get('confirm_password');

        if (newPass !== confirmPass) {
            showError('New passwords do not match');
            return;
        }
        if (newPass === currentPass) {
            showError('New password must be different from your current password');
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
            const orderedPages = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials'];
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
        const currentPass = formData.get('current_password');
        const newPass = formData.get('new_password');
        const confirmPass = formData.get('confirm_password');

        if (newPass !== confirmPass) {
            showError('New passwords do not match');
            return;
        }
        if (newPass === currentPass) {
            showError('New password must be different from your current password');
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

function parseRgbVar(rawValue, fallback) {
    const parsed = (rawValue || '').trim().match(/^(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})$/);
    if (!parsed) return fallback;
    return [
        Math.min(255, parseInt(parsed[1], 10)),
        Math.min(255, parseInt(parsed[2], 10)),
        Math.min(255, parseInt(parsed[3], 10)),
    ];
}

function initSpaceStarfield({ canvasId, hostId, baseCount = 90, linkDistance = 0, baseSpeed = 0.06 }) {
    const canvas = document.getElementById(canvasId);
    const host = document.getElementById(hostId);
    if (!canvas || !host) return;

    const ctx = canvas.getContext('2d');
    let animId = null;
    let slowTimer = null;
    let running = false;
    let stars = [];
    let farRGB = [150, 190, 255];
    let nearRGB = [225, 240, 255];

    function updatePalette() {
        const style = getComputedStyle(document.documentElement);
        farRGB = parseRgbVar(style.getPropertyValue('--space-star-far-rgb'), [150, 190, 255]);
        nearRGB = parseRgbVar(style.getPropertyValue('--space-star-near-rgb'), [225, 240, 255]);
    }

    function createStars() {
        const width = canvas.width || 1;
        const height = canvas.height || 1;
        stars = Array.from({ length: baseCount }, (_, i) => {
            const near = i < Math.floor(baseCount * 0.35);
            const speed = near ? baseSpeed * (0.9 + Math.random() * 0.8) : baseSpeed * (0.2 + Math.random() * 0.35);
            return {
                near,
                x: Math.random() * width,
                y: Math.random() * height,
                dx: (Math.random() - 0.5) * speed,
                dy: (Math.random() - 0.5) * speed,
                size: near ? (0.7 + Math.random() * 1.8) : (0.4 + Math.random() * 1.0),
                alpha: near ? (0.3 + Math.random() * 0.55) : (0.15 + Math.random() * 0.35),
                twinkle: Math.random() * Math.PI * 2,
            };
        });
    }

    function resize() {
        canvas.width = canvas.offsetWidth || window.innerWidth;
        canvas.height = canvas.offsetHeight || window.innerHeight;
        updatePalette();
        createStars();
    }

    function wrapStar(star) {
        if (star.x < -4) star.x = canvas.width + 4;
        else if (star.x > canvas.width + 4) star.x = -4;
        if (star.y < -4) star.y = canvas.height + 4;
        else if (star.y > canvas.height + 4) star.y = -4;
    }

    function draw() {
        if (!running) return;

        const intensity = getSpaceIntensityScalar();
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        if (intensity <= 0) {
            if (slowTimer) clearTimeout(slowTimer);
            slowTimer = window.setTimeout(() => {
                animId = requestAnimationFrame(draw);
            }, 320);
            return;
        }

        const moving = !isReducedMotion();
        const px = _spaceFxState.currentX;
        const py = _spaceFxState.currentY;
        const maxStars = Math.max(4, Math.floor(stars.length * intensity));

        for (let i = 0; i < maxStars; i++) {
            const s = stars[i];
            s.twinkle += moving ? 0.02 : 0;
            const twinkleAlpha = 0.75 + Math.sin(s.twinkle) * 0.25;
            const parallaxFactor = s.near ? 0.9 : 0.35;
            const sx = s.x + px * parallaxFactor;
            const sy = s.y + py * parallaxFactor;
            const rgb = s.near ? nearRGB : farRGB;

            ctx.beginPath();
            ctx.arc(sx, sy, s.size * (s.near ? 1 : 0.85), 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${Math.max(0.02, s.alpha * twinkleAlpha * intensity)})`;
            ctx.fill();

            if (moving) {
                s.x += s.dx;
                s.y += s.dy;
                wrapStar(s);
            }
        }

        if (linkDistance > 0) {
            for (let i = 0; i < maxStars; i++) {
                const a = stars[i];
                if (!a.near) continue;
                for (let j = i + 1; j < maxStars; j++) {
                    const b = stars[j];
                    if (!b.near) continue;
                    const dx = a.x - b.x;
                    const dy = a.y - b.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist > linkDistance) continue;
                    const alpha = (1 - dist / linkDistance) * 0.08 * intensity;
                    if (alpha <= 0.002) continue;
                    ctx.beginPath();
                    ctx.moveTo(a.x + px * 0.7, a.y + py * 0.7);
                    ctx.lineTo(b.x + px * 0.7, b.y + py * 0.7);
                    ctx.strokeStyle = `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, ${alpha})`;
                    ctx.lineWidth = 0.55;
                    ctx.stroke();
                }
            }
        }

        // Rare subtle light streak for depth
        if (!isReducedMotion() && Math.random() < 0.0035 * intensity) {
            const streakY = Math.random() * canvas.height;
            const streakX = Math.random() * canvas.width;
            const len = 45 + Math.random() * 130;
            const grad = ctx.createLinearGradient(streakX, streakY, streakX + len, streakY - len * 0.22);
            grad.addColorStop(0, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, 0)`);
            grad.addColorStop(0.45, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, ${0.14 * intensity})`);
            grad.addColorStop(1, `rgba(${nearRGB[0]}, ${nearRGB[1]}, ${nearRGB[2]}, 0)`);
            ctx.beginPath();
            ctx.strokeStyle = grad;
            ctx.lineWidth = 1.1;
            ctx.moveTo(streakX, streakY);
            ctx.lineTo(streakX + len, streakY - len * 0.22);
            ctx.stroke();
        }

        if (moving) {
            animId = requestAnimationFrame(draw);
        } else {
            if (slowTimer) clearTimeout(slowTimer);
            slowTimer = window.setTimeout(() => {
                animId = requestAnimationFrame(draw);
            }, 220);
        }
    }

    function syncRunningState() {
        // Use getComputedStyle to catch CSS-driven display:none (not just inline style)
        const visible = getComputedStyle(host).display !== 'none';
        if (visible && !running) {
            running = true;
            resize();
            animId = requestAnimationFrame(draw);
        } else if (!visible && running) {
            running = false;
            if (animId) cancelAnimationFrame(animId);
            if (slowTimer) clearTimeout(slowTimer);
            animId = null;
            slowTimer = null;
        }
    }

    resize();
    updatePalette();
    window.addEventListener('resize', resize);
    const themeObserver = new MutationObserver(() => {
        updatePalette();
        syncRunningState(); // Re-check visibility — theme CSS may show/hide the host
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    const visibilityObserver = new MutationObserver(syncRunningState);
    visibilityObserver.observe(host, { attributes: true, attributeFilter: ['style'] });
    syncRunningState();

    // Return cleanup function to prevent memory leaks on re-init
    return function destroy() {
        themeObserver.disconnect();
        visibilityObserver.disconnect();
        window.removeEventListener('resize', resize);
        if (animId) cancelAnimationFrame(animId);
        if (slowTimer) clearTimeout(slowTimer);
        running = false;
        animId = null;
        slowTimer = null;
    };
}

let _destroyLoginParticles = null;
function initLoginParticles() {
    if (_destroyLoginParticles) _destroyLoginParticles();
    _destroyLoginParticles = initSpaceStarfield({
        canvasId: 'login-particles',
        hostId: 'login-screen',
        baseCount: 135,
        linkDistance: 125,
        baseSpeed: 0.08,
    });
}

let _destroyAppParticles = null;
function initAppParticles() {
    if (_destroyAppParticles) _destroyAppParticles();
    _destroyAppParticles = initSpaceStarfield({
        canvasId: 'app-particles',
        hostId: 'app-container',
        baseCount: 95,
        linkDistance: 0,
        baseSpeed: 0.055,
    });
}

function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebar-toggle');
    if (!sidebar || !toggle) return;
    const COLLAPSED_KEY = 'plexus-sidebar-collapsed';
    if (localStorage.getItem(COLLAPSED_KEY) === '1') {
        sidebar.classList.add('collapsed');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Expand sidebar');
    }
    toggle.addEventListener('click', () => {
        sidebar.style.willChange = 'width, min-width';
        sidebar.classList.toggle('collapsed');
        const collapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
        toggle.setAttribute('aria-expanded', String(!collapsed));
        toggle.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
        sidebar.addEventListener('transitionend', () => { sidebar.style.willChange = ''; }, { once: true });
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

// Config Drift Detection -- migrated to modules/configuration.js

// ═══════════════════════════════════════════════════════════════════════════════
// Consolidated Page Tab Switching
// ═══════════════════════════════════════════════════════════════════════════════

// Configuration tab switching -- migrated to modules/configuration.js


// Change Management page tabs (Risk Analysis / Deployments)
window.switchChangeTab = function(tab) {
    listViewState.changeManagement.tab = tab;
    document.querySelectorAll('.change-tab-btn').forEach(b => b.classList.toggle('active', b.getAttribute('data-change-tab') === tab));
    document.querySelectorAll('.change-tab').forEach(t => t.style.display = 'none');
    const target = document.getElementById(`change-tab-${tab}`);
    if (target) target.style.display = '';
};

window.refreshChangeManagement = async function() {
    const mod = await _loadModule('change-management');
    await mod.loadRiskAnalysis({ preserveContent: false });
    await mod.loadDeployments({ preserveContent: false });
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
    { page: 'monitoring',   label: 'Monitoring',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' },
    { page: 'configuration', label: 'Configuration', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M12 18v-6"/><path d="M9 15l3 3 3-3"/></svg>' },
    { page: 'compliance',  label: 'Compliance',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>' },
    { page: 'change-management', label: 'Changes', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>' },
    { page: 'reports',     label: 'Reports',       icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' },
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
                if (!document.getElementById('app-container')?.classList.contains('hidden')) {
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
                'job-output-modal': () => window.closeJobOutputModal?.(),
                'user-menu-overlay': () => window.closeUserMenu?.(),
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
                if (!document.getElementById('app-container')?.classList.contains('hidden')) {
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
    let tiltRafPending = false;

    document.addEventListener('mousemove', (e) => {
        if (tiltRafPending) return; // throttle to one update per frame
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (!card || isReducedMotion()) return;

        tiltRafPending = true;
        const clientX = e.clientX;
        const clientY = e.clientY;

        requestAnimationFrame(() => {
            tiltRafPending = false;
            const rect = card.getBoundingClientRect();
            const x = (clientX - rect.left) / rect.width;
            const y = (clientY - rect.top) / rect.height;
            const rotateY = (x - 0.5) * MAX_TILT * 2;
            const rotateX = (0.5 - y) * MAX_TILT * 2;
            card.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-3px)`;
        });
    }, { passive: true });

    document.addEventListener('mouseleave', (e) => {
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (card) card.style.transform = '';
    }, { capture: true, passive: true });
    document.addEventListener('mouseout', (e) => {
        if (!e.target || !e.target.closest) return;
        const card = e.target.closest('.card, .stat-card');
        if (!card) return;
        if (!card.contains(e.relatedTarget)) {
            card.style.transform = '';
        }
    }, { passive: true });
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
};

function getEmptyIllustration(type) {
    return EMPTY_ILLUSTRATIONS[type] || EMPTY_ILLUSTRATIONS.default;
}

export function emptyStateHTML(message, type, actionBtn) {
    return `<div class="empty-state">
        <div class="empty-state-illustration">${getEmptyIllustration(type)}</div>
        <div class="empty-state-title">${message}</div>
        <div class="empty-state-text">Get started by creating your first ${type.replace(/s$/, '')}.</div>
        ${actionBtn || ''}
    </div>`;
}

// Config Backups -- migrated to modules/configuration.js


// Compliance -- migrated to modules/compliance.js

// Risk Analysis -- migrated to modules/change-management.js

// Real-Time Monitoring + SLA -- migrated to modules/monitoring.js

// Preserved utility functions imported by modules
export function formatUptime(seconds) {
    if (seconds == null) return 'N/A';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

export function formatMinutes(m) {
    if (m == null) return '-';
    if (m < 1) return '<1m';
    if (m < 60) return Math.round(m) + 'm';
    const h = Math.floor(m / 60);
    const rem = Math.round(m % 60);
    return rem > 0 ? `${h}h ${rem}m` : `${h}h`;
}

export function getHostSlaCompliance(host, targets) {
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

// Deployments / Rollback Orchestration -- migrated to modules/change-management.js
// ═══════════════════════════════════════════════════════════════════════════════
// Capacity Planning Page -- migrated to modules/reports.js


// Availability Tracking Page -- migrated to modules/reports.js

export function formatDuration(seconds) {
    if (seconds == null) return '-';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h < 24) return m > 0 ? `${h}h ${m}m` : `${h}h`;
    const d = Math.floor(h / 24);
    const rh = h % 24;
    return rh > 0 ? `${d}d ${rh}h` : `${d}d`;
}


// Syslog Events Page -- migrated to modules/reports.js

// ═══════════════════════════════════════════════════════════════════════════════
// Custom OID Profiles Page
// ═══════════════════════════════════════════════════════════════════════════════

async function loadOidProfiles(options = {}) {
    const { preserveContent = false } = options;
    const container = document.getElementById('oid-profiles-list');
    if (!preserveContent && container) container.innerHTML = skeletonCards(2);
    try {
        const vendor = document.getElementById('oid-vendor-filter')?.value || '';
        const result = await api.getOidProfiles(vendor || null);
        const profiles = result?.profiles || result || [];

        // Populate vendor filter
        const vendorSelect = document.getElementById('oid-vendor-filter');
        if (vendorSelect && vendorSelect.options.length <= 1) {
            const vendors = [...new Set(profiles.map(p => p.vendor).filter(Boolean))];
            vendors.forEach(v => {
                const opt = document.createElement('option');
                opt.value = v;
                opt.textContent = v;
                vendorSelect.appendChild(opt);
            });
        }

        if (container) {
            if (!profiles.length) {
                container.innerHTML = '<div class="card" style="padding:1.5rem;"><p class="text-muted">No custom OID profiles. Click "+ New Profile" to create one.</p></div>';
            } else {
                container.innerHTML = profiles.map(p => {
                    let oidCount = 0;
                    try { oidCount = JSON.parse(p.oids_json || '[]').length; } catch (_) {}
                    return `<div class="card" style="padding:1rem; margin-bottom:0.75rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <strong>${escapeHtml(p.name)}</strong>
                                ${p.vendor ? `<span class="badge badge-info" style="margin-left:0.5rem;">${escapeHtml(p.vendor)}</span>` : ''}
                                ${p.device_type ? `<span class="text-muted" style="margin-left:0.5rem;">${escapeHtml(p.device_type)}</span>` : ''}
                                ${p.is_default ? '<span class="badge badge-success" style="margin-left:0.5rem;">Default</span>' : ''}
                            </div>
                            <div style="display:flex; gap:0.5rem;">
                                <button class="btn btn-sm btn-secondary" onclick="editOidProfile(${p.id})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteOidProfile(${p.id})">Delete</button>
                            </div>
                        </div>
                        <div class="text-muted" style="font-size:0.85em; margin-top:0.25rem;">
                            ${escapeHtml(p.description || '')} &middot; ${oidCount} OID mapping${oidCount !== 1 ? 's' : ''}
                        </div>
                    </div>`;
                }).join('');
            }
        }

        // Built-in vendor defaults (informational)
        const defaultsEl = document.getElementById('vendor-oid-defaults-list');
        if (defaultsEl) {
            defaultsEl.innerHTML = `<div class="card" style="padding:1rem;">
                <p class="text-muted" style="margin-bottom:0.75rem;">These OIDs are polled automatically based on device type detection.</p>
                <table class="chart-table">
                    <thead><tr><th>Vendor</th><th>Metric</th><th>OID</th></tr></thead>
                    <tbody>
                        <tr><td>Cisco IOS</td><td>CPU 5min</td><td>1.3.6.1.4.1.9.9.109.1.1.1.1.8</td></tr>
                        <tr><td>Cisco IOS</td><td>Memory Used</td><td>1.3.6.1.4.1.9.9.48.1.1.1.5</td></tr>
                        <tr><td>Juniper</td><td>CPU</td><td>1.3.6.1.4.1.2636.3.1.13.1.8</td></tr>
                        <tr><td>Juniper</td><td>Memory</td><td>1.3.6.1.4.1.2636.3.1.13.1.11</td></tr>
                        <tr><td>Arista</td><td>CPU</td><td>1.3.6.1.2.1.25.3.3.1.2</td></tr>
                        <tr><td>Generic</td><td>sysUpTime</td><td>1.3.6.1.2.1.1.3.0</td></tr>
                        <tr><td>Generic</td><td>ifHCInOctets</td><td>1.3.6.1.2.1.31.1.1.1.6</td></tr>
                        <tr><td>Generic</td><td>ifHCOutOctets</td><td>1.3.6.1.2.1.31.1.1.1.10</td></tr>
                    </tbody>
                </table>
            </div>`;
        }
    } catch (error) {
        if (container) container.innerHTML = `<div class="card" style="color:var(--danger)">Error loading OID profiles: ${escapeHtml(error.message)}</div>`;
    }
}
window.loadOidProfiles = loadOidProfiles;

function showCreateOidProfile() {
    ensureModalDOM('oid-profile-modal', templateOidProfileModal);
    document.getElementById('oid-profile-edit-id').value = '';
    document.getElementById('oid-profile-modal-title').textContent = 'New OID Profile';
    document.getElementById('oid-profile-name').value = '';
    document.getElementById('oid-profile-vendor').value = '';
    document.getElementById('oid-profile-device-type').value = '';
    document.getElementById('oid-profile-description').value = '';
    document.getElementById('oid-profile-oids').value = '[\n  {"oid": "", "metric_name": "", "label": "", "type": "gauge"}\n]';
    document.getElementById('oid-profile-modal').style.display = '';
}
window.showCreateOidProfile = showCreateOidProfile;

async function editOidProfile(profileId) {
    ensureModalDOM('oid-profile-modal', templateOidProfileModal);
    try {
        const profile = await api.getOidProfile(profileId);
        document.getElementById('oid-profile-edit-id').value = profile.id;
        document.getElementById('oid-profile-modal-title').textContent = 'Edit OID Profile';
        document.getElementById('oid-profile-name').value = profile.name || '';
        document.getElementById('oid-profile-vendor').value = profile.vendor || '';
        document.getElementById('oid-profile-device-type').value = profile.device_type || '';
        document.getElementById('oid-profile-description').value = profile.description || '';
        document.getElementById('oid-profile-oids').value = profile.oids_json || '[]';
        document.getElementById('oid-profile-modal').style.display = '';
    } catch (e) { showError(e.message); }
}
window.editOidProfile = editOidProfile;

async function saveOidProfile() {
    const editId = document.getElementById('oid-profile-edit-id').value;
    const data = {
        name: document.getElementById('oid-profile-name').value.trim(),
        vendor: document.getElementById('oid-profile-vendor').value.trim(),
        device_type: document.getElementById('oid-profile-device-type').value.trim(),
        description: document.getElementById('oid-profile-description').value.trim(),
        oids_json: document.getElementById('oid-profile-oids').value.trim(),
    };
    if (!data.name) { showError('Profile name is required'); return; }
    // Validate JSON
    try { JSON.parse(data.oids_json); } catch (_) { showError('Invalid OID JSON'); return; }
    try {
        if (editId) {
            await api.updateOidProfile(editId, data);
            showSuccess('OID profile updated');
        } else {
            await api.createOidProfile(data);
            showSuccess('OID profile created');
        }
        closeOidProfileModal();
        loadOidProfiles();
    } catch (e) { showError(e.message); }
}
window.saveOidProfile = saveOidProfile;

function closeOidProfileModal() {
    document.getElementById('oid-profile-modal').style.display = 'none';
}
window.closeOidProfileModal = closeOidProfileModal;

async function deleteOidProfile(profileId) {
    if (!await showConfirm({ title: 'Delete OID Profile', message: 'Delete this OID profile?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
    try {
        await api.deleteOidProfile(profileId);
        showSuccess('OID profile deleted');
        loadOidProfiles();
    } catch (e) { showError(e.message); }
}
window.deleteOidProfile = deleteOidProfile;

// Reports & Export Page -- migrated to modules/reports.js

// ═══════════════════════════════════════════════════════════════════════════════
// Device Syslog Tab
// ═══════════════════════════════════════════════════════════════════════════════

async function renderDeviceSyslogTab(hostId) {
    const container = document.getElementById('device-syslog-events');
    if (!container) return;
    try {
        const events = await api.getSyslogEvents({ hostId, limit: 100 });
        const items = events?.events || events || [];
        if (!items.length) {
            container.innerHTML = '<p class="text-muted">No syslog events for this device</p>';
            return;
        }
        container.innerHTML = `<table class="chart-table">
            <thead><tr><th>Time</th><th>Severity</th><th>Message</th></tr></thead>
            <tbody>${items.map(e => {
                const sevClass = ['emergency', 'alert', 'critical'].includes(e.severity) ? 'danger' : e.severity === 'error' ? 'danger' : e.severity === 'warning' ? 'warning' : 'info';
                return `<tr>
                    <td style="white-space:nowrap;">${e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}</td>
                    <td><span class="badge badge-${sevClass}">${escapeHtml(e.severity || '-')}</span></td>
                    <td>${escapeHtml(e.message || e.event_data || '-')}</td>
                </tr>`;
            }).join('')}</tbody>
        </table>`;
    } catch (e) {
        container.innerHTML = '<p class="text-muted">Could not load syslog events</p>';
    }
}

// Graph Templates Page (Cacti-parity) -- migrated to modules/reports.js

// ── Hash-based routing: back/forward button support ─────────────────────────
window.addEventListener('popstate', () => {
    const page = getPageFromHash();
    if (page && page !== currentPage && !document.getElementById('app-container')?.classList.contains('hidden')) {
        navigateToPage(page, { updateHash: false });
    }
});

// ═════════════════════════════════════════════════════════════════════════════
// MAC/ARP Tracking Page
// ═════════════════════════════════════════════════════════════════════════════

async function loadMacTrackingPage({ preserveContent } = {}) {
    const resultsEl = document.getElementById('mac-tracking-results');
    const emptyEl = document.getElementById('mac-tracking-empty');
    if (!preserveContent && resultsEl) resultsEl.innerHTML = '';
    if (emptyEl) emptyEl.style.display = (!resultsEl || !resultsEl.innerHTML) ? '' : 'none';
}

async function searchMacTrackingUI() {
    const query = document.getElementById('mac-tracking-search')?.value?.trim();
    if (!query) return;
    const resultsEl = document.getElementById('mac-tracking-results');
    const emptyEl = document.getElementById('mac-tracking-empty');
    if (!resultsEl) return;

    resultsEl.innerHTML = '<div class="skeleton-loader" style="height:200px;"></div>';
    if (emptyEl) emptyEl.style.display = 'none';

    try {
        const results = await api.searchMacTracking(query);
        if (!results || results.length === 0) {
            resultsEl.innerHTML = '<div class="glass-card card" style="text-align:center; padding:2rem; opacity:0.7;">No results found for "' + escapeHtml(query) + '"</div>';
            return;
        }
        const fmtTime = (t) => t ? new Date(t).toLocaleString() : '-';
        resultsEl.innerHTML = `
            <div class="glass-card card" style="overflow-x:auto;">
                <table class="data-table" style="width:100%;">
                    <thead><tr>
                        <th>MAC Address</th><th>IP Address</th><th>Switch</th><th>Port</th>
                        <th>VLAN</th><th>Type</th><th>First Seen</th><th>Last Seen</th><th></th>
                    </tr></thead>
                    <tbody>
                    ${results.map(r => `<tr>
                        <td><code style="font-size:0.85em;">${escapeHtml(r.mac_address || '-')}</code></td>
                        <td>${escapeHtml(r.ip_address || '-')}</td>
                        <td>${escapeHtml(r.hostname || 'host-' + r.host_id)}</td>
                        <td>${escapeHtml(r.port_name || '-')}</td>
                        <td>${escapeHtml(String(r.vlan || '-'))}</td>
                        <td><span class="badge badge-sm">${escapeHtml(r.entry_type || 'dynamic')}</span></td>
                        <td style="font-size:0.85em;">${fmtTime(r.first_seen)}</td>
                        <td style="font-size:0.85em;">${fmtTime(r.last_seen)}</td>
                        <td><button class="btn btn-sm" onclick="showMacHistory('${escapeHtml(r.mac_address)}')">History</button></td>
                    </tr>`).join('')}
                    </tbody>
                </table>
                <div style="margin-top:0.5rem; font-size:0.85em; opacity:0.6;">${results.length} result(s)</div>
            </div>`;
    } catch (err) {
        resultsEl.innerHTML = '<div class="glass-card card" style="color:var(--danger);">Search error: ' + escapeHtml(err.message) + '</div>';
    }
}

async function showMacHistory(macAddress) {
    try {
        const history = await api.getMacHistory(macAddress);
        if (!history || history.length === 0) {
            showToast('No movement history found for ' + macAddress, 'info');
            return;
        }
        const fmtTime = (t) => t ? new Date(t).toLocaleString() : '-';
        const content = `
            <div style="max-height:400px; overflow-y:auto;">
                <h4>Movement History: <code>${escapeHtml(macAddress)}</code></h4>
                <table class="data-table" style="width:100%;">
                    <thead><tr><th>Time</th><th>Switch</th><th>Port</th><th>VLAN</th><th>IP</th></tr></thead>
                    <tbody>
                    ${history.map(h => `<tr>
                        <td style="font-size:0.85em;">${fmtTime(h.seen_at)}</td>
                        <td>${escapeHtml(h.hostname || 'host-' + h.host_id)}</td>
                        <td>${escapeHtml(h.port_name || '-')}</td>
                        <td>${escapeHtml(String(h.vlan || '-'))}</td>
                        <td>${escapeHtml(h.ip_address || '-')}</td>
                    </tr>`).join('')}
                    </tbody>
                </table>
            </div>`;
        showModal('MAC History', content);
    } catch (err) {
        showToast('Failed to load history: ' + err.message, 'error');
    }
}

async function triggerMacCollectionUI() {
    showToast('Starting MAC/ARP collection...', 'info');
    try {
        const result = await api.triggerMacCollection();
        showToast(`Collected ${result.macs_found || 0} MACs, ${result.arps_found || 0} ARPs from ${result.hosts_collected || 1} host(s)`, 'success');
    } catch (err) {
        showToast('Collection failed: ' + err.message, 'error');
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Traffic Analysis Page (NetFlow / sFlow / IPFIX)
// ═════════════════════════════════════════════════════════════════════════════

async function loadTrafficAnalysis({ preserveContent } = {}) {
    const hours = parseInt(document.getElementById('traffic-time-range')?.value || '6');

    // Load flow status
    try {
        const status = await api.getFlowStatus();
        const badge = document.getElementById('flow-collector-status');
        if (badge) {
            badge.textContent = status.running ? 'Collector Running' : 'Collector Stopped';
            badge.className = 'badge ' + (status.running ? 'badge-success' : 'badge-warning');
        }
    } catch (e) { /* ignore */ }

    // Load data in parallel
    const [topSrc, topDst, topApps, topConvos, timeline] = await Promise.allSettled([
        api.getFlowTopTalkers({ hours, direction: 'src', limit: 15 }),
        api.getFlowTopTalkers({ hours, direction: 'dst', limit: 15 }),
        api.getFlowTopApplications({ hours, limit: 15 }),
        api.getFlowTopConversations({ hours, limit: 15 }),
        api.getFlowTimeline({ hours, bucketMinutes: hours <= 1 ? 1 : hours <= 6 ? 5 : 15 }),
    ]);

    const emptyEl = document.getElementById('traffic-analysis-empty');
    const contentEl = document.getElementById('traffic-analysis-content');

    const hasData = [topSrc, topDst, topApps, topConvos].some(
        r => r.status === 'fulfilled' && r.value && r.value.length > 0
    );

    if (!hasData) {
        if (emptyEl) emptyEl.style.display = '';
        if (contentEl) contentEl.style.display = 'none';
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    if (contentEl) contentEl.style.display = '';

    const fmtBytes = (b) => {
        if (!b || b === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(b) / Math.log(1024));
        return (b / Math.pow(1024, i)).toFixed(1) + ' ' + units[Math.min(i, units.length - 1)];
    };

    // Render top sources
    const srcEl = document.getElementById('traffic-top-src');
    if (srcEl && topSrc.status === 'fulfilled' && topSrc.value?.length) {
        srcEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>IP</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topSrc.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (srcEl) { srcEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top destinations
    const dstEl = document.getElementById('traffic-top-dst');
    if (dstEl && topDst.status === 'fulfilled' && topDst.value?.length) {
        dstEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>IP</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topDst.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (dstEl) { dstEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top applications
    const appsEl = document.getElementById('traffic-top-apps');
    if (appsEl && topApps.status === 'fulfilled' && topApps.value?.length) {
        appsEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>Service</th><th>Port</th><th>Proto</th><th>Traffic</th></tr></thead>
            <tbody>${topApps.value.slice(0, 10).map(r => `<tr>
                <td>${escapeHtml(r.service_name || '-')}</td><td>${r.port}</td><td>${escapeHtml(r.protocol_name || String(r.protocol))}</td><td>${fmtBytes(r.total_bytes)}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (appsEl) { appsEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render top conversations
    const convosEl = document.getElementById('traffic-top-convos');
    if (convosEl && topConvos.status === 'fulfilled' && topConvos.value?.length) {
        convosEl.innerHTML = `<table class="data-table" style="width:100%; font-size:0.85em;">
            <thead><tr><th>Source</th><th>Destination</th><th>Traffic</th><th>Flows</th></tr></thead>
            <tbody>${topConvos.value.slice(0, 10).map(r => `<tr>
                <td><code>${escapeHtml(r.src_ip)}</code></td><td><code>${escapeHtml(r.dst_ip)}</code></td><td>${fmtBytes(r.total_bytes)}</td><td>${r.flow_count}</td>
            </tr>`).join('')}</tbody></table>`;
    } else if (convosEl) { convosEl.innerHTML = '<div style="opacity:0.5; text-align:center; padding:1rem;">No data</div>'; }

    // Render traffic timeline chart
    const chartEl = document.getElementById('traffic-timeline-chart');
    if (chartEl && timeline.status === 'fulfilled' && timeline.value?.length) {
        const data = timeline.value;
        PlexusChart.bar(
            'traffic-timeline-chart',
            data.map(d => d.bucket?.substring(11, 16) || ''),
            data.map(d => d.total_bytes || 0),
            { rotateLabels: 45 }
        );
    }
}


// ═════════════════════════════════════════════════════════════════════════════
// IOS-XE Upgrade Tool
// ═════════════════════════════════════════════════════════════════════════════

let _upgradeCurrentTab = 'campaigns';

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

async function loadUpgradesPage({ preserveContent } = {}) {
    if (_upgradeCurrentTab === 'images') {
        await loadUpgradeImages();
    } else if (_upgradeCurrentTab === 'backups') {
        await loadUpgradeBackups();
    } else {
        await loadUpgradeCampaigns();
    }
}

// ── Config Backups ──────────────────────────────────────────────────────────

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

// ── Campaign List ───────────────────────────────────────────────────────────

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

// ── Image Library ───────────────────────────────────────────────────────────

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

// ── Upload Image Modal ──────────────────────────────────────────────────────

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

// ── Create Campaign Modal ───────────────────────────────────────────────────

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

// ── Campaign Detail View ────────────────────────────────────────────────────

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


document.addEventListener('DOMContentLoaded', async () => {
    initThemeControls();
    initPerformanceMode();
    initSpaceControls();
    initSidebar();
    initTimeRangeBar();
    initLoginParticles();
    initAppParticles();
    initLoginForm();
    // initListPageControls is now called in navigateToPage() after ensurePageDOM()
    initKeyboardShortcuts();
    initCopyableBlocks();
    // Card tilt disabled — it interfered with clicking on inventory items

    // Window globals for lazily-loaded module functions are registered inside
    // each module file when it's first imported. No need to register them here.

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

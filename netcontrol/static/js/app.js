/**
 * Main Application Logic
 */

import * as api from './api.js';
import { getCsrfToken, setCsrfToken } from './api.js';
import { connectJobWebSocket, disconnectJobWebSocket, connectUpgradeWebSocket, disconnectUpgradeWebSocket } from './websocket.js';
import { ensurePageDOM, ensureModalDOM } from './page-templates.js';

// Global state
let currentPage = 'dashboard';
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
    'cloud-visibility': 'topology',
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
const CACHEABLE_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'settings', 'topology', 'cloud-visibility', 'configuration', 'graph-templates', 'mac-tracking', 'traffic-analysis', 'upgrades'];
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
    configBackups: {
        policies: [],
        backups: [],
        query: '',
        tab: 'policies',
        search: {
            query: '',
            mode: 'fulltext',
            limit: 50,
            contextLines: 1,
            results: [],
            hasMore: false,
            searched: false,
            searching: false,
            activeMode: 'fulltext',
        },
    },
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
    loadPageData(currentPage, { force: true });
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

// navigateToDeviceDetail is exported here because monitoring.js and
// topology.js import it from app.js.
export function navigateToDeviceDetail(hostId) {
    listViewState.deviceDetail.hostId = hostId;
    listViewState.deviceDetail.tab = 'overview';
    navigateToPage('device-detail');
}
window.navigateToDeviceDetail = navigateToDeviceDetail;


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
    if (String(currentUserData?.role || '').toLowerCase() === 'admin') return true;
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
        settingsLink.style.display = String(currentUserData?.role || '').toLowerCase() === 'admin' ? '' : 'none';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Navigation
// ═══════════════════════════════════════════════════════════════════════════════

// Map child pages to their nav-group id for auto-expand
const NAV_GROUP_CHILDREN = {
    'topology': 'network',
    'cloud-visibility': 'network',
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

const VALID_PAGES = ['dashboard', 'inventory', 'playbooks', 'jobs', 'templates', 'credentials', 'topology', 'cloud-visibility', 'monitoring', 'configuration', 'settings', 'device-detail', 'compliance', 'change-management', 'reports', 'graph-templates', 'mac-tracking', 'traffic-analysis', 'upgrades'];

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
    'cloud-visibility': 'Cloud Visibility',
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
    'cloud-visibility': 'dashboard',
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
    'cloud-visibility': {
        title: 'Hybrid Cloud Network Visibility',
        text: 'Track AWS/Azure/GCP network constructs alongside on-prem devices. Manage cloud accounts, refresh topology snapshots, and view cloud and hybrid connectivity paths.'
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
        text: 'Generate and export availability, compliance, utilization, and network documentation reports. View syslog events and SNMP traps. Manage custom OID profiles for monitoring.'
    },
    'graph-templates': {
        title: 'Graph Templates & Auto-Graphing',
        text: 'Manage reusable graph definitions that auto-apply to devices. Create host templates to map device types to graphs, and organize with graph trees for hierarchical navigation.'
    },
    'mac-tracking': {
        title: 'MAC & ARP Table Tracking',
        text: 'Search and browse MAC address and ARP tables collected from network devices. Track where hosts are connected and trace MAC-to-IP mappings across the network.'
    },
    'traffic-analysis': {
        title: 'Traffic Analysis',
        text: 'Analyze network traffic patterns, interface utilization, and bandwidth trends. Identify top talkers and spot congestion before it impacts users.'
    },
    upgrades: {
        title: 'IOS-XE Upgrade Management',
        text: 'Plan and execute firmware upgrades across your network devices. Stage images, schedule maintenance windows, and track upgrade campaigns with rollback support.'
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
    'cloud-visibility': 'destroyCloudVisibility',
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
        'cloud-visibility': () => import('./modules/cloud-visibility.js'),
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
            case 'cloud-visibility':
                await mod.loadCloudVisibility({ preserveContent });
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

export function isReducedMotion() {
    return document.body.classList.contains('reduced-motion');
}


export function skeletonCards(count = 3) {
    return Array.from({length: count}, () =>
        '<div class="skeleton skeleton-card" style="margin-bottom: 0.75rem;"></div>'
    ).join('');
}


export function textMatch(value, query) {
    if (!query) return true;
    return String(value || '').toLowerCase().includes(query);
}

export function byNameAsc(a, b) {
    return String(a.name || '').localeCompare(String(b.name || ''));
}

export function byNameDesc(a, b) {
    return String(b.name || '').localeCompare(String(a.name || ''));
}

function bindListControl(id, handler) {
    const el = document.getElementById(id);
    if (!el || el.dataset.bound === '1') return;
    el.dataset.bound = '1';
    el.addEventListener('input', handler);
    el.addEventListener('change', handler);
}

function initListPageControls() {
    // Handlers resolve filter/render functions from their loaded modules at call time.
    // By the time a user interacts with a search/sort control the module is loaded.
    const inv = () => _moduleCache['inventory'];
    const jobs = () => _moduleCache['playbooks'] || _moduleCache['jobs'];

    // Inventory search & sort
    bindListControl('inventory-search', debounce((e) => {
        listViewState.inventory.query = e.target.value;
        const m = inv(); if (m) m.renderInventoryGroups(m.applyInventoryFilters());
    }, 300));
    bindListControl('inventory-sort', (e) => {
        listViewState.inventory.sort = e.target.value;
        const m = inv(); if (m) m.renderInventoryGroups(m.applyInventoryFilters());
    });

    // Playbooks search & sort
    bindListControl('playbooks-search', debounce((e) => {
        listViewState.playbooks.query = e.target.value;
        const m = jobs(); if (m) m.renderPlaybooksList(m.applyPlaybookFilters());
    }, 300));
    bindListControl('playbooks-sort', (e) => {
        listViewState.playbooks.sort = e.target.value;
        const m = jobs(); if (m) m.renderPlaybooksList(m.applyPlaybookFilters());
    });

    // Jobs search, sort & filters
    bindListControl('jobs-search', debounce((e) => {
        listViewState.jobs.query = e.target.value;
        const m = jobs(); if (m) m.renderJobsList(m.applyJobFilters());
    }, 300));
    bindListControl('jobs-sort', (e) => {
        listViewState.jobs.sort = e.target.value;
        const m = jobs(); if (m) m.renderJobsList(m.applyJobFilters());
    });
    bindListControl('jobs-status-filter', (e) => {
        listViewState.jobs.status = e.target.value;
        const m = jobs(); if (m) m.renderJobsList(m.applyJobFilters());
    });
    bindListControl('jobs-dryrun-filter', (e) => {
        listViewState.jobs.dryRun = e.target.value;
        const m = jobs(); if (m) m.renderJobsList(m.applyJobFilters());
    });
    bindListControl('jobs-date-filter', (e) => {
        listViewState.jobs.dateRange = e.target.value;
        const m = jobs(); if (m) m.renderJobsList(m.applyJobFilters());
    });

    // Templates search & sort
    bindListControl('templates-search', debounce((e) => {
        listViewState.templates.query = e.target.value;
        const m = jobs(); if (m) m.renderTemplatesList(m.applyTemplateFilters());
    }, 300));
    bindListControl('templates-sort', (e) => {
        listViewState.templates.sort = e.target.value;
        const m = jobs(); if (m) m.renderTemplatesList(m.applyTemplateFilters());
    });

    // Credentials search & sort
    bindListControl('credentials-search', debounce((e) => {
        listViewState.credentials.query = e.target.value;
        const m = jobs(); if (m) m.renderCredentialsList(m.applyCredentialFilters());
    }, 300));
    bindListControl('credentials-sort', (e) => {
        listViewState.credentials.sort = e.target.value;
        const m = jobs(); if (m) m.renderCredentialsList(m.applyCredentialFilters());
    });
}

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
    currentUserData = {
        ...userData,
        role: String(userData?.role || '').toLowerCase(),
    };
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
        currentUserData = {
            ...profile,
            role: String(profile?.role || '').toLowerCase(),
        };

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
        roleEl.textContent = String(profile.role || '').toLowerCase();
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
                <input type="password" class="form-input" name="new_password" required minlength="8">
            </div>
            <div class="form-group">
                <label class="form-label">Confirm New Password</label>
                <input type="password" class="form-input" name="confirm_password" required minlength="8">
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
                <input type="password" class="form-input" name="new_password" required minlength="8">
            </div>
            <div class="form-group">
                <label class="form-label">Confirm New Password</label>
                <input type="password" class="form-input" name="confirm_password" required minlength="8">
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
// Keyboard Shortcuts & Command Palette
// ═══════════════════════════════════════════════════════════════════════════════

const COMMAND_PALETTE_PAGES = [
    { page: 'dashboard',   label: 'Dashboard',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>' },
    { page: 'inventory',   label: 'Inventory',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>' },
    { page: 'playbooks',   label: 'Playbooks',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>' },
    { page: 'jobs',        label: 'Jobs',         icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>' },
    { page: 'templates',   label: 'Templates',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>' },
    { page: 'credentials', label: 'Credentials',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>' },
    { page: 'cloud-visibility', label: 'Cloud Visibility', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.5 19H9a4 4 0 1 1 .8-7.92A5 5 0 0 1 19 13a3 3 0 0 1-1.5 6z"/><path d="M3 19h6"/></svg>' },
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
        if (item.page === 'settings' && String(currentUserData?.role || '').toLowerCase() !== 'admin') return false;
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

// Re-export emptyStateHTML from page-templates (moved there with SVG illustrations)
export { emptyStateHTML } from './page-templates.js';

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

export function rangeToMs(range) {
    const units = { h: 3600000, d: 86400000 };
    const m = /^(\d+)([hd])$/.exec(range);
    return m ? parseInt(m[1]) * units[m[2]] : 86400000;
}

export function formatInterval(seconds) {
    if (seconds == null) return '-';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) { const m = Math.floor(seconds / 60); return m === 1 ? '1 minute' : `${m} minutes`; }
    if (seconds < 86400) { const h = Math.floor(seconds / 3600); return h === 1 ? '1 hour' : `${h} hours`; }
    const d = Math.floor(seconds / 86400);
    return d === 1 ? '1 day' : `${d} days`;
}

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


// ── Hash-based routing: back/forward button support ─────────────────────────
window.addEventListener('popstate', () => {
    const page = getPageFromHash();
    if (page && page !== currentPage && !document.getElementById('app-container')?.classList.contains('hidden')) {
        navigateToPage(page, { updateHash: false });
    }
});

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

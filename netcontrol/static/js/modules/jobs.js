/**
 * Jobs Module — Jobs, Playbooks, Templates, Credentials, Secret Variables
 * page loaders, CRUD form modals, and Job Output Viewer.
 * Lazy-loaded when user navigates to #jobs, #playbooks, #templates, or #credentials
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast, formatDate, formatTime,
    showModal, closeAllModals, closeModal, showConfirm, navigateToPage,
    skeletonCards, emptyStateHTML, debounce, initCopyableBlocks,
    _groupCache, _hostCache,
    activateFocusTrap, deactivateFocusTrap,
    COPY_ICON_SVG
} from '../app.js';
import { connectJobWebSocket, disconnectJobWebSocket } from '../websocket.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers (local copies to avoid exporting from app.js)
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// Dynamic import helper for inventory reload
// ═══════════════════════════════════════════════════════════════════════════════

async function reloadInventory() {
    const { loadInventory } = await import('./inventory.js');
    await loadInventory();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Filter Functions
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Inventory Groups & Hosts
// (These call reloadInventory() via dynamic import to avoid circular deps)
// ═══════════════════════════════════════════════════════════════════════════════

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
        await reloadInventory();
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
        await reloadInventory();
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
            await reloadInventory();
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
        await reloadInventory();
        showSuccess('Host added successfully');
    } catch (error) {
        showError(`Failed to add host: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Launch Job
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Templates
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Credentials
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Playbooks
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Delete (Inventory)
// ═══════════════════════════════════════════════════════════════════════════════

window.deleteGroup = async function(groupId) {
    if (!await showConfirm('Delete Group', 'This will remove the group and all its hosts. This action cannot be undone.')) return;
    try {
        await api.deleteGroup(groupId);
        await reloadInventory();
        showSuccess('Group deleted successfully');
    } catch (error) {
        showError(`Failed to delete group: ${error.message}`);
    }
};

window.deleteHost = async function(groupId, hostId) {
    if (!await showConfirm('Delete Host', 'This will permanently remove this host from the inventory.')) return;
    try {
        await api.deleteHost(groupId, hostId);
        await reloadInventory();
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
        await reloadInventory();
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
        await reloadInventory();
        showSuccess(`${hostIds.length} host(s) moved.`);
    } catch (error) {
        showError(`Failed to move hosts: ${error.message}`);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CRUD Forms — Delete (Templates, Credentials)
// ═══════════════════════════════════════════════════════════════════════════════

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
// Cleanup / Destroy
// ═══════════════════════════════════════════════════════════════════════════════

function destroyJobs() {
    disconnectJobWebSocket();
    _currentViewJobId = null;
    _credentialCurrentTab = 'credentials';
    listViewState.jobs.items = [];
    listViewState.jobs.query = '';
    listViewState.playbooks.items = [];
    listViewState.playbooks.query = '';
    listViewState.templates.items = [];
    listViewState.templates.query = '';
    listViewState.credentials.items = [];
    listViewState.credentials.query = '';
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════════════════════

export {
    loadPlaybooks, loadJobs, loadTemplates, loadCredentials,
    renderPlaybooksList, renderJobsList, renderTemplatesList, renderCredentialsList,
    JOB_PRIORITY_LABELS, JOB_PRIORITY_COLORS,
    destroyJobs
};

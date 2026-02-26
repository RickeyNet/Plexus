/**
 * Main Application Logic
 */

import * as api from './api.js';
import { connectJobWebSocket, disconnectJobWebSocket } from './websocket.js';

// Global state
let currentPage = 'dashboard';
let dashboardData = null;

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
        }
    } catch (error) {
        console.error(`Error loading ${page}:`, error);
        showError(`Failed to load ${page}: ${error.message}`);
    }
}

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
        document.getElementById('stat-groups').textContent = data.stats?.groups || 0;
        document.getElementById('stat-hosts').textContent = data.stats?.hosts || 0;
        document.getElementById('stat-playbooks').textContent = data.stats?.playbooks || 0;
        document.getElementById('stat-jobs').textContent = data.stats?.jobs || 0;

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
        <div class="card">
            <div class="card-title">${escapeHtml(group.name)}</div>
            <div class="card-description">${escapeHtml(group.description || '')}</div>
            <div class="card-description" style="margin-top: 0.5rem;">
                ${group.host_count || 0} host(s)
            </div>
        </div>
    `).join('');
}

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
                <button class="btn btn-sm btn-danger" onclick="deleteGroup(${group.id})">Delete</button>
            </div>
            <div class="hosts-list">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong>Hosts</strong>
                    <button class="btn btn-sm btn-primary" onclick="showAddHostModal(${group.id})">+ Add Host</button>
                </div>
                ${group.hosts && group.hosts.length ? 
                    group.hosts.map(host => `
                        <div class="host-item">
                            <div class="host-info">
                                <span class="host-name">${escapeHtml(host.hostname)}</span>
                                <span class="host-ip">${escapeHtml(host.ip_address)}</span>
                            </div>
                            <button class="btn btn-sm btn-danger" onclick="deleteHost(${group.id}, ${host.id})">Delete</button>
                        </div>
                    `).join('') :
                    '<div class="empty-state" style="padding: 1rem;">No hosts</div>'
                }
            </div>
        </div>
    `).join('');
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
            container.innerHTML = '<div class="empty-state">No playbooks available</div>';
            return;
        }

        container.innerHTML = playbooks.map(pb => `
            <div class="card">
                <div class="card-title">${escapeHtml(pb.name)}</div>
                <div class="card-description">${escapeHtml(pb.description || '')}</div>
                <div style="margin-top: 0.5rem;">
                    ${pb.tags ? JSON.parse(pb.tags).map(tag => `<span class="status-badge" style="margin-right: 0.5rem;">${escapeHtml(tag)}</span>`).join('') : ''}
                </div>
            </div>
        `).join('');
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
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">${escapeHtml(cred.name)}</div>
                        <div class="card-description">Username: ${escapeHtml(cred.username)}</div>
                    </div>
                    <button class="btn btn-sm btn-danger" onclick="deleteCredential(${cred.id})">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Modals
// ═══════════════════════════════════════════════════════════════════════════════

function showModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal-overlay').classList.add('active');
}

function closeAllModals() {
    document.getElementById('modal-overlay').classList.remove('active');
    document.getElementById('modal-body').innerHTML = '';
}

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
        const [playbooks, groups, credentials] = await Promise.all([
            api.getPlaybooks(),
            api.getInventoryGroups(),
            api.getCredentials(),
        ]);

        showModal('Launch Job', `
            <form onsubmit="launchJob(event)">
                <div class="form-group">
                    <label class="form-label">Playbook</label>
                    <select class="form-select" name="playbook_id" required>
                        <option value="">Select a playbook...</option>
                        ${playbooks.map(pb => `<option value="${pb.id}">${escapeHtml(pb.name)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Inventory Group</label>
                    <select class="form-select" name="inventory_group_id" required>
                        <option value="">Select a group...</option>
                        ${groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Credential (optional)</label>
                    <select class="form-select" name="credential_id">
                        <option value="">None</option>
                        ${credentials.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('')}
                    </select>
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
    } catch (error) {
        showError(`Failed to load job form: ${error.message}`);
    }
};

window.launchJob = async function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        const job = await api.launchJob(
            parseInt(formData.get('playbook_id')),
            parseInt(formData.get('inventory_group_id')),
            formData.get('credential_id') ? parseInt(formData.get('credential_id')) : null,
            null,
            formData.get('dry_run') === 'on'
        );
        closeAllModals();
        await loadJobs();
        showSuccess('Job launched successfully');
        setTimeout(() => viewJobOutput(job.id), 500);
    } catch (error) {
        showError(`Failed to launch job: ${error.message}`);
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
                <textarea class="form-textarea" name="content" style="min-height: 200px;" required></textarea>
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

// Delete functions
window.deleteGroup = async function(groupId) {
    if (!confirm('Are you sure you want to delete this group?')) return;
    try {
        await api.deleteGroup(groupId);
        await loadInventory();
        showSuccess('Group deleted successfully');
    } catch (error) {
        showError(`Failed to delete group: ${error.message}`);
    }
};

window.deleteHost = async function(groupId, hostId) {
    if (!confirm('Are you sure you want to delete this host?')) return;
    try {
        await api.deleteHost(groupId, hostId);
        await loadInventory();
        showSuccess('Host deleted successfully');
    } catch (error) {
        showError(`Failed to delete host: ${error.message}`);
    }
};

window.deleteTemplate = async function(templateId) {
    if (!confirm('Are you sure you want to delete this template?')) return;
    try {
        await api.deleteTemplate(templateId);
        await loadTemplates();
        showSuccess('Template deleted successfully');
    } catch (error) {
        showError(`Failed to delete template: ${error.message}`);
    }
};

window.deleteCredential = async function(credentialId) {
    if (!confirm('Are you sure you want to delete this credential?')) return;
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
// Initialize
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadPageData('dashboard');
});

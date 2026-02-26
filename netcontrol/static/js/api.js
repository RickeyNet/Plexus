/**
 * API Client for NetControl
 * Handles all HTTP requests to the backend API
 */

const API_BASE = '/api';

async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        ...options,
    };

    if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
    }

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}: ${response.statusText}`);
        }

        return data;
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// Dashboard
export async function getDashboard() {
    return apiRequest('/dashboard');
}

// Inventory
export async function getInventoryGroups() {
    return apiRequest('/inventory');
}

export async function getGroup(groupId) {
    return apiRequest(`/inventory/${groupId}`);
}

export async function createGroup(name, description = '') {
    return apiRequest('/inventory', {
        method: 'POST',
        body: { name, description },
    });
}

export async function deleteGroup(groupId) {
    return apiRequest(`/inventory/${groupId}`, {
        method: 'DELETE',
    });
}

export async function addHost(groupId, hostname, ipAddress, deviceType = 'cisco_ios') {
    return apiRequest(`/inventory/${groupId}/hosts`, {
        method: 'POST',
        body: { hostname, ip_address: ipAddress, device_type: deviceType },
    });
}

export async function updateHost(hostId, hostname, ipAddress, deviceType = 'cisco_ios') {
    return apiRequest(`/hosts/${hostId}`, {
        method: 'PUT',
        body: { hostname, ip_address: ipAddress, device_type: deviceType },
    });
}

export async function deleteHost(groupId, hostId) {
    return apiRequest(`/hosts/${hostId}`, {
        method: 'DELETE',
    });
}

// Playbooks
export async function getPlaybooks() {
    return apiRequest('/playbooks');
}

export async function getPlaybook(playbookId) {
    return apiRequest(`/playbooks/${playbookId}`);
}

// Jobs
export async function getJobs(limit = 50) {
    return apiRequest(`/jobs?limit=${limit}`);
}

export async function getJob(jobId) {
    return apiRequest(`/jobs/${jobId}`);
}

export async function launchJob(playbookId, inventoryGroupId, credentialId = null, templateId = null, dryRun = true) {
    return apiRequest('/jobs/launch', {
        method: 'POST',
        body: {
            playbook_id: playbookId,
            inventory_group_id: inventoryGroupId,
            credential_id: credentialId,
            template_id: templateId,
            dry_run: dryRun,
        },
    });
}

export async function getJobEvents(jobId) {
    return apiRequest(`/jobs/${jobId}/events`);
}

// Templates
export async function getTemplates() {
    return apiRequest('/templates');
}

export async function getTemplate(templateId) {
    return apiRequest(`/templates/${templateId}`);
}

export async function createTemplate(name, content, description = '') {
    return apiRequest('/templates', {
        method: 'POST',
        body: { name, content, description },
    });
}

export async function updateTemplate(templateId, name, content, description = '') {
    return apiRequest(`/templates/${templateId}`, {
        method: 'PUT',
        body: { name, content, description },
    });
}

export async function deleteTemplate(templateId) {
    return apiRequest(`/templates/${templateId}`, {
        method: 'DELETE',
    });
}

// Credentials
export async function getCredentials() {
    return apiRequest('/credentials');
}

export async function getCredential(credentialId) {
    return apiRequest(`/credentials/${credentialId}`);
}

export async function createCredential(name, username, password, secret = '') {
    return apiRequest('/credentials', {
        method: 'POST',
        body: { name, username, password, secret },
    });
}

export async function deleteCredential(credentialId) {
    return apiRequest(`/credentials/${credentialId}`, {
        method: 'DELETE',
    });
}

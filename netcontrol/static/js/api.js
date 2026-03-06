/**
 * API Client for Plexus
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

// Auth
export async function login(username, password) {
    return apiRequest('/auth/login', {
        method: 'POST',
        body: { username, password },
    });
}

export async function register(username, password, displayName = '') {
    return apiRequest('/auth/register', {
        method: 'POST',
        body: { username, password, display_name: displayName },
    });
}

export async function logout() {
    return apiRequest('/auth/logout', { method: 'POST' });
}

export async function getAuthStatus() {
    return apiRequest('/auth/status');
}

export async function getProfile() {
    return apiRequest('/auth/profile');
}

export async function updateProfile(displayName) {
    return apiRequest('/auth/profile', {
        method: 'PUT',
        body: { display_name: displayName },
    });
}

export async function changePassword(currentPassword, newPassword) {
    return apiRequest('/auth/change-password', {
        method: 'POST',
        body: { current_password: currentPassword, new_password: newPassword },
    });
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

export async function updateGroup(groupId, name, description = '') {
    return apiRequest(`/inventory/${groupId}`, {
        method: 'PUT',
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

export async function createPlaybook(name, filename, description = '', tags = [], content = '') {
    return apiRequest('/playbooks', {
        method: 'POST',
        body: { name, filename, description, tags, content },
    });
}

export async function updatePlaybook(playbookId, data) {
    return apiRequest(`/playbooks/${playbookId}`, {
        method: 'PUT',
        body: data,
    });
}

export async function deletePlaybook(playbookId) {
    return apiRequest(`/playbooks/${playbookId}`, {
        method: 'DELETE',
    });
}

// Jobs
export async function getJobs(limit = 50) {
    return apiRequest(`/jobs?limit=${limit}`);
}

export async function getJob(jobId) {
    return apiRequest(`/jobs/${jobId}`);
}

export async function launchJob(playbookId, inventoryGroupId = null, credentialId = null, templateId = null, dryRun = true, hostIds = null) {
    const body = {
        playbook_id: playbookId,
        dry_run: dryRun,
    };
    
    // Only include fields if they have values (Pydantic Optional fields can be omitted)
    if (hostIds && Array.isArray(hostIds) && hostIds.length > 0) {
        // Ensure all IDs are integers
        body.host_ids = hostIds.map(id => parseInt(id)).filter(id => !isNaN(id));
    }
    
    if (inventoryGroupId !== null && inventoryGroupId !== undefined) {
        body.inventory_group_id = parseInt(inventoryGroupId);
    }
    
    if (credentialId !== null && credentialId !== undefined) {
        body.credential_id = parseInt(credentialId);
    }
    
    if (templateId !== null && templateId !== undefined) {
        body.template_id = parseInt(templateId);
    }
    
    console.log('Sending job launch request:', JSON.stringify(body, null, 2));
    
    return apiRequest('/jobs/launch', {
        method: 'POST',
        body: body,
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

export async function updateCredential(credentialId, data) {
    return apiRequest(`/credentials/${credentialId}`, {
        method: 'PUT',
        body: data,
    });
}

export async function deleteCredential(credentialId) {
    return apiRequest(`/credentials/${credentialId}`, {
        method: 'DELETE',
    });
}

// Admin Settings
export async function getAdminCapabilities() {
    return apiRequest('/admin/capabilities');
}

export async function getAdminUsers() {
    return apiRequest('/admin/users');
}

export async function createAdminUser(payload) {
    return apiRequest('/admin/users', {
        method: 'POST',
        body: payload,
    });
}

export async function updateAdminUser(userId, payload) {
    return apiRequest(`/admin/users/${userId}`, {
        method: 'PUT',
        body: payload,
    });
}

export async function resetAdminUserPassword(userId, newPassword) {
    return apiRequest(`/admin/users/${userId}/password`, {
        method: 'PUT',
        body: { new_password: newPassword },
    });
}

export async function setAdminUserGroups(userId, groupIds) {
    return apiRequest(`/admin/users/${userId}/groups`, {
        method: 'PUT',
        body: { group_ids: groupIds },
    });
}

export async function deleteAdminUser(userId) {
    return apiRequest(`/admin/users/${userId}`, {
        method: 'DELETE',
    });
}

export async function getAccessGroups() {
    return apiRequest('/admin/access-groups');
}

export async function createAccessGroup(payload) {
    return apiRequest('/admin/access-groups', {
        method: 'POST',
        body: payload,
    });
}

export async function updateAccessGroup(groupId, payload) {
    return apiRequest(`/admin/access-groups/${groupId}`, {
        method: 'PUT',
        body: payload,
    });
}

export async function deleteAccessGroup(groupId) {
    return apiRequest(`/admin/access-groups/${groupId}`, {
        method: 'DELETE',
    });
}

export async function getLoginRules() {
    return apiRequest('/admin/login-rules');
}

export async function updateLoginRules(payload) {
    return apiRequest('/admin/login-rules', {
        method: 'PUT',
        body: payload,
    });
}

export async function getAuthConfig() {
    return apiRequest('/admin/auth-config');
}

export async function updateAuthConfig(payload) {
    return apiRequest('/admin/auth-config', {
        method: 'PUT',
        body: payload,
    });
}

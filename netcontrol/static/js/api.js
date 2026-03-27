/**
 * API Client for Plexus
 * Handles all HTTP requests to the backend API
 */

const API_BASE = '/api';

let _csrfToken = '';

export function setCsrfToken(token) {
    _csrfToken = token || '';
}

export function getCsrfToken() {
    return _csrfToken;
}

async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        ...options,
    };

    // Attach CSRF token for state-changing requests
    if (_csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes((config.method || 'GET').toUpperCase())) {
        config.headers['X-CSRF-Token'] = _csrfToken;
    }

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
export async function getInventoryGroups(includeHosts = false) {
    return apiRequest(includeHosts ? '/inventory?include_hosts=true' : '/inventory');
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

export async function bulkDeleteHosts(hostIds) {
    return apiRequest('/hosts/bulk-delete', {
        method: 'POST',
        body: { host_ids: hostIds },
    });
}

export async function moveHosts(hostIds, targetGroupId) {
    return apiRequest('/hosts/move', {
        method: 'POST',
        body: { host_ids: hostIds, target_group_id: targetGroupId },
    });
}

export async function scanInventoryGroup(groupId, cidrs, options = {}) {
    return apiRequest(`/inventory/${groupId}/discovery/scan`, {
        method: 'POST',
        body: {
            cidrs,
            timeout_seconds: options.timeoutSeconds,
            max_hosts: options.maxHosts,
            device_type: options.deviceType,
            hostname_prefix: options.hostnamePrefix,
            use_snmp: options.useSnmp !== false,
        },
    });
}

export async function scanInventoryGroupStream(groupId, cidrs, options = {}, onEvent) {
    const url = `${API_BASE}/inventory/${groupId}/discovery/scan/stream`;
    const headers = { 'Content-Type': 'application/json' };
    if (_csrfToken) headers['X-CSRF-Token'] = _csrfToken;

    const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            cidrs,
            timeout_seconds: options.timeoutSeconds,
            max_hosts: options.maxHosts,
            device_type: options.deviceType,
            hostname_prefix: options.hostnamePrefix,
            use_snmp: options.useSnmp !== false,
        }),
    });

    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    const event = JSON.parse(line.slice(6));
                    onEvent(event);
                } catch { /* skip malformed */ }
            }
        }
    }
}

export async function syncInventoryGroup(groupId, cidrs, options = {}) {
    return apiRequest(`/inventory/${groupId}/discovery/sync`, {
        method: 'POST',
        body: {
            cidrs,
            timeout_seconds: options.timeoutSeconds,
            max_hosts: options.maxHosts,
            device_type: options.deviceType,
            hostname_prefix: options.hostnamePrefix,
            use_snmp: options.useSnmp !== false,
            remove_absent: !!options.removeAbsent,
        },
    });
}

export async function onboardDiscoveredHosts(groupId, discoveredHosts) {
    return apiRequest(`/inventory/${groupId}/discovery/onboard`, {
        method: 'POST',
        body: {
            discovered_hosts: discoveredHosts,
        },
    });
}

// Playbooks
export async function getPlaybooks() {
    return apiRequest('/playbooks');
}

export async function getPlaybook(playbookId) {
    return apiRequest(`/playbooks/${playbookId}`);
}

export async function createPlaybook(name, filename, description = '', tags = [], content = '', type = 'python') {
    return apiRequest('/playbooks', {
        method: 'POST',
        body: { name, filename, description, tags, content, type },
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

export async function launchJob(playbookId, inventoryGroupId = null, credentialId = null, templateId = null, dryRun = true, hostIds = null, priority = 2, dependsOn = null, adHocIps = null) {
    const body = {
        playbook_id: playbookId,
        dry_run: dryRun,
        priority: priority,
    };

    if (hostIds && Array.isArray(hostIds) && hostIds.length > 0) {
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

    if (dependsOn && Array.isArray(dependsOn) && dependsOn.length > 0) {
        body.depends_on = dependsOn;
    }

    if (adHocIps && Array.isArray(adHocIps) && adHocIps.length > 0) {
        body.ad_hoc_ips = adHocIps;
    }

    return apiRequest('/jobs/launch', {
        method: 'POST',
        body: body,
    });
}

export async function getJobEvents(jobId) {
    return apiRequest(`/jobs/${jobId}/events`);
}

export async function getJobQueue() {
    return apiRequest('/jobs/queue');
}

export async function cancelJob(jobId) {
    return apiRequest(`/jobs/${jobId}/cancel`, { method: 'POST' });
}

export async function retryJob(jobId) {
    return apiRequest(`/jobs/${jobId}/retry`, { method: 'POST' });
}

export async function rerunJobLive(jobId) {
    return apiRequest(`/jobs/${jobId}/rerun`, { method: 'POST' });
}

export async function updateJobPriority(jobId, priority) {
    return apiRequest(`/jobs/${jobId}/priority`, { method: 'PATCH', body: { priority } });
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

export async function getDiscoverySyncConfig() {
    return apiRequest('/admin/discovery-sync');
}

export async function updateDiscoverySyncConfig(payload) {
    return apiRequest('/admin/discovery-sync', {
        method: 'PUT',
        body: payload,
    });
}

export async function runDiscoverySyncNow() {
    return apiRequest('/admin/discovery-sync/run-now', {
        method: 'POST',
    });
}

export async function getSnmpDiscoveryConfig() {
    return apiRequest('/admin/snmp-discovery');
}

export async function updateSnmpDiscoveryConfig(payload) {
    return apiRequest('/admin/snmp-discovery', {
        method: 'PUT',
        body: payload,
    });
}

export async function getGroupSnmpDiscoveryProfile(groupId) {
    return apiRequest(`/inventory/${groupId}/snmp-discovery-profile`);
}

export async function updateGroupSnmpDiscoveryProfile(groupId, payload) {
    return apiRequest(`/inventory/${groupId}/snmp-discovery-profile`, {
        method: 'PUT',
        body: payload,
    });
}

export async function testGroupSnmpProfile(groupId, targetIp) {
    return apiRequest(`/inventory/${groupId}/snmp-discovery-profile/test`, {
        method: 'POST',
        body: { target_ip: targetIp },
    });
}

// ── Named SNMP Profiles ──────────────────────────────────────────────────────

export async function listSnmpProfiles() {
    return apiRequest('/admin/snmp-profiles');
}

export async function createSnmpProfile(payload) {
    return apiRequest('/admin/snmp-profiles', {
        method: 'POST',
        body: payload,
    });
}

export async function updateSnmpProfile(profileId, payload) {
    return apiRequest(`/admin/snmp-profiles/${profileId}`, {
        method: 'PUT',
        body: payload,
    });
}

export async function deleteSnmpProfile(profileId) {
    return apiRequest(`/admin/snmp-profiles/${profileId}`, {
        method: 'DELETE',
    });
}

export async function getGroupSnmpAssignment(groupId) {
    return apiRequest(`/inventory/${groupId}/snmp-profile-assignment`);
}

export async function updateGroupSnmpAssignment(groupId, profileId) {
    return apiRequest(`/inventory/${groupId}/snmp-profile-assignment`, {
        method: 'PUT',
        body: { snmp_profile_id: profileId },
    });
}

// ── Topology Discovery Schedule ──────────────────────────────────────────────

export async function getTopologyDiscoveryConfig() {
    return apiRequest('/admin/topology-discovery');
}

export async function updateTopologyDiscoveryConfig(payload) {
    return apiRequest('/admin/topology-discovery', {
        method: 'PUT',
        body: payload,
    });
}

export async function runTopologyDiscoveryNow() {
    return apiRequest('/admin/topology-discovery/run-now', {
        method: 'POST',
    });
}

// ── Topology ────────────────────────────────────────────────────────────────

export async function getTopology(groupId = null) {
    const params = groupId ? `?group_id=${groupId}` : '';
    return apiRequest(`/topology${params}`);
}

export async function discoverTopologyForGroup(groupId) {
    return apiRequest(`/topology/discover/${groupId}`, { method: 'POST' });
}

export async function discoverTopologyAll() {
    return apiRequest('/topology/discover', { method: 'POST' });
}

export async function discoverTopologyStream(groupId, onEvent) {
    const url = groupId
        ? `${API_BASE}/topology/discover/${groupId}/stream`
        : `${API_BASE}/topology/discover/stream`;
    const headers = { 'Content-Type': 'application/json' };
    if (_csrfToken) headers['X-CSRF-Token'] = _csrfToken;

    const response = await fetch(url, { method: 'POST', headers });

    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    const event = JSON.parse(line.slice(6));
                    onEvent(event);
                } catch { /* skip malformed */ }
            }
        }
    }
}

export async function getHostTopology(hostId) {
    return apiRequest(`/topology/host/${hostId}`);
}

export async function getTopologyChanges(unacknowledged = true, limit = 100) {
    return apiRequest(`/topology/changes?unacknowledged=${unacknowledged}&limit=${limit}`);
}

export async function acknowledgeTopologyChanges() {
    return apiRequest('/topology/changes/acknowledge', { method: 'POST' });
}

// ── Topology Node Positions ──────────────────────────────────────────────────

export async function getTopologyPositions() {
    return apiRequest('/topology/positions');
}

export async function saveTopologyPositions(positions) {
    return apiRequest('/topology/positions', {
        method: 'PUT',
        body: { positions },
    });
}

export async function deleteTopologyPositions() {
    return apiRequest('/topology/positions', {
        method: 'DELETE',
    });
}

// ── Config Drift ────────────────────────────────────────────────────────────

export async function getConfigDriftSummary() {
    return apiRequest('/config-drift/summary');
}

export async function getConfigDriftEvents(status = null, hostId = null, limit = 100) {
    const params = new URLSearchParams();
    if (status && status !== 'all') params.set('status', status);
    if (hostId) params.set('host_id', hostId);
    params.set('limit', limit);
    return apiRequest(`/config-drift/events?${params}`);
}

export async function getConfigDriftEvent(eventId) {
    return apiRequest(`/config-drift/events/${eventId}`);
}

export async function updateConfigDriftEventStatus(eventId, status) {
    return apiRequest(`/config-drift/events/${eventId}/status`, {
        method: 'PUT',
        body: { status },
    });
}

export async function revertDriftEvent(eventId, credentialId) {
    return apiRequest('/config-drift/events/revert', {
        method: 'POST',
        body: { event_id: eventId, credential_id: credentialId },
    });
}

export async function getConfigBaselines(hostId = null) {
    const params = new URLSearchParams();
    if (hostId) params.set('host_id', hostId);
    return apiRequest(`/config-drift/baselines?${params}`);
}

export async function getConfigBaseline(baselineId) {
    return apiRequest(`/config-drift/baselines/${baselineId}`);
}

export async function createConfigBaseline(data) {
    return apiRequest('/config-drift/baselines', { method: 'POST', body: data });
}

export async function updateConfigBaseline(baselineId, data) {
    return apiRequest(`/config-drift/baselines/${baselineId}`, { method: 'PUT', body: data });
}

export async function deleteConfigBaseline(baselineId) {
    return apiRequest(`/config-drift/baselines/${baselineId}`, { method: 'DELETE' });
}

export async function getConfigSnapshots(hostId, limit = 50) {
    return apiRequest(`/config-drift/snapshots?host_id=${hostId}&limit=${limit}`);
}

export async function getConfigSnapshot(snapshotId) {
    return apiRequest(`/config-drift/snapshots/${snapshotId}`);
}

export async function captureConfigSnapshot(hostId, credentialId) {
    return apiRequest('/config-drift/snapshots/capture', {
        method: 'POST',
        body: { host_id: hostId, credential_id: credentialId },
    });
}

export async function captureGroupConfigSnapshots(groupId, credentialId) {
    return apiRequest('/config-drift/snapshots/capture-group', {
        method: 'POST',
        body: { group_id: groupId, credential_id: credentialId },
    });
}

export async function startCaptureJob(groupId, credentialId) {
    return apiRequest('/config-drift/snapshots/capture-job', {
        method: 'POST',
        body: { group_id: groupId, credential_id: credentialId },
    });
}

export async function startCaptureSingleJob(hostId, credentialId) {
    return apiRequest('/config-drift/snapshots/capture-single-job', {
        method: 'POST',
        body: { host_id: hostId, credential_id: credentialId },
    });
}

export async function analyzeConfigDrift(hostId) {
    return apiRequest('/config-drift/analyze', { method: 'POST', body: { host_id: hostId } });
}

export async function analyzeGroupConfigDrift(groupId) {
    return apiRequest('/config-drift/analyze-group', { method: 'POST', body: { group_id: groupId } });
}

export async function fullDriftCheck(hostId, credentialId) {
    return apiRequest('/config-drift/check', {
        method: 'POST',
        body: { host_id: hostId, credential_id: credentialId },
    });
}

export async function deleteConfigSnapshot(snapshotId) {
    return apiRequest(`/config-drift/snapshots/${snapshotId}`, { method: 'DELETE' });
}

// ── Config Backups ──────────────────────────────────────────────────────────

export async function getConfigBackupPolicies(groupId = null) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    return apiRequest(`/config-backups/policies?${params}`);
}

export async function createConfigBackupPolicy(data) {
    return apiRequest('/config-backups/policies', { method: 'POST', body: data });
}

export async function updateConfigBackupPolicy(id, data) {
    return apiRequest(`/config-backups/policies/${id}`, { method: 'PUT', body: data });
}

export async function deleteConfigBackupPolicy(id) {
    return apiRequest(`/config-backups/policies/${id}`, { method: 'DELETE' });
}

export async function runConfigBackupPolicy(id) {
    return apiRequest(`/config-backups/policies/${id}/run-now`, { method: 'POST' });
}

export async function getConfigBackups(hostId = null, policyId = null, limit = 100) {
    const params = new URLSearchParams();
    if (hostId) params.set('host_id', hostId);
    if (policyId) params.set('policy_id', policyId);
    if (limit) params.set('limit', limit);
    return apiRequest(`/config-backups?${params}`);
}

export async function getConfigBackup(id) {
    return apiRequest(`/config-backups/${id}`);
}

export async function deleteConfigBackup(id) {
    return apiRequest(`/config-backups/${id}`, { method: 'DELETE' });
}

export async function restoreConfigBackup(data) {
    return apiRequest('/config-backups/restore', { method: 'POST', body: data });
}

export async function getConfigBackupSummary() {
    return apiRequest('/config-backups/summary');
}

// ── Compliance Profiles & Scans ──────────────────────────────────────────────

export async function getComplianceProfiles() {
    return apiRequest('/compliance/profiles');
}

export async function createComplianceProfile(data) {
    return apiRequest('/compliance/profiles', { method: 'POST', body: data });
}

export async function getComplianceProfile(id) {
    return apiRequest(`/compliance/profiles/${id}`);
}

export async function updateComplianceProfile(id, data) {
    return apiRequest(`/compliance/profiles/${id}`, { method: 'PUT', body: data });
}

export async function deleteComplianceProfile(id) {
    return apiRequest(`/compliance/profiles/${id}`, { method: 'DELETE' });
}

export async function getComplianceAssignments(profileId = null, groupId = null) {
    const params = new URLSearchParams();
    if (profileId) params.set('profile_id', profileId);
    if (groupId) params.set('group_id', groupId);
    const qs = params.toString();
    return apiRequest(`/compliance/assignments${qs ? '?' + qs : ''}`);
}

export async function createComplianceAssignment(data) {
    return apiRequest('/compliance/assignments', { method: 'POST', body: data });
}

export async function updateComplianceAssignment(id, data) {
    return apiRequest(`/compliance/assignments/${id}`, { method: 'PUT', body: data });
}

export async function deleteComplianceAssignment(id) {
    return apiRequest(`/compliance/assignments/${id}`, { method: 'DELETE' });
}

export async function getComplianceScanResults(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.profileId) qs.set('profile_id', params.profileId);
    if (params.status) qs.set('status', params.status);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return apiRequest(`/compliance/results${q ? '?' + q : ''}`);
}

export async function getComplianceScanResult(id) {
    return apiRequest(`/compliance/results/${id}`);
}

export async function deleteComplianceScanResult(id) {
    return apiRequest(`/compliance/results/${id}`, { method: 'DELETE' });
}

export async function getComplianceHostStatus(profileId = null) {
    const qs = profileId ? `?profile_id=${profileId}` : '';
    return apiRequest(`/compliance/status${qs}`);
}

export async function getComplianceSummary() {
    return apiRequest('/compliance/summary');
}

export async function runComplianceScan(data) {
    return apiRequest('/compliance/scan', { method: 'POST', body: data });
}

// ── Risk Analysis ────────────────────────────────────────────────────────────

export async function runRiskAnalysis(data) {
    return apiRequest('/risk-analysis/analyze', { method: 'POST', body: data });
}

export async function runOfflineRiskAnalysis(data) {
    return apiRequest('/risk-analysis/analyze-offline', { method: 'POST', body: data });
}

export async function getRiskAnalyses(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.groupId) qs.set('group_id', params.groupId);
    if (params.riskLevel) qs.set('risk_level', params.riskLevel);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return apiRequest(`/risk-analysis${q ? '?' + q : ''}`);
}

export async function getRiskAnalysisSummary() {
    return apiRequest('/risk-analysis/summary');
}

export async function getRiskAnalysis(id) {
    return apiRequest(`/risk-analysis/${id}`);
}

export async function approveRiskAnalysis(id) {
    return apiRequest(`/risk-analysis/${id}/approve`, { method: 'POST' });
}

export async function deleteRiskAnalysis(id) {
    return apiRequest(`/risk-analysis/${id}`, { method: 'DELETE' });
}

// ── Deployments / Rollback ──────────────────────────────────────────────────

export async function createDeployment(data) {
    return apiRequest('/deployments', { method: 'POST', body: data });
}

export async function getDeployments(params = {}) {
    const qs = new URLSearchParams();
    if (params.status) qs.set('status', params.status);
    if (params.groupId) qs.set('group_id', params.groupId);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return apiRequest(`/deployments${q ? '?' + q : ''}`);
}

export async function getDeploymentSummary() {
    return apiRequest('/deployments/summary');
}

export async function getDeployment(id) {
    return apiRequest(`/deployments/${id}`);
}

export async function executeDeployment(id) {
    return apiRequest(`/deployments/${id}/execute`, { method: 'POST' });
}

export async function rollbackDeployment(id) {
    return apiRequest(`/deployments/${id}/rollback`, { method: 'POST' });
}

export async function deleteDeployment(id) {
    return apiRequest(`/deployments/${id}`, { method: 'DELETE' });
}

export async function getDeploymentJobStatus(jobId) {
    return apiRequest(`/deployments/job/${jobId}/status`);
}

export async function getDeploymentCorrelation(deploymentId) {
    return apiRequest(`/deployments/${deploymentId}/correlation`);
}

export async function getAlertCorrelation(alertId) {
    return apiRequest(`/monitoring/alerts/${alertId}/correlation`);
}

// ── Real-Time Monitoring ────────────────────────────────────────────────────

export async function getMonitoringSummary(groupId = null) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    const qs = params.toString();
    return apiRequest(`/monitoring/summary${qs ? '?' + qs : ''}`);
}

export async function getMonitoringPolls(groupId = null, limit = 200) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    if (limit) params.set('limit', limit);
    return apiRequest(`/monitoring/polls?${params}`);
}

export async function getMonitoringPollHistory(hostId, limit = 100) {
    return apiRequest(`/monitoring/polls/${hostId}/history?limit=${limit}`);
}

export async function getMonitoringAlerts(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.acknowledged !== undefined && params.acknowledged !== null) qs.set('acknowledged', params.acknowledged);
    if (params.severity) qs.set('severity', params.severity);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return apiRequest(`/monitoring/alerts${q ? '?' + q : ''}`);
}

export async function acknowledgeMonitoringAlert(alertId) {
    return apiRequest(`/monitoring/alerts/${alertId}/acknowledge`, { method: 'POST' });
}

export async function getMonitoringRouteSnapshots(hostId, limit = 50) {
    return apiRequest(`/monitoring/routes/${hostId}?limit=${limit}`);
}

export async function runMonitoringPollNow() {
    return apiRequest('/monitoring/poll-now', { method: 'POST' });
}

export async function runMonitoringPollStream(onEvent) {
    const url = `${API_BASE}/monitoring/poll-now/stream`;
    const headers = { 'Content-Type': 'application/json' };
    if (_csrfToken) headers['X-CSRF-Token'] = _csrfToken;

    const response = await fetch(url, { method: 'POST', headers });

    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    const event = JSON.parse(line.slice(6));
                    onEvent(event);
                } catch { /* skip malformed */ }
            }
        }
    }
}

export async function getMonitoringConfig() {
    return apiRequest('/admin/monitoring');
}

export async function updateMonitoringConfig(data) {
    return apiRequest('/admin/monitoring', { method: 'PUT', body: data });
}

// ── Alert Rules ─────────────────────────────────────────────────────────────

export async function getAlertRules() {
    return apiRequest('/monitoring/rules');
}

export async function createAlertRule(data) {
    return apiRequest('/monitoring/rules', { method: 'POST', body: data });
}

export async function getAlertRule(id) {
    return apiRequest(`/monitoring/rules/${id}`);
}

export async function updateAlertRule(id, data) {
    return apiRequest(`/monitoring/rules/${id}`, { method: 'PUT', body: data });
}

export async function deleteAlertRule(id) {
    return apiRequest(`/monitoring/rules/${id}`, { method: 'DELETE' });
}

// ── Alert Suppressions ──────────────────────────────────────────────────────

export async function getAlertSuppressions(activeOnly = false) {
    const qs = activeOnly ? '?active_only=true' : '';
    return apiRequest(`/monitoring/suppressions${qs}`);
}

export async function createAlertSuppression(data) {
    return apiRequest('/monitoring/suppressions', { method: 'POST', body: data });
}

export async function deleteAlertSuppression(id) {
    return apiRequest(`/monitoring/suppressions/${id}`, { method: 'DELETE' });
}

// ── Bulk Alert Operations ───────────────────────────────────────────────────

export async function bulkAcknowledgeAlerts(alertIds) {
    return apiRequest('/monitoring/alerts/bulk-acknowledge', {
        method: 'POST',
        body: { alert_ids: alertIds },
    });
}

// ── SLA Dashboards ──────────────────────────────────────────────────────────

export async function getSlaSummary(groupId = null, days = 30) {
    const params = [`days=${days}`];
    if (groupId) params.push(`group_id=${groupId}`);
    return apiRequest(`/sla/summary?${params.join('&')}`);
}

export async function getSlaHostDetail(hostId, days = 30) {
    return apiRequest(`/sla/host/${hostId}?days=${days}`);
}

export async function getSlaTargets(hostId = null, groupId = null) {
    const params = [];
    if (hostId) params.push(`host_id=${hostId}`);
    if (groupId) params.push(`group_id=${groupId}`);
    const qs = params.length ? '?' + params.join('&') : '';
    return apiRequest(`/sla/targets${qs}`);
}

export async function createSlaTarget(data) {
    return apiRequest('/sla/targets', { method: 'POST', body: data });
}

export async function updateSlaTarget(id, data) {
    return apiRequest(`/sla/targets/${id}`, { method: 'PUT', body: data });
}

export async function deleteSlaTarget(id) {
    return apiRequest(`/sla/targets/${id}`, { method: 'DELETE' });
}

// ── Metrics Engine ──────────────────────────────────────────────────────────

export async function queryMetrics(metric, host = '*', range = '6h', step = 'auto', group = null) {
    const params = new URLSearchParams({ metric, host, range, step });
    if (group) params.set('group', group);
    return apiRequest(`/metrics/query?${params}`);
}

export async function getMetricNames() {
    return apiRequest('/metrics/names');
}

export async function getInterfaceTimeSeries(hostId, range = '6h', ifIndex = null) {
    const params = new URLSearchParams({ range });
    if (ifIndex != null) params.set('if_index', ifIndex);
    return apiRequest(`/metrics/interfaces/${hostId}?${params}`);
}

export async function getMetricEvents(params = {}) {
    const qs = new URLSearchParams();
    if (params.eventType) qs.set('event_type', params.eventType);
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.severity) qs.set('severity', params.severity);
    if (params.limit) qs.set('limit', params.limit);
    const q = qs.toString();
    return apiRequest(`/metrics/events${q ? '?' + q : ''}`);
}

export async function getCapacityPlanning(params = {}) {
    const qs = new URLSearchParams();
    if (params.metric) qs.set('metric', params.metric);
    if (params.host) qs.set('host', params.host);
    if (params.range) qs.set('range', params.range);
    if (params.group) qs.set('group', params.group);
    if (params.projectionDays) qs.set('projection_days', params.projectionDays);
    if (params.threshold) qs.set('threshold', params.threshold);
    const q = qs.toString();
    return apiRequest(`/metrics/capacity-planning${q ? '?' + q : ''}`);
}

// ── Annotations ─────────────────────────────────────────────────────────────

export async function getAnnotations(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.start) qs.set('start', params.start);
    if (params.end) qs.set('end', params.end);
    if (params.categories) qs.set('categories', params.categories);
    const q = qs.toString();
    return apiRequest(`/annotations${q ? '?' + q : ''}`);
}

// ── Custom Dashboards ───────────────────────────────────────────────────────

export async function getCustomDashboards() {
    return apiRequest('/dashboards');
}

export async function getCustomDashboard(id) {
    return apiRequest(`/dashboards/${id}`);
}

export async function createCustomDashboard(data) {
    return apiRequest('/dashboards', { method: 'POST', body: data });
}

export async function updateCustomDashboard(id, data) {
    return apiRequest(`/dashboards/${id}`, { method: 'PUT', body: data });
}

export async function deleteCustomDashboard(id) {
    return apiRequest(`/dashboards/${id}`, { method: 'DELETE' });
}

export async function createDashboardPanel(dashboardId, data) {
    return apiRequest(`/dashboards/${dashboardId}/panels`, { method: 'POST', body: data });
}

export async function updateDashboardPanel(dashboardId, panelId, data) {
    return apiRequest(`/dashboards/${dashboardId}/panels/${panelId}`, { method: 'PUT', body: data });
}

export async function deleteDashboardPanel(dashboardId, panelId) {
    return apiRequest(`/dashboards/${dashboardId}/panels/${panelId}`, { method: 'DELETE' });
}

// ── Availability Tracking ───────────────────────────────────────────────────

export async function getAvailabilitySummary(groupId = null, days = 30) {
    const params = [`days=${days}`];
    if (groupId) params.push(`group_id=${groupId}`);
    return apiRequest(`/availability/summary?${params.join('&')}`);
}

export async function getAvailabilityTransitions(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.entityType) qs.set('entity_type', params.entityType);
    if (params.start) qs.set('start', params.start);
    if (params.end) qs.set('end', params.end);
    if (params.limit) qs.set('limit', params.limit);
    return apiRequest(`/availability/transitions?${qs}`);
}

export async function getAvailabilityOutages(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.groupId) qs.set('group_id', params.groupId);
    if (params.days) qs.set('days', params.days);
    if (params.limit) qs.set('limit', params.limit);
    return apiRequest(`/availability/outages?${qs}`);
}

// ── Per-Port Utilization ────────────────────────────────────────────────────

export async function getInterfaceUtilizationSummary(hostId, days = 1) {
    return apiRequest(`/interfaces/${hostId}/summary?days=${days}`);
}

export async function getPortDetail(hostId, ifIndex, start = null, end = null) {
    const params = new URLSearchParams();
    if (start) params.set('start', start);
    if (end) params.set('end', end);
    const qs = params.toString();
    return apiRequest(`/interfaces/${hostId}/port/${ifIndex}${qs ? '?' + qs : ''}`);
}

// ── Custom OID Profiles ─────────────────────────────────────────────────────

export async function getOidProfiles(vendor = null) {
    const qs = vendor ? `?vendor=${encodeURIComponent(vendor)}` : '';
    return apiRequest(`/oid-profiles${qs}`);
}

export async function getOidProfile(id) {
    return apiRequest(`/oid-profiles/${id}`);
}

export async function createOidProfile(data) {
    return apiRequest('/oid-profiles', { method: 'POST', body: data });
}

export async function updateOidProfile(id, data) {
    return apiRequest(`/oid-profiles/${id}`, { method: 'PUT', body: data });
}

export async function deleteOidProfile(id) {
    return apiRequest(`/oid-profiles/${id}`, { method: 'DELETE' });
}

// ── Syslog Events ───────────────────────────────────────────────────────────

export async function getSyslogEvents(params = {}) {
    const qs = new URLSearchParams();
    if (params.hostId) qs.set('host_id', params.hostId);
    if (params.severity) qs.set('severity', params.severity);
    if (params.limit) qs.set('limit', params.limit);
    qs.set('event_type', params.eventType || 'syslog');
    return apiRequest(`/metrics/events?${qs}`);
}

// ── Reporting & Export ──────────────────────────────────────────────────────

export async function getReports() {
    return apiRequest('/reports');
}

export async function createReport(data) {
    return apiRequest('/reports', { method: 'POST', body: data });
}

export async function deleteReport(id) {
    return apiRequest(`/reports/${id}`, { method: 'DELETE' });
}

export async function generateReport(data) {
    return apiRequest('/reports/generate', { method: 'POST', body: data });
}

export async function getReportRuns(reportId = null) {
    const qs = reportId ? `?report_id=${reportId}` : '';
    return apiRequest(`/reports/runs${qs}`);
}

export async function getReportRun(runId) {
    return apiRequest(`/reports/runs/${runId}`);
}

export function getExportUrl(type, params = {}) {
    const qs = new URLSearchParams(params).toString();
    return `/api/reports/export/${type}${qs ? '?' + qs : ''}`;
}

// ── Graph Templates (Cacti-parity) ──────────────────────────────────────────

export async function getGraphTemplates(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/graph-templates${qs ? '?' + qs : ''}`);
}

export async function getGraphTemplate(id) {
    return apiRequest(`/graph-templates/${id}`);
}

export async function createGraphTemplate(data) {
    return apiRequest('/graph-templates', { method: 'POST', body: data });
}

export async function updateGraphTemplate(id, data) {
    return apiRequest(`/graph-templates/${id}`, { method: 'PUT', body: data });
}

export async function deleteGraphTemplate(id) {
    return apiRequest(`/graph-templates/${id}`, { method: 'DELETE' });
}

export async function createGraphTemplateItem(templateId, data) {
    return apiRequest(`/graph-templates/${templateId}/items`, { method: 'POST', body: data });
}

export async function updateGraphTemplateItem(templateId, itemId, data) {
    return apiRequest(`/graph-templates/${templateId}/items/${itemId}`, { method: 'PUT', body: data });
}

export async function deleteGraphTemplateItem(templateId, itemId) {
    return apiRequest(`/graph-templates/${templateId}/items/${itemId}`, { method: 'DELETE' });
}

// ── Host Templates ──────────────────────────────────────────────────────────

export async function getHostTemplates() {
    return apiRequest('/host-templates');
}

export async function getHostTemplate(id) {
    return apiRequest(`/host-templates/${id}`);
}

export async function createHostTemplate(data) {
    return apiRequest('/host-templates', { method: 'POST', body: data });
}

export async function updateHostTemplate(id, data) {
    return apiRequest(`/host-templates/${id}`, { method: 'PUT', body: data });
}

export async function deleteHostTemplate(id) {
    return apiRequest(`/host-templates/${id}`, { method: 'DELETE' });
}

export async function linkGraphToHostTemplate(hostTemplateId, graphTemplateId) {
    return apiRequest(`/host-templates/${hostTemplateId}/graph-templates/${graphTemplateId}`, { method: 'POST' });
}

export async function unlinkGraphFromHostTemplate(hostTemplateId, graphTemplateId) {
    return apiRequest(`/host-templates/${hostTemplateId}/graph-templates/${graphTemplateId}`, { method: 'DELETE' });
}

// ── Host Graphs ─────────────────────────────────────────────────────────────

export async function getHostGraphs(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/host-graphs${qs ? '?' + qs : ''}`);
}

export async function getHostGraph(id) {
    return apiRequest(`/host-graphs/${id}`);
}

export async function createHostGraph(data) {
    return apiRequest('/host-graphs', { method: 'POST', body: data });
}

export async function updateHostGraph(id, data) {
    return apiRequest(`/host-graphs/${id}`, { method: 'PUT', body: data });
}

export async function deleteHostGraph(id) {
    return apiRequest(`/host-graphs/${id}`, { method: 'DELETE' });
}

export async function applyGraphTemplatesToHost(hostId) {
    return apiRequest(`/hosts/${hostId}/apply-graph-templates`, { method: 'POST' });
}

// ── Graph Trees ─────────────────────────────────────────────────────────────

export async function getGraphTrees() {
    return apiRequest('/graph-trees');
}

export async function getGraphTree(id) {
    return apiRequest(`/graph-trees/${id}`);
}

export async function createGraphTree(data) {
    return apiRequest('/graph-trees', { method: 'POST', body: data });
}

export async function updateGraphTree(id, data) {
    return apiRequest(`/graph-trees/${id}`, { method: 'PUT', body: data });
}

export async function deleteGraphTree(id) {
    return apiRequest(`/graph-trees/${id}`, { method: 'DELETE' });
}

export async function createGraphTreeNode(treeId, data) {
    return apiRequest(`/graph-trees/${treeId}/nodes`, { method: 'POST', body: data });
}

export async function updateGraphTreeNode(treeId, nodeId, data) {
    return apiRequest(`/graph-trees/${treeId}/nodes/${nodeId}`, { method: 'PUT', body: data });
}

export async function deleteGraphTreeNode(treeId, nodeId) {
    return apiRequest(`/graph-trees/${treeId}/nodes/${nodeId}`, { method: 'DELETE' });
}

// ── Data Source Profiles ────────────────────────────────────────────────────

export async function getDataSourceProfiles(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/data-source-profiles${qs ? '?' + qs : ''}`);
}

export async function getDataSourceProfile(id) {
    return apiRequest(`/data-source-profiles/${id}`);
}

export async function createDataSourceProfile(data) {
    return apiRequest('/data-source-profiles', { method: 'POST', body: data });
}

export async function updateDataSourceProfile(id, data) {
    return apiRequest(`/data-source-profiles/${id}`, { method: 'PUT', body: data });
}

export async function deleteDataSourceProfile(id) {
    return apiRequest(`/data-source-profiles/${id}`, { method: 'DELETE' });
}

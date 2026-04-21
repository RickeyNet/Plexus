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

// ── Stale-While-Revalidate Cache ─────────────────────────────────────────────
const _cache = new Map();          // key → { data, time }
const _inflight = new Map();       // key → Promise (dedup concurrent requests)
const DEFAULT_TTL_MS = 30_000;     // 30 seconds fresh window
const MAX_CACHE_ENTRIES = 200;     // evict oldest entries when cache exceeds this

/**
 * Cached GET wrapper. Returns fresh data immediately if within TTL.
 * If stale, returns cached data instantly and revalidates in background.
 * Deduplicates concurrent identical requests.
 * @param {string} key    - cache key (usually the endpoint + params)
 * @param {Function} fetchFn - async function that returns fresh data
 * @param {number} ttlMs  - how long the entry is considered fresh
 */
async function cachedGet(key, fetchFn, ttlMs = DEFAULT_TTL_MS) {
    const entry = _cache.get(key);
    const now = Date.now();

    if (entry && (now - entry.time < ttlMs)) {
        // Fresh cache hit — return immediately
        return entry.data;
    }

    if (entry) {
        // Stale — return cached data, revalidate in background
        _revalidate(key, fetchFn);
        return entry.data;
    }

    // No cache — must wait for fetch (but dedup concurrent calls)
    return _revalidate(key, fetchFn);
}

async function _revalidate(key, fetchFn) {
    // Dedup: if already in-flight for this key, return the same promise
    if (_inflight.has(key)) return _inflight.get(key);
    const promise = fetchFn().then(data => {
        _cache.set(key, { data, time: Date.now() });
        // Evict oldest entries if cache exceeds size limit
        if (_cache.size > MAX_CACHE_ENTRIES) {
            const it = _cache.keys();
            while (_cache.size > MAX_CACHE_ENTRIES) _cache.delete(it.next().value);
        }
        _inflight.delete(key);
        return data;
    }).catch(err => {
        _inflight.delete(key);
        throw err;
    });
    _inflight.set(key, promise);
    return promise;
}

/**
 * Invalidate cache entries whose key starts with a given prefix.
 * Call after mutations (POST/PUT/DELETE) to bust related caches.
 */
export function invalidateApiCache(...prefixes) {
    if (!prefixes.length) { _cache.clear(); return; }
    for (const key of _cache.keys()) {
        if (prefixes.some(p => key.startsWith(p))) {
            _cache.delete(key);
        }
    }
}

// ── AbortController for page-navigation cancellation ────────────────────────
let _pageController = new AbortController();
const _getInflight = new Map(); // endpoint → Promise (dedup concurrent identical GETs)

/**
 * Abort all in-flight API requests (call on page navigation).
 * A new controller is created automatically for the next page's requests.
 */
export function abortPendingRequests() {
    _pageController.abort();
    _pageController = new AbortController();
    _getInflight.clear();
}

/**
 * Get the current page-level AbortSignal.
 * Stream functions or long-running callers can use this directly.
 */
export function getPageSignal() {
    return _pageController.signal;
}

/**
 * Shared SSE stream helper. Issues a fetch, then reads the response body as
 * newline-delimited SSE events ("data: {...}\n") and calls onEvent for each.
 */
async function _streamSSE(url, fetchOptions, onEvent) {
    const response = await fetch(url, fetchOptions);
    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${response.status}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    try {
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
                    } catch (e) { console.warn('Stream JSON parse error:', e.message, line); }
                }
            }
        }
    } finally {
        reader.releaseLock();
    }
}

const _MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        ...options,
    };

    const method = (config.method || 'GET').toUpperCase();
    const isMutation = _MUTATION_METHODS.has(method);

    // Attach CSRF token for state-changing requests
    if (_csrfToken && isMutation) {
        config.headers['X-CSRF-Token'] = _csrfToken;
    }

    if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
    }

    // Wire up abort signal: caller-provided signal takes priority, else use page-level
    if (!config.signal) {
        config.signal = _pageController.signal;
    }

    // Dedup concurrent identical GET requests — return the same in-flight promise
    if (!isMutation && _getInflight.has(endpoint)) {
        return _getInflight.get(endpoint);
    }

    const promise = _doApiRequest(url, config, endpoint, isMutation);

    if (!isMutation) {
        _getInflight.set(endpoint, promise);
        promise.finally(() => _getInflight.delete(endpoint));
    }

    return promise;
}

async function _doApiRequest(url, config, endpoint, isMutation) {
    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}: ${response.statusText}`);
        }

        // Auto-invalidate cache for the resource prefix after successful mutations
        if (isMutation) {
            // e.g. /api/inventory/5/hosts → invalidate keys starting with /inventory
            const prefix = endpoint.split('/').slice(0, 2).join('/');
            invalidateApiCache(prefix);
        }

        return data;
    } catch (error) {
        if (error.name === 'AbortError') throw error; // don't log aborts
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
    return cachedGet('/dashboard', () => apiRequest('/dashboard'));
}

// Inventory
export async function getInventoryGroups(includeHosts = false) {
    const key = includeHosts ? '/inventory?include_hosts=true' : '/inventory';
    return cachedGet(key, () => apiRequest(key));
}

export async function getGroup(groupId) {
    return cachedGet(`/inventory/${groupId}`, () => apiRequest(`/inventory/${groupId}`));
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

export async function updateHostCategory(hostId, deviceCategory) {
    return apiRequest(`/hosts/${hostId}/category`, {
        method: 'PATCH',
        body: { device_category: deviceCategory },
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
    return _streamSSE(url, {
        method: 'POST',
        headers,
        signal: options.signal || _pageController.signal,
        body: JSON.stringify({
            cidrs,
            timeout_seconds: options.timeoutSeconds,
            max_hosts: options.maxHosts,
            device_type: options.deviceType,
            hostname_prefix: options.hostnamePrefix,
            use_snmp: options.useSnmp !== false,
        }),
    }, onEvent);
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
    return cachedGet('/playbooks', () => apiRequest('/playbooks'));
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
    return cachedGet(`/jobs?limit=${limit}`, () => apiRequest(`/jobs?limit=${limit}`), 10_000);
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
    return cachedGet('/jobs/queue', () => apiRequest('/jobs/queue'), 10_000);
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
    return cachedGet('/templates', () => apiRequest('/templates'));
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
    return cachedGet('/credentials', () => apiRequest('/credentials'));
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

// Secret Variables
export async function getSecretVariables() {
    return apiRequest('/secret-variables');
}

export async function getSecretVariableNames() {
    return apiRequest('/secret-variables/names');
}

export async function createSecretVariable(name, value, description = '') {
    return apiRequest('/secret-variables', {
        method: 'POST',
        body: { name, value, description },
    });
}

export async function updateSecretVariable(varId, data) {
    return apiRequest(`/secret-variables/${varId}`, {
        method: 'PUT',
        body: data,
    });
}

export async function deleteSecretVariable(varId) {
    return apiRequest(`/secret-variables/${varId}`, {
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

export async function getTopologyStpDiscoveryConfig() {
    return apiRequest('/admin/topology-stp-discovery');
}

export async function updateTopologyStpDiscoveryConfig(payload) {
    return apiRequest('/admin/topology-stp-discovery', {
        method: 'PUT',
        body: payload,
    });
}

export async function runTopologyStpDiscoveryNow() {
    return apiRequest('/admin/topology-stp-discovery/run-now', {
        method: 'POST',
    });
}

export async function getTopologyStpRootPolicies(groupId = null, vlanId = null, enabledOnly = false, limit = 2000) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    if (vlanId) params.set('vlan_id', vlanId);
    if (enabledOnly) params.set('enabled_only', 'true');
    params.set('limit', limit);
    return apiRequest(`/admin/topology-stp-root-policies?${params}`);
}

export async function upsertTopologyStpRootPolicy(payload) {
    return apiRequest('/admin/topology-stp-root-policies', {
        method: 'PUT',
        body: payload,
    });
}

export async function deleteTopologyStpRootPolicy(policyId) {
    return apiRequest(`/admin/topology-stp-root-policies/${policyId}`, {
        method: 'DELETE',
    });
}

// ── Topology ────────────────────────────────────────────────────────────────

export async function getTopology(groupId = null) {
    const params = groupId ? `?group_id=${groupId}` : '';
    return cachedGet(`/topology${params}`, () => apiRequest(`/topology${params}`));
}

export async function discoverTopologyForGroup(groupId) {
    return apiRequest(`/topology/discover/${groupId}`, { method: 'POST' });
}

export async function discoverTopologyAll() {
    return apiRequest('/topology/discover', { method: 'POST' });
}

export async function discoverTopologyStream(groupId, onEvent, options = {}) {
    const url = groupId
        ? `${API_BASE}/topology/discover/${groupId}/stream`
        : `${API_BASE}/topology/discover/stream`;
    const headers = { 'Content-Type': 'application/json' };
    if (_csrfToken) headers['X-CSRF-Token'] = _csrfToken;
    return _streamSSE(url, {
        method: 'POST',
        headers,
        signal: options.signal || _pageController.signal,
    }, onEvent);
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

export async function discoverTopologyStp(groupId = null, vlanId = 1, allVlans = false, maxVlans = 64) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    if (vlanId) params.set('vlan_id', vlanId);
    if (allVlans) params.set('all_vlans', 'true');
    if (maxVlans) params.set('max_vlans', maxVlans);
    const suffix = params.toString() ? `?${params}` : '';
    return apiRequest(`/topology/stp/discover${suffix}`, { method: 'POST' });
}

export async function getTopologyStpState(groupId = null, hostId = null, vlanId = 1, limit = 5000) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    if (hostId) params.set('host_id', hostId);
    if (vlanId) params.set('vlan_id', vlanId);
    params.set('limit', limit);
    return apiRequest(`/topology/stp?${params}`);
}

export async function getTopologyStpEvents(unacknowledged = true, limit = 200) {
    return apiRequest(`/topology/stp/events?unacknowledged=${unacknowledged}&limit=${limit}`);
}

export async function acknowledgeTopologyStpEvents() {
    return apiRequest('/topology/stp/events/acknowledge', { method: 'POST' });
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
    return cachedGet('/config-drift/summary', () => apiRequest('/config-drift/summary'));
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

export async function getConfigDriftEventHistory(eventId, limit = 200) {
    return apiRequest(`/config-drift/events/${eventId}/history?limit=${limit}`);
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

export async function bulkAcceptDriftEvents(eventIds) {
    return apiRequest('/config-drift/events/bulk-accept', {
        method: 'POST',
        body: { event_ids: eventIds },
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

export async function searchConfigBackups(query, mode = 'fulltext', limit = 50, contextLines = 1) {
    const params = new URLSearchParams();
    params.set('q', query || '');
    params.set('mode', mode || 'fulltext');
    if (limit) params.set('limit', limit);
    if (contextLines != null) params.set('context_lines', contextLines);
    return apiRequest(`/config-backups/search?${params}`);
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

export async function getConfigBackupDiff(id) {
    return apiRequest(`/config-backups/${id}/diff`);
}

export async function deleteConfigBackup(id) {
    return apiRequest(`/config-backups/${id}`, { method: 'DELETE' });
}

export async function restoreConfigBackup(data) {
    return apiRequest('/config-backups/restore', { method: 'POST', body: data });
}

export async function getConfigBackupSummary() {
    return cachedGet('/config-backups/summary', () => apiRequest('/config-backups/summary'));
}

// ── Compliance Profiles & Scans ──────────────────────────────────────────────

export async function getComplianceProfiles() {
    return cachedGet('/compliance/profiles', () => apiRequest('/compliance/profiles'));
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
    return cachedGet('/compliance/summary', () => apiRequest('/compliance/summary'));
}

export async function runComplianceScan(data) {
    return apiRequest('/compliance/scan', { method: 'POST', body: data });
}

export async function runComplianceScanBulk(data) {
    return apiRequest('/compliance/scan-bulk', { method: 'POST', body: data });
}

export async function remediateComplianceFinding(data) {
    return apiRequest('/compliance/remediate', { method: 'POST', body: data });
}

export async function scanComplianceAssignmentNow(assignmentId) {
    return apiRequest(`/compliance/assignments/${assignmentId}/scan-now`, { method: 'POST' });
}

export async function loadBuiltinComplianceProfiles() {
    return apiRequest('/compliance/profiles/load-builtin', { method: 'POST' });
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
    return cachedGet('/risk-analysis/summary', () => apiRequest('/risk-analysis/summary'));
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
    return cachedGet('/deployments/summary', () => apiRequest('/deployments/summary'));
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
    const key = `/monitoring/summary${qs ? '?' + qs : ''}`;
    return cachedGet(key, () => apiRequest(key), 15_000);
}

export async function getMonitoringPolls(groupId = null, limit = 200) {
    const params = new URLSearchParams();
    if (groupId) params.set('group_id', groupId);
    if (limit) params.set('limit', limit);
    const key = `/monitoring/polls?${params}`;
    return cachedGet(key, () => apiRequest(key), 15_000);
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

export async function runMonitoringPollStream(onEvent, options = {}) {
    const url = `${API_BASE}/monitoring/poll-now/stream`;
    const headers = { 'Content-Type': 'application/json' };
    if (_csrfToken) headers['X-CSRF-Token'] = _csrfToken;
    return _streamSSE(url, {
        method: 'POST',
        headers,
        signal: options.signal || _pageController.signal,
    }, onEvent);
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
    return cachedGet('/dashboards', () => apiRequest('/dashboards'));
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

// ── Interface Error/Discard Trending ────────────────────────────────────────

export async function getInterfaceErrorSummary(hostId, days = 1) {
    return apiRequest(`/interfaces/${hostId}/errors?days=${days}`);
}

export async function getInterfaceErrorDetail(hostId, ifIndex, start = null, end = null) {
    const params = new URLSearchParams();
    if (start) params.set('start', start);
    if (end) params.set('end', end);
    const qs = params.toString();
    return apiRequest(`/interfaces/${hostId}/port/${ifIndex}/errors${qs ? '?' + qs : ''}`);
}

export async function getInterfaceErrorEvents(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/interface-error-events${qs ? '?' + qs : ''}`);
}

export async function getInterfaceErrorEvent(eventId) {
    return apiRequest(`/interface-error-events/${eventId}`);
}

export async function acknowledgeInterfaceErrorEvent(eventId) {
    return apiRequest(`/interface-error-events/${eventId}/acknowledge`, { method: 'POST' });
}

export async function resolveInterfaceErrorEvent(eventId) {
    return apiRequest(`/interface-error-events/${eventId}/resolve`, { method: 'POST' });
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

export async function getReportRunArtifacts(runId, limit = 20) {
    return apiRequest(`/reports/runs/${runId}/artifacts?limit=${encodeURIComponent(limit)}`);
}

export function getReportArtifactUrl(artifactId) {
    return `/api/reports/artifacts/${artifactId}`;
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

// ── CDEF Definitions ──────────────────────────────────────────────────────

export async function getCdefs() {
    return apiRequest('/cdefs');
}

export async function getCdef(id) {
    return apiRequest(`/cdefs/${id}`);
}

export async function createCdef(data) {
    return apiRequest('/cdefs', { method: 'POST', body: data });
}

export async function updateCdef(id, data) {
    return apiRequest(`/cdefs/${id}`, { method: 'PUT', body: data });
}

export async function deleteCdef(id) {
    return apiRequest(`/cdefs/${id}`, { method: 'DELETE' });
}

export async function evaluateCdef(data) {
    return apiRequest('/cdefs/evaluate', { method: 'POST', body: data });
}

// ── SNMP Data Sources ─────────────────────────────────────────────────────

export async function getDataSources(hostId, dsType) {
    let url = `/hosts/${hostId}/data-sources`;
    if (dsType) url += `?ds_type=${dsType}`;
    return apiRequest(url);
}

export async function discoverDataSources(hostId) {
    return apiRequest(`/hosts/${hostId}/data-sources/discover`, { method: 'POST' });
}

export async function updateDataSource(dsId, data) {
    return apiRequest(`/data-sources/${dsId}`, { method: 'PUT', body: data });
}

export async function deleteDataSource(dsId) {
    return apiRequest(`/data-sources/${dsId}`, { method: 'DELETE' });
}

// ── MAC/ARP Tracking ──────────────────────────────────────────────────────

export async function searchMacTracking(query) {
    return apiRequest(`/mac-tracking/search?query=${encodeURIComponent(query)}`);
}

export async function getHostMacArp(hostId) {
    return apiRequest(`/mac-tracking/host/${hostId}`);
}

export async function getMacHistory(macAddress) {
    return apiRequest(`/mac-tracking/history/${encodeURIComponent(macAddress)}`);
}

export async function getPortMacs(hostId, portName) {
    return apiRequest(`/mac-tracking/port/${hostId}/${encodeURIComponent(portName)}`);
}

export async function triggerMacCollection(hostId) {
    let url = '/mac-tracking/collect';
    if (hostId) url += `?host_id=${hostId}`;
    return apiRequest(url, { method: 'POST' });
}

// ── NetFlow / Traffic Analysis ────────────────────────────────────────────

export async function getFlowTopTalkers(opts = {}) {
    const params = new URLSearchParams();
    if (opts.hostId) params.set('host_id', opts.hostId);
    if (opts.hours) params.set('hours', opts.hours);
    if (opts.direction) params.set('direction', opts.direction);
    if (opts.limit) params.set('limit', opts.limit);
    return apiRequest(`/flows/top-talkers?${params}`);
}

export async function getFlowTopApplications(opts = {}) {
    const params = new URLSearchParams();
    if (opts.hostId) params.set('host_id', opts.hostId);
    if (opts.hours) params.set('hours', opts.hours);
    if (opts.limit) params.set('limit', opts.limit);
    return apiRequest(`/flows/top-applications?${params}`);
}

export async function getFlowTopConversations(opts = {}) {
    const params = new URLSearchParams();
    if (opts.hostId) params.set('host_id', opts.hostId);
    if (opts.hours) params.set('hours', opts.hours);
    if (opts.limit) params.set('limit', opts.limit);
    return apiRequest(`/flows/top-conversations?${params}`);
}

export async function getFlowTimeline(opts = {}) {
    const params = new URLSearchParams();
    if (opts.hostId) params.set('host_id', opts.hostId);
    if (opts.hours) params.set('hours', opts.hours);
    if (opts.bucketMinutes) params.set('bucket_minutes', opts.bucketMinutes);
    return apiRequest(`/flows/timeline?${params}`);
}

export async function getFlowStatus() {
    return apiRequest('/flows/status');
}

export async function startFlowCollector(port) {
    return apiRequest(`/admin/flows/start?port=${port || 2055}`, { method: 'POST' });
}

export async function stopFlowCollector() {
    return apiRequest('/admin/flows/stop', { method: 'POST' });
}

// ── Baseline Alerting ─────────────────────────────────────────────────────

export async function getBaselineRules(enabledOnly) {
    let url = '/baseline-rules';
    if (enabledOnly) url += '?enabled_only=true';
    return apiRequest(url);
}

export async function getBaselineRule(id) {
    return apiRequest(`/baseline-rules/${id}`);
}

export async function createBaselineRule(data) {
    return apiRequest('/baseline-rules', { method: 'POST', body: data });
}

export async function updateBaselineRule(id, data) {
    return apiRequest(`/baseline-rules/${id}`, { method: 'PUT', body: data });
}

export async function deleteBaselineRule(id) {
    return apiRequest(`/baseline-rules/${id}`, { method: 'DELETE' });
}

export async function getBaselines(hostId, metric) {
    let url = `/baselines?host_id=${hostId}`;
    if (metric) url += `&metric=${encodeURIComponent(metric)}`;
    return apiRequest(url);
}

export async function triggerBaselineCompute(hostId, metric, learningDays) {
    return apiRequest(`/baselines/compute?host_id=${hostId}&metric=${encodeURIComponent(metric)}&learning_days=${learningDays || 14}`, { method: 'POST' });
}

export async function getBaselineChartData(hostId, metric) {
    return apiRequest(`/baselines/${hostId}/${encodeURIComponent(metric)}/chart`);
}

// ── Graph Export ──────────────────────────────────────────────────────────

export async function getGraphConfig(hostGraphId, range, theme) {
    const params = new URLSearchParams();
    if (range) params.set('range', range);
    if (theme) params.set('theme', theme);
    return apiRequest(`/graphs/${hostGraphId}/config?${params}`);
}

export function getGraphEmbedUrl(hostGraphId, opts = {}) {
    const params = new URLSearchParams();
    if (opts.width) params.set('width', opts.width);
    if (opts.height) params.set('height', opts.height);
    if (opts.range) params.set('range', opts.range);
    if (opts.theme) params.set('theme', opts.theme);
    return `/api/graphs/${hostGraphId}/embed?${params}`;
}

export function getGraphSvgUrl(hostGraphId, opts = {}) {
    const params = new URLSearchParams();
    if (opts.width) params.set('width', opts.width);
    if (opts.height) params.set('height', opts.height);
    if (opts.range) params.set('range', opts.range);
    return `/api/graph-image/${hostGraphId}.svg?${params}`;
}

// ── Topology Utilization ──────────────────────────────────────────────────

export async function getTopologyUtilization(groupId) {
    let url = '/topology/utilization';
    if (groupId) url += `?group_id=${groupId}`;
    return apiRequest(url);
}

// ── Generic API helpers (use full path, bypass API_BASE prefix) ─────────

async function rawApiRequest(fullPath, options = {}) {
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        ...options,
    };
    if (_csrfToken && _MUTATION_METHODS.has((config.method || 'GET').toUpperCase())) {
        config.headers['X-CSRF-Token'] = _csrfToken;
    }
    if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
    }
    // Wire up abort signal so page navigation cancels these requests too
    if (!config.signal) {
        config.signal = _pageController.signal;
    }
    try {
        const response = await fetch(fullPath, config);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}: ${response.statusText}`);
        }
        return data;
    } catch (error) {
        if (error.name === 'AbortError') throw error;
        console.error('API request failed:', error);
        throw error;
    }
}

export async function apiGet(fullPath) {
    return rawApiRequest(fullPath);
}

export async function apiPost(fullPath, body) {
    return rawApiRequest(fullPath, { method: 'POST', body });
}

export async function apiPatch(fullPath, body) {
    return rawApiRequest(fullPath, { method: 'PATCH', body });
}

export async function apiDelete(fullPath) {
    return rawApiRequest(fullPath, { method: 'DELETE' });
}

// ── Cloud Visibility (AWS / Azure / GCP) ────────────────────────────────────

export async function getCloudProviders() {
    return apiRequest('/cloud/providers');
}

export async function getCloudAccounts(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/accounts${qs ? '?' + qs : ''}`);
}

export async function createCloudAccount(data) {
    return apiRequest('/cloud/accounts', { method: 'POST', body: data });
}

export async function updateCloudAccount(id, data) {
    return apiRequest(`/cloud/accounts/${id}`, { method: 'PUT', body: data });
}

export async function deleteCloudAccount(id) {
    return apiRequest(`/cloud/accounts/${id}`, { method: 'DELETE' });
}

export async function discoverCloudAccount(id, data = {}) {
    return apiRequest(`/cloud/accounts/${id}/discover`, { method: 'POST', body: data });
}

export async function validateCloudAccount(id, data = {}) {
    return apiRequest(`/cloud/accounts/${id}/validate`, { method: 'POST', body: data });
}

export async function ingestCloudFlowLogs(id, data = {}) {
    return apiRequest(`/cloud/accounts/${id}/flow-logs/ingest`, { method: 'POST', body: data });
}

export async function getCloudFlowSummary(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/flow-logs/summary${qs ? '?' + qs : ''}`);
}

export async function getCloudFlowTopTalkers(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/flow-logs/top-talkers${qs ? '?' + qs : ''}`);
}

export async function getCloudFlowTimeline(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/flow-logs/timeline${qs ? '?' + qs : ''}`);
}

export async function getCloudFlowSyncConfig() {
    return apiRequest('/cloud/flow-sync/config');
}

export async function updateCloudFlowSyncConfig(data = {}) {
    return apiRequest('/cloud/flow-sync/config', { method: 'PUT', body: data });
}

export async function triggerCloudFlowSyncPull(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/flow-sync/pull${qs ? '?' + qs : ''}`, { method: 'POST' });
}

export async function getCloudFlowSyncCursors() {
    return apiRequest('/cloud/flow-sync/cursors');
}

export async function getCloudResources(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/resources${qs ? '?' + qs : ''}`);
}

export async function getCloudConnections(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/connections${qs ? '?' + qs : ''}`);
}

export async function getCloudHybridLinks(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/hybrid-links${qs ? '?' + qs : ''}`);
}

export async function getCloudTopology(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/cloud/topology${qs ? '?' + qs : ''}`);
}

// ── Bandwidth Billing & 95th Percentile ─────────────────────────────────────

export async function getBillingCircuits(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/billing/circuits${qs ? '?' + qs : ''}`);
}

export async function getBillingCircuit(id) {
    return apiRequest(`/billing/circuits/${id}`);
}

export async function createBillingCircuit(data) {
    return apiRequest('/billing/circuits', { method: 'POST', body: data });
}

export async function updateBillingCircuit(id, data) {
    return apiRequest(`/billing/circuits/${id}`, { method: 'PUT', body: data });
}

export async function deleteBillingCircuit(id) {
    return apiRequest(`/billing/circuits/${id}`, { method: 'DELETE' });
}

export async function getBillingCustomers() {
    return apiRequest('/billing/customers');
}

export async function generateBilling(data) {
    return apiRequest('/billing/generate', { method: 'POST', body: data });
}

export async function getBillingPeriods(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/billing/periods${qs ? '?' + qs : ''}`);
}

export async function getBillingPeriod(id) {
    return apiRequest(`/billing/periods/${id}`);
}

export async function deleteBillingPeriod(id) {
    return apiRequest(`/billing/periods/${id}`, { method: 'DELETE' });
}

export async function getBillingPeriodUsage(id) {
    return apiRequest(`/billing/periods/${id}/usage`);
}

export async function getBillingSummary(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/billing/summary${qs ? '?' + qs : ''}`);
}

export function getBillingExportUrl(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return `/api/billing/export/periods${qs ? '?' + qs : ''}`;
}

// ── Federation ──────────────────────────────────────────────────────────────

export async function getFederationPeers() {
    return apiRequest('/federation/peers');
}

export async function createFederationPeer(data) {
    return apiRequest('/federation/peers', { method: 'POST', body: data });
}

export async function getFederationPeer(id) {
    return apiRequest(`/federation/peers/${id}`);
}

export async function updateFederationPeer(id, data) {
    return apiRequest(`/federation/peers/${id}`, { method: 'PUT', body: data });
}

export async function deleteFederationPeer(id) {
    return apiRequest(`/federation/peers/${id}`, { method: 'DELETE' });
}

export async function testFederationPeer(id) {
    return apiRequest(`/federation/peers/${id}/test`, { method: 'POST' });
}

export async function syncFederationPeer(id) {
    return apiRequest(`/federation/peers/${id}/sync`, { method: 'POST' });
}

export async function getFederationOverview() {
    return apiRequest('/federation/overview');
}

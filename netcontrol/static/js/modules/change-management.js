/**
 * Change Management Module — Risk Analysis + Deployments / Rollback Orchestration
 * Lazy-loaded when user navigates to #change-management
 */
import * as api from '../api.js';
import {
    listViewState, escapeHtml, showError, showSuccess, showToast,
    showModal, closeAllModals, showConfirm, formatDate, formatRelativeTime,
    skeletonCards, emptyStateHTML, navigateToPage, debounce,
    copyableCodeBlock, initCopyableBlocks, COPY_ICON_SVG, PlexusChart
} from '../app.js';

const closeModal = closeAllModals;

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
            ${result.proposed_diff ? `<div style="margin-top:1rem;"><strong>Predicted diff:</strong>${copyableCodeBlock(result.proposed_diff, { style: 'background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:300px; overflow:auto; white-space:pre-wrap' })}</div>` : ''}
            <div style="margin-top:1rem; text-align:right;">
                <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
            </div>
        `);
        initCopyableBlocks();
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
                <div style="margin-top:0.5rem;">${copyableCodeBlock(analysis.proposed_commands, { style: 'background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:200px; overflow:auto; white-space:pre-wrap' })}</div>
            </details>
        ` : ''}

        ${analysis.proposed_diff ? `
            <details style="margin-bottom:1rem;">
                <summary style="cursor:pointer; font-weight:600;">Predicted Config Diff</summary>
                <div style="margin-top:0.5rem;">${copyableCodeBlock(analysis.proposed_diff, { style: 'background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.8em; max-height:300px; overflow:auto; white-space:pre-wrap' })}</div>
            </details>
        ` : ''}

        <div style="margin-top:1rem; text-align:right;">
            ${!analysis.approved ? `<button class="btn btn-primary" onclick="approveRiskAnalysis(${analysis.id}); closeAllModals();">Approve Change</button>` : ''}
            <button class="btn btn-secondary" onclick="closeAllModals()">Close</button>
        </div>
    `);
    initCopyableBlocks();
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
    if (!await showConfirm({ title: 'Delete Risk Analysis', message: 'Delete this risk analysis?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
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
    if (!await showConfirm({ title: 'Execute Deployment', message: 'Execute this deployment? Pre-deployment snapshots will be captured before pushing config changes.', confirmText: 'Execute', confirmClass: 'btn-primary' })) return;
    try {
        const result = await api.executeDeployment(deploymentId);
        showDeploymentJobStream(result.job_id, deploymentId, 'Executing Deployment');
    } catch (e) { showError(e.message); }
}
window.executeDeploymentAction = executeDeploymentAction;

async function rollbackDeploymentAction(deploymentId) {
    if (!await showConfirm({ title: 'Rollback Deployment', message: 'Roll back this deployment? Pre-deployment config snapshots will be restored to all hosts.', confirmText: 'Roll Back', confirmClass: 'btn-danger' })) return;
    try {
        const result = await api.rollbackDeployment(deploymentId);
        showDeploymentJobStream(result.job_id, deploymentId, 'Rolling Back Deployment');
    } catch (e) { showError(e.message); }
}
window.rollbackDeploymentAction = rollbackDeploymentAction;

function showDeploymentJobStream(jobId, deploymentId, title) {
    showModal(title, `
        <div style="display:flex; flex-direction:column; gap:0.75rem;">
            <div style="display:flex; align-items:center; justify-content:space-between;">
                <span style="font-size:0.85em; color:var(--text-muted);">Deployment #${deploymentId} · Job: ${escapeHtml(jobId)}</span>
                <button class="btn btn-sm btn-secondary copyable-copy-btn" data-copyable-target="deploy-job-output" title="Copy output to clipboard">${COPY_ICON_SVG}Copy</button>
            </div>
            <pre id="deploy-job-output" class="copyable-content" tabindex="0" style="background:var(--bg-secondary); padding:1rem; border-radius:8px; max-height:400px; overflow-y:auto; font-family:var(--font-mono); font-size:0.82rem; white-space:pre-wrap; line-height:1.5; user-select:text; cursor:text;"></pre>
            <div id="deploy-job-status" style="text-align:center; color:var(--text-muted);">Connecting...</div>
        </div>
    `);
    initCopyableBlocks();

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

function renderVerificationMetrics(verifyChecks) {
    const healthChecks = verifyChecks.filter(c => c.check_type === 'metric_health');
    if (!healthChecks.length) return '';
    let rows = '';
    for (const cp of healthChecks) {
        let result;
        try { result = JSON.parse(cp.result || '{}'); } catch { continue; }
        const details = result.details || [];
        for (const m of details) {
            const preStr = m.pre != null ? m.pre.toFixed(1) : 'N/A';
            const postStr = m.post != null ? m.post.toFixed(1) : 'N/A';
            const deltaStr = m.delta != null ? (m.delta >= 0 ? `+${m.delta.toFixed(1)}` : m.delta.toFixed(1)) : '-';
            const color = m.concern ? 'var(--danger)' : 'var(--success)';
            rows += `<tr style="border-bottom:1px solid var(--border);">
                <td style="padding:4px 8px;">${escapeHtml(cp.hostname || cp.ip_address || '-')}</td>
                <td style="padding:4px 8px;">${escapeHtml(m.metric)}</td>
                <td style="padding:4px 8px;">${preStr}</td>
                <td style="padding:4px 8px;">${postStr}</td>
                <td style="padding:4px 8px; color:${color}; font-weight:600;">${deltaStr}</td>
                <td style="padding:4px 8px;">${m.concern ? '<span style="color:var(--danger);">CONCERN</span>' : '<span style="color:var(--success);">OK</span>'}</td>
            </tr>`;
        }
    }
    if (!rows) return '';
    return `<table style="width:100%; font-size:0.85em; border-collapse:collapse; margin-top:0.5rem;">
        <thead><tr style="text-align:left; border-bottom:1px solid var(--border);">
            <th style="padding:4px 8px;">Host</th><th style="padding:4px 8px;">Metric</th>
            <th style="padding:4px 8px;">Pre</th><th style="padding:4px 8px;">Post</th>
            <th style="padding:4px 8px;">Delta</th><th style="padding:4px 8px;">Status</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

async function showDeploymentDetail(deploymentId) {
    let dep;
    try { dep = await api.getDeployment(deploymentId); } catch (e) { showError(e.message); return; }

    const statusColors = {
        planning: 'text-muted', 'pre-check': 'warning', executing: 'warning',
        'post-check': 'warning', completed: 'success', failed: 'danger',
        'rolled-back': 'warning', 'rolling-back': 'warning',
        verifying: 'warning', verified: 'success', 'verification_failed': 'danger',
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
    const verifyChecks = checkpoints.filter(c => c.phase === 'verify');

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
    if (dep.status === 'completed' || dep.status === 'failed' || dep.status === 'verified' || dep.status === 'verification_failed') {
        actions += `<button class="btn btn-secondary" style="border:1px solid var(--warning); color:var(--warning);" onclick="closeModal(); rollbackDeploymentAction(${dep.id})">Rollback</button> `;
    }
    // Correlation view — available once deployment has started
    if (dep.started_at) {
        actions += `<button class="btn btn-secondary" onclick="closeAllModals(); showDeploymentCorrelation(${dep.id})">Correlation</button> `;
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
                <div style="margin-top:0.5rem;">${copyableCodeBlock(dep.proposed_commands || '', { style: 'background:var(--bg-secondary); padding:0.75rem; border-radius:6px; font-size:0.82rem; max-height:200px; overflow-y:auto; white-space:pre-wrap' })}</div>
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
            ${verifyChecks.length > 0 ? `<div>
                <h4 style="margin:0 0 0.5rem;">Verification</h4>
                ${renderCheckpointTable(verifyChecks, 'verification')}
                ${renderVerificationMetrics(verifyChecks)}
            </div>` : ''}

            <div style="display:flex; gap:0.75rem; font-size:0.85em; color:var(--text-muted);">
                <span>Pre-snapshots: ${preSnaps.length}</span>
                <span>Post-snapshots: ${postSnaps.length}</span>
            </div>

            ${actions ? `<div style="display:flex; gap:0.5rem; margin-top:0.5rem;">${actions}</div>` : ''}
        </div>
    `);
    initCopyableBlocks();
}
window.showDeploymentDetail = showDeploymentDetail;

async function showDeploymentCorrelation(deploymentId) {
    let data;
    try { data = await api.getDeploymentCorrelation(deploymentId); } catch (e) { showError(e.message); return; }
    const dep = data.deployment || {};
    const timeWindow = data.time_window || {};

    // Build a unified timeline of events sorted chronologically
    const events = [];

    // Deployment phases from checkpoints
    for (const cp of (data.checkpoints || [])) {
        events.push({
            time: cp.executed_at || cp.created_at,
            type: 'deployment',
            icon: cp.status === 'passed' ? '\u2713' : cp.status === 'failed' ? '\u2717' : '\u25CB',
            title: `${cp.phase}: ${cp.check_type}`,
            detail: `${cp.hostname || ''} — ${cp.status}`,
            color: cp.status === 'passed' ? 'var(--success)' : cp.status === 'failed' ? 'var(--danger)' : 'var(--text-muted)',
        });
    }

    // Drift events
    for (const drift of (data.drift_events || [])) {
        events.push({
            time: drift.detected_at,
            type: 'drift',
            icon: '\u26A0',
            title: 'Config Drift Detected',
            detail: `${drift.hostname || 'Host #' + drift.host_id} — +${drift.diff_lines_added || 0}/-${drift.diff_lines_removed || 0} lines`,
            color: 'var(--warning)',
        });
    }

    // Alerts
    for (const alert of (data.alerts || [])) {
        events.push({
            time: alert.created_at,
            type: 'alert',
            icon: '\u25CF',
            title: `Alert: ${alert.metric || alert.alert_type || 'unknown'}`,
            detail: `${alert.hostname || ''} — ${alert.message || ''}`.trim(),
            color: alert.severity === 'critical' ? 'var(--danger)' : 'var(--warning)',
        });
    }

    // Audit trail
    for (const ae of (data.audit_trail || [])) {
        events.push({
            time: ae.timestamp,
            type: 'audit',
            icon: '\u25B8',
            title: ae.action,
            detail: ae.detail || '',
            color: 'var(--text-muted)',
        });
    }

    events.sort((a, b) => (a.time || '').localeCompare(b.time || ''));

    const timelineHTML = events.length ? events.map(e => {
        const ts = e.time ? new Date(e.time + (e.time.includes('Z') || e.time.includes('+') ? '' : 'Z')).toLocaleTimeString() : '';
        return `<div style="display:flex; gap:0.75rem; padding:0.35rem 0; border-bottom:1px solid var(--border); font-size:0.85em;">
            <span style="min-width:60px; color:var(--text-muted);">${ts}</span>
            <span style="color:${e.color}; min-width:20px; text-align:center;">${e.icon}</span>
            <div>
                <div style="font-weight:600;">${escapeHtml(e.title)}</div>
                <div style="color:var(--text-muted); font-size:0.9em;">${escapeHtml(e.detail)}</div>
            </div>
        </div>`;
    }).join('') : '<div style="color:var(--text-muted); padding:1rem;">No correlated events found in the time window.</div>';

    const windowStart = timeWindow.start ? new Date(timeWindow.start + 'Z').toLocaleString() : '?';
    const windowEnd = timeWindow.end ? new Date(timeWindow.end + 'Z').toLocaleString() : '?';

    showModal(`Correlation — Deployment #${dep.id}`, `
        <div style="display:flex; flex-direction:column; gap:1rem;">
            <div style="font-size:0.85em; color:var(--text-muted);">
                Time window: ${windowStart} — ${windowEnd}
                <span style="margin-left:1rem;">Events: ${events.length}</span>
            </div>
            <div style="display:flex; gap:0.5rem; flex-wrap:wrap; font-size:0.8em;">
                <span style="color:#3b82f6;">\u25CF Deployment</span>
                <span style="color:var(--warning);">\u25CF Drift</span>
                <span style="color:var(--danger);">\u25CF Alert</span>
                <span style="color:var(--text-muted);">\u25CF Audit</span>
            </div>
            <div style="max-height:400px; overflow-y:auto; border:1px solid var(--border); border-radius:0.5rem; padding:0.5rem;">
                ${timelineHTML}
            </div>
            <div id="correlation-chart" style="height:200px;"></div>
        </div>
    `);

    // Render a mini metric chart for affected hosts during the window
    try {
        const hostIds = JSON.parse(dep.host_ids || '[]');
        if (hostIds.length) {
            const cpuData = await api.queryMetrics('cpu_percent', hostIds.join(','), '24h');
            const series = [];
            const byHost = {};
            for (const d of (cpuData?.data || [])) {
                const key = d.hostname || `host-${d.host_id}`;
                if (!byHost[key]) byHost[key] = [];
                byHost[key].push(d);
            }
            for (const [name, pts] of Object.entries(byHost)) {
                series.push({ name, data: pts.map(d => ({ time: d.sampled_at || d.period_start, value: d.val_avg ?? d.value ?? 0 })) });
            }
            if (series.length) {
                PlexusChart.timeSeries('correlation-chart', series, { area: true, yAxisName: 'CPU %', yMin: 0, yMax: 100 });
                // Add deployment annotations
                const depAnnotations = events
                    .filter(e => e.type === 'deployment' || e.type === 'alert')
                    .map(e => ({ timestamp: e.time, title: e.title, category: e.type === 'alert' ? 'alert' : 'deployment' }));
                if (depAnnotations.length) PlexusChart.addAnnotations('correlation-chart', depAnnotations);
            }
        }
    } catch { /* chart is non-critical */ }
}
window.showDeploymentCorrelation = showDeploymentCorrelation;

async function showAlertCorrelation(alertId) {
    let data;
    try { data = await api.getAlertCorrelation(alertId); } catch (e) { showError(e.message); return; }
    const alert = data.alert || {};

    const deploymentRows = (data.related_deployments || []).map(dep =>
        `<div style="display:flex; justify-content:space-between; align-items:center; padding:0.4rem 0; border-bottom:1px solid var(--border);">
            <div>
                <div style="font-weight:600;">${escapeHtml(dep.name || `Deployment #${dep.id}`)}</div>
                <div style="font-size:0.85em; color:var(--text-muted);">
                    ${dep.status} — ${dep.started_at ? new Date(dep.started_at + 'Z').toLocaleString() : ''}
                </div>
            </div>
            <button class="btn btn-sm btn-secondary" onclick="closeAllModals(); showDeploymentCorrelation(${dep.id})">View Correlation</button>
        </div>`
    ).join('') || '<div style="color:var(--text-muted);">No related deployments found.</div>';

    const driftRows = (data.related_drift_events || []).map(drift =>
        `<div style="padding:0.4rem 0; border-bottom:1px solid var(--border);">
            <div style="font-weight:600;">${escapeHtml(drift.hostname || `Host #${drift.host_id}`)} — Config Drift</div>
            <div style="font-size:0.85em; color:var(--text-muted);">
                +${drift.diff_lines_added || 0}/-${drift.diff_lines_removed || 0} lines — ${drift.detected_at ? new Date(drift.detected_at + 'Z').toLocaleString() : ''}
            </div>
        </div>`
    ).join('') || '<div style="color:var(--text-muted);">No related drift events found.</div>';

    showModal(`Alert Correlation — ${escapeHtml(alert.metric || alert.alert_type || 'Alert')}`, `
        <div style="display:flex; flex-direction:column; gap:1rem;">
            <div class="card" style="padding:1rem;">
                <div style="display:flex; gap:1rem; flex-wrap:wrap; font-size:0.9em;">
                    <span><strong>Host:</strong> ${escapeHtml(alert.hostname || '')}</span>
                    <span><strong>Severity:</strong> <span style="color:${alert.severity === 'critical' ? 'var(--danger)' : 'var(--warning)'};">${escapeHtml(alert.severity || 'unknown')}</span></span>
                    <span><strong>Value:</strong> ${alert.value != null ? alert.value : '-'}</span>
                    <span><strong>Time:</strong> ${alert.created_at ? new Date(alert.created_at + 'Z').toLocaleString() : '-'}</span>
                </div>
                ${alert.message ? `<div style="margin-top:0.5rem; color:var(--text-muted); font-size:0.85em;">${escapeHtml(alert.message)}</div>` : ''}
            </div>
            <div>
                <h4 style="margin:0 0 0.5rem;">Possibly Related Deployments (30 min window)</h4>
                ${deploymentRows}
            </div>
            <div>
                <h4 style="margin:0 0 0.5rem;">Related Config Drift</h4>
                ${driftRows}
            </div>
        </div>
    `);
}
window.showAlertCorrelation = showAlertCorrelation;

async function confirmDeleteDeployment(deploymentId) {
    if (!await showConfirm({ title: 'Delete Deployment', message: 'Delete this deployment and all its checkpoints/snapshots?', confirmText: 'Delete', confirmClass: 'btn-danger' })) return;
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


// ═══════════════════════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════════════════════

export { loadRiskAnalysis, loadDeployments };

export function destroyChangeManagement() {
    // Cleanup: cancel any pending operations if needed in the future
}

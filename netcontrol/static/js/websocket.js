/**
 * WebSocket Client for Job Output Streaming
 */

let currentJobSocket = null;

export function connectJobWebSocket(jobId, onMessage, onComplete, onError) {
    // Close existing connection if any
    if (currentJobSocket) {
        currentJobSocket.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/jobs/${jobId}`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log(`WebSocket connected for job ${jobId}`);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'job_complete') {
                if (onComplete) onComplete(data);
                ws.close();
                currentJobSocket = null;
            } else {
                if (onMessage) onMessage(data);
            }
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        if (onError) onError(error);
    };

    ws.onclose = () => {
        console.log(`WebSocket closed for job ${jobId}`);
        currentJobSocket = null;
    };

    currentJobSocket = ws;
    return ws;
}

export function disconnectJobWebSocket() {
    if (currentJobSocket) {
        currentJobSocket.close();
        currentJobSocket = null;
    }
}

// ── Upgrade Campaign WebSocket ──────────────────────────────────────────────

let currentUpgradeSocket = null;

export function connectUpgradeWebSocket(campaignId, onMessage, onComplete, onError) {
    if (currentUpgradeSocket) {
        currentUpgradeSocket.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/upgrades/${campaignId}`;

    const ws = new WebSocket(wsUrl);
    let replayDone = false;
    let lastReplayTimestamp = '';

    ws.onopen = () => {
        console.log(`Upgrade WebSocket connected for campaign ${campaignId}`);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            // Mark end of historical replay
            if (data.type === 'replay_complete') {
                lastReplayTimestamp = data.last_timestamp || '';
                replayDone = true;
                return;
            }

            if (data.type === 'campaign_complete') {
                if (onComplete) onComplete(data);
            } else {
                // Skip duplicate live events that were already sent during replay
                if (replayDone && lastReplayTimestamp && data.type === 'upgrade_event' && data.timestamp && data.timestamp <= lastReplayTimestamp) {
                    return;
                }
                if (onMessage) onMessage(data);
            }
        } catch (error) {
            console.error('Error parsing upgrade WebSocket message:', error);
        }
    };

    ws.onerror = (error) => {
        console.error('Upgrade WebSocket error:', error);
        if (onError) onError(error);
    };

    ws.onclose = (event) => {
        console.log(`Upgrade WebSocket closed for campaign ${campaignId} (code: ${event.code})`);
        currentUpgradeSocket = null;
        // Only fire error for abnormal closures (not clean close or auth rejection)
        if (event.code !== 1000 && event.code !== 1005 && event.code !== 4001) {
            if (onError) onError(event);
        }
    };

    currentUpgradeSocket = ws;
    return ws;
}

export function disconnectUpgradeWebSocket() {
    if (currentUpgradeSocket) {
        currentUpgradeSocket.close();
        currentUpgradeSocket = null;
    }
}

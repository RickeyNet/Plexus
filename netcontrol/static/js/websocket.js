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

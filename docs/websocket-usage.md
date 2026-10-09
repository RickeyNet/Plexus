# WebSocket Usage

Connect to `/ws/jobs/{job_id}` after launching a job:

```javascript
const ws = new WebSocket("ws://localhost:8080/ws/jobs/1");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === "job_complete") {
    console.log("Job finished!");
  } else {
    console.log(`[${data.level}] ${data.host ? data.host + ": " : ""}${data.message}`);
  }
};
```

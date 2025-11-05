// src/api/captureAPI.js
const BASE_URL = "http://localhost:5000";

export const captureAPI = {
  async startCapture(device, iface) {
    const res = await fetch(`${BASE_URL}/api/capture/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device, interface: iface }),
    });
    if (!res.ok) throw new Error("Failed to start capture");
    return res.json();
  },

  async stopCapture(sessionId) {
    const res = await fetch(`${BASE_URL}/api/capture/stop/${sessionId}`, {
      method: "POST",
    });
    if (!res.ok) throw new Error("Failed to stop capture");
    return res.json();
  },

  async parseCapture(fileUrl) {
    const res = await fetch(`${BASE_URL}/api/capture/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileUrl }),
    });
    if (!res.ok) throw new Error("Failed to parse capture");
    return res.json();
  },

  subscribeLogs(onMessage, onError) {
    const eventSource = new EventSource(`${BASE_URL}/api/capture/logs`);

    eventSource.onmessage = (event) => {
      try {
        // Remove ANSI color codes before parsing
        const sanitized = event.data.replace(/\x1B\[[0-9;]*[A-Za-z]/g, "");
        const data = JSON.parse(sanitized);

        // Only forward the "message" string
        if (data.message) onMessage(data.message);
      } catch (err) {
        console.error("Failed to parse SSE event:", event.data);
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE error:", err);
      eventSource.close();
      if (onError) onError(err);
    };

    return eventSource;
  },
};

// src/api/captureAPI.js
const BASE_URL = "http://localhost:5000";

export const captureAPI = {
  /**
   * List available access points from Raspberry Pi
   * Calls: POST /api/capture/list-aps
   */
  async listAccessPoints(iface = "wlan1") {
    const res = await fetch(`${BASE_URL}/api/capture/list-aps`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    });

    if (!res.ok) throw new Error("Failed to fetch access points");
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Failed to load APs");

    // Return AP list directly
    return data.aps || [];
  },

  /**
   * Start packet capture on given AP
   * Calls: POST /api/capture/start
   */
  async startCapture(device, iface, bssid, channel) {
    const payload = { device, interface: iface, bssid, channel };

    const res = await fetch(`${BASE_URL}/api/capture/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) throw new Error("Failed to start capture");
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Error starting capture");

    return data;
  },

  /**
   * Stop an active capture session
   * Calls: POST /api/capture/stop/:sessionId
   */
  async stopCapture(sessionId) {
    const res = await fetch(`${BASE_URL}/api/capture/stop/${sessionId}`, {
      method: "POST",
    });

    if (!res.ok) throw new Error("Failed to stop capture");
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Stop failed");

    return data;
  },

  /**
   * Parse capture file for summary
   * Calls: POST /api/capture/parse
   */
  async parseCapture(fileUrl) {
    const res = await fetch(`${BASE_URL}/api/capture/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileUrl }),
    });

    if (!res.ok) throw new Error("Failed to parse capture");
    const data = await res.json();

    return data;
  },

  /**
   * Subscribe to live logs (Server-Sent Events)
   * Calls: GET /api/capture/logs
   */
  subscribeLogs(onMessage, onError) {
  const eventSource = new EventSource(`${BASE_URL}/api/capture/logs`);

    eventSource.onmessage = (event) => {
      try {
        // Step 1 — ignore empty messages
        if (!event.data || event.data.trim() === "") return;

        // Step 2 — remove ANSI color codes
        let sanitized = event.data.replace(/\x1B\[[0-9;]*[A-Za-z]/g, "");

        // Step 3 — normalize Windows backslashes safely
        sanitized = sanitized.replace(/\\/g, "\\\\");

        // Step 4 — sometimes Flask sends multiple JSON objects joined by \n\n
        const parts = sanitized.split(/\n+/).filter(Boolean);

        for (const part of parts) {
          try {
            const data = JSON.parse(part);
            if (data?.message) onMessage(data.message);
          } catch (jsonErr) {
            // Just log and continue instead of breaking the stream
            console.debug("Skipping unparsable SSE fragment:", part);
          }
        }
      } catch (err) {
        console.warn("[!] Failed to parse SSE event:", event.data);
      }
    };

    eventSource.onerror = (err) => {
      console.error("[!] SSE connection error:", err);
      eventSource.close();
      if (onError) onError(err);
    };

    return eventSource;
  },


};

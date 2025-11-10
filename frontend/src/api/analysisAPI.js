// src/api/analysisAPI.js
const BASE_URL = "http://localhost:5000";

export const analysisAPI = {
  async analyze(fileUrl, ssid, bssid) {
    const res = await fetch(`${BASE_URL}/api/analysis/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileUrl, ssid, bssid }),
    });

    if (!res.ok) throw new Error("Failed to analyze capture");
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Analysis failed");

    return data;
  },

  /**
   * Download a capture file from the server
   * @param {string} filename - The filename to download
   */
  downloadFile(filename) {
    // Create download URL
    const downloadUrl = `${BASE_URL}/api/analysis/download/${filename}`;
    // Trigger download by setting window location
    window.location.href = downloadUrl;
  },
};

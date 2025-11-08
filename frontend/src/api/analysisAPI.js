const BASE_URL = "http://localhost:5000";

export const analysisAPI = {
    /**
     * Fetch analysis of the latest capture file.
     */
    async getLatestCaptureAnalysis() {
        const res = await fetch(`${BASE_URL}/api/analysis/latest`);
        const data = await res.json();

        if (!res.ok || !data.ok) {
        throw new Error(data.error || "Failed to analyze latest capture");
        }
        return data;
    }

};

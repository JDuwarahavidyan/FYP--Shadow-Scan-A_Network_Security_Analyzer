const BASE_URL = "http://localhost:5000";

export const analysisAPI = {
  async analyze(fileUrl) {
    const res = await fetch(`${BASE_URL}/api/analysis/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileUrl }),
    });

    if (!res.ok) throw new Error("Failed to analyze capture");
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Error analyzing capture");

    return data;
  },
};

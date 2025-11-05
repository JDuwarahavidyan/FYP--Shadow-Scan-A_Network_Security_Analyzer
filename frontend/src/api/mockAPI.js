// src/api/mockAPI.js
export const mockAPI = {
  captureSession: null,
  mitigationSession: null,

  async startCapture(device, iface) {
    await new Promise(resolve => setTimeout(resolve, 500));
    const sessionId = `cap-${Date.now()}`;
    this.captureSession = sessionId;
    return { ok: true, sessionId, startedAt: new Date().toISOString() };
  },

  async stopCapture(sessionId) {
    await new Promise(resolve => setTimeout(resolve, 800));
    const fileUrl = `/files/capture-${Date.now()}.cap`;
    return {
      ok: true,
      fileUrl,
      meta: {
        packetCount: Math.floor(Math.random() * 10000) + 1000,
        duration: Math.floor(Math.random() * 300) + 60,
      },
    };
  },

  async parseCapture(file) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return {
      summary: {
        totalPackets: Math.floor(Math.random() * 10000) + 1000,
        protocols: { TCP: 45, UDP: 30, ICMP: 15, Other: 10 },
      },
      flows: [
        { src: '192.168.1.10', dst: '8.8.8.8', protocol: 'DNS', packets: 124 },
        { src: '192.168.1.15', dst: '192.168.1.1', protocol: 'HTTP', packets: 856 },
      ],
      topHosts: ['192.168.1.10', '192.168.1.15', '192.168.1.20'],
    };
  },

  async startJob(type, fileUrl) {
    await new Promise(resolve => setTimeout(resolve, 300));
    return { ok: true, jobId: `job-${type}-${Date.now()}` };
  },

  async startMitigation(profile, target, iface) {
    await new Promise(resolve => setTimeout(resolve, 500));
    const sessionId = `mit-${Date.now()}`;
    this.mitigationSession = sessionId;
    return { ok: true, sessionId, startedAt: new Date().toISOString() };
  },

  async stopMitigation(sessionId) {
    await new Promise(resolve => setTimeout(resolve, 800));
    return {
      ok: true,
      fileUrl: `/files/mitigation-${Date.now()}.cap`,
      meta: { packetsInjected: Math.floor(Math.random() * 500) + 50 },
    };
  },
};

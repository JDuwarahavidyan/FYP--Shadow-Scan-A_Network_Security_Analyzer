import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Wifi, WifiOff, Zap, ZapOff, Shield, ShieldAlert, Activity, Download, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

// Mock API and Socket.io simulation
const mockAPI = {
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
        duration: Math.floor(Math.random() * 300) + 60
      }
    };
  },
  
  async parseCapture(file) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return {
      summary: {
        totalPackets: Math.floor(Math.random() * 10000) + 1000,
        protocols: { TCP: 45, UDP: 30, ICMP: 15, Other: 10 }
      },
      flows: [
        { src: '192.168.1.10', dst: '8.8.8.8', protocol: 'DNS', packets: 124 },
        { src: '192.168.1.15', dst: '192.168.1.1', protocol: 'HTTP', packets: 856 }
      ],
      topHosts: ['192.168.1.10', '192.168.1.15', '192.168.1.20']
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
      meta: { packetsInjected: Math.floor(Math.random() * 500) + 50 }
    };
  }
};

// Simulate WebSocket events
const useSocketEvents = (callback) => {
  useEffect(() => {
    const interval = setInterval(() => {
      // Simulated socket events would fire here
    }, 1000);
    return () => clearInterval(interval);
  }, [callback]);
};

// Status Badge Component
const StatusBadge = ({ status }) => {
  const configs = {
    idle: { bg: 'bg-gray-700', text: 'text-gray-300', label: 'Idle' },
    capturing: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', label: 'Capturing', pulse: true },
    stopping: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Stopping' },
    error: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Error' },
    running: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Running', pulse: true }
  };
  
  const config = configs[status] || configs.idle;
  
  return (
    <div className={`inline-flex items-center px-3 py-1 rounded-full ${config.bg} ${config.text} text-xs font-mono`}>
      {config.pulse && <span className="w-2 h-2 bg-current rounded-full mr-2 animate-pulse" />}
      {config.label}
    </div>
  );
};

// Card Component
const Card = ({ title, icon: Icon, children, className = '' }) => (
  <div className={`bg-gray-900/50 backdrop-blur-sm border border-cyan-500/30 rounded-lg p-4 shadow-lg shadow-cyan-500/10 ${className}`}>
    {title && (
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-cyan-500/20">
        {Icon && <Icon className="w-5 h-5 text-cyan-400" />}
        <h3 className="text-cyan-400 font-mono font-semibold">{title}</h3>
      </div>
    )}
    {children}
  </div>
);

// Live Log Terminal Component
const LiveLogTerminal = ({ logs, title = "Live Terminal" }) => {
  const termRef = useRef(null);
  
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [logs]);
  
  return (
    <Card title={title} icon={Terminal}>
      <div 
        ref={termRef}
        className="bg-black/50 rounded p-3 h-64 overflow-y-auto font-mono text-xs text-green-400 space-y-1"
      >
        {logs.length === 0 ? (
          <div className="text-gray-500">Waiting for events...</div>
        ) : (
          logs.map((log, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-cyan-600">[{log.ts}]</span>
              <span>{log.line}</span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
};

// Packet Capture Panel Component
const PacketCapturePanel = ({ onCaptureComplete }) => {
  const [status, setStatus] = useState('idle');
  const [sessionId, setSessionId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [packetCount, setPacketCount] = useState(0);
  
  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };
  
  const startCapture = async () => {
    setStatus('capturing');
    setLogs([]);
    setPacketCount(0);
    addLog('Initializing packet capture...');
    
    try {
      const result = await mockAPI.startCapture('raspberrypi-1', 'wlan0');
      setSessionId(result.sessionId);
      addLog(`Capture started: ${result.sessionId}`);
      addLog('Listening on interface wlan0...');
      
      // Simulate packet counting
      const interval = setInterval(() => {
        setPacketCount(prev => prev + Math.floor(Math.random() * 50) + 10);
        if (Math.random() > 0.7) {
          addLog(`Captured ${Math.floor(Math.random() * 20)} packets`);
        }
      }, 1500);
      
      // Store interval for cleanup
      window.captureInterval = interval;
    } catch (error) {
      setStatus('error');
      addLog(`Error: ${error.message}`);
    }
  };
  
  const stopCapture = async () => {
    if (!sessionId) return;
    
    setStatus('stopping');
    addLog('Stopping capture...');
    
    if (window.captureInterval) {
      clearInterval(window.captureInterval);
    }
    
    try {
      const result = await mockAPI.stopCapture(sessionId);
      addLog(`Capture stopped. File: ${result.fileUrl}`);
      addLog(`Total packets: ${result.meta.packetCount}`);
      setStatus('idle');
      setSessionId(null);
      
      // Parse the capture
      addLog('Parsing capture file...');
      const parsed = await mockAPI.parseCapture(result.fileUrl);
      addLog('Parse complete!');
      
      if (onCaptureComplete) {
        onCaptureComplete(result.fileUrl, parsed);
      }
    } catch (error) {
      setStatus('error');
      addLog(`Error: ${error.message}`);
    }
  };
  
  return (
    <div className="space-y-4">
      <Card title="Packet Capture Control" icon={Wifi}>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
            <div className="text-cyan-400 font-mono text-sm">
              Packets: <span className="text-white font-bold">{packetCount}</span>
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={startCapture}
              disabled={status === 'capturing'}
              className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500 text-green-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Wifi className="w-4 h-4" />
              Start Capture
            </button>
            
            <button
              onClick={stopCapture}
              disabled={status !== 'capturing'}
              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500 text-red-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <WifiOff className="w-4 h-4" />
              Stop Capture
            </button>
          </div>
        </div>
      </Card>
      
      <LiveLogTerminal logs={logs} title="Capture Logs" />
    </div>
  );
};

// PCAP Viewer Component
const PcapViewer = ({ fileUrl, parsed }) => {
  if (!parsed) return null;
  
  return (
    <Card title="Capture Analysis" icon={Activity}>
      <div className="space-y-4">
        <div className="bg-black/30 rounded p-3">
          <div className="text-xs text-gray-400 mb-2">File: {fileUrl}</div>
          <div className="text-sm text-cyan-400">
            Total Packets: <span className="text-white font-bold">{parsed.summary.totalPackets}</span>
          </div>
        </div>
        
        <div>
          <div className="text-sm text-cyan-400 mb-2">Protocol Distribution</div>
          <div className="space-y-2">
            {Object.entries(parsed.summary.protocols).map(([protocol, percent]) => (
              <div key={protocol} className="flex items-center gap-2">
                <div className="text-xs text-gray-400 w-16">{protocol}</div>
                <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                  <div 
                    className="bg-cyan-500 h-full transition-all"
                    style={{ width: `${percent}%` }}
                  />
                </div>
                <div className="text-xs text-white w-12 text-right">{percent}%</div>
              </div>
            ))}
          </div>
        </div>
        
        <div>
          <div className="text-sm text-cyan-400 mb-2">Top Flows</div>
          <div className="space-y-2">
            {parsed.flows.map((flow, i) => (
              <div key={i} className="bg-black/30 rounded p-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-green-400">{flow.src}</span>
                  <span className="text-gray-500">→</span>
                  <span className="text-magenta-400">{flow.dst}</span>
                </div>
                <div className="text-gray-400 mt-1">
                  {flow.protocol} • {flow.packets} packets
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <button className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all flex items-center justify-center gap-2">
          <Download className="w-4 h-4" />
          Download PCAP
        </button>
      </div>
    </Card>
  );
};

// Fingerprint Results Component
const FingerprintResults = ({ fileUrl }) => {
  const [loading, setLoading] = useState(false);
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  
  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };
  
  const runFingerprint = async () => {
    setLoading(true);
    setLogs([]);
    addLog('Starting device fingerprinting...');
    
    try {
      const { jobId } = await mockAPI.startJob('fingerprint', fileUrl);
      addLog(`Job created: ${jobId}`);
      
      // Simulate progress
      await new Promise(resolve => setTimeout(resolve, 1000));
      addLog('Analyzing MAC addresses...');
      
      await new Promise(resolve => setTimeout(resolve, 1500));
      addLog('Querying vendor database...');
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      addLog('Running ML fingerprint model...');
      
      // Mock results
      const mockDevices = [
        { mac: 'AA:BB:CC:11:22:33', vendor: 'Apple Inc.', fingerprint: 'iPhone 12', confidence: 0.94, tags: ['mobile', 'iOS'] },
        { mac: '00:11:22:33:44:55', vendor: 'Samsung', fingerprint: 'Smart TV', confidence: 0.87, tags: ['IoT', 'media'] },
        { mac: 'FF:EE:DD:CC:BB:AA', vendor: 'Unknown', fingerprint: 'Linux Device', confidence: 0.65, tags: ['unknown'] }
      ];
      
      setDevices(mockDevices);
      addLog(`Fingerprinting complete! Found ${mockDevices.length} devices.`);
      setLoading(false);
    } catch (error) {
      addLog(`Error: ${error.message}`);
      setLoading(false);
    }
  };
  
  return (
    <div className="space-y-4">
      <Card title="Device Fingerprinting" icon={Shield}>
        <button
          onClick={runFingerprint}
          disabled={!fileUrl || loading}
          className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Analyzing...' : 'Run Fingerprint Analysis'}
        </button>
        
        {devices.length > 0 && (
          <div className="mt-4 space-y-3">
            {devices.map((device, i) => (
              <div key={i} className="bg-black/30 rounded p-3 border border-cyan-500/20">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="text-sm font-mono text-white">{device.fingerprint}</div>
                    <div className="text-xs text-gray-400">{device.vendor}</div>
                  </div>
                  <div className="text-xs text-cyan-400">
                    {(device.confidence * 100).toFixed(0)}%
                  </div>
                </div>
                <div className="text-xs font-mono text-gray-500 mb-2">{device.mac}</div>
                <div className="flex gap-2">
                  {device.tags.map(tag => (
                    <span key={tag} className="px-2 py-1 bg-magenta-500/20 text-magenta-400 rounded text-xs">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
      
      {logs.length > 0 && <LiveLogTerminal logs={logs} title="Fingerprint Logs" />}
    </div>
  );
};

// Mitigation Panel Component
const MitigationPanel = ({ onMitigationComplete }) => {
  const [status, setStatus] = useState('idle');
  const [sessionId, setSessionId] = useState(null);
  const [showWarning, setShowWarning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [profile, setProfile] = useState('reset-arp');
  
  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };
  
  const startMitigation = async () => {
    setShowWarning(false);
    setStatus('running');
    setLogs([]);
    addLog('⚠️  MITIGATION ACTIVE - Legal authorization required!');
    addLog(`Starting ${profile} mitigation...`);
    
    try {
      const result = await mockAPI.startMitigation(profile, '192.168.1.10', 'wlan0');
      setSessionId(result.sessionId);
      addLog(`Session: ${result.sessionId}`);
      addLog('Injecting packets...');
      
      const interval = setInterval(() => {
        if (Math.random() > 0.6) {
          addLog(`Injected ${Math.floor(Math.random() * 10) + 1} packets`);
        }
      }, 2000);
      
      window.mitigationInterval = interval;
    } catch (error) {
      setStatus('error');
      addLog(`Error: ${error.message}`);
    }
  };
  
  const stopMitigation = async () => {
    if (!sessionId) return;
    
    addLog('Stopping mitigation...');
    
    if (window.mitigationInterval) {
      clearInterval(window.mitigationInterval);
    }
    
    try {
      const result = await mockAPI.stopMitigation(sessionId);
      addLog(`Mitigation stopped. File: ${result.fileUrl}`);
      addLog(`Packets injected: ${result.meta.packetsInjected}`);
      setStatus('idle');
      setSessionId(null);
      
      if (onMitigationComplete) {
        onMitigationComplete(result.fileUrl);
      }
    } catch (error) {
      setStatus('error');
      addLog(`Error: ${error.message}`);
    }
  };
  
  return (
    <div className="space-y-4">
      <Card title="Packet Injection & Mitigation" icon={Zap}>
        <div className="space-y-4">
          <div className="bg-red-500/10 border border-red-500/50 rounded p-3 text-xs text-red-400">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold mb-1">⚠️ WARNING - Authorized Use Only</div>
                <div>Packet injection may be illegal without proper authorization. Only use on networks you own or have explicit permission to test.</div>
              </div>
            </div>
          </div>
          
          <div>
            <label className="text-xs text-gray-400 mb-2 block">Mitigation Profile</label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              disabled={status === 'running'}
              className="w-full bg-black/50 border border-cyan-500/30 rounded px-3 py-2 text-white font-mono text-sm focus:outline-none focus:border-cyan-500"
            >
              <option value="reset-arp">ARP Reset</option>
              <option value="tcp-reset">TCP Reset</option>
              <option value="dns-spoof">DNS Response</option>
              <option value="deauth">WiFi Deauth</option>
            </select>
          </div>
          
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
          </div>
          
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={() => setShowWarning(true)}
              disabled={status === 'running'}
              className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500 text-green-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Zap className="w-4 h-4" />
              Start Mitigation
            </button>
            
            <button
              onClick={stopMitigation}
              disabled={status !== 'running'}
              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500 text-red-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <ZapOff className="w-4 h-4" />
              Stop Mitigation
            </button>
          </div>
        </div>
      </Card>
      
      <LiveLogTerminal logs={logs} title="Mitigation Logs" />
      
      {showWarning && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border-2 border-red-500 rounded-lg p-6 max-w-md">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 shrink-0" />
              <div>
                <h3 className="text-red-500 font-bold text-lg mb-2">Confirm Authorization</h3>
                <p className="text-gray-300 text-sm mb-3">
                  You are about to perform packet injection. This action:
                </p>
                <ul className="text-gray-400 text-xs space-y-1 list-disc list-inside mb-3">
                  <li>May disrupt network services</li>
                  <li>Requires legal authorization</li>
                  <li>Is logged and monitored</li>
                  <li>Could violate laws if misused</li>
                </ul>
                <p className="text-white text-sm font-bold">
                  Do you have authorization to perform this action?
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setShowWarning(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-mono text-sm transition-all"
              >
                Cancel
              </button>
              <button
                onClick={startMitigation}
                className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded font-mono text-sm transition-all"
              >
                I Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// 🔹 Main Dashboard (Updated Layout)
export default function CyberpunkDashboard() {
  const [captureFile, setCaptureFile] = useState(null);
  const [parsedData, setParsedData] = useState(null);

  return (
    <div className="min-h-screen bg-linear-to-br from-gray-900 via-black to-gray-900 text-white">
      {/* Header */}
      <nav className="border-b border-cyan-500/30 bg-black/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <ShieldAlert  className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold font-mono text-cyan-400">Shadow Scan</h1>
              <p className="text-xs text-gray-500">Network Security Command Center</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" /> System Online
          </div>
        </div>
      </nav>

      {/* Main Body (Now Single Column) */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="flex flex-col gap-6">
          {/* Controls */}
          <div className="space-y-6">
            <PacketCapturePanel onCaptureComplete={(f, p) => { setCaptureFile(f); setParsedData(p); }} />
            <MitigationPanel onMitigationComplete={setCaptureFile} />
          </div>

          {/* Results */}
          <div className="space-y-6">
            <PcapViewer fileUrl={captureFile} parsed={parsedData} />
            <FingerprintResults fileUrl={captureFile} />
          </div>
        </div>

        {/* Footer */}
        <div className="mt-12 pt-6 border-t border-cyan-500/20 text-center">
          <p className="text-xs text-gray-500 font-mono">NetWatch v1.0 • Raspberry Pi + Jetson Nano Integration Ready</p>
          <p className="text-xs text-red-500 mt-2">⚠️ Authorized Use Only • All Activity Logged</p>
        </div>
      </div>
    </div>
  );
}
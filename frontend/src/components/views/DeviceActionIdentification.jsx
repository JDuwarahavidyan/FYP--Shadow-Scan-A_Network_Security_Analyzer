import React, { useState } from 'react';
import { Activity, Play, Users } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { mockAPI } from '../../api/mockAPI';

export function DeviceActionIdentification({ fileUrl, devices = [] }) {
  const [loading, setLoading] = useState(false);
  const [activeDevices, setActiveDevices] = useState([]);
  const [logs, setLogs] = useState([]);

  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };

  const runActionAnalysis = async () => {
    setLoading(true);
    setLogs([]);
    addLog('Starting device action identification...');
    
    try {
      const { jobId } = await mockAPI.startJob('action-analysis', fileUrl);
      addLog(`Analysis job created: ${jobId}`);
      
      await new Promise(r => setTimeout(r, 1000));
      addLog('Analyzing packet timestamps...');
      
      await new Promise(r => setTimeout(r, 1500));
      addLog('Correlating device activities...');
      
      await new Promise(r => setTimeout(r, 1000));
      addLog('Identifying active communication patterns...');
      
      await new Promise(r => setTimeout(r, 800));
      addLog('Processing traffic flow data...');

      // Mock active devices based on fingerprinted devices or create sample data
      const mockActiveDevices = devices.length > 0 
        ? devices.map(device => ({
            ...device,
            isActive: Math.random() > 0.3, // 70% chance to be active
            lastSeen: new Date(Date.now() - Math.random() * 300000).toLocaleTimeString(), // Last 5 minutes
            packetCount: Math.floor(Math.random() * 500) + 50,
            actions: generateMockActions(device.fingerprint),
            trafficType: getTrafficType(device.fingerprint),
            signalStrength: Math.floor(Math.random() * 40) - 80 // -80 to -40 dBm
          }))
        : [
            {
              mac: 'AA:BB:CC:11:22:33',
              vendor: 'Apple Inc.',
              fingerprint: 'iPhone 12',
              confidence: 0.94,
              tags: ['mobile', 'iOS'],
              isActive: true,
              lastSeen: new Date(Date.now() - 30000).toLocaleTimeString(),
              packetCount: 342,
              actions: ['Data Transmission', 'Background Sync', 'Location Services'],
              trafficType: 'Mixed',
              signalStrength: -45
            },
            {
              mac: '00:11:22:33:44:55',
              vendor: 'Samsung',
              fingerprint: 'Smart TV',
              confidence: 0.87,
              tags: ['IoT', 'media'],
              isActive: true,
              lastSeen: new Date(Date.now() - 120000).toLocaleTimeString(),
              packetCount: 156,
              actions: ['Media Streaming', 'Firmware Update Check'],
              trafficType: 'Streaming',
              signalStrength: -52
            },
            {
              mac: 'FF:EE:DD:CC:BB:AA',
              vendor: 'Unknown',
              fingerprint: 'Linux Device',
              confidence: 0.65,
              tags: ['unknown'],
              isActive: false,
              lastSeen: new Date(Date.now() - 600000).toLocaleTimeString(),
              packetCount: 23,
              actions: ['Periodic Beacon'],
              trafficType: 'Minimal',
              signalStrength: -78
            }
          ];

      const activeCount = mockActiveDevices.filter(d => d.isActive).length;
      setActiveDevices(mockActiveDevices);
      addLog(`Action analysis complete! Found ${activeCount} active devices out of ${mockActiveDevices.length} total.`);
      
    } catch (err) {
      addLog(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const generateMockActions = (fingerprint) => {
    const actionMap = {
      'iPhone 12': ['Data Transmission', 'Background Sync', 'Location Services', 'Push Notifications'],
      'Smart TV': ['Media Streaming', 'Firmware Update Check', 'Remote Control Response'],
      'Linux Device': ['Periodic Beacon', 'Network Scan', 'SSH Connection'],
      'Android Phone': ['App Updates', 'Social Media Sync', 'GPS Tracking'],
      'Smart Thermostat': ['Temperature Reporting', 'Schedule Sync'],
      'Laptop': ['Web Browsing', 'File Transfer', 'VPN Connection']
    };
    
    const actions = actionMap[fingerprint] || ['Data Transmission', 'Network Activity'];
    return actions.slice(0, Math.floor(Math.random() * actions.length) + 1);
  };

  const getTrafficType = (fingerprint) => {
    const typeMap = {
      'iPhone 12': 'Mixed',
      'Smart TV': 'Streaming',
      'Linux Device': 'Minimal',
      'Android Phone': 'Mixed',
      'Smart Thermostat': 'IoT',
      'Laptop': 'Heavy'
    };
    return typeMap[fingerprint] || 'Unknown';
  };

  const getStatusColor = (isActive) => {
    return isActive ? 'text-green-400' : 'text-gray-500';
  };

  const getSignalColor = (strength) => {
    if (strength > -50) return 'text-green-400';
    if (strength > -70) return 'text-yellow-400';
    return 'text-red-400';
  };

  return (
    <div className="space-y-4">
      <Card title="Device Action Identification" icon={Activity}>
        <div className="space-y-4">
          <div className="text-xs text-gray-400">
            {devices.length > 0 
              ? `Analyzing actions for ${devices.length} fingerprinted devices`
              : 'Run device fingerprinting first for better results'
            }
          </div>
          
          <button
            onClick={runActionAnalysis}
            disabled={!fileUrl || loading}
            className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <Play className="w-4 h-4" />
            {loading ? 'Analyzing Actions...' : 'Identify Device Actions'}
          </button>

          {activeDevices.length > 0 && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2 text-sm text-cyan-400 mb-3">
                <Users className="w-4 h-4" />
                Device Activity Summary ({activeDevices.filter(d => d.isActive).length} active)
              </div>
              
              {activeDevices.map((device, i) => (
                <div key={i} className={`bg-black/30 rounded p-4 border ${device.isActive ? 'border-green-500/30' : 'border-gray-500/20'}`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="text-sm font-mono text-white">{device.fingerprint}</div>
                        <div className={`w-2 h-2 rounded-full ${device.isActive ? 'bg-green-500' : 'bg-gray-500'}`}></div>
                        <span className={`text-xs ${getStatusColor(device.isActive)}`}>
                          {device.isActive ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                      <div className="text-xs text-gray-400">{device.vendor}</div>
                      <div className="text-xs font-mono text-gray-500 mt-1">{device.mac}</div>
                    </div>
                    
                    <div className="text-right">
                      <div className="text-xs text-cyan-400 mb-1">{(device.confidence * 100).toFixed(0)}% confidence</div>
                      <div className={`text-xs ${getSignalColor(device.signalStrength)}`}>
                        {device.signalStrength} dBm
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-3 text-xs">
                    <div>
                      <span className="text-gray-400">Last Seen:</span>
                      <span className="text-white ml-2">{device.lastSeen}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Packets:</span>
                      <span className="text-white ml-2">{device.packetCount}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Traffic Type:</span>
                      <span className="text-white ml-2">{device.trafficType}</span>
                    </div>
                  </div>

                  <div className="mb-3">
                    <div className="text-xs text-gray-400 mb-2">Detected Actions:</div>
                    <div className="flex flex-wrap gap-2">
                      {device.actions.map((action, idx) => (
                        <span key={idx} className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs">
                          {action}
                        </span>
                      ))}
                    </div>
                  </div>

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
        </div>
      </Card>

      {logs.length > 0 && <LiveLogTerminal logs={logs} title="Action Analysis Logs" />}
    </div>
  );
}
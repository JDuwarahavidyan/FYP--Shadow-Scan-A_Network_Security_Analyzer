import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { analyzeLatestCapture } from '../../api/devicefpAPI';

export function FingerprintResults({ fileUrl, onDevicesIdentified }) {
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
      addLog('Analyzing MAC addresses...');
      await new Promise(r => setTimeout(r, 500));
      addLog('Querying vendor database...');
      await new Promise(r => setTimeout(r, 500));
      addLog('Processing packet captures...');
      
      // Call real API
      const response = await analyzeLatestCapture();
      
      addLog(`Router BSSID: ${response.router_bssid}`);
      addLog(`File analyzed: ${response.file_analyzed}`);
      
      // Transform API response to match component format
      const transformedDevices = response.devices.map(device => ({
        mac: device.mac_address,
        vendor: device.vendor,
        fingerprint: device.device_name,
        confidence: device.confidence,
        tags: ['IoT'],
        totalPackets: device.total_packets,
        dataPackets: device.packet_types?.data?.count || 0,
        managementPackets: device.packet_types?.management?.count || 0,
        controlPackets: device.packet_types?.control?.count || 0,
        firstSeen: device.first_seen,
        lastSeen: device.last_seen,
        avgSignalStrength: device.avg_signal_strength,
        connectedToRouter: device.connected_to_router
      }));
      
      setDevices(transformedDevices);
      
      // Pass devices to parent component for action identification
      if (onDevicesIdentified) {
        onDevicesIdentified(transformedDevices);
      }
      
      addLog(`Fingerprinting complete! Found ${transformedDevices.length} devices.`);
    } catch (err) {
      addLog(`Error: ${err.message}`);
      console.error('Fingerprint error:', err);
    } finally {
      setLoading(false);
    }
  };

  // const runTestFingerprint = async () => {
  //   setLoading(true);
  //   setLogs([]);
  //   addLog('Starting TEST device fingerprinting...');
  //   try {
  //     addLog('Analyzing MAC addresses...');
  //     await new Promise(r => setTimeout(r, 500));
  //     addLog('Querying vendor database...');
  //     await new Promise(r => setTimeout(r, 500));
  //     addLog('Processing packet captures...');
      
  //     // Call real API (same as runFingerprint)
  //     const response = await analyzeLatestCapture();
      
  //     addLog(`Router BSSID: ${response.router_bssid}`);
  //     addLog(`File analyzed: ${response.file_analyzed}`);
      
  //     // Transform API response to match component format
  //     const transformedDevices = response.devices.map(device => ({
  //       mac: device.mac_address,
  //       vendor: device.vendor,
  //       fingerprint: device.device_name,
  //       confidence: device.confidence,
  //       tags: ['IoT'],
  //       totalPackets: device.total_packets,
  //       dataPackets: device.packet_types?.data?.count || 0,
  //       managementPackets: device.packet_types?.management?.count || 0,
  //       controlPackets: device.packet_types?.control?.count || 0,
  //       firstSeen: device.first_seen,
  //       lastSeen: device.last_seen,
  //       avgSignalStrength: device.avg_signal_strength,
  //       connectedToRouter: device.connected_to_router
  //     }));
      
  //     setDevices(transformedDevices);
      
  //     // Pass devices to parent component for action identification
  //     if (onDevicesIdentified) {
  //       onDevicesIdentified(transformedDevices);
  //     }
      
  //     addLog(`TEST Fingerprinting complete! Found ${transformedDevices.length} devices.`);
  //   } catch (err) {
  //     addLog(`Error: ${err.message}`);
  //     console.error('Test fingerprint error:', err);
  //   } finally {
  //     setLoading(false);
  //   }
  // };

  return (
    <div className="space-y-4">
      <Card title="Device Fingerprinting" icon={Shield}>
        <div className="space-y-2">
          <button
            onClick={runFingerprint}
            disabled={!fileUrl || loading}
            className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Analyzing...' : 'Run Fingerprint Analysis'}
          </button>
          
          <button
            onClick={runTestFingerprint}
            disabled={loading}
            className="w-full px-4 py-2 bg-yellow-500/20 hover:bg-yellow-500/30 border border-yellow-500 text-yellow-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Testing...' : 'Test Run Fingerprint Analysis'}
          </button>
        </div>

        {devices.length > 0 && (
          <div className="mt-4 space-y-3">
            {devices.map((device, i) => (
              <div key={i} className="bg-black/30 rounded p-3 border border-cyan-500/20">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="text-sm font-mono text-white">{device.fingerprint}</div>
                    <div className="text-xs text-gray-400">{device.vendor}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="text-xs text-cyan-400">{(device.confidence * 100).toFixed(0)}%</div>
                    {device.connectedToRouter && (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">Connected</span>
                    )}
                  </div>
                </div>
                <div className="text-xs font-mono text-gray-500 mb-2">{device.mac}</div>
                <div className="grid grid-cols-2 gap-2 text-xs mb-2">
                  <div className="text-gray-400">
                    Total Packets: <span className="text-cyan-400">{device.totalPackets}</span>
                  </div>
                  {device.avgSignalStrength && (
                    <div className="text-gray-400">
                      Signal: <span className="text-cyan-400">{device.avgSignalStrength} dBm</span>
                    </div>
                  )}
                  <div className="text-gray-400">
                    Data: <span className="text-cyan-400">{device.dataPackets}</span>
                  </div>
                  <div className="text-gray-400">
                    Mgmt: <span className="text-cyan-400">{device.managementPackets}</span>
                  </div>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {device.tags.map(tag => (
                    <span key={tag} className="px-2 py-1 bg-magenta-500/20 text-magenta-400 rounded text-xs">{tag}</span>
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
}

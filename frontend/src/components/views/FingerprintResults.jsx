import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { mockAPI } from '../../api/mockAPI';

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
      const { jobId } = await mockAPI.startJob('fingerprint', fileUrl);
      addLog(`Job created: ${jobId}`);
      await new Promise(r => setTimeout(r, 1000));
      addLog('Analyzing MAC addresses...');
      await new Promise(r => setTimeout(r, 1500));
      addLog('Querying vendor database...');
      await new Promise(r => setTimeout(r, 1000));
      addLog('Running ML fingerprint model...');
      const mockDevices = [
        { mac: 'AA:BB:CC:11:22:33', vendor: 'Apple Inc.', fingerprint: 'iPhone 12', confidence: 0.94, tags: ['mobile', 'iOS'] },
        { mac: '00:11:22:33:44:55', vendor: 'Samsung', fingerprint: 'Smart TV', confidence: 0.87, tags: ['IoT', 'media'] },
        { mac: 'FF:EE:DD:CC:BB:AA', vendor: 'Unknown', fingerprint: 'Linux Device', confidence: 0.65, tags: ['unknown'] }
      ];
      setDevices(mockDevices);
      // Pass devices to parent component for action identification
      if (onDevicesIdentified) {
        onDevicesIdentified(mockDevices);
      }
      addLog(`Fingerprinting complete! Found ${mockDevices.length} devices.`);
    } catch (err) {
      addLog(`Error: ${err.message}`);
    } finally {
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
                  <div className="text-xs text-cyan-400">{(device.confidence * 100).toFixed(0)}%</div>
                </div>
                <div className="text-xs font-mono text-gray-500 mb-2">{device.mac}</div>
                <div className="flex gap-2">
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

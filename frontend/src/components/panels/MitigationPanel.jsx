import React, { useState } from 'react';
import { Zap, ZapOff, AlertTriangle } from 'lucide-react';
import { Card } from '../core/Card';
import { StatusBadge } from '../core/StatusBadge';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { mockAPI } from '../../api/mockAPI';

export function MitigationPanel({ onMitigationComplete }) {
  const [status, setStatus] = useState('idle');
  const [sessionId, setSessionId] = useState(null);
  const [showWarning, setShowWarning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [profile, setProfile] = useState('reset-arp');

  // Add timestamped log lines
  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { ts, line }]);
  };

  // Start mitigation
  const startMitigation = async () => {
    setShowWarning(false);
    setStatus('running');
    setLogs([]);
    addLog('MITIGATION ACTIVE - Legal authorization required!');
    addLog(`Starting ${profile} mitigation...`);

    try {
      const result = await mockAPI.startMitigation(profile, '192.168.1.10', 'wlan0');
      setSessionId(result.sessionId);
      addLog(`Session: ${result.sessionId}`);
      addLog('Injecting packets...');

      // Simulate live log updates
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

  // Stop mitigation
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
      {/* Mitigation Panel */}
      <Card title="Packet Injection & Mitigation" icon={Zap}>
        <div className="space-y-4">
          {/* Warning Box */}
          <div className="bg-red-500/10 border border-red-500/50 rounded p-3 text-xs text-red-400">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold mb-1">WARNING - Authorized Use Only</div>
                <div>
                  Packet injection may be illegal without proper authorization. Only use on networks you own or have explicit permission to test.
                </div>
              </div>
            </div>
          </div>

          {/* Profile Selector */}
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

          {/* Status + Buttons */}
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

      {/* Live Logs */}
      <LiveLogTerminal logs={logs} title="Mitigation Logs" />

      {/* Warning Modal */}
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
}

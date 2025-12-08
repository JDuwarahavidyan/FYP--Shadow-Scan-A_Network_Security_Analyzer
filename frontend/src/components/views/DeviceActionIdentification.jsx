import React, { useState } from 'react';
import { Activity, Play, Users } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { analyzeDeviceActions } from '../../api/deviceActionAPI';

export function DeviceActionIdentification({ fileUrl, devices = [], bssid, pcapFile, onDeviceActionsIdentified }) {
  const [loading, setLoading] = useState(false);
  const [activeDevices, setActiveDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [triggerSequence, setTriggerSequence] = useState([]);
  const [deviceSequence, setDeviceSequence] = useState([]);
  const [analysisMeta, setAnalysisMeta] = useState({ pcap_file: null, router_bssid: null });

  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };

  // Convert backend 'yes'/'no' to boolean/null expected by UI
  const convertTriggeredFlag = (flag) => {
    if (flag === 'yes') return true;
    if (flag === 'no') return false;
    return null;
  };

  const performActionAnalysis = async () => {
    addLog('Starting device action identification (live API)...');

    try {
      if (!pcapFile) {
        addLog('Error: No PCAP file path provided from fingerprinting');
        return;
      }

      // Basic UX logs (keeps the feel of progress)
      addLog('Preparing payload for backend...');
      addLog(`Using PCAP file: ${pcapFile}`);
      await new Promise(r => setTimeout(r, 200));

      // Call the API - note: analyzeDeviceActions will transform to backend shape itself,
      // but we pass the devices array we received from FingerprintResults (it matches the expected frontend shape).
      addLog('Posting devices to action analysis API...');
      const resp = await analyzeDeviceActions(devices, bssid, pcapFile);

      // The API returns a structure with:
      // { status, pcap_file, router_bssid, devices_processed, trigger_sequence, device_sequence, ... }
      if (!resp) {
        addLog('No response received from action API');
        return;
      }

      addLog('Received response from server.');
      // Extract and save meta
      setAnalysisMeta({
        pcap_file: resp.pcap_file || resp.file_analyzed || null,
        router_bssid: resp.router_bssid || null
      });

      // Show the trigger sequence and device sequence (UI may display them)
      const seq = resp.trigger_sequence || [];
      setTriggerSequence(seq);
      setDeviceSequence(resp.device_sequence || []);

      // Map backend devices_processed -> UI device shape used in this component
      const processed = (resp.devices_processed || []).map(d => {
        // actions are array of objects { action, confidence, evidence } in your backend
        const actionsRaw = d.actions || [];
        const actions = actionsRaw.map(a => (typeof a === 'string' ? a : (a.action || JSON.stringify(a))));

        // choose a trafficType from top action or fallback
        const trafficType = actions[0] || 'Unknown';

        return {
          fingerprint: d.device_name || d.device_type || 'Unknown Device', // used in UI to show name
          vendor: d.vendor || 'Unknown',
          mac: d.mac_address || d.mac || '',
          confidence: (d.prediction_confidence !== undefined) ? (d.prediction_confidence) : (d.confidence ?? 0),
          tags: [ (d.device_type || d.label || '').toString() || 'IoT' ],
          isActive: true, // processed devices are active in this output
          isTriggered: convertTriggeredFlag(d.isTriggered),
          lastSeen: d.last_seen || d.lastSeen || null,
          packetCount: d.total_packets || d.packet_count || 0,
          actions: actions,
          trafficType: trafficType,
          signalStrength: d.avg_signal_strength || d.signal_strength || null,
          raw: d // keep raw backend object if caller wants more data
        };
      });

      setActiveDevices(processed);

      // Inform parent if needed
      if (onDeviceActionsIdentified) {
        onDeviceActionsIdentified(processed, { triggerSequence: seq, deviceSequence: resp.device_sequence || [], meta: resp });
      }

      addLog(`Action analysis complete — returned ${processed.length} devices, ${seq.length} triggers found.`);
    } catch (err) {
      addLog(`Error during action analysis: ${err.message || err}`);
      console.error('Action analysis error', err);
    }
  };

  const runActionAnalysis = async () => {
    setLoading(true);
    setLogs([]);
    setTriggerSequence([]);
    setDeviceSequence([]);
    setActiveDevices([]);
    try {
      await performActionAnalysis();
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (isActive) => {
    return isActive ? 'text-green-400' : 'text-gray-500';
  };

  const getSignalColor = (strength) => {
    if (strength === null || strength === undefined) return 'text-gray-500';
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
              ? `Ready to analyze ${devices.length} fingerprinted devices`
              : 'Run device fingerprinting first'}
            {pcapFile && (
              <div className="mt-1 text-cyan-400">
                Using: {pcapFile.split(/[/\\]/).pop()}
              </div>
            )}
          </div>

          <button
            onClick={runActionAnalysis}
            disabled={!devices || devices.length === 0 || !bssid || !pcapFile || loading}
            className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <Play className="w-4 h-4" />
            {loading ? 'Analyzing Actions...' : 'Identify Device Actions'}
          </button>

          {/* Show analysis metadata and trigger sequence */}
          {analysisMeta.pcap_file && (
            <div className="text-xs text-gray-400 mt-2">
              <div>PCAP: <span className="text-white ml-1 font-mono">{analysisMeta.pcap_file}</span></div>
              <div>Router BSSID: <span className="text-white ml-1 font-mono">{analysisMeta.router_bssid}</span></div>
            </div>
          )}

          {deviceSequence.length > 0 && (
            <div className="mt-3">
              <div className="text-xs text-cyan-400 mb-2"><Users className="inline w-4 h-4 mr-1" /> Trigger sequence</div>
              <div className="flex flex-wrap gap-2">
                {deviceSequence.map((n, idx) => (
                  <span key={idx} className="px-2 py-1 bg-black/20 text-white rounded text-xs border border-cyan-500/20">
                    {n}
                  </span>
                ))}
              </div>
            </div>
          )}

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
                        {device.isActive && device.isTriggered !== null && (
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            device.isTriggered
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                          }`}>
                            {device.isTriggered ? 'Triggered' : 'Not Triggered'}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-gray-400">{device.vendor}</div>
                      <div className="text-xs font-mono text-gray-500 mt-1">{device.mac}</div>
                    </div>

                    <div className="text-right">
                      <div className="text-xs text-cyan-400 mb-1">{Math.round((device.confidence || 0) * 100)}% confidence</div>
                      {device.signalStrength !== null && device.signalStrength !== undefined && (
                        <div className={`text-xs ${getSignalColor(device.signalStrength)}`}>{device.signalStrength} dBm</div>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-3 text-xs">
                    <div>
                      <span className="text-gray-400">Last Seen:</span>
                      <span className="text-white ml-2">{device.lastSeen || '—'}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Packets:</span>
                      <span className="text-white ml-2">{device.packetCount}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Traffic Type:</span>
                      <span className="text-white ml-2">{device.trafficType}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Tags:</span>
                      <span className="text-white ml-2">{(device.tags || []).join(', ')}</span>
                    </div>
                  </div>

                  <div className="mb-3">
                    <div className="text-xs text-gray-400 mb-2">Actions:</div>
                    <div className="flex flex-wrap gap-2">
                      {(device.actions || []).length > 0 ? device.actions.map((action, idx) => (
                        <span key={idx} className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs">
                          {action}
                        </span>
                      )) : (
                        <span className="px-2 py-1 bg-gray-500/10 text-gray-400 rounded text-xs">No actions detected</span>
                      )}
                    </div>
                  </div>

                  <div className="flex gap-2">
                    {(device.tags || []).map(tag => (
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

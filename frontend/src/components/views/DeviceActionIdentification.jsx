import React, { useState } from 'react';
import { Activity, Play, Users, Video } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { analyzeDeviceActions } from '../../api/deviceActionAPI';

export function DeviceActionIdentification({ fileUrl, devices = [], bssid, pcapFile, onDeviceActionsIdentified }) {
  const [loading, setLoading] = useState(false);
  const [activeDevices, setActiveDevices] = useState([]);       // triggered devices summary
  const [cameraDevices, setCameraDevices] = useState([]);       // camera devices summary
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
    if (flag === 'yes' || flag === true) return true;
    if (flag === 'no' || flag === false) return false;
    return null;
  };

  // Common mapper from backend device object -> UI device object
  const mapBackendDeviceToUI = (d) => {
    const actionsRaw = d.actions || [];
    const actions = actionsRaw.map(a =>
      typeof a === 'string' ? a : (a.action || JSON.stringify(a))
    );

    const trafficType = actions[0] || 'Unknown';

    const uiDevice = {
      fingerprint: d.device_name || d.device_type || d.label || 'Unknown Device',
      vendor: d.vendor || 'Unknown',
      mac: d.mac_address || d.mac || '',
      confidence:
        d.prediction_confidence !== undefined
          ? d.prediction_confidence
          : (d.confidence ?? 0),
      tags: [(d.device_type || d.label || 'IoT').toString()],
      isActive: d.isActive === 'yes' || d.isActive === true,
      isTriggered: convertTriggeredFlag(d.isTriggered),
      lastSeen: d.last_seen || d.lastSeen || null,
      packetCount: d.total_packets || d.packet_count || 0,
      actions,
      trafficType,
      signalStrength: d.avg_signal_strength || d.signal_strength || null,
      raw: d,
    };

    return uiDevice;
  };

  const performActionAnalysis = async () => {
    addLog('Starting device action identification (live API)...');

    try {
      if (!pcapFile) {
        addLog('Error: No PCAP file path provided from fingerprinting');
        return;
      }

      addLog('Preparing payload for backend...');
      addLog(`Using PCAP file: ${pcapFile}`);
      await new Promise(r => setTimeout(r, 200));

      // Call the API
      addLog('Posting devices to action analysis API...');
      const resp = await analyzeDeviceActions(devices, bssid, pcapFile);

      if (!resp) {
        addLog('No response received from action API');
        return;
      }

      addLog('Received response from server.');

      // Extract and save meta
      setAnalysisMeta({
        pcap_file: resp.pcap_file || resp.file_analyzed || null,
        router_bssid: resp.router_bssid || null,
      });

      // Save sequences
      const seqObjects = resp.trigger_sequence || [];
      const seqNames = resp.device_sequence || [];
      setTriggerSequence(seqObjects);
      setDeviceSequence(seqNames);

      // Map ALL processed devices (for parent / debugging if needed)
      const allProcessedDevices = (resp.devices_processed || []).map(mapBackendDeviceToUI);
      console.log('Mapped processed devices (check lastSeen here):', allProcessedDevices);

      // -------- DEVICE ACTIVITY SUMMARY (TRIGGERED ONLY) --------
      const triggeredSource =
        resp.trigger_sequence && resp.trigger_sequence.length > 0
          ? resp.trigger_sequence
          : (resp.devices_processed || []).filter(
              d => convertTriggeredFlag(d.isTriggered) === true
            );

      const triggeredDevices = triggeredSource.map(mapBackendDeviceToUI);
      setActiveDevices(triggeredDevices);

      // -------- CAMERA ACTIVITY SUMMARY --------
      // Camera detection based on device_type / label / device_name
      const cameraDevicesRaw = (resp.devices_processed || []).filter(d => {
        const idString = `${d.device_type || ''} ${d.label || ''} ${d.device_name || ''}`
          .toString()
          .toLowerCase();
        return idString.includes('camera') || idString.includes('cam');
      });

      const cameraDevicesUI = cameraDevicesRaw.map(mapBackendDeviceToUI);
      setCameraDevices(cameraDevicesUI);

      // Inform parent if needed
      if (onDeviceActionsIdentified) {
        onDeviceActionsIdentified(triggeredDevices, {
          triggerSequence: seqObjects,
          deviceSequence: seqNames,
          meta: resp,
          allDevices: allProcessedDevices,
          cameraDevices: cameraDevicesUI,
        });
      }

      addLog(
        `Action analysis complete — ${allProcessedDevices.length} devices processed, ` +
        `${triggeredDevices.length} triggered, ${cameraDevicesUI.length} camera devices, ` +
        `${seqObjects.length} triggers in sequence.`
      );
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
    setCameraDevices([]);
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

  // Camera-specific badge if we see "Camera Streaming (possible)" in actions
  const getCameraStreamingBadge = (device) => {
    const actions = device.actions || [];
    const hasStreaming = actions.some(a =>
      a.toString().toLowerCase().includes('camera streaming')
    );
    if (!hasStreaming) return null;

    return (
      <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] border border-purple-400/40 bg-purple-500/10 text-purple-300">
        Camera Streaming (possible)
      </span>
    );
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

          {/* Analysis metadata */}
          {analysisMeta.pcap_file && (
            <div className="text-xs text-gray-400 mt-2">
              <div>
                PCAP:
                <span className="text-white ml-1 font-mono">
                  {analysisMeta.pcap_file}
                </span>
              </div>
              <div>
                Router BSSID:
                <span className="text-white ml-1 font-mono">
                  {analysisMeta.router_bssid}
                </span>
              </div>
            </div>
          )}

          {/* Trigger sequence names */}
          {deviceSequence.length > 0 && (
            <div className="mt-3">
              <div className="text-xs text-cyan-400 mb-2">
                <Users className="inline w-4 h-4 mr-1" /> Trigger sequence
              </div>
              <div className="flex flex-wrap gap-2">
                {deviceSequence.map((n, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-1 bg-black/20 text-white rounded text-xs border border-cyan-500/20"
                  >
                    {n}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* -------- DEVICE ACTIVITY SUMMARY (TRIGGERED DEVICES) -------- */}
          {analysisMeta.pcap_file && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2 text-sm text-cyan-400 mb-3">
                <Users className="w-4 h-4" />
                Device Activity Summary ({activeDevices.length} triggered device{activeDevices.length !== 1 ? 's' : ''})
              </div>

              {activeDevices.length === 0 ? (
                <div className="rounded border border-dashed border-gray-500/40 bg-black/30 px-4 py-6 text-center">
                  <div className="text-sm font-mono text-gray-200 mb-1">
                    No triggered devices detected in this capture
                  </div>
                  <div className="text-xs text-gray-500">
                    All devices are operating normally without trigger events.
                  </div>
                </div>
              ) : (
                activeDevices.map((device, i) => (
                  <div
                    key={i}
                    className={`bg-black/30 rounded p-4 border ${
                      device.isActive ? 'border-green-500/30' : 'border-gray-500/20'
                    }`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <div className="text-sm font-mono text-white">
                            {device.fingerprint}
                          </div>
                          <div
                            className={`w-2 h-2 rounded-full ${
                              device.isActive ? 'bg-green-500' : 'bg-gray-500'
                            }`}
                          ></div>
                          <span className={`text-xs ${getStatusColor(device.isActive)}`}>
                            {device.isActive ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                        <div className="text-xs text-gray-400">{device.vendor}</div>
                        <div className="text-xs font-mono text-gray-500 mt-1">
                          {device.mac}
                        </div>
                      </div>

                      <div className="text-right space-y-1">
                        {device.isTriggered !== null && (
                          <span
                            className={`px-2 py-1 rounded-full text-xs ${
                              device.isTriggered
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                            }`}
                          >
                            {device.isTriggered ? 'Triggered' : 'Not Triggered'}
                          </span>
                        )}
                        {device.signalStrength !== null &&
                          device.signalStrength !== undefined && (
                            <div className={`text-xs ${getSignalColor(device.signalStrength)}`}>
                              {device.signalStrength} dBm
                            </div>
                          )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4 mb-3 text-xs">
                      <div>
                        <span className="text-gray-400">Last Seen:</span>
                        <span className="text-white ml-2">
                          {device.lastSeen || '—'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Packets:</span>
                        <span className="text-white ml-2">{device.packetCount}</span>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="text-xs text-gray-400 mb-2">Actions:</div>
                      <div className="flex flex-wrap gap-2">
                        {(device.actions || []).length > 0 ? (
                          device.actions.map((action, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs"
                            >
                              {action}
                            </span>
                          ))
                        ) : (
                          <span className="px-2 py-1 bg-gray-500/10 text-gray-400 rounded text-xs">
                            No actions detected
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex gap-2">
                      {(device.tags || []).map(tag => (
                        <span
                          key={tag}
                          className="px-2 py-1 bg-magenta-500/20 text-magenta-400 rounded text-xs"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* -------- CAMERA ACTIVITY SUMMARY -------- */}
          {analysisMeta.pcap_file && (
            <div className="mt-6 space-y-3">
              <div className="flex items-center gap-2 text-sm text-cyan-400 mb-3">
                <Video className="w-4 h-4" />
                Camera Activity Summary ({cameraDevices.length} camera{cameraDevices.length !== 1 ? 's' : ''} detected)
              </div>

              {cameraDevices.length > 0 ? (
                cameraDevices.map((device, i) => (
                  <div
                    key={i}
                    className="bg-black/30 rounded p-4 border border-gray-500/30"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <div className="text-sm font-mono text-white">
                            {device.fingerprint}
                          </div>
                          <div
                            className={`w-2 h-2 rounded-full ${
                              device.isActive ? 'bg-green-500' : 'bg-gray-500'
                            }`}
                          ></div>
                          <span className={`text-xs ${getStatusColor(device.isActive)}`}>
                            {device.isActive ? 'Active' : 'Inactive'}
                          </span>
                          {getCameraStreamingBadge(device)}
                        </div>
                        <div className="text-xs text-gray-400">{device.vendor}</div>
                        <div className="text-xs font-mono text-gray-500 mt-1">
                          {device.mac}
                        </div>
                      </div>

                      <div className="text-right space-y-1">
                        {device.isTriggered !== null && (
                          <span
                            className={`px-2 py-1 rounded-full text-xs ${
                              device.isTriggered
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : 'bg-gray-500/20 text-gray-300 border border-gray-500/30'
                            }`}
                          >
                            {device.isTriggered ? 'Triggered' : 'Not Triggered'}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4 mb-3 text-xs">
                      <div>
                        <span className="text-gray-400">Last Seen:</span>
                        <span className="text-white ml-2">
                          {device.lastSeen || '—'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Packets:</span>
                        <span className="text-white ml-2">{device.packetCount}</span>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="text-xs text-gray-400 mb-2">Actions:</div>
                      <div className="flex flex-wrap gap-2">
                        {(device.actions || []).length > 0 ? (
                          device.actions.map((action, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-blue-500/20 text-blue-200 rounded-full text-xs"
                            >
                              {action}
                            </span>
                          ))
                        ) : (
                          <span className="px-2 py-1 bg-gray-500/10 text-gray-400 rounded text-xs">
                            No camera-specific activity detected
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex gap-2">
                      {(device.tags || []).map(tag => (
                        <span
                          key={tag}
                          className="px-2 py-1 bg-magenta-500/20 text-magenta-400 rounded text-xs"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded border border-dashed border-gray-500/40 bg-black/30 px-4 py-6 text-center">
                  <div className="text-sm font-mono text-gray-200 mb-1">
                    No camera devices detected in this capture
                  </div>
                  <div className="text-xs text-gray-500">
                    Run another scan or add IP cameras to see live camera activity here.
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </Card>

      {logs.length > 0 && (
        <LiveLogTerminal logs={logs} title="Action Analysis Logs" />
      )}
    </div>
  );
}

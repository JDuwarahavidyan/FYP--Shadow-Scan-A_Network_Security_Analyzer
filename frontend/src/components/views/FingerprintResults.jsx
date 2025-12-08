import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { analyzeLatestCapture } from '../../api/devicefpAPI';

export function FingerprintResults({ fileUrl, parsedData, onDevicesIdentified }) {
  const [loading, setLoading] = useState(false);
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [bssid, setBssid] = useState(null);

  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };

  // ---------- FORMAT DEVICE TYPE ----------
  const formatDeviceType = (typeStr) => {
    if (!typeStr) return "";

    const s = String(typeStr).trim();

    // Replace underscores → spaces
    const cleaned = s.replace(/_/g, " ");

    // Capitalize first letter of each word
    return cleaned
      .split(" ")
      .map(w => (w ? w.charAt(0).toUpperCase() + w.slice(1) : ""))
      .join(" ");
  };

  // helper: derive base key from token (device_type or device_name)
  // - splits on '_' tokens
  // - if last token is purely numeric, remove it (switch_1 -> ['switch'])
  // - join remaining tokens with '_' to produce canonical base key (e.g. 'door_sensor', 'new_device')
  const deriveBaseKey = (token) => {
    const s = String(token || "").trim().toLowerCase();
    if (!s) return "unknown";
    const parts = s.split('_').filter(p => p !== "");
    if (parts.length === 0) return "unknown";
    // if last token is numeric, drop it
    if (parts.length > 1 && /^\d+$/.test(parts[parts.length - 1])) {
      parts.pop();
    }
    // join with underscore as canonical base key
    return parts.join('_') || parts[0] || s;
  };

  // ---------- MAIN LOGIC ----------
  const runFingerprint = async () => {
    setLoading(true);
    setLogs([]);
    addLog("Starting device fingerprinting...");

    try {
      const useBssid = parsedData?.bssid || null;
      if (useBssid) addLog(`Using BSSID: ${useBssid}`);

      addLog("Analyzing MAC addresses...");
      await new Promise(r => setTimeout(r, 300));
      addLog("Querying vendor database...");
      await new Promise(r => setTimeout(r, 300));
      addLog("Processing packet captures...");

      const response = await analyzeLatestCapture(useBssid);

      addLog(`Router BSSID: ${response.router_bssid}`);
      addLog(`File analyzed: ${response.file_analyzed}`);

      // ----------------------------
      // Transform API response devices
      // - If multiple devices share same base type (e.g. switch_1, switch_2),
      //   label them "Switch (1)", "Switch (2)".
      // - If only one device of that base type exists, label "Switch".
      // ----------------------------

      // STEP 1 — Count occurrences by canonical base key
      const typeCounts = {};
      response.devices.forEach(device => {
        // Prefer device_type if present, else derive from device_name
        const token = (device.device_type || device.device_name || "").toString().trim();
        const baseKey = deriveBaseKey(token); // e.g. "switch", "door_sensor", "new_device"
        typeCounts[baseKey] = (typeCounts[baseKey] || 0) + 1;
      });

      // STEP 2 — Assign indices for duplicates
      const typeIndex = {};

      const transformedDevices = response.devices.map(device => {
        const token = (device.device_type || device.device_name || "").toString().trim();
        const baseKey = deriveBaseKey(token); // canonical base key
        const formattedBase = formatDeviceType(baseKey); // "door_sensor" -> "Door Sensor"

        // Decide display name (number only when multiple of same base exist)
        let displayName = formattedBase;
        if (typeCounts[baseKey] > 1) {
          typeIndex[baseKey] = (typeIndex[baseKey] || 0) + 1;
          displayName = `${formattedBase} (${typeIndex[baseKey]})`;
        }

        return {
          mac: device.mac_address,
          vendor: device.vendor,
          device_type: displayName,     // formatted label shown in UI (e.g. "Switch (1)")
          raw_type: device.device_type, // keep raw backend value (e.g. "switch" or "switch")
          device_name: device.device_name, // keep original name (switch_1 etc.)
          confidence: device.confidence ?? 0,
          tags: ["IoT"],
          totalPackets: device.total_packets ?? 0,
          dataPackets: device.packet_types?.data?.count || 0,
          managementPackets: device.packet_types?.management?.count || 0,
          controlPackets: device.packet_types?.control?.count || 0,
          avgSignalStrength: device.avg_signal_strength,
          connectedToRouter: device.connected_to_router
        };
      });

      setDevices(transformedDevices);
      setBssid(response.router_bssid);

      if (onDevicesIdentified) {
        onDevicesIdentified(transformedDevices, response.router_bssid);
      }

      addLog(`Fingerprinting complete! Found ${transformedDevices.length} devices.`);

    } catch (err) {
      addLog(`Error: ${err.message}`);
      console.error("Fingerprint error:", err);
    } finally {
      setLoading(false);
    }
  };

  // ---------- RENDER ----------
  return (
    <div className="space-y-4">
      <Card title="Device Fingerprinting" icon={Shield}>
        <div className="space-y-2">
          <button
            onClick={runFingerprint}
            disabled={!fileUrl || loading}
            className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Analyzing..." : "Run Fingerprint Analysis"}
          </button>
        </div>

        {devices.length > 0 && (
          <div className="mt-4 space-y-3">
            {devices.map((device, i) => (
              <div key={i} className="bg-black/30 rounded p-3 border border-cyan-500/20">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    {/* Display formatted device_type */}
                    <div className="text-sm font-mono text-white">
                      {device.device_type}
                    </div>
                    <div className="text-xs text-gray-400">{device.vendor}</div>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* <div className="text-xs text-cyan-400">
                      {(device.confidence * 100).toFixed(0)}%
                    </div> */}
                    {device.connectedToRouter && (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">
                        Connected
                      </span>
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
                      Signal:{" "}
                      <span className="text-cyan-400">{device.avgSignalStrength} dBm</span>
                    </div>
                  )}
                  <div className="text-gray-400">
                    Data: <span className="text-cyan-400">{device.dataPackets}</span>
                  </div>
                  <div className="text-gray-400">
                    Management: <span className="text-cyan-400">{device.managementPackets}</span>
                  </div>
                  <div className="text-gray-400">
                    Control: <span className="text-cyan-400">{device.controlPackets}</span>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
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

      {logs.length > 0 && (
        <LiveLogTerminal logs={logs} title="Fingerprint Logs" />
      )}
    </div>
  );
}

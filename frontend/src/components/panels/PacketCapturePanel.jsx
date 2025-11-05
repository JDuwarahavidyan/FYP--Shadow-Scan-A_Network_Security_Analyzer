import React, { useState, useEffect, useRef } from "react";
import { Wifi, WifiOff, RefreshCw, ChevronDown } from "lucide-react";
import { Card } from "../core/Card";
import { StatusBadge } from "../core/StatusBadge";
import { LiveLogTerminal } from "../core/LiveLogTerminal";
import { captureAPI } from "../../api/captureAPI";

export function PacketCapturePanel({ onCaptureComplete }) {
  const [status, setStatus] = useState("idle");
  const [sessionId, setSessionId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [packetCount, setPacketCount] = useState(0);
  const [aps, setAps] = useState([]);
  const [selectedAp, setSelectedAp] = useState(null);
  const [loadingAps, setLoadingAps] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);
  const eventSourceRef = useRef(null);

  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { ts, line }]);
  };

  const fetchAps = async () => {
    try {
      setLoadingAps(true);
      addLog("🔍 Scanning for nearby Access Points...");
      const list = await captureAPI.listAccessPoints("wlan1");
      setAps(list);
      addLog(`📡 Found ${list.length} Access Points.`);
    } catch (err) {
      addLog(`❌ Failed to fetch APs: ${err.message}`);
    } finally {
      setLoadingAps(false);
    }
  };

  useEffect(() => {
    fetchAps();
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const startCapture = async () => {
    if (!selectedAp) {
      addLog("⚠️ Please select an Access Point before starting capture.");
      return;
    }

    setStatus("capturing");
    setLogs([]);
    setPacketCount(0);
    addLog("Initializing packet capture...");

    try {
      const result = await captureAPI.startCapture(
        "raspberrypi-1",
        "wlan1",
        selectedAp.bssid,
        selectedAp.channel
      );
      setSessionId(result.sessionId);
      addLog(`✅ Capture started for ${selectedAp.ssid} (${selectedAp.bssid}) on CH ${selectedAp.channel}`);

      eventSourceRef.current = captureAPI.subscribeLogs(
        (message) => {
          addLog(message);
          if (message.toLowerCase().includes("packet")) {
            setPacketCount((prev) => prev + 1);
          }
        },
        (error) => {
          console.error("Log stream error:", error);
          addLog("⚠️ Log stream disconnected.");
        }
      );
    } catch (error) {
      setStatus("error");
      addLog(`❌ Error: ${error.message}`);
    }
  };

  const stopCapture = async () => {
    if (!sessionId) return;

    setStatus("stopping");
    addLog("Stopping capture...");

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    try {
      const result = await captureAPI.stopCapture(sessionId);
      addLog(`✅ Capture stopped. File saved: ${result.fileUrl}`);
      addLog(`📊 Total packets: ${result.meta.packetCount}`);
      setPacketCount(result.meta.packetCount);
      setStatus("idle");
      setSessionId(null);

      addLog("🔍 Parsing capture file...");
      const parsed = await captureAPI.parseCapture(result.fileUrl);
      addLog("✅ Parse complete!");

      if (onCaptureComplete) {
        onCaptureComplete(result.fileUrl, parsed);
      }
    } catch (error) {
      setStatus("error");
      addLog(`❌ Error: ${error.message}`);
    }
  };

  return (
    <div className="space-y-4">
      <Card title="Packet Capture Control" icon={Wifi}>
        <div className="space-y-5">
          {/* Status + Counter */}
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
            <div className="text-cyan-400 font-mono text-sm">
              Packets: <span className="text-white font-bold">{packetCount}</span>
            </div>
          </div>

          {/* Custom Dropdown */}
          <div className="space-y-2 relative" ref={dropdownRef}>
            <label className="text-sm text-cyan-300 font-mono tracking-wide">
              Select Access Point
            </label>
            <div className="flex gap-2 items-center">
              <div
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className={`flex justify-between items-center w-full bg-linear-to-r from-black/90 to-cyan-950/50 border border-cyan-600/60 text-cyan-200 px-3 py-2 rounded-md cursor-pointer font-mono text-sm tracking-wide shadow-[0_0_10px_rgba(0,255,255,0.25)] hover:shadow-[0_0_15px_rgba(0,255,255,0.45)] transition-all ${
                  dropdownOpen ? "ring-1 ring-cyan-400" : ""
                }`}
              >
                <span>
                  {selectedAp
                    ? `${selectedAp.ssid} | ${selectedAp.bssid} | CH ${selectedAp.channel}`
                    : "-- Choose AP --"}
                </span>
                <ChevronDown className="w-4 h-4 text-cyan-400" />
              </div>

              <button
                onClick={fetchAps}
                disabled={loadingAps}
                className={`p-2 border border-cyan-500 rounded-md hover:bg-cyan-500/20 transition-all ${
                  loadingAps ? "animate-pulse" : ""
                }`}
                title="Refresh AP List"
              >
                <RefreshCw className="w-4 h-4 text-cyan-400" />
              </button>
            </div>

            {dropdownOpen && (
              <div className="absolute z-20 mt-1 w-full bg-black/90 border border-cyan-700/60 rounded-md shadow-[0_0_12px_rgba(0,255,255,0.3)] backdrop-blur-sm max-h-48 overflow-y-auto">
                {aps.length === 0 ? (
                  <div className="text-gray-400 text-xs p-3 text-center font-mono">
                    No Access Points Found
                  </div>
                ) : (
                  aps.map((ap, idx) => (
                    <div
                      key={ap.bssid}
                      onClick={() => {
                        setSelectedAp(ap);
                        setDropdownOpen(false);
                      }}
                      className="px-3 py-2 text-sm text-cyan-200 font-mono hover:bg-cyan-500/20 cursor-pointer transition-all"
                    >
                      {ap.ssid} | {ap.bssid} | CH {ap.channel} | PWR {ap.power}
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Control Buttons */}
          <div className="grid grid-cols-2 gap-3 pt-2">
            <button
              onClick={startCapture}
              disabled={status === "capturing"}
              className="px-4 py-2 bg-green-500/10 hover:bg-green-500/20 border border-green-400 text-green-300 rounded font-mono text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Wifi className="w-4 h-4" />
              Start Capture
            </button>

            <button
              onClick={stopCapture}
              disabled={status !== "capturing"}
              className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-400 text-red-300 rounded font-mono text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <WifiOff className="w-4 h-4" />
              Stop Capture
            </button>
          </div>
        </div>
      </Card>

      {/* Logs */}
      <LiveLogTerminal logs={logs} title="Capture Logs" />
    </div>
  );
}

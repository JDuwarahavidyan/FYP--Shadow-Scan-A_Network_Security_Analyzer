import React, { useState, useEffect, useRef } from "react";
import { Wifi, WifiOff, Radar, ChevronDown } from "lucide-react";
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
  const [scannedOnce, setScannedOnce] = useState(false);
  const dropdownRef = useRef(null);
  const eventSourceRef = useRef(null);

  // === Helper: Add logs ===
  const addLog = (line, isError = false) => {
    const ts = new Date().toLocaleTimeString();
    const formattedLine = isError ? `❌ ERROR: ${line}` : line;
    setLogs((prev) => [...prev, { ts, line: formattedLine }]);
  };

  // === Helper: Add section divider ===
  const addDivider = (label) => {
    const divider = `──────────── ${label} ────────────`;
    setLogs((prev) => [...prev, { ts: "", line: divider }]);
  };

  // === Fetch Access Points ===
  const fetchAps = async () => {
    try {
      setLoadingAps(true);
      setStatus("scanning");
      setLogs([]);
      addDivider("NEW SCAN SESSION");
      addLog("📡 Starting Wi-Fi scan on Raspberry Pi...");
      addLog("⏳ Waiting for scan results...");

      // ✅ Close any previous EventSource before starting new one
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }

      // Start new SSE subscription
      eventSourceRef.current = captureAPI.subscribeLogs(
        (msg) => addLog(msg),
        () => addLog("⚠️ Log stream disconnected during scan.")
      );

      const result = await captureAPI.listAccessPoints("wlan1");
      setAps(result);
      setScannedOnce(true);
    } catch (err) {
      setStatus("error");
      addLog(err.message, true);
    } finally {
      setLoadingAps(false);
      setStatus("idle");
      // Close SSE after scan completes
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    }
  };

  // === Start Capture ===
  const startCapture = async () => {
    if (!selectedAp) {
      addLog("⚠️ Please select an Access Point before starting capture.");
      return;
    }

    setStatus("capturing");
    setLogs([]);
    setPacketCount(0);
    // addDivider("NEW CAPTURE SESSION");
    addLog(`->  Target: ${selectedAp.ssid} (${selectedAp.bssid}) on CH ${selectedAp.channel}`);
    addLog("[+] Initializing packet capture...");

    try {
      const result = await captureAPI.startCapture(
        "raspberrypi-1",
        "wlan1",
        selectedAp.bssid,
        selectedAp.channel
      );

      setSessionId(result.sessionId);
      addLog("[✓] Capture started successfully. Listening for packets...");

      // Close any previous EventSource before opening new one
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }

      // Start log streaming
      eventSourceRef.current = captureAPI.subscribeLogs(
        (message) => {
          addLog(message);
          if (message.toLowerCase().includes("capturing")) {
            setPacketCount((prev) => prev + 1);
          }
        },
        (error) => {
          console.error("Log stream error:", error);
          addLog("[!] Log stream disconnected.");
        }
      );
    } catch (error) {
      setStatus("error");
      addLog(error.message, true);
    }
  };

  // === Stop Capture ===
  const stopCapture = async () => {
    if (!sessionId) return;

    setStatus("stopping");
    addLog("🛑 Stopping capture...");

    //  Close the existing EventSource stream before stopping
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    try {
      const result = await captureAPI.stopCapture(sessionId);
      addLog(`[✓] Capture stopped. File saved: ${result.fileUrl}`);
      addLog(`[+] Total packets captured: ${result.meta.packetCount}`);
      setPacketCount(result.meta.packetCount);
      setStatus("idle");
      setSessionId(null);

      addLog("[/] Parsing capture file...");
      const parsed = await captureAPI.parseCapture(result.fileUrl);
      addLog("[✓] Parse complete.");

      if (onCaptureComplete) {
        onCaptureComplete(result.fileUrl, parsed);
      }
    } catch (error) {
      setStatus("error");
      addLog(error.message, true);
    }
  };

  // === Cleanup on unmount ===
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, []);

  // === Dropdown close on outside click ===
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // === Render UI ===
  return (
    <div className="space-y-4">
      <Card title="Packet Capture Control" icon={Wifi}>
        <div className="space-y-5">
          {/* Status & Packet Counter */}
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
            <div className="text-cyan-400 font-mono text-sm">
              Packets:{" "}
              <span className="text-white font-bold">{packetCount}</span>
            </div>
          </div>

          {/* Scan Button */}
          <div className="flex justify-center">
            <button
              onClick={fetchAps}
              disabled={loadingAps}
              className={`flex items-center gap-2 px-5 py-2.5 bg-linear-to-r from-cyan-900/40 to-cyan-700/30 border border-cyan-500/60 text-cyan-300 rounded-md font-mono text-sm tracking-wide shadow-[0_0_12px_rgba(0,255,255,0.25)] hover:shadow-[0_0_18px_rgba(0,255,255,0.45)] transition-all ${
                loadingAps
                  ? "opacity-60 cursor-not-allowed animate-pulse"
                  : "hover:bg-cyan-500/10"
              }`}
            >
              <Radar className="w-4 h-4 text-cyan-400 animate-pulse" />
              {loadingAps ? "Scanning..." : "Scan for Access Points"}
            </button>
          </div>

          {/* Custom Dropdown */}
          <div className="space-y-2 relative" ref={dropdownRef}>
            <label className="text-sm text-cyan-300 font-mono tracking-wide">
              Select Access Point
            </label>

            <div className="flex gap-2 items-center">
              <div
                onClick={() => scannedOnce && setDropdownOpen(!dropdownOpen)}
                className={`flex justify-between items-center w-full 
                  bg-linear-to-r from-black/90 to-cyan-950/50 
                  border border-cyan-600/60 text-cyan-200 px-3 py-2 rounded-md 
                  cursor-pointer font-mono text-sm tracking-wide 
                  shadow-[0_0_10px_rgba(0,255,255,0.25)] hover:shadow-[0_0_15px_rgba(0,255,255,0.45)] 
                  transition-all duration-200 
                  ${dropdownOpen ? "ring-1 ring-cyan-400" : ""} 
                  ${!scannedOnce ? "opacity-40 cursor-not-allowed" : ""}`}
              >
                <div className="flex flex-col text-left">
                  {selectedAp ? (
                    <>
                      <span className="text-white font-semibold text-[13px] tracking-wide">
                        {selectedAp.ssid || "<hidden>"}
                      </span>
                      <span className="text-[11px] text-cyan-400/70 mt-px">
                        {selectedAp.bssid} | CH {selectedAp.channel} | PWR{" "}
                        {selectedAp.power}
                      </span>
                    </>
                  ) : (
                    <span className="text-cyan-400/70 mt-2 mb-2 text-sm">
                      -- Choose AP --
                    </span>
                  )}
                </div>

                <ChevronDown
                  className={`w-4 h-4 text-cyan-400 transition-transform duration-200 ${
                    dropdownOpen ? "rotate-180" : ""
                  }`}
                />
              </div>
            </div>

            {/* Dropdown Menu */}
            {dropdownOpen && (
              <div
                className="absolute left-0 top-full mt-1 w-full z-9999 
                            bg-black/95 border border-cyan-700/70 rounded-md 
                            shadow-[0_0_20px_rgba(0,255,255,0.35)] backdrop-blur-md 
                            divide-y divide-cyan-900/40
                            overflow-y-auto max-h-40 
                            scrollbar-thin scrollbar-thumb-cyan-700/60 scrollbar-track-cyan-900/20"
              >
                {aps.length === 0 ? (
                  <div className="text-gray-400 text-xs p-3 text-center font-mono">
                    No Access Points Found
                  </div>
                ) : (
                  aps.map((ap) => (
                    <div
                      key={ap.bssid}
                      onClick={() => {
                        setSelectedAp(ap);
                        setDropdownOpen(false);
                      }}
                      className="px-3 py-2 text-sm text-cyan-200 font-mono 
                                 hover:bg-cyan-500/20 cursor-pointer transition-all"
                    >
                      <div className="text-white font-semibold text-[13px] tracking-wide">
                        {ap.ssid || "<hidden>"}
                      </div>
                      <div className="text-[11px] text-cyan-400/70 mt-0.5">
                        {ap.bssid} | CH {ap.channel} | PWR {ap.power}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Legal Warning */}
          <div className="flex items-start gap-2 mt-3 p-3 rounded-md border border-red-500/40 
                          bg-red-950/20 text-red-300 font-mono text-xs 
                          shadow-[0_0_8px_rgba(255,0,0,0.1)]">
            <div className="pt-px">
              <svg xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4 text-red-400 shrink-0"
                fill="none" viewBox="0 0 24 24"
                stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round"
                  d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
              </svg>
            </div>
            <div className="flex flex-col leading-relaxed">
              <span className="font-semibold text-red-400 uppercase tracking-wide text-[12px]">
                Attention
              </span>
              <span className="text-[11px] text-red-300/90">
                Only select and analyze access points that you own or have explicit permission to test. 
                Unauthorized network observation is strictly prohibited by law.
              </span>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="grid grid-cols-2 gap-3 pt-2">
            <button
              onClick={startCapture}
              disabled={!selectedAp || status === "capturing"}
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

      {/* Live Logs */}
      <LiveLogTerminal logs={logs} title="Capture Logs" />
    </div>
  );
}

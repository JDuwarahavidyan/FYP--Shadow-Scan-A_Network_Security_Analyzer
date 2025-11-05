import React, { useState, useEffect, useRef } from "react";
import { Wifi, WifiOff } from "lucide-react";
import { Card } from "../core/Card";
import { StatusBadge } from "../core/StatusBadge";
import { LiveLogTerminal } from "../core/LiveLogTerminal";
import { captureAPI } from "../../api/captureAPI";

export function PacketCapturePanel({ onCaptureComplete }) {
  const [status, setStatus] = useState("idle");
  const [sessionId, setSessionId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [packetCount, setPacketCount] = useState(0);
  const eventSourceRef = useRef(null);

  // Append a new line to the UI terminal
  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { ts, line }]);
  };

  // Cleanup SSE connection on unmount
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, []);

  // Start Capture
  const startCapture = async () => {
    setStatus("capturing");
    setLogs([]);
    setPacketCount(0);
    addLog("Initializing packet capture...");

    try {
      // Start capture on backend
      const result = await captureAPI.startCapture("raspberrypi-1", "wlan0");
      setSessionId(result.sessionId);
      addLog(`Capture started: ${result.sessionId}`);
      addLog("Listening on interface wlan0...");

      // Subscribe to live logs (SSE)
      eventSourceRef.current = captureAPI.subscribeLogs(
        (message) => {
          // message = plain string only
          addLog(message);
          if (message.toLowerCase().includes("packet")) {
            setPacketCount((prev) => prev + 1);
          }
        },
        (error) => {
          console.error("Log stream error:", error);
          addLog("Log stream disconnected");
        }
      );
    } catch (error) {
      setStatus("error");
      addLog(`Error: ${error.message}`);
    }
  };

  // Stop Capture
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
      addLog(`Capture stopped. File: ${result.fileUrl}`);
      addLog(`Total packets: ${result.meta.packetCount}`);
      setPacketCount(result.meta.packetCount);
      setStatus("idle");
      setSessionId(null);

      // Parse capture
      addLog("Parsing capture file...");
      const parsed = await captureAPI.parseCapture(result.fileUrl);
      addLog("Parse complete!");

      if (onCaptureComplete) {
        onCaptureComplete(result.fileUrl, parsed);
      }
    } catch (error) {
      setStatus("error");
      addLog(`Error: ${error.message}`);
    }
  };

  return (
    <div className="space-y-4">
      <Card title="Packet Capture Control" icon={Wifi}>
        <div className="space-y-4">
          {/* Status + Counter */}
          <div className="flex items-center justify-between">
            <StatusBadge status={status} />
            <div className="text-cyan-400 font-mono text-sm">
              Packets:{" "}
              <span className="text-white font-bold">{packetCount}</span>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={startCapture}
              disabled={status === "capturing"}
              className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500 text-green-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Wifi className="w-4 h-4" />
              Start Capture
            </button>

            <button
              onClick={stopCapture}
              disabled={status !== "capturing"}
              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500 text-red-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
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

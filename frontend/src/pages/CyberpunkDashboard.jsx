import React, { useState } from "react";
import { Navbar } from "../components/layout/Navbar";
import { Footer } from "../components/layout/Footer";
import { PacketCapturePanel } from "../components/panels/PacketCapturePanel";
import { MitigationPanel } from "../components/panels/MitigationPanel";
import { PcapViewer } from "../components/views/PcapViewer";
import { FingerprintResults } from "../components/views/FingerprintResults";
import { DeviceActionIdentification } from "../components/views/DeviceActionIdentification";
import { UserBehaviourAnalysis } from "../components/views/UserBehaviourAnalysis";

export default function CyberpunkDashboard() {
  const [captureFile, setCaptureFile] = useState(null);
  const [parsedData, setParsedData] = useState(null);
  const [fingerprintedDevices, setFingerprintedDevices] = useState([]);
  const [activeDevices, setActiveDevices] = useState([]);
  const [bssid, setBssid] = useState(null);
  const [pcapFile, setPcapFile] = useState(null);

  const handleDevicesIdentified = (devices, detectedBssid, analyzedFile) => {
    setFingerprintedDevices(devices);
    setBssid(detectedBssid);
    setPcapFile(analyzedFile);
  };

  const handleCaptureComplete = (fileUrl, parsed) => {
    setCaptureFile(fileUrl);
    setParsedData(parsed);
  };

  const handleMitigationComplete = (fileUrl) => {
    setCaptureFile(fileUrl);
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-gray-900 via-black to-gray-900 text-white">
      {/* Background scanline effect */}
      <div
        className="fixed inset-0 pointer-events-none opacity-5 z-50"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, cyan 2px, cyan 4px)",
        }}
      />

      {/* Navbar */}
      <Navbar />

      {/* Main Layout */}
      <div className="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-1 gap-6">
        <div className="space-y-6">
          <PacketCapturePanel onCaptureComplete={handleCaptureComplete} />
        </div>

        <div className="space-y-6">
          <PcapViewer fileUrl={captureFile} parsed={parsedData} />
          <FingerprintResults 
            fileUrl={captureFile}
            parsedData={parsedData}
            onDevicesIdentified={handleDevicesIdentified}
          />
          <DeviceActionIdentification 
            fileUrl={captureFile} 
            devices={fingerprintedDevices}
            bssid={bssid}
            pcapFile={pcapFile}
            onDeviceActionsIdentified={setActiveDevices}
          />
          <UserBehaviourAnalysis 
            fileUrl={captureFile} 
            activeDevices={activeDevices}
          />
          <MitigationPanel onMitigationComplete={handleMitigationComplete} />
        </div>
      </div>

      {/* Footer */}
      <Footer />
    </div>
  );
}

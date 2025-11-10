import React from 'react';
import { Activity, Download } from 'lucide-react';
import { Card } from '../core/Card';
import { analysisAPI } from '../../api/analysisAPI';

export function PcapViewer({ fileUrl, parsed }) {
  if (!parsed) return null;

  
  const fileName = fileUrl ? fileUrl.split(/[/\\]/).pop() : "Unknown File";

  return (
    <Card title="Capture Analysis" icon={Activity}>
      <div className="space-y-4">
        {/* File Metadata */}
        <div className="bg-black/30 rounded p-3">
          <div className="text-xs text-gray-400 mb-2">
            Packet Level Analysis on {fileName} for {parsed.ssid}
          </div>
        
          <div className="text-sm text-cyan-400">
            Total Packets Captured:{' '} 
            <span className="text-white font-bold">
              {parsed.summary.totalBeforeFilter}
            </span>
            <span> </span>
            <span className="text-sm text-cyan-400">
               and Total Packets Filtered Based on {parsed.bssid}:{' '}
              <span className="text-white font-bold">
                {parsed.summary.totalPacketsAfterFilter}
              </span>
            </span>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div>
          <div className="text-sm text-cyan-400 mb-2">Packet Type Distribution</div>
          <div className="space-y-2">
            {Object.entries(parsed.summary.packetTypePercentages).map(([protocol, percent]) => (
              <div key={protocol} className="flex items-center gap-6">
                <div className="text-xs text-gray-400 w-16">{protocol}</div>
                <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-cyan-500 h-full transition-all"
                    style={{ width: `${percent}%` }}
                  />
                </div>
                <div className="text-xs text-white w-12 text-right">{percent}%</div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Flows */}
        <div>
          <div className="text-sm text-cyan-400 mb-2">Top Flows</div>
          <div className="space-y-2">
            {parsed.flows.map((flow, i) => (
              <div
                key={i}
                className="bg-black/30 rounded p-2 text-xs font-mono border border-cyan-500/10"
              >
                <div className="flex justify-between">
                  <span className="text-green-400">{flow.src}</span>
                  <span className="text-gray-500">→</span>
                  <span className="text-pink-400">{flow.dst}</span>
                </div>
                <div className="text-gray-400 mt-1">
                  {flow.protocol} • {flow.packets} packets
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Download Button */}
        <button
          onClick={() => analysisAPI.downloadFile(fileName)}
          className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all flex items-center justify-center gap-2"
        >
          <Download className="w-4 h-4" />
          Download {fileName}
        </button>
      </div>
    </Card>
  );
}

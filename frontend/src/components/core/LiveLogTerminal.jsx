import React, { useRef, useEffect } from 'react';
import { Terminal } from 'lucide-react';
import { Card } from './Card';

export const LiveLogTerminal = ({ logs, title = "Live Terminal" }) => {
  const termRef = useRef(null);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logs]);

  return (
    <Card title={title} icon={Terminal}>
      <div ref={termRef} className="bg-black/50 rounded p-3 h-64 overflow-y-auto font-mono text-xs text-green-400 space-y-1">
        {logs.length === 0 ? (
          <div className="text-gray-500">Waiting for events...</div>
        ) : (
          logs.map((log, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-cyan-600">[{log.ts}]</span>
              <span>{log.line}</span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
};

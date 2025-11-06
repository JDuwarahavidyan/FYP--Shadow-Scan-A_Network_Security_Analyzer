import React from 'react';

export const StatusBadge = ({ status }) => {
  const configs = {
    idle: { 
      bg: 'bg-gray-700', 
      text: 'text-gray-300', 
      label: 'Idle' 
    },
    scanning: { 
      bg: 'bg-blue-500/20', 
      text: 'text-blue-400', 
      label: 'Scanning', 
      pulse: true 
    },
    capturing: { 
      bg: 'bg-cyan-500/20', 
      text: 'text-cyan-400', 
      label: 'Capturing', 
      pulse: true 
    },
    stopping: { 
      bg: 'bg-yellow-500/20', 
      text: 'text-yellow-400', 
      label: 'Stopping' 
    },
    running: { 
      bg: 'bg-green-500/20', 
      text: 'text-green-400', 
      label: 'Running', 
      pulse: true 
    },
    error: { 
      bg: 'bg-red-500/20', 
      text: 'text-red-400', 
      label: 'Error' 
    },
  };

  const config = configs[status] || configs.idle;

  return (
    <div
      className={`inline-flex items-center px-3 py-1 rounded-full 
                  ${config.bg} ${config.text} text-xs font-mono`}
    >
      {config.pulse && (
        <span className="w-2 h-2 bg-current rounded-full mr-2 animate-pulse" />
      )}
      {config.label}
    </div>
  );
};

import React from 'react';

export const Card = ({ title, icon: Icon, children, className = '' }) => (
  <div className="relative overflow-visible bg-gray-900/50 backdrop-blur-sm border border-cyan-500/30 rounded-lg p-4 shadow-lg shadow-cyan-500/10">


    {title && (
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-cyan-500/20">
        {Icon && <Icon className="w-5 h-5 text-cyan-400" />}
        <h3 className="text-cyan-400 font-mono font-semibold">{title}</h3>
      </div>
    )}
    {children}
  </div>
);

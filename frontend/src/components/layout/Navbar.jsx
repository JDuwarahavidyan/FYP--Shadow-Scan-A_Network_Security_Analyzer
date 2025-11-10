import React, { useState, useEffect } from "react";

export const Navbar = () => {
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);

    // Cleanup interval when component unmounts
    return () => clearInterval(timer);
  }, []);

  return (
    <nav className="border-b border-cyan-500/30 bg-black/50 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img src="/logo.png" alt="Shadow Scan Logo" className="w-12 h-12 object-contain" />
          <div>
            <h1 className="text-xl font-bold font-mono text-cyan-400">ShadowScan</h1>
            <p className="text-xs text-gray-500">See Everything. Reveal Nothing.</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span>System Online</span>
          </div>
          <div className="text-xs text-gray-500 font-mono">{currentTime}</div>
        </div>
      </div>
    </nav>
  );
};

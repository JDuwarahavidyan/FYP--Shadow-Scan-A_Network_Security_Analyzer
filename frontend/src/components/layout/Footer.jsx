import React from "react";
import { AlertTriangle } from "lucide-react";

export const Footer = () => (
  <footer className="mt-12 pt-6 border-t border-cyan-500/20 text-center">
    <p className="text-xs text-gray-500 font-mono">
      Shadow-Scan v1.0 • Raspberry Pi Integration Ready
    </p>

    <p className="flex items-center justify-center text-xs text-red-500 mt-2 space-x-1">
      <AlertTriangle className="w-4 h-4 shrink-0" />
      <span>Authorized Use Only • All Activity Logged</span>
    </p>


    <p className="text-xs text-gray-500 font-mono mt-2">
      © 2025 Shadow-Scan. All rights reserved.
    </p>
  </footer>
);


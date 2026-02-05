"use client";

import { useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Info, 
  AlertTriangle, 
  XCircle, 
  CheckCircle2,
  Terminal,
  Cpu
} from "lucide-react";
import type { AgentLog } from "@/types";

interface StatusFeedProps {
  logs: AgentLog[];
}

const iconMap = {
  info: Info,
  warning: AlertTriangle,
  error: XCircle,
  success: CheckCircle2,
};

const colorMap = {
  info: "text-cyan-400",
  warning: "text-amber-400",
  error: "text-red-400",
  success: "text-emerald-400",
};

const prefixMap = {
  info: "[INFO]",
  warning: "[WARN]",
  error: "[ERR!]",
  success: "[DONE]",
};

export function StatusFeed({ logs }: StatusFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  if (logs.length === 0) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      className="w-full max-w-6xl mx-auto mt-8"
    >
      {/* Terminal Window - Keeping Dark Theme */}
      <div className="rounded-2xl overflow-hidden border border-slate-700 bg-slate-900 shadow-2xl">
        {/* Terminal Header */}
        <div className="bg-slate-800 px-4 py-3 flex items-center gap-3 border-b border-slate-700">
          {/* Window Controls */}
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-red-500"></span>
            <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
            <span className="w-3 h-3 rounded-full bg-green-500"></span>
          </div>
          
          <div className="flex items-center gap-2 ml-2">
            <Terminal className="w-4 h-4 text-slate-400" />
            <span className="font-mono text-sm text-slate-400">phishguard-agent-monitor</span>
          </div>
          
          <div className="ml-auto flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-400 animate-pulse" />
            <span className="text-xs text-slate-500 font-mono">
              {logs.length} events
            </span>
          </div>
        </div>

        {/* Log Feed - Terminal Style */}
        <div
          ref={scrollRef}
          className="max-h-72 overflow-y-auto p-4 font-mono text-sm bg-slate-950"
        >
          <AnimatePresence mode="popLayout">
            {logs.map((log, index) => {
              const Icon = iconMap[log.type];
              return (
                <motion.div
                  key={`${log.timestamp}-${index}`}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="flex items-start gap-2 py-1.5 border-b border-slate-800/50 last:border-0"
                >
                  {/* Timestamp */}
                  <span className="text-slate-600 text-xs shrink-0">
                    {formatTime(log.timestamp)}
                  </span>
                  
                  {/* Status Prefix */}
                  <span className={`text-xs shrink-0 font-bold ${colorMap[log.type]}`}>
                    {prefixMap[log.type]}
                  </span>
                  
                  {/* Agent Name */}
                  <span className="text-violet-400 shrink-0">
                    [{log.agentName}]
                  </span>
                  
                  {/* Icon */}
                  <Icon className={`w-4 h-4 shrink-0 ${colorMap[log.type]}`} />
                  
                  {/* Message */}
                  <span className="text-slate-300 break-words">
                    {log.message}
                  </span>
                </motion.div>
              );
            })}
          </AnimatePresence>
          
          {/* Blinking Cursor */}
          <div className="flex items-center gap-1 pt-2 text-emerald-400">
            <span className="text-slate-500">$</span>
            <span className="animate-pulse">_</span>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

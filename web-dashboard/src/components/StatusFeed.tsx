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
  success: "text-green-400",
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
      className="w-full max-w-3xl mx-auto mt-8"
    >
      <div className="rounded-2xl overflow-hidden border border-white/10 bg-black/60 backdrop-blur-xl shadow-2xl">
        {/* Terminal Header */}
        <div className="bg-gradient-to-r from-gray-900 to-gray-800 px-4 py-3 flex items-center gap-3 border-b border-white/10">
          {/* Window Controls */}
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-red-500/80"></span>
            <span className="w-3 h-3 rounded-full bg-yellow-500/80"></span>
            <span className="w-3 h-3 rounded-full bg-green-500/80"></span>
          </div>
          
          <div className="flex items-center gap-2 ml-2">
            <Terminal className="w-4 h-4 text-purple-400" />
            <span className="font-mono text-sm text-gray-400">phishguard-agent-monitor</span>
          </div>
          
          <div className="ml-auto flex items-center gap-2">
            <Cpu className="w-4 h-4 text-green-400 animate-pulse" />
            <span className="text-xs text-gray-500 font-mono">
              {logs.length} events
            </span>
          </div>
        </div>

        {/* Log Feed - Terminal Style */}
        <div
          ref={scrollRef}
          className="max-h-72 overflow-y-auto p-4 font-mono text-sm bg-gray-950/50"
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
                  className="flex items-start gap-2 py-1.5 border-b border-white/5 last:border-0"
                >
                  {/* Timestamp */}
                  <span className="text-gray-600 text-xs shrink-0">
                    {formatTime(log.timestamp)}
                  </span>
                  
                  {/* Status Prefix */}
                  <span className={`text-xs shrink-0 font-bold ${colorMap[log.type]}`}>
                    {prefixMap[log.type]}
                  </span>
                  
                  {/* Agent Name */}
                  <span className="text-purple-400 shrink-0">
                    [{log.agentName}]
                  </span>
                  
                  {/* Icon */}
                  <Icon className={`w-4 h-4 shrink-0 ${colorMap[log.type]}`} />
                  
                  {/* Message */}
                  <span className="text-gray-300 break-words">
                    {log.message}
                  </span>
                </motion.div>
              );
            })}
          </AnimatePresence>
          
          {/* Blinking Cursor */}
          <div className="flex items-center gap-1 pt-2 text-green-400">
            <span className="text-gray-500">$</span>
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

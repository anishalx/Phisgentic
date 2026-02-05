"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ChevronDown, 
  ChevronRight, 
  Link as LinkIcon, 
  Globe, 
  FileText, 
  Brain,
  TestTube,
  AlertTriangle,
  AlertCircle,
  Info,
  XCircle
} from "lucide-react";
import type { AgentResult, Signal } from "@/types";

interface AgentBreakdownProps {
  results: AgentResult[];
}

const agentIcons: Record<string, typeof LinkIcon> = {
  urlAgent: LinkIcon,
  domainAgent: Globe,
  contentAgent: FileText,
  heuristicAgent: Brain,
  testerAgent: TestTube,
};

const severityColors: Record<Signal["severity"], string> = {
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
};

const severityIcons: Record<Signal["severity"], typeof Info> = {
  low: Info,
  medium: AlertCircle,
  high: AlertTriangle,
  critical: XCircle,
};

function getRiskColor(score: number): string {
  if (score <= 30) return "text-green-400";
  if (score <= 70) return "text-yellow-400";
  return "text-red-400";
}

function getRiskBg(score: number): string {
  if (score <= 30) return "bg-green-500";
  if (score <= 70) return "bg-yellow-500";
  return "bg-red-500";
}

export function AgentBreakdown({ results }: AgentBreakdownProps) {
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set());

  const toggleAgent = (agentId: string) => {
    setExpandedAgents((prev) => {
      const next = new Set(prev);
      if (next.has(agentId)) {
        next.delete(agentId);
      } else {
        next.add(agentId);
      }
      return next;
    });
  };

  if (results.length === 0) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 }}
      className="w-full max-w-3xl mx-auto mt-8"
    >
      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
        <Brain className="w-5 h-5 text-purple-400" />
        Agent Analysis Details
      </h3>

      <div className="space-y-3">
        {results.map((result) => {
          const isExpanded = expandedAgents.has(result.agentId);
          const Icon = agentIcons[result.agentId] || Brain;

          return (
            <motion.div
              key={result.agentId}
              className="glass rounded-xl overflow-hidden"
              layout
            >
              {/* Agent Header */}
              <button
                onClick={() => toggleAgent(result.agentId)}
                className="w-full flex items-center gap-3 p-4 hover:bg-white/5 transition-colors"
              >
                <Icon className="w-5 h-5 text-purple-400 flex-shrink-0" />
                <div className="flex-1 text-left">
                  <span className="text-white font-medium">
                    {result.agentName}
                  </span>
                  <p className="text-gray-500 text-xs">
                    {result.signals.length} signals • {result.executionTimeMs}ms
                  </p>
                </div>

                {/* Score */}
                <div className="flex items-center gap-3">
                  <div className="w-24 h-2 bg-white/10 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${result.riskScore}%` }}
                      transition={{ duration: 0.5 }}
                      className={`h-full rounded-full ${getRiskBg(result.riskScore)}`}
                    />
                  </div>
                  <span className={`text-lg font-bold ${getRiskColor(result.riskScore)}`}>
                    {result.riskScore}
                  </span>
                </div>

                {isExpanded ? (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                )}
              </button>

              {/* Expanded Content */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="p-4 pt-0 space-y-4 border-t border-white/10">
                      {/* Explanation */}
                      <div className="mt-4">
                        <p className="text-gray-400 text-sm">
                          {result.explanation}
                        </p>
                      </div>

                      {/* Signals */}
                      {result.signals.length > 0 && (
                        <div>
                          <h4 className="text-white text-sm font-medium mb-2">
                            Detected Signals
                          </h4>
                          <div className="space-y-2">
                            {result.signals.map((signal, index) => {
                              const SeverityIcon = severityIcons[signal.severity];
                              return (
                                <div
                                  key={index}
                                  className={`flex items-start gap-2 p-2 rounded-lg border ${severityColors[signal.severity]}`}
                                >
                                  <SeverityIcon className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className="font-medium text-sm">
                                        {signal.type}
                                      </span>
                                      <span className="text-xs opacity-75 uppercase">
                                        {signal.severity}
                                      </span>
                                    </div>
                                    <p className="text-sm opacity-75">
                                      {signal.description}
                                    </p>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Confidence */}
                      <div className="flex items-center gap-2 text-sm text-gray-500">
                        <span>Confidence:</span>
                        <span className="text-white">
                          {Math.round(result.confidence * 100)}%
                        </span>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}
      </div>
    </motion.div>
  );
}

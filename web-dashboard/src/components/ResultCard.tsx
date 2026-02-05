"use client";

import { motion } from "framer-motion";
import { 
  ShieldAlert, 
  ShieldX,
  ShieldCheck,
  ExternalLink,
  Clock,
  Image as ImageIcon,
  AlertTriangle,
  XCircle,
  AlertOctagon,
  Zap
} from "lucide-react";
import type { FinalVerdict, Signal } from "@/types";

interface ResultCardProps {
  verdict: FinalVerdict;
}

// Get all critical/high signals across all agents
function getCriticalSignals(verdict: FinalVerdict): Signal[] {
  const signals: Signal[] = [];
  verdict.agentResults.forEach(result => {
    result.signals.forEach(signal => {
      if (signal.severity === "critical" || signal.severity === "high") {
        signals.push(signal);
      }
    });
  });
  return signals;
}

export function ResultCard({ verdict }: ResultCardProps) {
  const criticalSignals = getCriticalSignals(verdict);
  
  const getVerdictStyles = () => {
    switch (verdict.action) {
      case "allow":
        return {
          bgColor: "bg-green-50",
          borderColor: "border-green-300",
          textColor: "text-green-700",
          iconBg: "bg-green-100",
          icon: ShieldCheck,
          label: "SAFE",
          sublabel: "No threats detected",
          gaugeClass: "gauge-safe",
        };
      case "warn":
        return {
          bgColor: "bg-amber-50",
          borderColor: "border-amber-300",
          textColor: "text-amber-700",
          iconBg: "bg-amber-100",
          icon: ShieldAlert,
          label: "SUSPICIOUS",
          sublabel: "Proceed with caution",
          gaugeClass: "gauge-warning",
        };
      case "block":
        return {
          bgColor: "bg-red-50",
          borderColor: "border-red-300",
          textColor: "text-red-700",
          iconBg: "bg-red-100",
          icon: ShieldX,
          label: "DANGEROUS",
          sublabel: "Phishing threat detected",
          gaugeClass: "gauge-danger",
        };
    }
  };

  const styles = getVerdictStyles();
  const Icon = styles.icon;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.5, type: "spring" }}
      className="w-full max-w-6xl mx-auto mt-8"
    >
      <div
        className={`glass rounded-2xl border-2 ${styles.borderColor} overflow-hidden shadow-xl`}
      >
        {/* Header - Verdict Display */}
        <div className={`${styles.bgColor} p-8`}>
          <div className="flex items-center gap-6">
            {/* Animated Icon */}
            <motion.div
              initial={{ rotate: -180, opacity: 0, scale: 0 }}
              animate={{ rotate: 0, opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, type: "spring" }}
              className={`p-4 rounded-2xl ${styles.iconBg} ${verdict.action === "block" ? "animate-pulse" : ""}`}
            >
              <Icon className={`w-16 h-16 ${styles.textColor}`} />
            </motion.div>
            
            {/* Verdict Text */}
            <div className="flex-1">
              <motion.p 
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 }}
                className="text-gray-500 text-sm uppercase tracking-wider mb-1 font-medium"
              >
                Security Verdict
              </motion.p>
              <motion.h2 
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 }}
                className={`text-4xl font-black ${styles.textColor} tracking-tight`}
              >
                {styles.label}
              </motion.h2>
              <motion.p 
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 }}
                className="text-gray-600 text-sm mt-1"
              >
                {styles.sublabel}
              </motion.p>
            </div>
            
            {/* Score Gauge */}
            <div className="relative w-28 h-28">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="56"
                  cy="56"
                  r="48"
                  fill="none"
                  stroke="rgba(0,0,0,0.08)"
                  strokeWidth="10"
                />
                <motion.circle
                  cx="56"
                  cy="56"
                  r="48"
                  fill="none"
                  strokeWidth="10"
                  strokeLinecap="round"
                  className={styles.gaugeClass}
                  initial={{ strokeDasharray: "0 301.6" }}
                  animate={{
                    strokeDasharray: `${(verdict.overallRiskScore / 100) * 301.6} 301.6`,
                  }}
                  transition={{ duration: 1, delay: 0.3 }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <motion.span 
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.5 }}
                  className={`text-3xl font-black ${styles.textColor}`}
                >
                  {verdict.overallRiskScore}
                </motion.span>
                <span className="text-xs text-gray-500 uppercase font-medium">Risk</span>
              </div>
            </div>
          </div>
        </div>

        {/* Critical Threats Banner */}
        {verdict.action === "block" && criticalSignals.length > 0 && (
          <motion.div 
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            transition={{ delay: 0.5 }}
            className="bg-red-100 border-y border-red-200 px-6 py-4"
          >
            <div className="flex items-center gap-2 mb-3">
              <AlertOctagon className="w-5 h-5 text-red-600" />
              <span className="text-red-700 font-bold text-sm uppercase tracking-wider">
                Critical Threats Detected ({criticalSignals.length})
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {criticalSignals.slice(0, 5).map((signal, index) => (
                <motion.span
                  key={index}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.6 + index * 0.1 }}
                  className="signal-critical inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
                >
                  <XCircle className="w-3 h-3" />
                  {signal.type.replace(/_/g, " ")}
                </motion.span>
              ))}
              {criticalSignals.length > 5 && (
                <span className="px-3 py-1.5 text-xs text-red-600 font-medium">
                  +{criticalSignals.length - 5} more
                </span>
              )}
            </div>
          </motion.div>
        )}

        {/* Warning Signals Banner */}
        {verdict.action === "warn" && criticalSignals.length > 0 && (
          <motion.div 
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            transition={{ delay: 0.5 }}
            className="bg-amber-100 border-y border-amber-200 px-6 py-4"
          >
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-amber-600" />
              <span className="text-amber-700 font-bold text-sm uppercase tracking-wider">
                Warning Signals ({criticalSignals.length})
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {criticalSignals.slice(0, 4).map((signal, index) => (
                <motion.span
                  key={index}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.6 + index * 0.1 }}
                  className="signal-high inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
                >
                  <AlertTriangle className="w-3 h-3" />
                  {signal.type.replace(/_/g, " ")}
                </motion.span>
              ))}
            </div>
          </motion.div>
        )}

        {/* Body */}
        <div className="p-6 space-y-6">
          {/* URL */}
          <div className="flex items-center gap-3 p-4 bg-gray-50 rounded-xl border border-gray-200">
            <ExternalLink className="w-5 h-5 text-gray-500 flex-shrink-0" />
            <span className="text-gray-500 text-sm font-medium">URL:</span>
            <a
              href={verdict.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-700 hover:text-red-600 truncate text-sm font-mono transition-colors"
            >
              {verdict.url}
            </a>
          </div>

          {/* Summary */}
          <div className="bg-white rounded-xl p-5 border border-gray-200 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <Zap className="w-4 h-4 text-red-600" />
              <h3 className="text-gray-900 font-semibold">Analysis Summary</h3>
            </div>
            <p className="text-gray-700 text-sm leading-relaxed">
              {verdict.summary}
            </p>
          </div>

          {/* Screenshot */}
          {verdict.screenshot && (
            <div>
              <h3 className="text-gray-900 font-semibold mb-3 flex items-center gap-2">
                <ImageIcon className="w-4 h-4 text-red-600" />
                Page Screenshot
              </h3>
              <div className="relative rounded-xl overflow-hidden border border-gray-200 shadow-md">
                <img
                  src={`data:image/jpeg;base64,${verdict.screenshot}`}
                  alt="Page screenshot"
                  className="w-full h-auto"
                />
                {verdict.action === "block" && (
                  <div className="absolute inset-0 bg-red-500/5 pointer-events-none" />
                )}
              </div>
            </div>
          )}

          {/* Meta Info */}
          <div className="flex items-center justify-between pt-4 border-t border-gray-200">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" />
              <span className="text-gray-500 text-sm">
                {new Date(verdict.timestamp).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-gray-500 text-sm">
                Confidence: <span className="text-gray-900 font-semibold">{Math.round(verdict.confidence * 100)}%</span>
              </span>
              <span className="text-gray-500 text-sm">
                Agents: <span className="text-gray-900 font-semibold">{verdict.agentResults.length}</span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

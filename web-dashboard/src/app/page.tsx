"use client";

import { useState, useCallback, useRef } from "react";
import { motion } from "framer-motion";
import { 
  ScanningInterface, 
  StatusFeed, 
  ResultCard, 
  AgentBreakdown,
  ErrorBoundary 
} from "@/components";
import { scanUrlWithStream } from "@/lib/api";
import type { FinalVerdict, AgentLog, ScanStatus } from "@/types";

export default function Home() {
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [logs, setLogs] = useState<AgentLog[]>([]);
  const [verdict, setVerdict] = useState<FinalVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  const handleScan = useCallback(async (url: string) => {
    // Clean up any previous SSE connection
    if (cleanupRef.current) {
      cleanupRef.current();
      cleanupRef.current = null;
    }

    // Reset state
    setStatus("scanning");
    setLogs([]);
    setVerdict(null);
    setError(null);

    // Add initial log
    setLogs([{
      agentId: "dashboard",
      agentName: "Dashboard",
      message: `Starting analysis of ${url}`,
      timestamp: Date.now(),
      type: "info",
    }]);

    // Use SSE streaming for real-time updates
    const cleanup = scanUrlWithStream(
      url,
      // onLog — append each log as it arrives
      (log) => {
        setLogs((prev) => [...prev, log]);
      },
      // onResult — final verdict
      (result) => {
        setVerdict(result);
      },
      // onError
      (errMsg) => {
        setError(errMsg);
        setStatus("error");
      },
      // onComplete
      () => {
        setStatus("complete");
        cleanupRef.current = null;
      },
    );

    cleanupRef.current = cleanup;
  }, []);

  return (
    <ErrorBoundary>
    <main className="min-h-screen py-12 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Scanning Interface */}
        <ScanningInterface onScan={handleScan} status={status} />

        {/* Status Feed */}
        {(status === "scanning" || logs.length > 0) && (
          <StatusFeed logs={logs} />
        )}

        {/* Error Display */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="w-full max-w-6xl mx-auto mt-8 p-6 bg-red-50 rounded-2xl border-2 border-red-300"
          >
            <p className="text-red-700 font-medium">{error}</p>
          </motion.div>
        )}

        {/* Results */}
        {verdict && (
          <>
            <ResultCard verdict={verdict} />
            <AgentBreakdown results={verdict.agentResults} />
          </>
        )}

        {/* Footer */}
        <motion.footer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="text-center mt-16 text-gray-500 text-sm"
        >
          <p className="font-medium text-gray-600">
            PhishGuard AI - Multi-Agent Phishing Detection System
          </p>
          <p className="mt-1">
            Powered by Dual-Model AI (Groq Llama 3.3 + Google Gemini Flash)
          </p>
        </motion.footer>
      </div>
    </main>
    </ErrorBoundary>
  );
}

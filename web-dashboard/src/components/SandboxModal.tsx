"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Monitor,
  Shield,
  ExternalLink,
  Clock,
  FileText,
  Link2,
  ArrowRight,
  Loader2,
  AlertTriangle,
  RefreshCw,
  Lock,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { openSandbox } from "@/lib/api";
import type { SandboxResult } from "@/types";

interface SandboxModalProps {
  url: string;
  onClose: () => void;
}

export function SandboxModal({ url, onClose }: SandboxModalProps) {
  const [state, setState] = useState<"loading" | "success" | "error">("loading");
  const [result, setResult] = useState<SandboxResult | null>(null);
  const [error, setError] = useState<string>("");
  const [showRedirects, setShowRedirects] = useState(false);

  const fetchSandbox = useCallback(async () => {
    setState("loading");
    setError("");
    setResult(null);

    try {
      const data = await openSandbox(url);
      setResult(data);
      setState("success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to capture sandbox preview");
      setState("error");
    }
  }, [url]);

  useEffect(() => {
    fetchSandbox();
  }, [fetchSandbox]);

  // Close on Escape key
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  // Prevent body scroll while modal is open
  useEffect(() => {
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = "";
    };
  }, []);

  const hasRedirects = result && result.redirectChain.length > 0;
  const wasRedirected = result && result.url !== result.finalUrl;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        className="sandbox-backdrop"
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.92, y: 30 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.92, y: 30 }}
          transition={{ duration: 0.3, type: "spring", damping: 25, stiffness: 300 }}
          className="sandbox-modal"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Safety Banner */}
          <div className="sandbox-safety-banner">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              <span className="font-semibold text-xs sm:text-sm uppercase tracking-wider">
                Sandbox Preview
              </span>
            </div>
            <span className="text-xs opacity-90 hidden sm:inline">
              Server-side render — no connection from your browser
            </span>
          </div>

          {/* Browser Chrome Header */}
          <div className="sandbox-chrome">
            <div className="flex items-center gap-3 flex-1 min-w-0">
              {/* Traffic lights */}
              <div className="flex items-center gap-1.5 flex-shrink-0">
                <button
                  onClick={onClose}
                  className="w-3 h-3 rounded-full bg-red-500 hover:bg-red-600 transition-colors cursor-pointer"
                  title="Close"
                />
                <div className="w-3 h-3 rounded-full bg-yellow-500 opacity-50" />
                <div className="w-3 h-3 rounded-full bg-green-500 opacity-50" />
              </div>

              {/* URL bar */}
              <div className="sandbox-url-bar">
                <Lock className="w-3 h-3 text-red-500 flex-shrink-0" />
                <span className="truncate text-xs text-slate-400 font-mono">
                  {state === "success" && result ? result.finalUrl : url}
                </span>
              </div>
            </div>

            {/* Close button */}
            <button
              onClick={onClose}
              className="flex-shrink-0 p-1.5 rounded-lg hover:bg-slate-700 transition-colors text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Content Area */}
          <div className="sandbox-content">
            {/* Loading State */}
            {state === "loading" && (
              <div className="sandbox-loading">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                >
                  <Loader2 className="w-10 h-10 text-slate-400" />
                </motion.div>
                <div className="text-center">
                  <p className="text-slate-300 font-medium text-sm">
                    Capturing page in sandbox...
                  </p>
                  <p className="text-slate-500 text-xs mt-1">
                    Rendering via headless browser on our server
                  </p>
                </div>
              </div>
            )}

            {/* Error State */}
            {state === "error" && (
              <div className="sandbox-loading">
                <div className="p-3 rounded-full bg-red-500/10">
                  <AlertTriangle className="w-10 h-10 text-red-400" />
                </div>
                <div className="text-center">
                  <p className="text-slate-300 font-medium text-sm">
                    Failed to capture preview
                  </p>
                  <p className="text-slate-500 text-xs mt-1 max-w-sm">
                    {error}
                  </p>
                </div>
                <button
                  onClick={fetchSandbox}
                  className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  Try Again
                </button>
              </div>
            )}

            {/* Success State */}
            {state === "success" && result && (
              <>
                {/* Screenshot */}
                <div className="sandbox-screenshot-container">
                  {result.screenshot ? (
                    <div className="relative">
                      <img
                        src={`data:image/jpeg;base64,${result.screenshot}`}
                        alt="Sandbox page preview"
                        className="w-full h-auto"
                      />
                      {/* Danger watermark overlay */}
                      <div className="sandbox-danger-overlay">
                        <span className="sandbox-watermark">SANDBOX</span>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-48 bg-slate-800 text-slate-500 text-sm">
                      <Monitor className="w-6 h-6 mr-2 opacity-50" />
                      Screenshot unavailable
                    </div>
                  )}
                </div>

                {/* Page Metadata */}
                <div className="sandbox-metadata">
                  {/* Redirect Warning */}
                  {wasRedirected && (
                    <div className="sandbox-redirect-warning">
                      <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-amber-200 text-xs font-medium">
                          Page redirected to a different URL
                        </p>
                        <div className="flex items-center gap-1.5 mt-1 text-xs text-amber-300/70 font-mono">
                          <span className="truncate">{result.url}</span>
                          <ArrowRight className="w-3 h-3 flex-shrink-0" />
                          <span className="truncate">{result.finalUrl}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {/* Page Title */}
                    <div className="col-span-2 sm:col-span-4 flex items-start gap-2 p-3 bg-slate-800/50 rounded-lg">
                      <FileText className="w-4 h-4 text-slate-400 flex-shrink-0 mt-0.5" />
                      <div className="min-w-0">
                        <p className="text-slate-500 text-[10px] uppercase tracking-wider font-medium">
                          Page Title
                        </p>
                        <p className="text-slate-200 text-xs mt-0.5 break-words">
                          {result.title || "(No title)"}
                        </p>
                      </div>
                    </div>

                    {/* Load Time */}
                    <div className="flex items-center gap-2 p-3 bg-slate-800/50 rounded-lg">
                      <Clock className="w-4 h-4 text-slate-400 flex-shrink-0" />
                      <div>
                        <p className="text-slate-500 text-[10px] uppercase tracking-wider font-medium">
                          Load Time
                        </p>
                        <p className="text-slate-200 text-xs mt-0.5">
                          {(result.loadTimeMs / 1000).toFixed(1)}s
                        </p>
                      </div>
                    </div>

                    {/* Forms */}
                    <div className="flex items-center gap-2 p-3 bg-slate-800/50 rounded-lg">
                      <FileText className="w-4 h-4 text-slate-400 flex-shrink-0" />
                      <div>
                        <p className="text-slate-500 text-[10px] uppercase tracking-wider font-medium">
                          Forms
                        </p>
                        <p className="text-slate-200 text-xs mt-0.5">
                          {result.formCount}
                        </p>
                      </div>
                    </div>

                    {/* Links */}
                    <div className="flex items-center gap-2 p-3 bg-slate-800/50 rounded-lg">
                      <Link2 className="w-4 h-4 text-slate-400 flex-shrink-0" />
                      <div>
                        <p className="text-slate-500 text-[10px] uppercase tracking-wider font-medium">
                          Links
                        </p>
                        <p className="text-slate-200 text-xs mt-0.5">
                          {result.linkCount}
                        </p>
                      </div>
                    </div>

                    {/* Redirects */}
                    <div className="flex items-center gap-2 p-3 bg-slate-800/50 rounded-lg">
                      <ExternalLink className="w-4 h-4 text-slate-400 flex-shrink-0" />
                      <div>
                        <p className="text-slate-500 text-[10px] uppercase tracking-wider font-medium">
                          Redirects
                        </p>
                        <p className="text-slate-200 text-xs mt-0.5">
                          {result.redirectChain.length}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Redirect Chain (expandable) */}
                  {hasRedirects && (
                    <div className="mt-3">
                      <button
                        onClick={() => setShowRedirects(!showRedirects)}
                        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                      >
                        {showRedirects ? (
                          <ChevronUp className="w-3 h-3" />
                        ) : (
                          <ChevronDown className="w-3 h-3" />
                        )}
                        {showRedirects ? "Hide" : "Show"} redirect chain
                      </button>
                      <AnimatePresence>
                        {showRedirects && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="mt-2 space-y-1.5 pl-4 border-l-2 border-slate-700">
                              <div className="text-xs font-mono text-slate-400">
                                {result.url}
                              </div>
                              {result.redirectChain.map((hop, i) => (
                                <div
                                  key={i}
                                  className="flex items-center gap-1.5 text-xs font-mono text-amber-400/70"
                                >
                                  <ArrowRight className="w-3 h-3 flex-shrink-0" />
                                  <span className="truncate">{hop}</span>
                                </div>
                              ))}
                              <div className="flex items-center gap-1.5 text-xs font-mono text-slate-200">
                                <ArrowRight className="w-3 h-3 flex-shrink-0" />
                                <span className="truncate">{result.finalUrl}</span>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="sandbox-footer">
            <div className="flex items-center gap-1.5 text-slate-500 text-[10px] sm:text-xs">
              <Shield className="w-3 h-3" />
              <span>
                This is a server-side screenshot. No connection was made from your browser.
              </span>
            </div>
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-medium transition-colors"
            >
              Close
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

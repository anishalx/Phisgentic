"use client";

import { useState, FormEvent } from "react";
import { motion } from "framer-motion";
import { Search, Shield, Loader2 } from "lucide-react";
import type { ScanStatus } from "@/types";

interface ScanningInterfaceProps {
  onScan: (url: string) => void;
  status: ScanStatus;
}

export function ScanningInterface({ onScan, status }: ScanningInterfaceProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError("");

    // Basic URL validation
    try {
      new URL(url);
      onScan(url);
    } catch {
      // Try adding https://
      if (!url.startsWith("http")) {
        try {
          new URL(`https://${url}`);
          onScan(`https://${url}`);
          return;
        } catch {
          setError("Please enter a valid URL");
          return;
        }
      }
      setError("Please enter a valid URL");
    }
  };

  const isScanning = status === "scanning";

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full max-w-3xl mx-auto"
    >
      {/* Header */}
      <div className="text-center mb-8">
        <motion.div
          className="inline-flex items-center justify-center mb-4"
          animate={{ scale: isScanning ? [1, 1.1, 1] : 1 }}
          transition={{ duration: 2, repeat: isScanning ? Infinity : 0 }}
        >
          <Shield className="w-16 h-16 text-purple-500" />
        </motion.div>
        <h1 className="text-4xl font-bold gradient-text mb-2">PhishGuard AI</h1>
        <p className="text-gray-400">
          Multi-Agent Phishing Detection System
        </p>
      </div>

      {/* Search Form */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="glass rounded-2xl p-2 transition-all duration-300 hover:border-purple-500/50">
          <div className="flex items-center gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to analyze (e.g., https://example.com)"
                className="w-full bg-transparent pl-12 pr-4 py-4 text-white placeholder-gray-500 text-lg rounded-xl focus:outline-none"
                disabled={isScanning}
              />
            </div>
            <motion.button
              type="submit"
              disabled={isScanning || !url.trim()}
              className="btn-primary px-8 py-4 rounded-xl font-semibold text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Scan URL
                </>
              )}
            </motion.button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <motion.p
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-red-400 text-sm mt-2 pl-4"
          >
            {error}
          </motion.p>
        )}
      </form>

      {/* Quick Test Links */}
      <div className="mt-8">
        <p className="text-gray-500 text-sm mb-3 text-center">Quick test URLs:</p>
        <div className="flex flex-col gap-2">
          {/* Safe Sites Row */}
          <div className="flex justify-center gap-3 flex-wrap">
            <span className="text-green-500/70 text-xs uppercase tracking-wider self-center">Safe:</span>
            <QuickTestButton 
              url="https://google.com" 
              label="google.com" 
              type="safe"
              onClick={setUrl}
              disabled={isScanning}
            />
            <QuickTestButton 
              url="https://github.com" 
              label="github.com" 
              type="safe"
              onClick={setUrl}
              disabled={isScanning}
            />
            <QuickTestButton 
              url="https://microsoft.com" 
              label="microsoft.com" 
              type="safe"
              onClick={setUrl}
              disabled={isScanning}
            />
          </div>
          
          {/* Suspicious Sites Row */}
          <div className="flex justify-center gap-3 flex-wrap">
            <span className="text-amber-500/70 text-xs uppercase tracking-wider self-center">Suspicious:</span>
            <QuickTestButton 
              url="https://paypal-secure-login.tk" 
              label="paypal-secure-login.tk" 
              type="warning"
              onClick={setUrl}
              disabled={isScanning}
            />
            <QuickTestButton 
              url="https://appleid-verify.000webhostapp.com" 
              label="appleid-verify.000webhostapp.com" 
              type="warning"
              onClick={setUrl}
              disabled={isScanning}
            />
          </div>
          
          {/* Dangerous Sites Row */}
          <div className="flex justify-center gap-3 flex-wrap">
            <span className="text-red-500/70 text-xs uppercase tracking-wider self-center">Phishing:</span>
            <QuickTestButton 
              url="https://secure-login-facebook.ml/verify" 
              label="secure-login-facebook.ml" 
              type="danger"
              onClick={setUrl}
              disabled={isScanning}
            />
            <QuickTestButton 
              url="https://netflix-billing-update.xyz" 
              label="netflix-billing-update.xyz" 
              type="danger"
              onClick={setUrl}
              disabled={isScanning}
            />
          </div>
        </div>
      </div>
    </motion.div>
  );
}

interface QuickTestButtonProps {
  url: string;
  label: string;
  type: "safe" | "warning" | "danger";
  onClick: (url: string) => void;
  disabled: boolean;
}

function QuickTestButton({ url, label, type, onClick, disabled }: QuickTestButtonProps) {
  const typeStyles = {
    safe: "border-green-500/30 text-green-400/70 hover:bg-green-500/10 hover:border-green-500/50",
    warning: "border-amber-500/30 text-amber-400/70 hover:bg-amber-500/10 hover:border-amber-500/50",
    danger: "border-red-500/30 text-red-400/70 hover:bg-red-500/10 hover:border-red-500/50",
  };
  
  return (
    <button
      type="button"
      onClick={() => onClick(url)}
      disabled={disabled}
      className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-200 disabled:opacity-50 ${typeStyles[type]}`}
    >
      {label}
    </button>
  );
}

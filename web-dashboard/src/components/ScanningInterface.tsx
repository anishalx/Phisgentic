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

    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      setError("Please enter a URL");
      return;
    }

    // Basic URL validation
    try {
      new URL(trimmedUrl);
      onScan(trimmedUrl);
    } catch {
      // Try adding https://
      if (!trimmedUrl.startsWith("http")) {
        try {
          new URL(`https://${trimmedUrl}`);
          onScan(`https://${trimmedUrl}`);
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
      className="w-full max-w-6xl mx-auto px-4 sm:px-6"
    >
      {/* Header */}
      <div className="text-center mb-6 sm:mb-10">
        <motion.div
          className="inline-flex items-center justify-center mb-4 sm:mb-5"
          animate={{ scale: isScanning ? [1, 1.05, 1] : 1 }}
          transition={{ duration: 2, repeat: isScanning ? Infinity : 0 }}
        >
          <Shield className="w-14 h-14 sm:w-20 sm:h-20 text-red-600" />
        </motion.div>
        <h1 className="text-3xl sm:text-5xl font-bold gradient-text mb-2 sm:mb-3 tracking-tight">PhishGuard AI</h1>
        <p className="text-gray-600 text-base sm:text-lg">
          Multi-Agent Phishing Detection System
        </p>
      </div>

      {/* Search Form */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="glass rounded-2xl p-2 transition-all duration-300 hover:shadow-lg">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to analyze..."
                className="w-full bg-transparent pl-12 pr-4 py-3 sm:py-4 text-gray-900 placeholder-gray-400 text-base sm:text-lg rounded-xl focus:outline-none"
                disabled={isScanning}
              />
            </div>
            <motion.button
              type="submit"
              disabled={isScanning || !url.trim()}
              className="btn-primary w-full sm:w-auto px-6 sm:px-8 py-3 sm:py-4 rounded-xl font-semibold text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
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
            className="text-red-600 text-sm mt-3 pl-4"
          >
            {error}
          </motion.p>
        )}
      </form>

      {/* Quick Test Links */}
      <div className="mt-6 sm:mt-10">
        <p className="text-gray-500 text-sm mb-3 sm:mb-4 text-center font-medium">Quick test URLs:</p>
        <div className="flex flex-col gap-2 sm:gap-3">
          {/* Safe Sites Row */}
          <div className="flex flex-col sm:flex-row justify-center items-center gap-2 sm:gap-3">
            <span className="text-green-700 text-xs font-semibold uppercase tracking-wider sm:w-24 sm:text-right">Safe:</span>
            <div className="flex flex-wrap justify-center gap-2">
              <QuickTestButton 
                url="https://google.com" 
                label="google.com" 
                type="safe"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
              <QuickTestButton 
                url="https://github.com" 
                label="github.com" 
                type="safe"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
              <QuickTestButton 
                url="https://microsoft.com" 
                label="microsoft.com" 
                type="safe"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
            </div>
          </div>
          
          {/* Suspicious Sites Row */}
          <div className="flex flex-col sm:flex-row justify-center items-center gap-2 sm:gap-3">
            <span className="text-amber-700 text-xs font-semibold uppercase tracking-wider sm:w-24 sm:text-right">Suspicious:</span>
            <div className="flex flex-wrap justify-center gap-2">
              <QuickTestButton 
                url="https://paypal-secure-login.tk" 
                label="paypal-secure-login.tk" 
                type="warning"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
              <QuickTestButton 
                url="https://appleid-verify.000webhostapp.com" 
                label="appleid-verify..." 
                type="warning"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
            </div>
          </div>
          
          {/* Dangerous Sites Row */}
          <div className="flex flex-col sm:flex-row justify-center items-center gap-2 sm:gap-3">
            <span className="text-red-700 text-xs font-semibold uppercase tracking-wider sm:w-24 sm:text-right">Phishing:</span>
            <div className="flex flex-wrap justify-center gap-2">
              <QuickTestButton 
                url="https://secure-login-facebook.ml/verify" 
                label="secure-login-facebook.ml" 
                type="danger"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
              <QuickTestButton 
                url="https://netflix-billing-update.xyz" 
                label="netflix-billing-update.xyz" 
                type="danger"
                onSetUrl={setUrl}
                onScan={onScan}
                disabled={isScanning}
              />
            </div>
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
  onSetUrl: (url: string) => void;
  onScan: (url: string) => void;
  disabled: boolean;
}

function QuickTestButton({ url, label, type, onSetUrl, onScan, disabled }: QuickTestButtonProps) {
  const typeStyles = {
    safe: "bg-green-50 border-green-200 text-green-700 hover:bg-green-100 hover:border-green-300",
    warning: "bg-amber-50 border-amber-200 text-amber-700 hover:bg-amber-100 hover:border-amber-300",
    danger: "bg-red-50 border-red-200 text-red-700 hover:bg-red-100 hover:border-red-300",
  };
  
  return (
    <button
      type="button"
      onClick={() => {
        onSetUrl(url);
        onScan(url);
      }}
      disabled={disabled}
      className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-200 disabled:opacity-50 ${typeStyles[type]}`}
    >
      {label}
    </button>
  );
}

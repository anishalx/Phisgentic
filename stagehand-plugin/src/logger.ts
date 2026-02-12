// PhishGuard Stagehand Plugin - Structured Logger with Color Coding

import type { PhishGuardResult, SuspiciousLink, LinkScanReport } from "./types.js";

// ANSI color codes for terminal output
const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",

  // Status colors
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",

  // Background colors
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
} as const;

const PREFIX = `${COLORS.bold}${COLORS.magenta}[PhishGuard]${COLORS.reset}`;

export class PhishGuardLogger {
  private verbose: boolean;

  constructor(verbose: boolean = true) {
    this.verbose = verbose;
  }

  /** Log scan start */
  scanStart(url: string): void {
    if (!this.verbose) return;
    console.log(`${PREFIX} ${COLORS.cyan}Scanning:${COLORS.reset} ${url}`);
  }

  /** Log scan result with color-coded risk level */
  scanResult(result: PhishGuardResult): void {
    if (!this.verbose) return;

    const { action, riskScore, url, scanTimeMs, mode, fromCache } = result;
    const cacheTag = fromCache ? ` ${COLORS.dim}(cached)${COLORS.reset}` : "";
    const modeTag = `${COLORS.dim}[${mode}]${COLORS.reset}`;

    let statusLine: string;

    switch (action) {
      case "allow":
        statusLine = `${COLORS.bgGreen}${COLORS.bold} SAFE ${COLORS.reset} ${COLORS.green}Score: ${riskScore}/100${COLORS.reset}`;
        break;
      case "warn":
        statusLine = `${COLORS.bgYellow}${COLORS.bold} WARN ${COLORS.reset} ${COLORS.yellow}Score: ${riskScore}/100${COLORS.reset}`;
        break;
      case "block":
        statusLine = `${COLORS.bgRed}${COLORS.bold} DANGER ${COLORS.reset} ${COLORS.red}Score: ${riskScore}/100${COLORS.reset}`;
        break;
    }

    console.log(`${PREFIX} ${statusLine} ${modeTag}${cacheTag} (${scanTimeMs}ms)`);
    console.log(`${PREFIX}   ${COLORS.dim}URL: ${url}${COLORS.reset}`);
    console.log(`${PREFIX}   ${COLORS.dim}${result.summary}${COLORS.reset}`);

    // Show agent breakdown in full mode
    if (result.agentResults.length > 0 && action !== "allow") {
      console.log(`${PREFIX}   ${COLORS.dim}Agent Breakdown:${COLORS.reset}`);
      for (const agent of result.agentResults) {
        const agentColor = agent.riskScore > 60 ? COLORS.red : agent.riskScore > 30 ? COLORS.yellow : COLORS.green;
        console.log(
          `${PREFIX}     ${agentColor}${agent.agentName}: ${agent.riskScore}/100${COLORS.reset} ${COLORS.dim}(conf: ${agent.confidence.toFixed(2)})${COLORS.reset}`,
        );
      }
    }

    // Show critical signals
    const criticalSignals = result.signals.filter((s) => s.severity === "critical");
    if (criticalSignals.length > 0) {
      console.log(`${PREFIX}   ${COLORS.red}${COLORS.bold}Critical Signals:${COLORS.reset}`);
      for (const signal of criticalSignals) {
        console.log(`${PREFIX}     ${COLORS.red}! ${signal.description}${COLORS.reset}`);
      }
    }
  }

  /** Log phishing detection warning */
  phishingDetected(result: PhishGuardResult): void {
    const border = COLORS.red + "=".repeat(60) + COLORS.reset;
    console.log("");
    console.log(border);
    console.log(
      `${PREFIX} ${COLORS.bgRed}${COLORS.bold} PHISHING DETECTED ${COLORS.reset}`,
    );
    console.log(`${PREFIX} ${COLORS.red}URL: ${result.url}${COLORS.reset}`);
    console.log(`${PREFIX} ${COLORS.red}Risk Score: ${result.riskScore}/100${COLORS.reset}`);
    console.log(`${PREFIX} ${COLORS.red}${result.summary}${COLORS.reset}`);
    console.log(border);
    console.log("");
  }

  /** Log link scan report */
  linkScanReport(report: LinkScanReport): void {
    if (!this.verbose) return;

    const { pageUrl, totalLinks, scannedLinks, suspiciousLinks, scanTimeMs } = report;

    console.log(
      `${PREFIX} ${COLORS.cyan}Link Scan:${COLORS.reset} ${totalLinks} total, ${scannedLinks} scanned, ${suspiciousLinks.length} suspicious (${scanTimeMs}ms)`,
    );

    if (suspiciousLinks.length > 0) {
      console.log(`${PREFIX}   ${COLORS.yellow}Suspicious Links Found:${COLORS.reset}`);
      for (const link of suspiciousLinks) {
        console.log(
          `${PREFIX}     ${COLORS.yellow}[${link.riskScore}/100]${COLORS.reset} ${link.url}`,
        );
        console.log(
          `${PREFIX}       ${COLORS.dim}${link.reason}${COLORS.reset}`,
        );
      }
    }
  }

  /** Log info message */
  info(message: string): void {
    if (!this.verbose) return;
    console.log(`${PREFIX} ${COLORS.blue}${message}${COLORS.reset}`);
  }

  /** Log warning message */
  warn(message: string): void {
    console.log(`${PREFIX} ${COLORS.yellow}${message}${COLORS.reset}`);
  }

  /** Log error message */
  error(message: string, error?: unknown): void {
    console.error(`${PREFIX} ${COLORS.red}ERROR: ${message}${COLORS.reset}`);
    if (error && this.verbose) {
      console.error(`${PREFIX}   ${COLORS.dim}${error}${COLORS.reset}`);
    }
  }

  /** Log debug message (only in verbose mode) */
  debug(message: string): void {
    if (!this.verbose) return;
    console.log(`${PREFIX} ${COLORS.dim}${message}${COLORS.reset}`);
  }
}

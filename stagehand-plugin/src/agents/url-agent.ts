// PhishGuard Plugin - URL Analysis Agent (Self-contained)
// Adapted from server/src/agents/url-agent.ts
// Performs URL structure analysis with local pattern matching.
// In fast mode, skips LLM entirely.

import type { AgentResult, Signal } from "../types.js";
import {
  SAFE_DOMAINS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
  PHISHING_KEYWORDS,
  PROTECTED_BRANDS,
} from "./config.js";

interface ParsedUrl {
  full: string;
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  domain: string;
  subdomain: string;
  tld: string;
  isIP: boolean;
  hasNonStandardPort: boolean;
}

// Two-part TLDs that need special handling (e.g., "co.uk", "com.au")
const TWO_PART_TLDS = new Set([
  "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za", "co.id", "co.il", "co.th",
  "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "com.tw", "com.ar",
  "com.tr", "com.pk", "com.ng", "com.eg", "com.ph", "com.my", "com.vn", "com.co",
  "org.uk", "org.au", "org.in",
  "net.au", "net.br", "net.in",
  "gov.uk", "gov.au", "gov.in",
  "ac.uk", "ac.in", "ac.jp",
  "edu.au", "edu.cn",
]);

function parseUrl(urlString: string): ParsedUrl | null {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const parts = hostname.split(".");
    let domain = hostname;
    let subdomain = "";
    let tld = "";

    if (!isIP && parts.length >= 2) {
      // Check for two-part TLDs (e.g., "co.uk")
      const lastTwo = parts.slice(-2).join(".");
      if (parts.length >= 3 && TWO_PART_TLDS.has(lastTwo)) {
        tld = "." + lastTwo;
        domain = parts.slice(-3).join(".");
        subdomain = parts.slice(0, -3).join(".");
      } else {
        tld = "." + parts[parts.length - 1];
        domain = parts.slice(-2).join(".");
        subdomain = parts.slice(0, -2).join(".");
      }
    }

    const isHttps = url.protocol === "https:";
    const isHttp = url.protocol === "http:";
    const standardPort =
      (isHttps && url.port === "443") ||
      (isHttp && url.port === "80") ||
      url.port === "";

    return {
      full: urlString,
      protocol: url.protocol,
      hostname,
      port: url.port,
      pathname: url.pathname,
      search: url.search,
      domain,
      subdomain,
      tld,
      isIP,
      hasNonStandardPort: !standardPort,
    };
  } catch {
    return null;
  }
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function hasHomoglyphCharacters(text: string): boolean {
  return /[\u0430-\u044f\u0400-\u042f\u0370-\u03ff\u1d00-\u1d7f]/.test(text);
}

function hasEncodedCharacters(url: string): boolean {
  return /%[0-9A-Fa-f]{2}/.test(url);
}

function countSpecialCharacters(url: string): number {
  const matches = url.match(/[-@#$%^&*()+=\[\]{}|\\:;"'<>,?]/g);
  return matches ? matches.length : 0;
}

function countSubdomains(hostname: string): number {
  const parts = hostname.split(".");
  return Math.max(0, parts.length - 2);
}

function createSignal(
  type: string,
  severity: Signal["severity"],
  value: string | number | boolean,
  description: string,
): Signal {
  return { type, severity, value, description };
}

export class PluginUrlAgent {
  async analyze(url: string): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let score = 0;

    const parsed = parseUrl(url);
    if (!parsed) {
      return {
        agentId: "urlAgent",
        agentName: "URL Analysis Agent",
        riskScore: 50,
        confidence: 0.1,
        signals: [createSignal("error", "medium", "Invalid URL", "Analysis failed")],
        explanation: "Invalid URL format",
        executionTimeMs: Date.now() - startTime,
      };
    }

    // IP address check
    // M10 fix: Downgrade severity to "high" (removed from CRITICAL_VETO_SIGNALS in config)
    // and skip private/loopback IPs which are legitimate internal tools
    if (parsed.isIP) {
      const isPrivateIP = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/.test(parsed.hostname);
      if (!isPrivateIP) {
        signals.push(createSignal("ip_address", "high", parsed.hostname, "URL uses IP address instead of domain"));
        score += 30;
      }
    }

    // URL length
    if (parsed.full.length > 100) {
      signals.push(createSignal("url_length", "high", parsed.full.length, "Excessively long URL"));
      score += 15;
    } else if (parsed.full.length > 75) {
      signals.push(createSignal("url_length", "medium", parsed.full.length, "Long URL"));
      score += 8;
    }

    // Subdomain depth
    const subdomainCount = countSubdomains(parsed.hostname);
    if (subdomainCount > 3) {
      signals.push(createSignal("subdomain_depth", "high", subdomainCount, `Excessive subdomain depth: ${subdomainCount}`));
      score += 15;
    } else if (subdomainCount > 2) {
      signals.push(createSignal("subdomain_depth", "medium", subdomainCount, `Multiple subdomains: ${subdomainCount}`));
      score += 8;
    }

    // Suspicious TLD
    if (SUSPICIOUS_TLDS.some((tld: string) => parsed.tld === tld)) {
      signals.push(createSignal("suspicious_tld", "high", parsed.tld, "Suspicious top-level domain"));
      score += 20;
    }

    // URL shortener
    if (URL_SHORTENERS.some((s: string) => parsed.hostname.includes(s))) {
      signals.push(createSignal("url_shortener", "medium", parsed.hostname, "URL shortener detected"));
      score += 15;
    }

    // Encoded characters
    if (hasEncodedCharacters(parsed.full)) {
      signals.push(createSignal("encoded_chars", "medium", true, "URL contains encoded characters"));
      score += 10;
    }

    // Special characters
    const specialCount = countSpecialCharacters(parsed.pathname);
    if (specialCount > 10) {
      signals.push(createSignal("special_chars", "medium", specialCount, "High number of special characters"));
      score += 10;
    }

    // Homograph attack
    if (hasHomoglyphCharacters(parsed.hostname)) {
      signals.push(createSignal("homograph", "critical", true, "Potential homograph attack detected"));
      score += 35;
    }

    // Phishing keywords
    const foundKeywords = PHISHING_KEYWORDS.filter(
      (kw: string) => parsed.pathname.toLowerCase().includes(kw) || parsed.hostname.toLowerCase().includes(kw),
    );
    if (foundKeywords.length > 2) {
      signals.push(createSignal("phishing_keywords", "high", foundKeywords.join(", "), "Multiple phishing keywords detected"));
      score += 15;
    } else if (foundKeywords.length > 0) {
      signals.push(createSignal("phishing_keywords", "low", foundKeywords.join(", "), "Phishing keywords found"));
      score += 5;
    }

    // Typosquatting
    // H2 fix: Use domain name without TLD, only strip hyphens (not all non-alpha)
    // to avoid false positives like "applet.com" -> "applet" matching "apple"
    const brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix", "instagram"];
    const domainWithoutTld = parsed.domain.split(".")[0].toLowerCase();
    const cleanDomain = domainWithoutTld.replace(/-/g, "");
    for (const brand of brands) {
      const distance = levenshteinDistance(cleanDomain, brand);
      if (distance > 0 && distance <= 2 && cleanDomain !== brand) {
        signals.push(createSignal("typosquatting", "critical", brand, `Possible typosquatting of ${brand}`));
        score += 35;
        break;
      }
    }

    // No HTTPS
    if (parsed.protocol !== "https:") {
      signals.push(createSignal("no_https", "medium", parsed.protocol, "Connection is not secure (no HTTPS)"));
      score += 10;
    }

    // Non-standard port
    if (parsed.hasNonStandardPort) {
      signals.push(createSignal("non_standard_port", "high", parsed.port, "Non-standard port detected"));
      score += 15;
    }

    score = Math.min(100, score);

    return {
      agentId: "urlAgent",
      agentName: "URL Analysis Agent",
      riskScore: score,
      confidence: 0.7,
      signals,
      explanation: this.generateExplanation(signals, score),
      executionTimeMs: Date.now() - startTime,
    };
  }

  private generateExplanation(signals: Signal[], score: number): string {
    const critical = signals.filter((s) => s.severity === "critical");
    const high = signals.filter((s) => s.severity === "high");
    if (critical.length > 0) return `CRITICAL: ${critical.map((s) => s.description).join("; ")}`;
    if (high.length > 0) return `High-risk: ${high.map((s) => s.description).join("; ")}`;
    if (score < 20) return "URL structure appears normal.";
    return `URL analysis: ${signals.slice(0, 2).map((s) => s.description).join("; ")}`;
  }
}

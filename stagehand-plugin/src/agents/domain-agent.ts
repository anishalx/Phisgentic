// PhishGuard Plugin - Domain Intelligence Agent (Self-contained)
// Adapted from server/src/agents/domain-agent.ts
// Performs domain reputation checks with local pattern matching.

import type { AgentResult, Signal } from "../types.js";
import {
  SAFE_DOMAINS,
  BLOCKLIST_DOMAINS,
  SUSPICIOUS_TLDS,
  SUSPICIOUS_HOSTING_PATTERNS,
  PROTECTED_BRANDS,
} from "./config.js";

function createSignal(
  type: string,
  severity: Signal["severity"],
  value: string | number | boolean,
  description: string,
): Signal {
  return { type, severity, value, description };
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

function parseUrl(urlString: string): { domain: string; hostname: string; tld: string; isIP: boolean } | null {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const parts = hostname.split(".");
    let domain = hostname;
    let tld = "";

    if (!isIP && parts.length >= 2) {
      // Check for two-part TLDs (e.g., "co.uk")
      const lastTwo = parts.slice(-2).join(".");
      if (parts.length >= 3 && TWO_PART_TLDS.has(lastTwo)) {
        tld = "." + lastTwo;
        domain = parts.slice(-3).join(".");
      } else {
        tld = "." + parts[parts.length - 1];
        domain = parts.slice(-2).join(".");
      }
    }

    return { domain, hostname, tld, isIP };
  } catch {
    return null;
  }
}

export class PluginDomainAgent {
  async analyze(url: string): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let score = 0;

    const parsed = parseUrl(url);
    if (!parsed) {
      return {
        agentId: "domainAgent",
        agentName: "Domain Intelligence Agent",
        riskScore: 50,
        confidence: 0.1,
        signals: [createSignal("error", "medium", "Invalid URL", "Analysis failed")],
        explanation: "Invalid URL format",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const { domain, hostname, tld } = parsed;

    // Safe domain whitelist
    if (SAFE_DOMAINS.some((safe: string) => hostname === safe || hostname.endsWith(`.${safe}`))) {
      return {
        agentId: "domainAgent",
        agentName: "Domain Intelligence Agent",
        riskScore: 0,
        confidence: 0.99,
        signals: [createSignal("known_safe", "low", domain, "Verified safe domain")],
        explanation: "Domain is on the verified safe list.",
        executionTimeMs: Date.now() - startTime,
      };
    }

    // Blocklist match
    if (BLOCKLIST_DOMAINS.some((blocked: string) => hostname === blocked || hostname.endsWith(`.${blocked}`))) {
      return {
        agentId: "domainAgent",
        agentName: "Domain Intelligence Agent",
        riskScore: 95,
        confidence: 0.95,
        signals: [createSignal("blocklist_match", "critical", hostname, "Domain matches known phishing/abuse blocklist")],
        explanation: `CRITICAL: ${hostname} is on the phishing blocklist.`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    // Suspicious free hosting
    // Fix: Use domain matching instead of includes() to avoid false positives
    // (e.g., "notvercel.app" should not match "vercel.app")
    for (const pattern of SUSPICIOUS_HOSTING_PATTERNS) {
      if (hostname === pattern || hostname.endsWith(`.${pattern}`)) {
        signals.push(createSignal("suspicious_hosting", "critical", pattern, `Uses free hosting: ${pattern}`));
        score += 50;
        break;
      }
    }

    // Brand impersonation in domain
    // Fix: Use word-boundary matching for short brand names (<=3 chars) to avoid
    // false positives like "setup.com" matching "ups" or "metadata.com" matching "meta"
    let brandImpersonationMatched = false;
    for (const brand of PROTECTED_BRANDS) {
      // Skip if this is the brand's official domain
      if (hostname.endsWith(brand.domain) || domain === brand.domain) continue;

      let matchesInDomain = false;
      if (brand.name.length <= (brand.minLength ?? 4) - 1) {
        // Short brand names: require word-boundary match (separated by dots or hyphens)
        const parts = hostname.split(/[.\-]/);
        matchesInDomain = parts.some(part => part === brand.name);
      } else {
        // Longer brand names: includes() is safe enough
        matchesInDomain = domain.includes(brand.name) || hostname.includes(brand.name);
      }

      if (matchesInDomain) {
        signals.push(createSignal("brand_impersonation", "critical", brand.name,
          `Impersonating ${brand.name} - not official ${brand.domain}`));
        score += 45;
        brandImpersonationMatched = true;
        break;
      }
    }

    // Brand in subdomain
    // Fix: Properly extract subdomain by removing the domain suffix, and use
    // word-boundary matching for short brand names
    if (!brandImpersonationMatched) {
      // Extract subdomain: remove trailing dot + domain from hostname
      const subdomainPart = hostname.endsWith(`.${domain}`)
        ? hostname.slice(0, -(domain.length + 1))
        : (hostname === domain ? "" : hostname.replace(`.${domain}`, ""));

      if (subdomainPart) {
        for (const brand of PROTECTED_BRANDS) {
          if (hostname.endsWith(brand.domain) || domain === brand.domain) continue;

          let matchesInSubdomain = false;
          if (brand.name.length <= (brand.minLength ?? 4) - 1) {
            const parts = subdomainPart.split(/[.\-]/);
            matchesInSubdomain = parts.some(part => part === brand.name);
          } else {
            matchesInSubdomain = subdomainPart.includes(brand.name);
          }

          if (matchesInSubdomain) {
            signals.push(createSignal("brand_in_subdomain", "critical", brand.name,
              `Brand "${brand.name}" in subdomain but not official domain`));
            score += 40;
            break;
          }
        }
      }
    }

    // Suspicious TLD
    const fullTld = tld.startsWith(".") ? tld : `.${tld}`;
    if (SUSPICIOUS_TLDS.includes(fullTld)) {
      signals.push(createSignal("suspicious_tld", "high", tld, `High-risk TLD: ${tld}`));
      score += 25;
    }

    // Suspicious domain patterns
    const suspiciousPatterns = [
      { pattern: /-login/i, name: "login keyword", score: 15 },
      { pattern: /-secure/i, name: "secure keyword", score: 15 },
      { pattern: /-verify/i, name: "verify keyword", score: 15 },
      { pattern: /-account/i, name: "account keyword", score: 15 },
      { pattern: /\d{5,}/, name: "many digits", score: 12 },
      { pattern: /-{2,}/, name: "multiple dashes", score: 8 },
    ];

    for (const { pattern, name, score: patternScore } of suspiciousPatterns) {
      if (pattern.test(hostname)) {
        signals.push(createSignal("suspicious_domain_pattern", "medium", name, `Suspicious pattern: ${name}`));
        score += patternScore;
      }
    }

    // DGA detection
    const domainName = domain.split(".")[0];
    if (domainName.length >= 8) {
      const consonants = domainName.toLowerCase().replace(/[^bcdfghjklmnpqrstvwxyz]/g, "").length;
      const letters = domainName.toLowerCase().replace(/[^a-z]/g, "").length;
      if (letters >= 5) {
        const consonantRatio = consonants / letters;
        if (consonantRatio > 0.8 || /[bcdfghjklmnpqrstvwxyz]{7,}/i.test(domainName)) {
          signals.push(createSignal("dga_pattern", "high", domain, "Domain appears randomly generated"));
          score += 30;
        }
      }
    }

    // Excessive length
    if (hostname.length > 50) {
      signals.push(createSignal("long_domain", "high", hostname.length, "Unusually long domain name"));
      score += 15;
    }

    // Multiple hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      signals.push(createSignal("excessive_hyphens", "high", hyphenCount, "Excessive hyphens"));
      score += 20;
    } else if (hyphenCount > 1) {
      signals.push(createSignal("multiple_hyphens", "medium", hyphenCount, "Multiple hyphens"));
      score += 8;
    }

    score = Math.min(100, score);

    return {
      agentId: "domainAgent",
      agentName: "Domain Intelligence Agent",
      riskScore: score,
      confidence: 0.75,
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
    if (score < 20) return "Domain appears legitimate.";
    return `Domain analysis: ${signals.slice(0, 2).map((s) => s.description).join("; ")}`;
  }
}

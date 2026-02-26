// Domain Analysis Agent - Aggressive domain reputation and blocklist checking

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal } from "../types/index.js";
import { CONFIG } from "../config/index.js";
import { parseUrl } from "../utils/url-parser.js";

const SYSTEM_PROMPT = `You are a cybersecurity analyst specializing in domain threat intelligence.
Analyze the provided domain carefully and accurately for phishing indicators.

IMPORTANT: Many legitimate websites exist on various hosting platforms and TLDs. Do NOT flag a domain as phishing simply because it uses a free hosting service or has an uncommon TLD. Look for COMBINATIONS of suspicious indicators.

CRITICAL RED FLAGS (score 70-100) — require STRONG evidence:
- Domain clearly mimicking a major brand with typos or extra characters (e.g., paypa1.com, amaz0n-login.com)
- Known malicious dynamic DNS services (duckdns.org, etc.)
- IP addresses used as hostnames with credential-harvesting pages
- Domains with brand names in subdomains pointing to unrelated hosts

MODERATE FLAGS (score 30-60):
- Suspicious TLDs (.tk, .ml, .ga) combined with brand-related keywords
- Recently registered domains with login/payment pages
- Random character patterns suggesting automated domain generation

LOW RISK (score 0-30):
- Established domains even if they use hosting platforms like Vercel, Netlify, or GitHub Pages
- Domains with common words like "login" or "account" that are part of legitimate services
- Uncommon TLDs without other suspicious indicators

Be ACCURATE. Only score high when there are multiple strong indicators of phishing. A single suspicious characteristic is not enough.

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

export class DomainAgent extends BaseAgent {
  constructor() {
    super("domainAgent", "Domain Intelligence Agent", SYSTEM_PROMPT);
  }

  async analyze(url: string): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;

    const parsed = parseUrl(url);
    if (!parsed) {
      return this.createErrorResult(
        "Invalid URL format",
        Date.now() - startTime,
      );
    }

    // Perform aggressive local domain checks
    const localAnalysis = this.performAggressiveAnalysis(
      parsed.domain,
      parsed.hostname,
      parsed.tld,
      signals,
    );
    localRiskScore = localAnalysis.score;

    // FAST-PATH: If local heuristics found nothing suspicious (score < 10),
    // skip the expensive LLM call entirely — saves 2-4 seconds per scan
    if (localRiskScore < 10) {
      return this.createResult(
        localRiskScore,
        0.8,
        signals,
        "Domain appears legitimate — no suspicious indicators found.",
        Date.now() - startTime,
      );
    }

    // If already flagged as critical, skip LLM
    if (localRiskScore >= 80) {
      return this.createResult(
        localRiskScore,
        0.95,
        signals,
        this.generateLocalExplanation(signals),
        Date.now() - startTime,
      );
    }

    // Use LLM for deeper analysis (dual-model)
    try {
      const { result: llmResult } = await this.dualModelAnalyze({
        domain: parsed.domain,
        hostname: parsed.hostname,
        subdomain: parsed.subdomain,
        tld: parsed.tld,
        isIP: parsed.isIP,
        localSignals: signals.map((s) => ({
          type: s.type,
          severity: s.severity,
          description: s.description,
        })),
        localRiskScore,
        instruction: "Be accurate. Score 70+ only with strong evidence of phishing. Legitimate hosting platforms and uncommon TLDs alone are not phishing.",
      });

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        const allSignals = [...signals, ...llmSignals];

        // Weighted average of local and LLM scores (not MAX — MAX causes over-scoring on legit sites)
        const combinedScore = Math.round(localRiskScore * 0.4 + llmResult.riskScore * 0.6);

        return this.createResult(
          combinedScore,
          Math.max(0.7, llmResult.confidence),
          allSignals,
          llmResult.explanation,
          Date.now() - startTime,
        );
      }
    } catch (error) {
      console.error("Domain Agent LLM analysis failed:", error);
    }

    return this.createResult(
      localRiskScore,
      0.7,
      signals,
      this.generateLocalExplanation(signals),
      Date.now() - startTime,
    );
  }

  private performAggressiveAnalysis(
    domain: string,
    hostname: string,
    tld: string,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // CHECK 1: Safe domain whitelist (instant clear)
    if (this.isSafeDomain(hostname)) {
      signals.push(
        this.createSignal(
          "known_safe",
          "low",
          domain,
          "Verified safe domain",
        ),
      );
      return { score: 0 };
    }

    // CHECK 2: Blocklist match (instant critical)
    if (this.isBlocklisted(hostname)) {
      signals.push(
        this.createSignal(
          "blocklist_match",
          "critical",
          hostname,
          "Domain matches known phishing/abuse blocklist",
        ),
      );
      return { score: 95 };
    }

    // CHECK 3: Suspicious free hosting (medium risk)
    // Many legitimate projects use Vercel, Netlify, GitHub Pages, etc.
    // Only treat as a moderate signal, not critical — real phishing on these
    // platforms will still be caught by content/heuristic agents.
    const hostingMatch = this.matchesSuspiciousHosting(hostname);
    if (hostingMatch) {
      signals.push(
        this.createSignal(
          "suspicious_hosting",
          "medium",
          hostingMatch,
          `Uses free hosting service sometimes abused for phishing: ${hostingMatch}`,
        ),
      );
      score += 20;
    }

    // CHECK 4: Brand impersonation in domain
    const brandCheck = this.checkBrandImpersonation(domain, hostname);
    if (brandCheck.isImpersonation) {
      signals.push(
        this.createSignal(
          "brand_impersonation",
          "critical",
          brandCheck.brand || "",
          `Impersonating ${brandCheck.brand} - domain is not the official ${brandCheck.officialDomain}`,
        ),
      );
      score += 45;
    }

    // CHECK 5: Brand name in subdomain (classic phishing)
    const subdomainBrand = this.checkBrandInSubdomain(domain, hostname);
    if (subdomainBrand) {
      signals.push(
        this.createSignal(
          "brand_in_subdomain",
          "critical",
          subdomainBrand,
          `Brand "${subdomainBrand}" in subdomain but not the official domain`,
        ),
      );
      score += 40;
    }

    // CHECK 6: Suspicious TLD
    const suspiciousTlds = CONFIG.SUSPICIOUS_TLDS as readonly string[];
    const fullTld = tld.startsWith(".") ? tld : `.${tld}`;
    if (suspiciousTlds.includes(fullTld)) {
      signals.push(
        this.createSignal(
          "suspicious_tld",
          "high",
          tld,
          `High-risk TLD commonly used for phishing: ${tld}`,
        ),
      );
      score += 25;
    }

    // CHECK 7: Suspicious patterns in domain name
    const patternScore = this.checkSuspiciousPatterns(hostname, signals);
    score += patternScore;

    // CHECK 8: Domain looks randomly generated (DGA)
    if (this.looksRandomlyGenerated(domain.split(".")[0])) {
      signals.push(
        this.createSignal(
          "dga_pattern",
          "high",
          domain,
          "Domain appears randomly generated (possible DGA)",
        ),
      );
      score += 30;
    }

    // CHECK 9: Excessive length
    if (hostname.length > 50) {
      signals.push(
        this.createSignal(
          "long_domain",
          "high",
          hostname.length,
          "Unusually long domain name",
        ),
      );
      score += 15;
    } else if (hostname.length > 35) {
      signals.push(
        this.createSignal(
          "long_domain",
          "medium",
          hostname.length,
          "Long domain name",
        ),
      );
      score += 8;
    }

    // CHECK 10: Multiple hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      signals.push(
        this.createSignal(
          "excessive_hyphens",
          "high",
          hyphenCount,
          "Excessive hyphens often indicate phishing",
        ),
      );
      score += 20;
    } else if (hyphenCount > 1) {
      signals.push(
        this.createSignal(
          "multiple_hyphens",
          "medium",
          hyphenCount,
          "Multiple hyphens in domain",
        ),
      );
      score += 8;
    }

    return { score: Math.min(100, score) };
  }

  private isSafeDomain(hostname: string): boolean {
    return CONFIG.SAFE_DOMAINS.some(
      (safe) => hostname === safe || hostname.endsWith(`.${safe}`),
    );
  }

  private isBlocklisted(hostname: string): boolean {
    return CONFIG.BLOCKLIST_DOMAINS.some(
      (blocked) => hostname === blocked || hostname.endsWith(`.${blocked}`),
    );
  }

  private matchesSuspiciousHosting(hostname: string): string | null {
    const hostingPatterns = CONFIG.SUSPICIOUS_HOSTING_PATTERNS as readonly string[];
    for (const pattern of hostingPatterns) {
      // Use proper domain matching: exact match or subdomain of the pattern
      if (hostname === pattern || hostname.endsWith(`.${pattern}`)) {
        return pattern;
      }
    }
    return null;
  }

  private checkBrandImpersonation(domain: string, hostname: string): { 
    isImpersonation: boolean; 
    brand?: string;
    officialDomain?: string;
  } {
    const brands = CONFIG.PROTECTED_BRANDS;
    const domainLower = domain.toLowerCase();
    const hostnameLower = hostname.toLowerCase();

    for (const brand of brands) {
      const brandName = brand.name;
      
      // For short brand names (<=3 chars like "ups", "dhl", "meta"),
      // require word-boundary matching to avoid false positives
      // e.g., "setup.com" should NOT match "ups", "metadata.io" should NOT match "meta"
      let matches = false;
      
      if (brandName.length <= 3) {
        // Short brand: require it appears as a distinct segment
        // Split on dots and hyphens, check if any segment exactly equals the brand
        const segments = hostnameLower.split(/[.\-]/);
        matches = segments.some(seg => seg === brandName);
      } else {
        // Longer brand: require segment-based matching to avoid false positives
        // e.g., "apple-login.evil.com" = match, but "appleseed.com" = no match
        const segments = hostnameLower.split(/[.\-]/);
        matches = segments.some(seg => seg === brandName);
      }

      if (
        matches &&
        !hostnameLower.endsWith(brand.domain) &&
        domainLower !== brand.domain
      ) {
        return {
          isImpersonation: true,
          brand: brandName,
          officialDomain: brand.domain,
        };
      }
    }
    return { isImpersonation: false };
  }

  private checkBrandInSubdomain(domain: string, hostname: string): string | null {
    const brands = CONFIG.PROTECTED_BRANDS;
    // Extract just the subdomain portion (everything before the registered domain)
    // e.g., "paypal.login.evil.com" -> "paypal.login"
    const subdomainPart = hostname.endsWith(domain) 
      ? hostname.slice(0, -(domain.length + 1)).toLowerCase()  // +1 for the dot
      : "";

    if (!subdomainPart) return null;

    const subdomainSegments = subdomainPart.split(".");

    for (const brand of brands) {
      // For ALL brands, require exact segment match in subdomain
      // e.g., "paypal.login.evil.com" = match, but "paypalresearch.evil.com" = no match
      if (subdomainSegments.some(seg => seg === brand.name) && !hostname.endsWith(brand.domain)) {
        return brand.name;
      }
    }
    return null;
  }

  private checkSuspiciousPatterns(hostname: string, signals: Signal[]): number {
    let score = 0;
    const hostnameLower = hostname.toLowerCase();

    const suspiciousPatterns = [
      { pattern: /-login/i, name: "login keyword", score: 8 },
      { pattern: /-secure/i, name: "secure keyword", score: 8 },
      { pattern: /-verify/i, name: "verify keyword", score: 8 },
      { pattern: /-account/i, name: "account keyword", score: 8 },
      { pattern: /-update/i, name: "update keyword", score: 6 },
      { pattern: /-confirm/i, name: "confirm keyword", score: 6 },
      { pattern: /-signin/i, name: "signin keyword", score: 8 },
      { pattern: /-support/i, name: "support keyword", score: 5 },
      { pattern: /\d{5,}/, name: "many digits", score: 12 },
      { pattern: /-{2,}/, name: "multiple dashes", score: 8 },
      { pattern: /[0-9]{2,}-[a-z]+|[a-z]+-[0-9]{2,}/, name: "number-word mix", score: 10 },
    ];

    for (const { pattern, name, score: patternScore } of suspiciousPatterns) {
      if (pattern.test(hostnameLower)) {
        signals.push(
          this.createSignal(
            "suspicious_domain_pattern",
            "medium",
            name,
            `Suspicious pattern: ${name}`,
          ),
        );
        score += patternScore;
      }
    }

    return score;
  }

  private looksRandomlyGenerated(domainName: string): boolean {
    if (domainName.length < 10) return false;

    // Check consonant ratio
    const consonants = domainName.toLowerCase().replace(/[^bcdfghjklmnpqrstvwxyz]/g, "").length;
    const vowels = domainName.toLowerCase().replace(/[^aeiou]/g, "").length;
    const letters = domainName.toLowerCase().replace(/[^a-z]/g, "").length;

    if (letters < 5) return false;

    const consonantRatio = consonants / letters;
    const vowelRatio = vowels / letters;

    // Too many consonants or too few vowels suggests random generation
    // Tightened thresholds to reduce false positives on legitimate domains
    if (consonantRatio > 0.85 || vowelRatio < 0.12) {
      return true;
    }

    // Check for unusual character patterns (like "qxzpkv")
    const unusualPattern = /[qxz]{2,}|[bcdfghjklmnpqrstvwxyz]{5,}/i;
    if (unusualPattern.test(domainName)) {
      return true;
    }

    return false;
  }

  private generateLocalExplanation(signals: Signal[]): string {
    const critical = signals.filter(s => s.severity === "critical");
    const high = signals.filter(s => s.severity === "high");

    if (critical.length > 0) {
      return `CRITICAL: ${critical.map(s => s.description).join("; ")}`;
    }
    if (high.length > 0) {
      return `High-risk indicators: ${high.map(s => s.description).join("; ")}`;
    }
    if (signals.length > 0) {
      return `Domain analysis: ${signals.slice(0, 2).map(s => s.description).join("; ")}`;
    }
    return "Domain analysis complete - no major concerns.";
  }
}

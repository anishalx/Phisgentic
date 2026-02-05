// Domain Analysis Agent - Aggressive domain reputation and blocklist checking

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal } from "../types/index.js";
import { CONFIG } from "../config/index.js";
import { parseUrl } from "../utils/url-parser.js";

const SYSTEM_PROMPT = `You are an elite cybersecurity analyst specializing in domain threat intelligence.
Analyze the provided domain with EXTREME scrutiny for phishing indicators.

CRITICAL RED FLAGS (should result in high scores 70-100):
- Any domain mimicking a major brand (PayPal, Amazon, Microsoft, etc.)
- Free hosting services (weebly, wix, 000webhost, netlify, vercel)
- Recently registered domains or privacy-protected WHOIS
- Suspicious TLDs (.xyz, .tk, .ml, .top, .click, etc.)
- Random character patterns suggesting DGA (domain generation algorithm)
- Subdomains containing brand names when main domain is different
- IP addresses used as domains
- URL shorteners

MODERATE FLAGS (scores 40-70):
- Domains with many hyphens or numbers
- Non-standard registrars
- Missing SSL or self-signed certificates

Be AGGRESSIVE in scoring. When in doubt, score HIGHER. False positives are preferable to missing phishing.

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

    // Use LLM for deeper analysis
    try {
      const llmResult = await this.groqClient.analyzeForAgent(
        this.agentName,
        this.systemPrompt,
        {
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
          instruction: "Score aggressively. If suspicious, give 70+. If clearly phishing, give 90+.",
        },
      );

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        const allSignals = [...signals, ...llmSignals];

        // Take the MAXIMUM of local and LLM scores (not average)
        const combinedScore = Math.max(localRiskScore, llmResult.riskScore);

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

    // CHECK 3: Suspicious free hosting (high risk)
    const hostingMatch = this.matchesSuspiciousHosting(hostname);
    if (hostingMatch) {
      signals.push(
        this.createSignal(
          "suspicious_hosting",
          "critical",
          hostingMatch,
          `Uses free hosting service commonly abused for phishing: ${hostingMatch}`,
        ),
      );
      score += 50;
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
      if (hostname.includes(pattern)) {
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
      // Check if brand name appears in domain but this is NOT the official domain
      if (
        (domainLower.includes(brand.name) || hostnameLower.includes(brand.name)) &&
        !hostnameLower.endsWith(brand.domain) &&
        domainLower !== brand.domain
      ) {
        return {
          isImpersonation: true,
          brand: brand.name,
          officialDomain: brand.domain,
        };
      }
    }
    return { isImpersonation: false };
  }

  private checkBrandInSubdomain(domain: string, hostname: string): string | null {
    const brands = CONFIG.PROTECTED_BRANDS;
    const subdomainPart = hostname.replace(domain, "").toLowerCase();

    for (const brand of brands) {
      if (subdomainPart.includes(brand.name) && !hostname.endsWith(brand.domain)) {
        return brand.name;
      }
    }
    return null;
  }

  private checkSuspiciousPatterns(hostname: string, signals: Signal[]): number {
    let score = 0;
    const hostnameLower = hostname.toLowerCase();

    const suspiciousPatterns = [
      { pattern: /-login/i, name: "login keyword", score: 15 },
      { pattern: /-secure/i, name: "secure keyword", score: 15 },
      { pattern: /-verify/i, name: "verify keyword", score: 15 },
      { pattern: /-account/i, name: "account keyword", score: 15 },
      { pattern: /-update/i, name: "update keyword", score: 12 },
      { pattern: /-confirm/i, name: "confirm keyword", score: 12 },
      { pattern: /-signin/i, name: "signin keyword", score: 15 },
      { pattern: /-support/i, name: "support keyword", score: 10 },
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
    if (domainName.length < 8) return false;

    // Check consonant ratio
    const consonants = domainName.toLowerCase().replace(/[^bcdfghjklmnpqrstvwxyz]/g, "").length;
    const vowels = domainName.toLowerCase().replace(/[^aeiou]/g, "").length;
    const letters = domainName.toLowerCase().replace(/[^a-z]/g, "").length;

    if (letters < 5) return false;

    const consonantRatio = consonants / letters;
    const vowelRatio = vowels / letters;

    // Too many consonants or too few vowels suggests random generation
    if (consonantRatio > 0.8 || vowelRatio < 0.15) {
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

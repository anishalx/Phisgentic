// Domain Analysis Agent - Analyzes domain reputation and characteristics

import { BaseAgent } from "./base-agent";
import type { AgentResult, Signal } from "../types";
import { CONFIG } from "../config";
import { parseUrl } from "../utils/url-parser";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in domain reputation analysis for phishing detection.
Analyze the provided domain information and identify phishing indicators.

Consider these risk factors:
- Newly registered domains (common for phishing)
- Domains with privacy-protected WHOIS data
- Self-signed or expired SSL certificates
- Domains mimicking well-known brands
- Suspicious registrar patterns
- Missing or unusual DNS records
- Domains on known blacklists
- Low Alexa/Tranco ranking (unknown domains)
- Domain age and history

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

export class DomainAgent extends BaseAgent {
  constructor() {
    super("domainAgent", "Domain Reputation Agent", SYSTEM_PROMPT);
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

    // Perform local domain checks
    const localAnalysis = this.performLocalAnalysis(
      parsed.domain,
      parsed.hostname,
      signals,
    );
    localRiskScore = localAnalysis.score;

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
          })),
          // Note: In production, you would fetch real WHOIS/DNS data here
          analysisNote:
            "Analyze based on domain name patterns and known phishing indicators",
        },
      );

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        const allSignals = [...signals, ...llmSignals];

        const combinedScore = Math.round(
          localRiskScore * 0.3 + llmResult.riskScore * 0.7,
        );

        return this.createResult(
          combinedScore,
          llmResult.confidence,
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
      0.5,
      signals,
      "Analysis based on domain pattern matching",
      Date.now() - startTime,
    );
  }

  private performLocalAnalysis(
    domain: string,
    hostname: string,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // Check if domain is in safe list
    if (
      CONFIG.SAFE_DOMAINS.some(
        (safe) => domain === safe || hostname.endsWith(`.${safe}`),
      )
    ) {
      signals.push(
        this.createSignal(
          "known_safe",
          "low",
          domain,
          "Domain is in the safe list",
        ),
      );
      return { score: 0 };
    }

    // Check for suspicious patterns in domain name
    const suspiciousPatterns = [
      { pattern: /-login/i, name: "login in domain" },
      { pattern: /-secure/i, name: "secure in domain" },
      { pattern: /-verify/i, name: "verify in domain" },
      { pattern: /-account/i, name: "account in domain" },
      { pattern: /-update/i, name: "update in domain" },
      { pattern: /\d{4,}/, name: "many digits in domain" },
      { pattern: /-{2,}/, name: "multiple dashes in domain" },
    ];

    for (const { pattern, name } of suspiciousPatterns) {
      if (pattern.test(hostname)) {
        signals.push(
          this.createSignal(
            "suspicious_domain_pattern",
            "medium",
            name,
            `Suspicious pattern: ${name}`,
          ),
        );
        score += 12;
      }
    }

    // Check domain length (very long domains are suspicious)
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
    } else if (hostname.length > 30) {
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

    // Check for brand names in subdomain (phishing indicator)
    const brands = [
      "paypal",
      "amazon",
      "apple",
      "microsoft",
      "google",
      "facebook",
      "netflix",
      "bank",
    ];
    for (const brand of brands) {
      // If brand is in hostname but NOT the actual domain
      if (hostname.includes(brand) && !domain.startsWith(brand)) {
        signals.push(
          this.createSignal(
            "brand_in_subdomain",
            "critical",
            brand,
            `Brand "${brand}" appears in subdomain but not main domain`,
          ),
        );
        score += 30;
        break;
      }
    }

    // Check for random-looking domain names
    const consonantRatio = this.getConsonantRatio(domain.split(".")[0]);
    if (consonantRatio > 0.75) {
      signals.push(
        this.createSignal(
          "random_domain",
          "medium",
          consonantRatio,
          "Domain appears randomly generated",
        ),
      );
      score += 15;
    }

    // Check for excessive hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      signals.push(
        this.createSignal(
          "excessive_hyphens",
          "high",
          hyphenCount,
          "Too many hyphens in domain",
        ),
      );
      score += 15;
    } else if (hyphenCount > 1) {
      signals.push(
        this.createSignal(
          "multiple_hyphens",
          "low",
          hyphenCount,
          "Multiple hyphens in domain",
        ),
      );
      score += 5;
    }

    // Check TLD
    const tld = "." + domain.split(".").pop();
    if ((CONFIG.SUSPICIOUS_TLDS as readonly string[]).includes(tld)) {
      signals.push(
        this.createSignal(
          "suspicious_tld",
          "high",
          tld,
          `Suspicious TLD: ${tld}`,
        ),
      );
      score += 20;
    }

    return { score: Math.min(100, score) };
  }

  private getConsonantRatio(text: string): number {
    const consonants = text
      .toLowerCase()
      .replace(/[^bcdfghjklmnpqrstvwxyz]/g, "").length;
    const letters = text.toLowerCase().replace(/[^a-z]/g, "").length;
    return letters > 0 ? consonants / letters : 0;
  }
}

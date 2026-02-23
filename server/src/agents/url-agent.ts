// URL Analysis Agent - Analyzes URL structure for phishing indicators

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal } from "../types/index.js";
import { CONFIG } from "../config/index.js";
import {
  parseUrl,
  countSubdomains,
  hasEncodedCharacters,
  countSpecialCharacters,
  hasHomoglyphCharacters,
  isSimilarToBrand,
  type ParsedUrl,
} from "../utils/url-parser.js";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in URL analysis for phishing detection.
Analyze the provided URL structure and identify phishing indicators.

Consider these risk factors:
- Suspicious URL length (>75 chars often indicates phishing)
- Excessive special characters or encoding
- IP addresses instead of domain names
- Multiple subdomains (domain depth >3)
- Typosquatting patterns (misspelled brand names)
- Homograph attacks (Unicode lookalikes)
- URL shorteners hiding destination
- Suspicious keywords in path (login, verify, secure, account)
- Missing HTTPS on sensitive pages
- Non-standard port numbers

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

export class UrlAgent extends BaseAgent {
  constructor() {
    super("urlAgent", "URL Analysis Agent", SYSTEM_PROMPT);
  }

  async analyze(url: string): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;

    // Parse the URL
    const parsed = parseUrl(url);
    if (!parsed) {
      return this.createErrorResult(
        "Invalid URL format",
        Date.now() - startTime,
      );
    }

    // Perform local analysis first (fast checks)
    const localAnalysis = this.performLocalAnalysis(parsed, signals);
    localRiskScore = localAnalysis.score;

    // Use LLM for deeper analysis (dual-model)
    try {
      const { result: llmResult } = await this.dualModelAnalyze({
        url,
        parsed: {
          hostname: parsed.hostname,
          domain: parsed.domain,
          subdomain: parsed.subdomain,
          tld: parsed.tld,
          pathname: parsed.pathname,
          isIP: parsed.isIP,
          protocol: parsed.protocol,
        },
        localSignals: signals.map((s) => ({
          type: s.type,
          severity: s.severity,
        })),
      });

      if (llmResult) {
        // Merge LLM signals with local signals (signals are already properly typed from LLMAnalysisResult)
        const allSignals = [...signals, ...llmResult.signals];

        // Combine scores (weighted average: 40% local, 60% LLM)
        const combinedScore = Math.round(
          localRiskScore * 0.4 + llmResult.riskScore * 0.6,
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
      console.error("URL Agent LLM analysis failed:", error);
    }

    // Fallback to local analysis only
    return this.createResult(
      localRiskScore,
      0.6, // Medium confidence for local-only analysis
      signals,
      "Analysis based on URL pattern matching",
      Date.now() - startTime,
    );
  }

  private performLocalAnalysis(
    parsed: ParsedUrl,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // Check URL length
    if (parsed.full.length > 100) {
      signals.push(
        this.createSignal(
          "url_length",
          "high",
          parsed.full.length,
          "Excessively long URL",
        ),
      );
      score += 15;
    } else if (parsed.full.length > 75) {
      signals.push(
        this.createSignal(
          "url_length",
          "medium",
          parsed.full.length,
          "Long URL",
        ),
      );
      score += 8;
    }

    // Check for IP address
    if (parsed.isIP) {
      signals.push(
        this.createSignal(
          "ip_address",
          "critical",
          parsed.hostname,
          "URL uses IP address instead of domain",
        ),
      );
      score += 30;
    }

    // Check subdomain depth
    const subdomainCount = countSubdomains(parsed.full);
    if (subdomainCount > 3) {
      signals.push(
        this.createSignal(
          "subdomain_depth",
          "high",
          subdomainCount,
          `Excessive subdomain depth: ${subdomainCount}`,
        ),
      );
      score += 15;
    } else if (subdomainCount > 2) {
      signals.push(
        this.createSignal(
          "subdomain_depth",
          "medium",
          subdomainCount,
          `Multiple subdomains: ${subdomainCount}`,
        ),
      );
      score += 8;
    }

    // Check for suspicious TLD
    const suspiciousTlds = CONFIG.SUSPICIOUS_TLDS as readonly string[];
    if (suspiciousTlds.some((tld) => parsed.tld === tld)) {
      signals.push(
        this.createSignal(
          "suspicious_tld",
          "high",
          parsed.tld,
          "Suspicious top-level domain",
        ),
      );
      score += 20;
    }

    // Check for URL shorteners
    if (
      CONFIG.URL_SHORTENERS.some((shortener) =>
        parsed.hostname.includes(shortener),
      )
    ) {
      signals.push(
        this.createSignal(
          "url_shortener",
          "medium",
          parsed.hostname,
          "URL shortener detected",
        ),
      );
      score += 15;
    }

    // Check for encoded characters
    if (hasEncodedCharacters(parsed.full)) {
      signals.push(
        this.createSignal(
          "encoded_chars",
          "medium",
          true,
          "URL contains encoded characters",
        ),
      );
      score += 10;
    }

    // Check special character count
    const specialCount = countSpecialCharacters(parsed.pathname);
    if (specialCount > 10) {
      signals.push(
        this.createSignal(
          "special_chars",
          "medium",
          specialCount,
          "High number of special characters",
        ),
      );
      score += 10;
    }

    // Check for homograph characters
    if (hasHomoglyphCharacters(parsed.hostname)) {
      signals.push(
        this.createSignal(
          "homograph",
          "critical",
          true,
          "Potential homograph attack detected",
        ),
      );
      score += 35;
    }

    // Check for phishing keywords
    const foundKeywords = CONFIG.PHISHING_KEYWORDS.filter(
      (kw) =>
        parsed.pathname.toLowerCase().includes(kw) ||
        parsed.hostname.toLowerCase().includes(kw),
    );
    if (foundKeywords.length > 2) {
      signals.push(
        this.createSignal(
          "phishing_keywords",
          "high",
          foundKeywords.join(", "),
          "Multiple phishing keywords detected",
        ),
      );
      score += 15;
    } else if (foundKeywords.length > 0) {
      signals.push(
        this.createSignal(
          "phishing_keywords",
          "low",
          foundKeywords.join(", "),
          "Phishing keywords found",
        ),
      );
      score += 5;
    }

    // Check for typosquatting
    const brands = [
      "paypal",
      "amazon",
      "apple",
      "microsoft",
      "google",
      "facebook",
      "netflix",
      "instagram",
    ];
    const typosquatCheck = isSimilarToBrand(parsed.domain, brands);
    if (typosquatCheck.isSimilar) {
      signals.push(
        this.createSignal(
          "typosquatting",
          "critical",
          typosquatCheck.brand || "",
          `Possible typosquatting of ${typosquatCheck.brand}`,
        ),
      );
      score += 35;
    }

    // Check for HTTPS
    if (parsed.protocol !== "https:") {
      signals.push(
        this.createSignal(
          "no_https",
          "medium",
          parsed.protocol,
          "Connection is not secure (no HTTPS)",
        ),
      );
      score += 10;
    }

    // Check for non-standard port
    if (parsed.hasNonStandardPort) {
      signals.push(
        this.createSignal(
          "non_standard_port",
          "high",
          parsed.port,
          "Non-standard port detected",
        ),
      );
      score += 15;
    }

    return { score: Math.min(100, score) };
  }
}

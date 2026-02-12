// PhishGuard Plugin - Heuristic Analysis Agent (Self-contained)
// Adapted from server/src/agents/heuristic-agent.ts
// Analyzes URL and page content for social engineering patterns.

import type { Page } from "playwright";
import type { AgentResult, Signal } from "../types.js";
import { URGENCY_PATTERNS } from "./config.js";

function createSignal(
  type: string,
  severity: Signal["severity"],
  value: string | number | boolean,
  description: string,
): Signal {
  return { type, severity, value, description };
}

export class PluginHeuristicAgent {
  /**
   * Analyze for social engineering patterns.
   * If a page is provided, also analyzes page content.
   */
  async analyze(url: string, page?: Page): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let score = 0;

    // URL heuristics
    score += this.analyzeUrlHeuristics(url, signals);

    // Page content heuristics (if page available)
    if (page) {
      try {
        const textContent = await page.evaluate(() => {
          return {
            text: document.body?.innerText?.substring(0, 10000) || "",
            title: document.title || "",
          };
        });
        score += this.analyzeContentHeuristics(textContent.text, textContent.title, signals);
      } catch {
        // Page evaluation failed, continue with URL-only analysis
      }
    }

    score = Math.min(100, score);

    return {
      agentId: "heuristicAgent",
      agentName: "Heuristic Analysis Agent",
      riskScore: score,
      confidence: page ? 0.65 : 0.5,
      signals,
      explanation: this.generateExplanation(signals, score),
      executionTimeMs: Date.now() - startTime,
    };
  }

  private analyzeUrlHeuristics(url: string, signals: Signal[]): number {
    let score = 0;
    const urlLower = url.toLowerCase();

    // Urgency patterns in URL
    const urgencyInUrl = URGENCY_PATTERNS.filter(
      (pattern: string) =>
        urlLower.includes(pattern.replace(/\s/g, "-")) ||
        urlLower.includes(pattern.replace(/\s/g, "_")),
    );
    if (urgencyInUrl.length > 0) {
      signals.push(createSignal("urgency_in_url", "high", urgencyInUrl.join(", "), "Urgency language in URL"));
      score += 15;
    }

    // Suspicious URL parameters
    try {
      const params = new URL(url).searchParams;
      const suspiciousParams = ["token", "verify", "confirm", "secure", "login", "session"];
      let suspiciousParamCount = 0;
      for (const param of suspiciousParams) {
        if (params.has(param) || urlLower.includes(`${param}=`)) suspiciousParamCount++;
      }
      if (suspiciousParamCount > 2) {
        signals.push(createSignal("suspicious_params", "high", suspiciousParamCount, "Multiple suspicious URL parameters"));
        score += 15;
      } else if (suspiciousParamCount > 0) {
        signals.push(createSignal("suspicious_params", "low", suspiciousParamCount, "Suspicious URL parameters"));
        score += 5;
      }
    } catch { /* invalid URL */ }

    // Base64-like data in URL
    // M9 fix: Target base64 in query parameter values only, not the entire URL
    // The old regex /[A-Za-z0-9+/=]{30,}/ matched nearly all URLs with 30+ path chars
    if (/[?&=][A-Za-z0-9+/]{30,}={0,2}(?:&|$)/.test(url)) {
      signals.push(createSignal("encoded_data", "medium", true, "URL contains encoded data"));
      score += 10;
    }

    return score;
  }

  private analyzeContentHeuristics(text: string, title: string, signals: Signal[]): number {
    let score = 0;
    const textLower = text.toLowerCase();
    const titleLower = title.toLowerCase();

    // Urgency patterns
    let urgencyCount = 0;
    for (const pattern of URGENCY_PATTERNS) {
      if (textLower.includes(pattern.toLowerCase())) urgencyCount++;
    }
    if (urgencyCount >= 3) {
      signals.push(createSignal("high_urgency", "critical", urgencyCount, "Multiple urgency indicators detected"));
      score += 25;
    } else if (urgencyCount >= 1) {
      signals.push(createSignal("urgency_language", "high", urgencyCount, "Urgency language detected"));
      score += 12;
    }

    // Threat language
    const threatPatterns = [
      "suspended", "terminated", "locked", "disabled", "unauthorized",
      "breach", "compromised", "security alert", "warning:", "important:",
    ];
    let threatCount = 0;
    for (const pattern of threatPatterns) {
      if (textLower.includes(pattern)) threatCount++;
    }
    if (threatCount >= 3) {
      signals.push(createSignal("high_threat", "critical", threatCount, "Multiple threat indicators detected"));
      score += 25;
    } else if (threatCount >= 1) {
      signals.push(createSignal("threat_language", "high", threatCount, "Threat language detected"));
      score += 12;
    }

    // Sensitive data requests
    const sensitivePatterns = [
      "social security", "ssn", "credit card", "cvv",
      "pin number", "date of birth", "mother's maiden", "bank account",
    ];
    for (const pattern of sensitivePatterns) {
      if (textLower.includes(pattern)) {
        signals.push(createSignal("sensitive_data_request", "critical", pattern, `Requests sensitive data: ${pattern}`));
        score += 20;
        break;
      }
    }

    // Reward/prize scam
    const rewardPatterns = [
      "you have won", "congratulations", "selected winner",
      "claim your prize", "gift card", "free iphone", "lucky winner",
    ];
    for (const pattern of rewardPatterns) {
      if (textLower.includes(pattern)) {
        signals.push(createSignal("reward_scam", "high", pattern, "Reward/prize scam language detected"));
        score += 20;
        break;
      }
    }

    // Manipulative title
    if (titleLower.includes("verify") || titleLower.includes("confirm") || titleLower.includes("secure")) {
      signals.push(createSignal("manipulative_title", "medium", title, "Manipulative page title"));
      score += 10;
    }

    // Spelling errors
    const typos = ["recieve", "occured", "definately", "seperate", "wiil", "youre account", "your account have been"];
    for (const typo of typos) {
      if (textLower.includes(typo)) {
        signals.push(createSignal("poor_grammar", "medium", typo, "Spelling/grammar errors detected"));
        score += 10;
        break;
      }
    }

    return score;
  }

  private generateExplanation(signals: Signal[], score: number): string {
    const critical = signals.filter((s) => s.severity === "critical");
    const high = signals.filter((s) => s.severity === "high");
    if (critical.length > 0) return `CRITICAL: ${critical.map((s) => s.description).join("; ")}`;
    if (high.length > 0) return `Heuristic flags: ${high.map((s) => s.description).join("; ")}`;
    if (score < 20) return "No social engineering patterns detected.";
    return "Heuristic analysis complete.";
  }
}

// Heuristic Analysis Agent - Pattern matching and behavioral analysis

import { BaseAgent } from "./base-agent";
import type { AgentResult, Signal, PageContent } from "../types";
import { CONFIG } from "../config";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in heuristic phishing detection.
Analyze the provided data using behavioral patterns and psychological manipulation indicators.

Consider these risk factors:
- Urgency language ("act now", "24 hours", "immediately")
- Threat language ("suspended", "locked", "unauthorized access")
- Requests for sensitive personal data
- Spelling and grammar errors
- Pressure tactics and fear-inducing content
- Promises of rewards or prizes
- Authority impersonation
- Social engineering patterns
- Unusual call-to-action patterns

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

interface HeuristicAnalysisInput {
  url: string;
  pageContent?: PageContent;
}

export class HeuristicAgent extends BaseAgent {
  constructor() {
    super("heuristicAgent", "Heuristic Analysis Agent", SYSTEM_PROMPT);
  }

  async analyze(input: HeuristicAnalysisInput): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;

    const { url, pageContent } = input;

    // Perform local heuristic analysis
    const localAnalysis = this.performLocalAnalysis(url, pageContent, signals);
    localRiskScore = localAnalysis.score;

    // Use LLM for deeper heuristic analysis
    try {
      const analysisData: Record<string, unknown> = {
        url,
        localSignals: signals.map((s) => ({
          type: s.type,
          severity: s.severity,
          description: s.description,
        })),
      };

      if (pageContent) {
        analysisData.pageTitle = pageContent.title;
        analysisData.textSample = pageContent.textContent.substring(0, 3000);
        analysisData.hasLoginForm = pageContent.hasLoginForm;
        analysisData.hasPasswordField = pageContent.hasPasswordField;
      }

      const llmResult = await this.groqClient.analyzeForAgent(
        this.agentName,
        this.systemPrompt,
        analysisData,
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
      console.error("Heuristic Agent LLM analysis failed:", error);
    }

    return this.createResult(
      localRiskScore,
      0.5,
      signals,
      "Analysis based on heuristic pattern matching",
      Date.now() - startTime,
    );
  }

  private performLocalAnalysis(
    url: string,
    content: PageContent | undefined,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // Analyze URL for heuristic patterns
    score += this.analyzeUrlHeuristics(url, signals);

    // Analyze content if available
    if (content) {
      score += this.analyzeContentHeuristics(content, signals);
    }

    return { score: Math.min(100, score) };
  }

  private analyzeUrlHeuristics(url: string, signals: Signal[]): number {
    let score = 0;
    const urlLower = url.toLowerCase();

    // Check for urgency patterns in URL
    const urgencyInUrl = CONFIG.URGENCY_PATTERNS.filter(
      (pattern) =>
        urlLower.includes(pattern.replace(/\s/g, "-")) ||
        urlLower.includes(pattern.replace(/\s/g, "_")),
    );

    if (urgencyInUrl.length > 0) {
      signals.push(
        this.createSignal(
          "urgency_in_url",
          "high",
          urgencyInUrl.join(", "),
          "Urgency language in URL",
        ),
      );
      score += 15;
    }

    // Check for suspicious parameter patterns
    const params = new URL(url).searchParams;
    const suspiciousParams = [
      "token",
      "verify",
      "confirm",
      "secure",
      "login",
      "session",
    ];
    let suspiciousParamCount = 0;

    for (const param of suspiciousParams) {
      if (params.has(param) || urlLower.includes(`${param}=`)) {
        suspiciousParamCount++;
      }
    }

    if (suspiciousParamCount > 2) {
      signals.push(
        this.createSignal(
          "suspicious_params",
          "high",
          suspiciousParamCount,
          "Multiple suspicious URL parameters",
        ),
      );
      score += 15;
    } else if (suspiciousParamCount > 0) {
      signals.push(
        this.createSignal(
          "suspicious_params",
          "low",
          suspiciousParamCount,
          "Suspicious URL parameters",
        ),
      );
      score += 5;
    }

    // Check for Base64-like patterns in URL
    const base64Pattern = /[A-Za-z0-9+/=]{30,}/;
    if (base64Pattern.test(url)) {
      signals.push(
        this.createSignal(
          "encoded_data",
          "medium",
          true,
          "URL contains encoded data",
        ),
      );
      score += 10;
    }

    return score;
  }

  private analyzeContentHeuristics(
    content: PageContent,
    signals: Signal[],
  ): number {
    let score = 0;
    const textLower = content.textContent.toLowerCase();
    const titleLower = content.title.toLowerCase();

    // Check for urgency patterns
    let urgencyCount = 0;
    for (const pattern of CONFIG.URGENCY_PATTERNS) {
      if (textLower.includes(pattern.toLowerCase())) {
        urgencyCount++;
      }
    }

    if (urgencyCount >= 3) {
      signals.push(
        this.createSignal(
          "high_urgency",
          "critical",
          urgencyCount,
          "Multiple urgency indicators detected",
        ),
      );
      score += 25;
    } else if (urgencyCount >= 1) {
      signals.push(
        this.createSignal(
          "urgency_language",
          "high",
          urgencyCount,
          "Urgency language detected",
        ),
      );
      score += 12;
    }

    // Check for threat language
    const threatPatterns = [
      "suspended",
      "terminated",
      "locked",
      "disabled",
      "unauthorized",
      "breach",
      "compromised",
      "security alert",
      "warning:",
      "important:",
    ];

    let threatCount = 0;
    for (const pattern of threatPatterns) {
      if (textLower.includes(pattern)) {
        threatCount++;
      }
    }

    if (threatCount >= 3) {
      signals.push(
        this.createSignal(
          "high_threat",
          "critical",
          threatCount,
          "Multiple threat indicators detected",
        ),
      );
      score += 25;
    } else if (threatCount >= 1) {
      signals.push(
        this.createSignal(
          "threat_language",
          "high",
          threatCount,
          "Threat language detected",
        ),
      );
      score += 12;
    }

    // Check for sensitive data requests
    const sensitivePatterns = [
      "social security",
      "ssn",
      "credit card",
      "cvv",
      "pin number",
      "date of birth",
      "mother's maiden",
      "bank account",
    ];

    for (const pattern of sensitivePatterns) {
      if (textLower.includes(pattern)) {
        signals.push(
          this.createSignal(
            "sensitive_data_request",
            "critical",
            pattern,
            `Requests sensitive data: ${pattern}`,
          ),
        );
        score += 20;
        break;
      }
    }

    // Check for reward/prize language (often phishing)
    const rewardPatterns = [
      "you have won",
      "congratulations",
      "selected winner",
      "claim your prize",
      "gift card",
      "free iphone",
      "lucky winner",
    ];

    for (const pattern of rewardPatterns) {
      if (textLower.includes(pattern)) {
        signals.push(
          this.createSignal(
            "reward_scam",
            "high",
            pattern,
            "Reward/prize scam language detected",
          ),
        );
        score += 20;
        break;
      }
    }

    // Check title for manipulative patterns
    if (
      titleLower.includes("verify") ||
      titleLower.includes("confirm") ||
      titleLower.includes("secure")
    ) {
      signals.push(
        this.createSignal(
          "manipulative_title",
          "medium",
          content.title,
          "Manipulative page title",
        ),
      );
      score += 10;
    }

    // Check for spelling/grammar indicators (rough heuristic)
    const commonTypos = [
      "recieve",
      "occured",
      "definately",
      "seperate",
      "accomodation",
      "wiil",
      "youre account",
      "your account have been",
    ];

    for (const typo of commonTypos) {
      if (textLower.includes(typo)) {
        signals.push(
          this.createSignal(
            "poor_grammar",
            "medium",
            typo,
            "Spelling/grammar errors detected",
          ),
        );
        score += 10;
        break;
      }
    }

    return score;
  }
}

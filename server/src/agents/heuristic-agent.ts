// Heuristic Analysis Agent - Pattern matching and behavioral analysis

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal, PageContent } from "../types/index.js";
import { CONFIG } from "../config/index.js";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in heuristic phishing detection.
Analyze the provided data using behavioral patterns and psychological manipulation indicators.

IMPORTANT: News websites, security blogs, and legitimate alert pages naturally contain words like "breach", "suspended", "unauthorized", "security alert". These are NOT phishing indicators when they appear in editorial/news content. Only flag urgency/threat language when it is DIRECTED AT THE USER and combined with credential/data requests.

Consider these risk factors:
- Urgency language DIRECTED AT THE USER ("YOUR account", "act now", "verify YOUR identity")
- Threat language targeting the user personally ("your account will be suspended")
- Direct requests for sensitive personal data (SSN, credit card) on non-financial sites
- Pressure tactics combined with login forms
- Reward/prize scam language ("you have won", "claim your prize")
- Poor grammar/spelling in official-looking communications

Do NOT flag:
- News articles discussing data breaches, security incidents, or account suspensions
- Security advisories or blog posts about threats
- Pages with article/news structure discussing security topics
- Legitimate marketing with time-limited offers

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

    // Use LLM for deeper heuristic analysis (dual-model)
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

      const { result: llmResult } = await this.dualModelAnalyze(analysisData);

      if (llmResult) {
        const allSignals = [...signals, ...llmResult.signals];

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
    const urgencyPatterns = CONFIG.URGENCY_PATTERNS as readonly string[];
    const urgencyInUrl = urgencyPatterns.filter(
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
    try {
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
    } catch {
      // Invalid URL, skip parameter analysis
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

    // NEWS CONTEXT DETECTION: News articles, blogs, and journalistic content
    // naturally contain words like "breach", "suspended", "security alert", etc.
    // Detect news context and reduce threat/urgency sensitivity accordingly.
    const isNewsContext = this.detectNewsContext(content, textLower, titleLower);

    // Check for urgency patterns
    let urgencyCount = 0;
    const urgencyPatterns = CONFIG.URGENCY_PATTERNS as readonly string[];
    for (const pattern of urgencyPatterns) {
      if (textLower.includes(pattern.toLowerCase())) {
        urgencyCount++;
      }
    }

    // In news context, require much higher urgency counts to flag
    if (isNewsContext) {
      // News sites naturally have urgency language — only flag extreme cases
      if (urgencyCount >= 6) {
        signals.push(
          this.createSignal(
            "urgency_language",
            "medium",
            urgencyCount,
            "Elevated urgency indicators detected (news context noted)",
          ),
        );
        score += 8;
      }
    } else if (urgencyCount >= 3) {
      signals.push(
        this.createSignal(
          "high_urgency",
          "high",
          urgencyCount,
          "Multiple urgency indicators detected",
        ),
      );
      score += 20;
    } else if (urgencyCount >= 1) {
      signals.push(
        this.createSignal(
          "urgency_language",
          "medium",
          urgencyCount,
          "Urgency language detected",
        ),
      );
      score += 8;
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

    // In news context, threat language is expected — only flag extreme cases
    if (isNewsContext) {
      if (threatCount >= 6) {
        signals.push(
          this.createSignal(
            "threat_language",
            "medium",
            threatCount,
            "Elevated threat indicators detected (news context noted)",
          ),
        );
        score += 8;
      }
    } else if (threatCount >= 5) {
      signals.push(
        this.createSignal(
          "high_threat",
          "high",
          threatCount,
          "Numerous threat indicators detected",
        ),
      );
      score += 15;
    } else if (threatCount >= 3) {
      signals.push(
        this.createSignal(
          "threat_language",
          "medium",
          threatCount,
          "Multiple threat language patterns detected",
        ),
      );
      score += 8;
    }
    // 1-2 threat matches: ignored (too common on legitimate sites)

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
            "medium",
            pattern,
            "Reward/prize scam language detected",
          ),
        );
        score += 10;
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
          "low",
          content.title,
          "Potentially manipulative page title",
        ),
      );
      score += 5;
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

  /**
   * Detect whether the page is a news article, blog post, or journalistic content.
   * These pages naturally contain threat/urgency language (e.g., "breach", "suspended",
   * "security alert") as part of reporting, NOT as phishing tactics.
   */
  private detectNewsContext(
    content: PageContent,
    textLower: string,
    titleLower: string,
  ): boolean {
    // Check meta tags and structural indicators from the page
    const metaEntries = content.metaTags || {};
    const metaLower = Object.entries(metaEntries)
      .map(([key, value]) => `${key.toLowerCase()} ${value.toLowerCase()}`)
      .join(" ");

    // 1. Open Graph type = "article" is a strong signal
    if (metaLower.includes('og:type') && metaLower.includes('article')) {
      return true;
    }

    // 2. Common news/article meta patterns
    const newsMetaPatterns = [
      "article:published_time",
      "article:author",
      "article:section",
      "news_keywords",
      "article:tag",
      "parsely-page",
      "sailthru.",
    ];
    for (const pattern of newsMetaPatterns) {
      if (metaLower.includes(pattern)) {
        return true;
      }
    }

    // 3. Title patterns suggesting news
    const newsTitlePatterns = [
      " - bbc",
      " - cnn",
      " | reuters",
      " - the guardian",
      " - ndtv",
      " | the verge",
      " - techcrunch",
      " | ars technica",
      " - wired",
      "news",
      "report:",
      "breaking:",
      " - times of india",
      " | economic times",
    ];
    for (const pattern of newsTitlePatterns) {
      if (titleLower.includes(pattern)) {
        return true;
      }
    }

    // 4. Content-based heuristics: articles tend to be long with journalistic markers
    const articleMarkers = [
      "published on",
      "by reporter",
      "staff writer",
      "associated press",
      "reuters",
      "read more:",
      "related stories",
      "share this article",
      "subscribe to newsletter",
      "copyright ©",
      "all rights reserved",
      "editor's note",
      "correspondent",
      "press release",
    ];
    let markerCount = 0;
    for (const marker of articleMarkers) {
      if (textLower.includes(marker)) {
        markerCount++;
      }
    }
    // If the page has 2+ article markers AND is long text, it's likely news
    if (markerCount >= 2 && textLower.length > 2000) {
      return true;
    }

    return false;
  }
}

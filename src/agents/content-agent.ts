// Content Analysis Agent - Analyzes page content for phishing indicators

import { BaseAgent } from "./base-agent";
import type { AgentResult, Signal, PageContent } from "../types";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in webpage content analysis for phishing detection.
Analyze the provided page content and identify phishing indicators.

Consider these risk factors:
- Login forms with suspicious action URLs
- Password fields on unexpected pages
- Brand impersonation (logos, text claiming to be a known company)
- Forms submitting to external domains
- Hidden form fields or iframes
- Suspicious meta tags
- Mismatched page title and actual domain
- Requests for sensitive information (SSN, credit card, etc.)
- External resources from suspicious sources

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

interface ContentAnalysisInput {
  url: string;
  pageContent: PageContent;
}

export class ContentAgent extends BaseAgent {
  constructor() {
    super("contentAgent", "Content Analysis Agent", SYSTEM_PROMPT);
  }

  async analyze(input: ContentAnalysisInput): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;

    const { url, pageContent } = input;

    if (!pageContent) {
      return this.createResult(
        30, // Neutral-low score when no content
        0.3,
        [
          this.createSignal(
            "no_content",
            "low",
            true,
            "Page content not available for analysis",
          ),
        ],
        "Unable to analyze page content",
        Date.now() - startTime,
      );
    }

    // Perform local content analysis
    const localAnalysis = this.performLocalAnalysis(url, pageContent, signals);
    localRiskScore = localAnalysis.score;

    // Use LLM for deeper content analysis
    try {
      const llmResult = await this.groqClient.analyzeForAgent(
        this.agentName,
        this.systemPrompt,
        {
          url,
          pageTitle: pageContent.title,
          hasPasswordField: pageContent.hasPasswordField,
          hasLoginForm: pageContent.hasLoginForm,
          formCount: pageContent.forms.length,
          forms: pageContent.forms.slice(0, 5).map((f) => ({
            action: f.action,
            method: f.method,
            hasPassword: f.hasPasswordField,
          })),
          externalLinks: pageContent.links.filter((l) => l.isExternal).length,
          textSample: pageContent.textContent.substring(0, 2000),
          metaTags: pageContent.metaTags,
          localSignals: signals.map((s) => ({
            type: s.type,
            severity: s.severity,
          })),
        },
      );

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        const allSignals = [...signals, ...llmSignals];

        const combinedScore = Math.round(
          localRiskScore * 0.35 + llmResult.riskScore * 0.65,
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
      console.error("Content Agent LLM analysis failed:", error);
    }

    return this.createResult(
      localRiskScore,
      0.5,
      signals,
      "Analysis based on page content patterns",
      Date.now() - startTime,
    );
  }

  private performLocalAnalysis(
    url: string,
    content: PageContent,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // Check for login forms
    if (content.hasLoginForm) {
      signals.push(
        this.createSignal(
          "login_form",
          "medium",
          true,
          "Page contains a login form",
        ),
      );
      score += 10; // Not inherently bad, but note it
    }

    // Check for password fields
    if (content.hasPasswordField) {
      signals.push(
        this.createSignal(
          "password_field",
          "medium",
          true,
          "Page contains password input",
        ),
      );
      score += 10;
    }

    // Check form actions
    for (const form of content.forms) {
      if (form.hasPasswordField && form.action) {
        const formUrl = new URL(form.action, url);
        const pageUrl = new URL(url);

        // Form submits to different domain
        if (formUrl.hostname !== pageUrl.hostname) {
          signals.push(
            this.createSignal(
              "external_form_action",
              "critical",
              form.action,
              "Login form submits to external domain",
            ),
          );
          score += 35;
        }
      }
    }

    // Check title mismatch with URL
    const urlLower = url.toLowerCase();
    const titleLower = content.title.toLowerCase();
    const brandMentions = [
      "paypal",
      "amazon",
      "apple",
      "microsoft",
      "google",
      "facebook",
      "bank",
      "netflix",
    ];

    for (const brand of brandMentions) {
      if (titleLower.includes(brand) && !urlLower.includes(brand)) {
        signals.push(
          this.createSignal(
            "title_brand_mismatch",
            "critical",
            brand,
            `Title mentions "${brand}" but URL does not match`,
          ),
        );
        score += 30;
        break;
      }
    }

    // Check for suspicious text patterns
    const suspiciousTextPatterns = [
      {
        pattern: /verify your (account|identity|email)/i,
        name: "verify account request",
      },
      {
        pattern: /update your (payment|billing|card)/i,
        name: "update payment request",
      },
      {
        pattern: /account (suspended|locked|limited)/i,
        name: "account threat",
      },
      {
        pattern: /unusual (activity|sign-?in|access)/i,
        name: "unusual activity claim",
      },
      {
        pattern: /enter your (ssn|social security|credit card)/i,
        name: "sensitive data request",
      },
      {
        pattern: /confirm your (identity|password|details)/i,
        name: "confirm identity request",
      },
    ];

    for (const { pattern, name } of suspiciousTextPatterns) {
      if (pattern.test(content.textContent)) {
        signals.push(
          this.createSignal(
            "suspicious_text",
            "high",
            name,
            `Suspicious text pattern: ${name}`,
          ),
        );
        score += 12;
      }
    }

    // Check for hidden iframes or forms
    if (
      content.textContent.includes("visibility:hidden") ||
      content.textContent.includes("display:none")
    ) {
      signals.push(
        this.createSignal(
          "hidden_elements",
          "medium",
          true,
          "Page contains hidden elements",
        ),
      );
      score += 10;
    }

    // Check links for mismatches (display text vs actual URL)
    let mismatchedLinks = 0;
    for (const link of content.links) {
      const textLower = link.text.toLowerCase();
      const hrefLower = link.href.toLowerCase();

      // Check if display text looks like a URL but doesn't match href
      if (
        textLower.startsWith("http") ||
        textLower.includes(".com") ||
        textLower.includes(".org")
      ) {
        if (!hrefLower.includes(textLower.replace(/https?:\/\//, ""))) {
          mismatchedLinks++;
        }
      }
    }

    if (mismatchedLinks > 2) {
      signals.push(
        this.createSignal(
          "mismatched_links",
          "high",
          mismatchedLinks,
          "Multiple links with mismatched display text",
        ),
      );
      score += 20;
    } else if (mismatchedLinks > 0) {
      signals.push(
        this.createSignal(
          "mismatched_links",
          "medium",
          mismatchedLinks,
          "Links with mismatched display text",
        ),
      );
      score += 10;
    }

    return { score: Math.min(100, score) };
  }
}

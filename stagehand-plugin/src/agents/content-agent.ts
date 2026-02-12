// PhishGuard Plugin - Content Analysis Agent (Self-contained)
// Adapted from server/src/agents/content-agent.ts
// Operates on an external Playwright Page from Stagehand.

import type { Page } from "playwright";
import type { AgentResult, Signal } from "../types.js";
import { SAFE_DOMAINS, PROTECTED_BRANDS } from "./config.js";

function createSignal(
  type: string,
  severity: Signal["severity"],
  value: string | number | boolean,
  description: string,
): Signal {
  return { type, severity, value, description };
}

interface ExtractedContent {
  title: string;
  forms: { action: string; method: string; hasPasswordField: boolean; inputTypes: string[] }[];
  links: { href: string; text: string; isExternal: boolean }[];
  textContent: string;
  metaTags: Record<string, string>;
  hasPasswordField: boolean;
  hasLoginForm: boolean;
  isCaptcha: boolean;
  isEmpty: boolean;
}

export class PluginContentAgent {
  /**
   * Analyze page content using the provided Playwright Page.
   * Does NOT navigate - the page should already be on the target URL.
   */
  async analyze(page: Page, url: string): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let score = 0;

    let content: ExtractedContent;
    try {
      content = await this.extractContent(page);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      signals.push(createSignal("fetch_blocked", "high", errorMsg,
        "Page blocked content extraction - possible anti-bot protection"));
      return {
        agentId: "contentAgent",
        agentName: "Content Analyzer",
        riskScore: 55,
        confidence: 0.6,
        signals,
        explanation: "Page could not be analyzed - this is suspicious.",
        executionTimeMs: Date.now() - startTime,
      };
    }

    // Blocked/CAPTCHA check
    if (content.isCaptcha) {
      signals.push(createSignal("content_blocked", "high", "CAPTCHA/access restricted",
        "Page shows CAPTCHA or blocks access - common phishing evasion"));
      score += 40;
    }

    // Empty page
    if (content.isEmpty) {
      signals.push(createSignal("empty_page", "high", true, "Page is essentially empty"));
      score += 35;
    }

    // Login form on suspicious domain
    if (content.hasLoginForm || content.hasPasswordField) {
      try {
        const hostname = new URL(url).hostname;
        const isSafe = SAFE_DOMAINS.some(
          (safe: string) => hostname === safe || hostname.endsWith(`.${safe}`),
        );
        if (!isSafe) {
          signals.push(createSignal("login_form_suspicious_domain", "high", hostname,
            "Login form detected on non-verified domain"));
          score += 25;
        }
      } catch { /* invalid URL */ }
    }

    // External form action (CRITICAL)
    // M11 fix: Also check forms with sensitive input types, not just password forms
    for (const form of content.forms) {
      if (form.action) {
        try {
          const formUrl = new URL(form.action, url);
          const pageUrl = new URL(url);
          if (formUrl.hostname !== pageUrl.hostname) {
            // Check if form has password field (original check)
            if (form.hasPasswordField) {
              signals.push(createSignal("external_form_action", "critical", form.action,
                "Credentials submitted to external domain - HIGH RISK"));
              score += 45;
            }
            // M11: Also flag forms with sensitive input types (email, tel, credit card autocomplete)
            else {
              const sensitiveTypes = ["email", "tel"];
              const hasSensitiveInput = form.inputTypes.some(
                (t) => sensitiveTypes.includes(t),
              );
              if (hasSensitiveInput) {
                signals.push(createSignal("external_form_sensitive", "high", form.action,
                  "Form with sensitive inputs submits to external domain"));
                score += 25;
              }
            }
          }
        } catch { /* invalid URL */ }
      }
    }

    // Brand impersonation in title
    // H4 fix: Check against hostname only, not full URL (prevents path injection bypass)
    const titleLower = content.title.toLowerCase();
    let urlHostname = "";
    try {
      urlHostname = new URL(url).hostname.toLowerCase();
    } catch { /* invalid URL */ }
    for (const brand of PROTECTED_BRANDS) {
      if (titleLower.includes(brand.name) && !urlHostname.includes(brand.domain)) {
        signals.push(createSignal("title_brand_mismatch", "critical", brand.name,
          `Page claims to be ${brand.name} but URL is not ${brand.domain}`));
        score += 40;
        break;
      }
    }

    // Sensitive data requests
    const sensitivePatterns = [
      { pattern: /social security|ssn/i, name: "SSN request", score: 35 },
      { pattern: /credit card|card number|cvv/i, name: "Credit card request", score: 35 },
      { pattern: /bank account|routing number/i, name: "Bank details request", score: 35 },
      { pattern: /mother'?s? maiden/i, name: "Security question", score: 25 },
      { pattern: /date of birth|dob/i, name: "DOB request", score: 15 },
    ];

    for (const { pattern, name, score: patternScore } of sensitivePatterns) {
      if (pattern.test(content.textContent)) {
        signals.push(createSignal("sensitive_data_request", "critical", name,
          `Page requests ${name} - HIGH RISK`));
        score += patternScore;
        break;
      }
    }

    // Urgency/threat language
    const urgencyPatterns = [
      { pattern: /account.{0,20}(suspended|locked|disabled|terminated)/i, name: "account threat" },
      { pattern: /verify.{0,20}(now|immediately|urgent)/i, name: "urgency" },
      { pattern: /within.{0,10}(24|48).{0,5}hours/i, name: "time pressure" },
      { pattern: /unauthorized.{0,20}(access|activity|login)/i, name: "security scare" },
      { pattern: /click.{0,20}(here|below|link).{0,20}(verify|confirm)/i, name: "action demand" },
    ];

    let urgencyCount = 0;
    for (const { pattern, name } of urgencyPatterns) {
      if (pattern.test(content.textContent)) {
        urgencyCount++;
        if (urgencyCount <= 2) {
          signals.push(createSignal("urgency_threat", "high", name, `Manipulation tactic: ${name}`));
        }
      }
    }
    score += Math.min(30, urgencyCount * 10);

    // Mismatched brand links
    let mismatchCount = 0;
    for (const link of content.links) {
      const textLower = link.text.toLowerCase();
      if (
        (textLower.includes("paypal") && !link.href.includes("paypal.com")) ||
        (textLower.includes("amazon") && !link.href.includes("amazon.")) ||
        (textLower.includes("apple") && !link.href.includes("apple.com")) ||
        (textLower.includes("microsoft") && !link.href.includes("microsoft.com"))
      ) {
        mismatchCount++;
      }
    }
    if (mismatchCount > 0) {
      signals.push(createSignal("mismatched_brand_links", "critical", mismatchCount,
        `${mismatchCount} link(s) claim to be major brands but go elsewhere`));
      score += 35;
    }

    score = Math.min(100, score);

    return {
      agentId: "contentAgent",
      agentName: "Content Analyzer",
      riskScore: score,
      confidence: 0.7,
      signals,
      explanation: this.generateExplanation(signals, score),
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async extractContent(page: Page): Promise<ExtractedContent> {
    return page.evaluate(() => {
      const bodyText = document.body?.innerText?.toLowerCase() || "";
      const title = document.title?.toLowerCase() || "";

      const captchaIndicators = [
        "captcha", "verify you are human", "prove you're not a robot",
        "security check", "access denied", "blocked", "cloudflare",
        "ddos protection", "please wait", "checking your browser",
        "just a moment", "enable javascript",
      ];
      const isCaptcha = captchaIndicators.some(
        (ind) => bodyText.includes(ind) || title.includes(ind),
      );
      const isEmpty = bodyText.trim().length < 100;

      const forms = Array.from(document.forms).map((form: HTMLFormElement) => ({
        action: form.getAttribute("action") || "",  // H3 fix: use getAttribute, not DOM property
        method: form.method || "get",
        hasPasswordField: form.querySelector('input[type="password"]') !== null,
        inputTypes: Array.from(form.querySelectorAll("input")).map(
          (input) => (input as HTMLInputElement).type,
        ),
      }));

      const links = Array.from(document.querySelectorAll("a[href]")).map((a) => {
        const anchor = a as HTMLAnchorElement;
        const href = anchor.href;
        let isExternal = false;
        try {
          isExternal = new URL(href).hostname !== window.location.hostname;
        } catch { isExternal = false; }
        return { href, text: a.textContent?.trim() || "", isExternal };
      });

      const metaTags: Record<string, string> = {};
      document.querySelectorAll("meta").forEach((meta) => {
        const name = meta.getAttribute("name") || meta.getAttribute("property");
        const contentAttr = meta.getAttribute("content");
        if (name && contentAttr) metaTags[name] = contentAttr;
      });

      return {
        title: document.title || "",
        forms,
        links,
        textContent: document.body?.innerText?.substring(0, 10000) || "",
        metaTags,
        hasPasswordField: document.querySelector('input[type="password"]') !== null,
        hasLoginForm: document.querySelector('form input[type="password"], form input[name*="password"]') !== null,
        isCaptcha,
        isEmpty,
      };
    });
  }

  private generateExplanation(signals: Signal[], score: number): string {
    const critical = signals.filter((s) => s.severity === "critical");
    const high = signals.filter((s) => s.severity === "high");
    if (critical.length > 0) return `CRITICAL: ${critical.map((s) => s.description).join("; ")}`;
    if (high.length > 0) return `High-risk content: ${high.map((s) => s.description).join("; ")}`;
    if (score < 20) return "Page content appears normal.";
    return "Content analysis complete.";
  }
}

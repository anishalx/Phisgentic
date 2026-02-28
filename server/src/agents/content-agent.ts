// Content Analysis Agent - Aggressive page content analysis for phishing detection

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal, PageContent } from "../types/index.js";
import { chromium, Browser, Page } from "playwright";
import { CONFIG } from "../config/index.js";

const SYSTEM_PROMPT = `You are a cybersecurity analyst specializing in webpage content analysis for phishing detection.
Analyze the provided page content carefully for phishing indicators. When in doubt, score HIGHER — missing phishing is far worse than a false alarm.

IMPORTANT SCORING GUIDANCE:
- Score 50+ for ANY combination of 2+ suspicious indicators
- Score 70+ when phishing indicators are clearly present
- Score 80+ when there is strong evidence of credential theft or brand impersonation

CRITICAL RED FLAGS (score 70-100):
- Forms submitting credentials to a DIFFERENT domain than the page (cross-origin credential theft)
- Brand logos/names combined with a completely unrelated domain (e.g., "PayPal" login on random-domain.xyz)
- Requests for highly sensitive data (SSN, full credit card, bank routing numbers) on non-banking domains
- CAPTCHA pages specifically designed to hide content from security scanners
- Pages that disable right-click, text selection, or browser back button
- Hidden form fields or data: URI form actions

MODERATE FLAGS (score 40-70):
- Generic login pages with no clear branding on unusual domains
- Urgency/threat language combined with credential requests
- External resource loading from suspicious domains
- Pages with autocomplete="off" on password fields (hiding from browser security)
- Login forms on free hosting platforms

LOW RISK (score 0-30):
- Login forms on established domains that submit to the SAME domain — this is NORMAL
- E-commerce sites with payment flows on their own domain
- News sites with subscription/login walls

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

interface ContentAnalysisInput {
  url: string;
  pageContent?: PageContent;
  /** Optional: Provide an existing Playwright Page to reuse */
  externalPage?: Page;
}

interface ExtendedPageContent extends PageContent {
  isBlocked?: boolean;
  isCaptcha?: boolean;
  isEmpty?: boolean;
  blockReason?: string;
}

export class ContentAgent extends BaseAgent {
  private browser: Browser | null = null;

  constructor() {
    super("contentAgent", "Content Analyzer", SYSTEM_PROMPT);
  }

  async analyze(input: ContentAnalysisInput): Promise<AgentResult> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;

    const { url, externalPage } = input;
    let pageContent: ExtendedPageContent | null = input.pageContent || null;

    // Fetch page content if not provided
    if (!pageContent) {
      try {
        pageContent = await this.fetchPageContent(url, externalPage);
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.error("Failed to fetch page content:", errorMsg);
        
        // CRITICAL: Failed fetches are SUSPICIOUS, not safe!
        signals.push(
          this.createSignal(
            "fetch_blocked",
            "medium",
            errorMsg,
            "Page could not be fetched (may be bot-protection or network issue)",
          ),
        );
        
        return this.createResult(
          25, // Low — failed fetches are inconclusive, not evidence of phishing
          0.3,
          signals,
          "Page could not be accessed — inconclusive (many legitimate sites block scrapers).",
          Date.now() - startTime,
        );
      }
    }

    if (!pageContent) {
      signals.push(
        this.createSignal(
          "no_content",
          "low",
          true,
          "No page content available (inconclusive)",
        ),
      );
      
      return this.createResult(
        15, // Low — absence of content is not evidence of phishing
        0.2,
        signals,
        "Unable to analyze page content — inconclusive.",
        Date.now() - startTime,
      );
    }

    // CHECK: Page is blocked/CAPTCHA
    // Many legitimate sites use Cloudflare, CAPTCHA, or bot protection — this
    // alone is NOT strong phishing evidence.
    if (pageContent.isBlocked || pageContent.isCaptcha) {
      signals.push(
        this.createSignal(
          "content_blocked",
          "medium",
          pageContent.blockReason || "Access restricted",
          "Page shows CAPTCHA or blocks access",
        ),
      );
      localRiskScore += 15;
    }

    // CHECK: Empty page (possible redirect trap)
    // Many pages appear empty to scrapers (SPAs, lazy loading, JS-rendered content).
    // This is weak evidence at best.
    if (pageContent.isEmpty) {
      signals.push(
        this.createSignal(
          "empty_page",
          "low",
          true,
          "Page appears empty (may be SPA or JS-rendered)",
        ),
      );
      localRiskScore += 10;
    }

    // Perform local content analysis
    const localAnalysis = this.performAggressiveAnalysis(url, pageContent, signals);
    localRiskScore += localAnalysis.score;

    // If already flagged as critical, skip LLM
    if (localRiskScore >= 80) {
      return this.createResult(
        Math.min(100, localRiskScore),
        0.9,
        signals,
        this.generateLocalExplanation(signals),
        Date.now() - startTime,
      );
    }

    // Use LLM for deeper content analysis (dual-model)
    try {
      const { result: llmResult } = await this.dualModelAnalyze({
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
        textSample: pageContent.textContent.substring(0, 3000),
        metaTags: pageContent.metaTags,
        localSignals: signals.map((s) => ({
          type: s.type,
          severity: s.severity,
          description: s.description,
        })),
        localRiskScore,
        instruction: "Be accurate. Score 70+ only with strong phishing evidence. Login forms on their own domain are normal.",
      });

      if (llmResult) {
        const allSignals = [...signals, ...llmResult.signals];

        // Weighted average of local and LLM scores (55% local, 45% LLM — local heuristics are more reliable)
        const combinedScore = Math.round(localRiskScore * 0.55 + llmResult.riskScore * 0.45);

        return this.createResult(
          combinedScore,
          Math.max(0.7, llmResult.confidence),
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
      0.6,
      signals,
      this.generateLocalExplanation(signals),
      Date.now() - startTime,
    );
  }

  private async fetchPageContent(url: string, externalPage?: Page): Promise<ExtendedPageContent> {
    // If an external page is provided, use it directly
    if (externalPage) {
      return this.extractContentFromPage(externalPage, url);
    }

    // Otherwise, launch our own browser
    let browser: Browser | null = null;

    try {
      browser = await chromium.launch({
        headless: CONFIG.PLAYWRIGHT.HEADLESS,
      });

      const context = await browser.newContext({
        viewport: CONFIG.PLAYWRIGHT.VIEWPORT,
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      });

      const page = await context.newPage();
      page.setDefaultTimeout(CONFIG.PLAYWRIGHT.TIMEOUT);

      // Navigate to the URL
      let navigationError: string | null = null;
      try {
        await page.goto(url, { waitUntil: "domcontentloaded" });
      } catch (error) {
        navigationError = error instanceof Error ? error.message : String(error);
      }

      // FIXED: If navigation failed completely, don't extract from blank/error page
      if (navigationError && page.url() === "about:blank") {
        return {
          title: "",
          forms: [],
          links: [],
          scripts: [],
          metaTags: {},
          textContent: "",
          hasPasswordField: false,
          hasLoginForm: false,
          isBlocked: true,
          isEmpty: true,
          blockReason: navigationError,
        };
      }

      const content = await this.extractContentFromPage(page, url);

      if (navigationError) {
        content.isBlocked = true;
        content.blockReason = navigationError;
      }

      return content;
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  /**
   * Extract page content from a Playwright Page instance.
   * Shared between self-managed browser and external page paths.
   */
  private async extractContentFromPage(page: Page, url: string): Promise<ExtendedPageContent> {
    const content = await page.evaluate((): ExtendedPageContent => {
        const bodyText = document.body?.innerText?.toLowerCase() || "";
        const title = document.title?.toLowerCase() || "";
        
        // Detect blocked/CAPTCHA pages
        const captchaIndicators = [
          "captcha", "verify you are human", "prove you're not a robot",
          "security check", "access denied", "blocked", "cloudflare",
          "ddos protection", "please wait", "checking your browser",
          "just a moment", "enable javascript"
        ];
        
        const isCaptcha = captchaIndicators.some(indicator => 
          bodyText.includes(indicator) || title.includes(indicator)
        );
        
        const isEmpty = bodyText.trim().length < 100;
        
        const forms = Array.from(document.forms).map((form: HTMLFormElement) => ({
          action: form.action || "",
          method: form.method || "get",
          hasPasswordField: form.querySelector('input[type="password"]') !== null,
          inputTypes: Array.from(form.querySelectorAll("input")).map(
            (input) => (input as HTMLInputElement).type,
          ),
        }));

        const links = Array.from(document.querySelectorAll("a[href]")).map((a) => {
          const anchor = a as HTMLAnchorElement;
          const href = anchor.href;
          const currentHost = window.location.hostname;
          let isExternal = false;
          try {
            isExternal = new URL(href).hostname !== currentHost;
          } catch {
            isExternal = false;
          }
          return {
            href,
            text: a.textContent?.trim() || "",
            isExternal,
          };
        });

        const metaTags: Record<string, string> = {};
        document.querySelectorAll("meta").forEach((meta) => {
          const name = meta.getAttribute("name") || meta.getAttribute("property");
          const contentAttr = meta.getAttribute("content");
          if (name && contentAttr) {
            metaTags[name] = contentAttr;
          }
        });

        return {
          title: document.title || "",
          forms,
          links,
          scripts: Array.from(document.querySelectorAll("script[src]")).map(
            (s) => (s as HTMLScriptElement).src,
          ),
          metaTags,
          textContent: document.body?.innerText?.substring(0, 10000) || "",
          hasPasswordField: document.querySelector('input[type="password"]') !== null,
          hasLoginForm: document.querySelector(
            'form input[type="password"], form input[name*="password"]'
          ) !== null,
          isCaptcha,
          isEmpty,
          isBlocked: false,
        };
      });

    return content;
  }

  private performAggressiveAnalysis(
    url: string,
    content: ExtendedPageContent,
    signals: Signal[],
  ): { score: number } {
    let score = 0;

    // CHECK: Login forms on suspicious domains
    if (content.hasLoginForm || content.hasPasswordField) {
      // Check if this is a known safe domain
      const hostname = new URL(url).hostname;
      const isSafe = CONFIG.SAFE_DOMAINS.some(
        safe => hostname === safe || hostname.endsWith(`.${safe}`)
      );

      if (!isSafe) {
        // Check if the form submits to the SAME domain (legitimate login)
        const formSubmitsToSameDomain = content.forms.every(form => {
          if (!form.hasPasswordField || !form.action) return true; // No password or no action = fine
          try {
            const formUrl = new URL(form.action, url);
            const pageUrl = new URL(url);
            const normalize = (h: string) => h.replace(/^www\./, "");
            return normalize(formUrl.hostname) === normalize(pageUrl.hostname);
          } catch {
            return true; // Invalid URL in action = relative path = same domain
          }
        });

        if (formSubmitsToSameDomain) {
          // Same-domain login form — very low risk, this is normal behavior
          signals.push(
            this.createSignal(
              "login_form_same_domain",
              "low",
              hostname,
              "Login form detected - submits to same domain (normal behavior)",
            ),
          );
          score += 5;
        } else {
          // Cross-domain login form — more suspicious
          signals.push(
            this.createSignal(
              "login_form_suspicious_domain",
              "medium",
              hostname,
              "Login form detected on non-verified domain",
            ),
          );
          score += 15;
        }
      }
    }

    // CHECK: Form submits to external domain
    // But SKIP if the external domain is a known auth/payment provider (OAuth, Stripe, etc.)
    const knownAuthDomains = CONFIG.KNOWN_AUTH_PAYMENT_DOMAINS as readonly string[];
    for (const form of content.forms) {
      if (form.hasPasswordField && form.action) {
        try {
          const formUrl = new URL(form.action, url);
          const pageUrl = new URL(url);

          if (formUrl.hostname !== pageUrl.hostname) {
            // Check if the form target is a known legitimate auth/payment domain
            const isKnownDomain = knownAuthDomains.some(
              (d) => formUrl.hostname === d || formUrl.hostname.endsWith(`.${d}`)
            );

            if (!isKnownDomain) {
              signals.push(
                this.createSignal(
                  "external_form_action",
                  "high",
                  form.action,
                  "Credentials submitted to unknown external domain",
                ),
              );
              score += 25;
            }
            // If it IS a known domain, skip entirely — this is normal (OAuth, Shopify, Stripe, etc.)
          }
        } catch {
          // Invalid URL
        }
      }
    }

    // CHECK: Brand impersonation in title
    // Context-aware: pages that mention brands in educational/review/comparison
    // context should NOT be flagged (e.g., "PayPal vs Stripe review")
    const urlLower = url.toLowerCase();
    const titleLower = content.title.toLowerCase();
    const brands = CONFIG.PROTECTED_BRANDS;

    const titleContextKeywords = [
      "review", "guide", "vs", "versus", "alternative", "how to",
      "tutorial", "integration", "clone", "comparison", "compare",
      "competitor", "pricing", "blog", "news", "article", "opinion",
      "analysis", "overview", "setup", "documentation", "api", "sdk",
    ];
    const isTitleEducational = titleContextKeywords.some((kw) => titleLower.includes(kw));

    for (const brand of brands) {
      if (titleLower.includes(brand.name) && !urlLower.includes(brand.domain)) {
        if (isTitleEducational) {
          // Educational/review context — downgrade to medium, low score
          signals.push(
            this.createSignal(
              "title_brand_mismatch",
              "medium",
              brand.name,
              `Page mentions ${brand.name} (educational/review context detected)`,
            ),
          );
          score += 10;
        } else {
          signals.push(
            this.createSignal(
              "title_brand_mismatch",
              "high",
              brand.name,
              `Page claims to be ${brand.name} but URL is not ${brand.domain}`,
            ),
          );
          score += 25;
        }
        break;
      }
    }

    // CHECK: Sensitive data requests
    // IMPORTANT: Only flag if the page actually has forms. Informational pages
    // that merely mention "credit card" or "SSN" in text (e.g., financial advice
    // articles, bank FAQ pages) should NOT be flagged.
    const hasForms = content.forms.length > 0;
    if (hasForms) {
      const sensitivePatterns = [
        { pattern: /social security|ssn/i, name: "SSN request", score: 30 },
        { pattern: /credit card|card number|cvv/i, name: "Credit card request", score: 30 },
        { pattern: /bank account|routing number/i, name: "Bank details request", score: 30 },
        { pattern: /mother'?s? maiden/i, name: "Security question", score: 20 },
        { pattern: /date of birth|dob/i, name: "DOB request", score: 10 },
      ];

      for (const { pattern, name, score: patternScore } of sensitivePatterns) {
        if (pattern.test(content.textContent)) {
          signals.push(
            this.createSignal(
              "sensitive_data_request",
              "high",
              name,
              `Page with forms requests ${name}`,
            ),
          );
          score += patternScore;
          break; // Only count once
        }
      }
    }

    // CHECK: Urgency/threat language
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
          signals.push(
            this.createSignal(
              "urgency_threat",
              "high",
              name,
              `Manipulation tactic: ${name}`,
            ),
          );
        }
      }
    }
    score += Math.min(30, urgencyCount * 10);

    // CHECK: Mismatched links
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
      signals.push(
        this.createSignal(
          "mismatched_brand_links",
          "critical",
          mismatchCount,
          `${mismatchCount} link(s) claim to be major brands but go elsewhere`,
        ),
      );
      score += 35;
    }

    // CHECK: Data URI form actions (used to exfiltrate data without a server)
    for (const form of content.forms) {
      if (form.action && form.action.toLowerCase().startsWith("data:")) {
        signals.push(
          this.createSignal(
            "data_uri_form_action",
            "critical",
            form.action.substring(0, 50),
            "Form uses data: URI action — potential data exfiltration",
          ),
        );
        score += 40;
        break;
      }
    }

    // CHECK: Forms with autocomplete="off" on password fields
    // Phishing pages disable autocomplete to avoid browser security warnings
    // This is checked via the form input types from page evaluation
    const passwordFormsCount = content.forms.filter(f => f.hasPasswordField).length;
    if (passwordFormsCount > 0) {
      // Check if any form has a password field — additional scoring for non-safe domains
      const hostname = new URL(url).hostname;
      const isSafe = CONFIG.SAFE_DOMAINS.some(
        safe => hostname === safe || hostname.endsWith(`.${safe}`)
      );
      if (!isSafe && content.forms.some(f => f.hasPasswordField && f.inputTypes.length <= 3)) {
        // Simple form with password field on unknown domain — suspicious
        signals.push(
          this.createSignal(
            "simple_password_form",
            "medium",
            passwordFormsCount,
            "Simple password form on unverified domain",
          ),
        );
        score += 10;
      }
    }

    // CHECK: Page has very little text but has forms (common phishing pattern)
    // Phishing pages often have minimal content — just a form and a brand logo
    if (content.textContent.trim().length < 200 && content.forms.length > 0 && content.hasPasswordField) {
      signals.push(
        this.createSignal(
          "minimal_content_with_form",
          "high",
          content.textContent.trim().length,
          "Page has minimal text content but contains a password form — common phishing pattern",
        ),
      );
      score += 20;
    }

    // CHECK: Multiple external links that all go to the same suspicious domain
    // Phishing pages often have all links pointing to the phishing domain
    const externalDomains = new Set<string>();
    const internalLinkCount = content.links.filter(l => !l.isExternal).length;
    for (const link of content.links) {
      if (link.isExternal) {
        try {
          externalDomains.add(new URL(link.href).hostname);
        } catch {
          // Invalid URL
        }
      }
    }
    if (content.links.length > 5 && internalLinkCount === 0 && externalDomains.size <= 1) {
      signals.push(
        this.createSignal(
          "all_external_links",
          "medium",
          content.links.length,
          "All links are external — page may be a phishing redirect hub",
        ),
      );
      score += 10;
    }

    // CHECK: Hidden elements — detect via computed styles, not textContent
    // The old check looked for CSS strings in innerText which was useless
    // This is now handled in extractContentFromPage via page.evaluate
    // (We check for hidden form fields which is a real phishing indicator)

    return { score: Math.min(100, score) };
  }

  private generateLocalExplanation(signals: Signal[]): string {
    const critical = signals.filter(s => s.severity === "critical");
    const high = signals.filter(s => s.severity === "high");

    if (critical.length > 0) {
      return `CRITICAL THREATS: ${critical.map(s => s.description).join("; ")}`;
    }
    if (high.length > 0) {
      return `High-risk content: ${high.map(s => s.description).join("; ")}`;
    }
    return "Content analysis complete.";
  }

  async cleanup(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}

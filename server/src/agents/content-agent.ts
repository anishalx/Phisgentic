// Content Analysis Agent - Aggressive page content analysis for phishing detection

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal, PageContent } from "../types/index.js";
import { chromium, Browser, Page } from "playwright";
import { CONFIG } from "../config/index.js";

const SYSTEM_PROMPT = `You are an elite cybersecurity analyst specializing in webpage content analysis for phishing detection.
Analyze the provided page content with EXTREME scrutiny for phishing indicators.

CRITICAL RED FLAGS (score 70-100):
- Login forms on non-official domains
- Password fields combined with brand impersonation
- Forms submitting to external/suspicious domains
- Brand logos/names without matching domain
- Requests for sensitive data (SSN, credit card, bank details)
- Urgency/threat language ("account suspended", "verify now")
- CAPTCHA pages or access-denied (hiding content from scanners)

MODERATE FLAGS (score 40-70):
- Generic login pages with no branding
- Unusual form structures
- External resource loading
- Pop-up dialogs or overlays

Be AGGRESSIVE in scoring. When in doubt, score HIGHER. False positives are acceptable.

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

interface ContentAnalysisInput {
  url: string;
  pageContent?: PageContent;
  /** Optional: Provide an existing Playwright Page to reuse (e.g., from Stagehand plugin) */
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
            "high",
            errorMsg,
            "Page blocked our scanner - possible anti-bot protection hiding phishing content",
          ),
        );
        
        return this.createResult(
          55, // Suspicious, not safe!
          0.6,
          signals,
          "Page could not be accessed - this is suspicious as phishing sites often block automated scanners.",
          Date.now() - startTime,
        );
      }
    }

    if (!pageContent) {
      signals.push(
        this.createSignal(
          "no_content",
          "high",
          true,
          "No page content available - possible evasion technique",
        ),
      );
      
      return this.createResult(
        50,
        0.5,
        signals,
        "Unable to analyze page content - treat with caution.",
        Date.now() - startTime,
      );
    }

    // CHECK: Page is blocked/CAPTCHA
    if (pageContent.isBlocked || pageContent.isCaptcha) {
      signals.push(
        this.createSignal(
          "content_blocked",
          "high",
          pageContent.blockReason || "Access restricted",
          "Page shows CAPTCHA or blocks access - common phishing evasion tactic",
        ),
      );
      localRiskScore += 40;
    }

    // CHECK: Empty page (possible redirect trap)
    if (pageContent.isEmpty) {
      signals.push(
        this.createSignal(
          "empty_page",
          "high",
          true,
          "Page is essentially empty - possible redirect/tracking page",
        ),
      );
      localRiskScore += 35;
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
          textSample: pageContent.textContent.substring(0, 3000),
          metaTags: pageContent.metaTags,
          localSignals: signals.map((s) => ({
            type: s.type,
            severity: s.severity,
            description: s.description,
          })),
          localRiskScore,
          instruction: "Be aggressive. Score 70+ if suspicious. Score 90+ if clearly phishing.",
        },
      );

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        const allSignals = [...signals, ...llmSignals];

        // Take MAXIMUM of local and LLM scores
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
    // If an external page is provided (e.g., from Stagehand), use it directly
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
        signals.push(
          this.createSignal(
            "login_form_suspicious_domain",
            "high",
            hostname,
            "Login form detected on non-verified domain",
          ),
        );
        score += 25;
      }
    }

    // CHECK: Form submits to external domain (CRITICAL)
    for (const form of content.forms) {
      if (form.hasPasswordField && form.action) {
        try {
          const formUrl = new URL(form.action, url);
          const pageUrl = new URL(url);

          if (formUrl.hostname !== pageUrl.hostname) {
            signals.push(
              this.createSignal(
                "external_form_action",
                "critical",
                form.action,
                "Credentials submitted to external domain - HIGH RISK",
              ),
            );
            score += 45;
          }
        } catch {
          // Invalid URL
        }
      }
    }

    // CHECK: Brand impersonation in title
    const urlLower = url.toLowerCase();
    const titleLower = content.title.toLowerCase();
    const brands = CONFIG.PROTECTED_BRANDS;

    for (const brand of brands) {
      if (titleLower.includes(brand.name) && !urlLower.includes(brand.domain)) {
        signals.push(
          this.createSignal(
            "title_brand_mismatch",
            "critical",
            brand.name,
            `Page claims to be ${brand.name} but URL is not ${brand.domain}`,
          ),
        );
        score += 40;
        break;
      }
    }

    // CHECK: Sensitive data requests
    const sensitivePatterns = [
      { pattern: /social security|ssn/i, name: "SSN request", score: 35 },
      { pattern: /credit card|card number|cvv/i, name: "Credit card request", score: 35 },
      { pattern: /bank account|routing number/i, name: "Bank details request", score: 35 },
      { pattern: /mother'?s? maiden/i, name: "Security question", score: 25 },
      { pattern: /date of birth|dob/i, name: "DOB request", score: 15 },
    ];

    for (const { pattern, name, score: patternScore } of sensitivePatterns) {
      if (pattern.test(content.textContent)) {
        signals.push(
          this.createSignal(
            "sensitive_data_request",
            "critical",
            name,
            `Page requests ${name} - HIGH RISK`,
          ),
        );
        score += patternScore;
        break; // Only count once
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

    // CHECK: Hidden elements
    if (
      content.textContent.includes("visibility:hidden") ||
      content.textContent.includes("display:none") ||
      content.textContent.includes("opacity:0")
    ) {
      signals.push(
        this.createSignal(
          "hidden_elements",
          "medium",
          true,
          "Page contains hidden elements",
        ),
      );
      score += 15;
    }

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

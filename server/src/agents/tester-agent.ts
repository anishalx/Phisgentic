// Tester Agent - Simulates user interaction and checks behavioral anomalies

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal, BrowserTestResult, FormAnalysis, LogoDetectionResult } from "../types/index.js";
import { chromium, Browser, BrowserContext } from "playwright";
import { CONFIG } from "../config/index.js";
import { getGroqClient } from "../api/groq-client.js";

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in behavioral phishing detection.
Analyze the browser test results to identify phishing indicators.

Consider these risk factors:
- Multiple redirects, especially to different domains
- Popup windows or overlays appearing immediately
- Permission requests (notifications, location, camera, etc.)
- Automatic download attempts
- Console or network errors suggesting blocked content
- Google Safe Browsing or similar warnings
- Page load issues or unusual behavior
- Mismatched final URL vs original URL

Provide a risk score (0-100), confidence (0-1), detected signals, and explanation.`;

// Browser Singleton for resource efficiency
let browserInstance: Browser | null = null;
let browserInitPromise: Promise<Browser> | null = null;

async function getBrowser(): Promise<Browser> {
  if (browserInstance && browserInstance.isConnected()) {
    return browserInstance;
  }
  
  // Prevent multiple simultaneous initializations
  if (browserInitPromise) {
    return browserInitPromise;
  }
  
  browserInitPromise = chromium.launch({
    headless: CONFIG.PLAYWRIGHT.HEADLESS,
  }).then((browser) => {
    browserInstance = browser;
    browserInitPromise = null;
    
    // Handle browser disconnection
    browser.on("disconnected", () => {
      browserInstance = null;
    });
    
    console.log("[TesterAgent] Browser singleton initialized");
    return browser;
  }).catch((error) => {
    browserInitPromise = null;
    throw error;
  });
  
  return browserInitPromise;
}

// Graceful shutdown helper
export async function closeBrowser(): Promise<void> {
  if (browserInstance) {
    await browserInstance.close();
    browserInstance = null;
    console.log("[TesterAgent] Browser singleton closed");
  }
}

export class TesterAgent extends BaseAgent {
  constructor() {
    super("testerAgent", "Tester Agent", SYSTEM_PROMPT);
  }

  async analyze(url: string): Promise<AgentResult & { screenshot?: string }> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;
    let screenshot: string | undefined;

    // Check if Tester Agent is disabled (e.g., on Render where Playwright isn't available)
    if (process.env.DISABLE_TESTER_AGENT === "true") {
      console.log("Tester Agent is disabled via environment variable");
      return {
        ...this.createResult(
          0,  // Neutral score - won't affect final verdict
          0.1, // Very low confidence
          [],
          "Browser testing disabled in this environment",
          Date.now() - startTime,
        ),
        screenshot: undefined,
      };
    }

    // Perform browser test
    let testResult: BrowserTestResult | null = null;
    try {
      testResult = await this.performBrowserTest(url);
      screenshot = testResult.screenshot;
    } catch (error) {
      console.error("Tester Agent browser test failed:", error);
      // Return neutral result to not affect final score when browser is unavailable
      return {
        ...this.createResult(
          0,  // Changed from 50 to 0 - neutral, won't penalize
          0.1, // Very low confidence
          [
            this.createSignal(
              "test_skipped",
              "low",
              true,
              "Browser test skipped (browser unavailable)",
            ),
          ],
          "Browser testing unavailable in this environment",
          Date.now() - startTime,
        ),
        screenshot: undefined,
      };
    }

    // Analyze test results locally
    localRiskScore = this.analyzeTestResults(testResult, signals);

    // Vision-based Logo Detection (runs in parallel with LLM analysis)
    let logoDetectionPromise: Promise<LogoDetectionResult | null> = Promise.resolve(null);
    
    if (screenshot && process.env.DISABLE_VISION_DETECTION !== "true") {
      const groqClient = getGroqClient();
      logoDetectionPromise = groqClient.analyzeLogoInScreenshot(screenshot, testResult.finalUrl)
        .catch((error) => {
          console.error("[TesterAgent] Logo detection failed:", error);
          return null;
        });
    }

    // Use LLM for deeper analysis
    try {
      const llmResult = await this.groqClient.analyzeForAgent(
        this.agentName,
        this.systemPrompt,
        {
          originalUrl: url,
          finalUrl: testResult.finalUrl,
          redirectCount: testResult.redirectChain.length,
          redirectChain: testResult.redirectChain,
          hasPopups: testResult.hasPopups,
          hasOverlays: testResult.hasOverlays,
          downloadAttempted: testResult.downloadAttempted,
          permissionRequests: testResult.permissionRequests,
          consoleErrorCount: testResult.consoleErrors.length,
          networkErrorCount: testResult.networkErrors.length,
          loadTimeMs: testResult.loadTimeMs,
          safetyWarning: testResult.safetyWarning,
          localSignals: signals.map((s) => ({
            type: s.type,
            severity: s.severity,
            description: s.description,
          })),
        },
      );

      if (llmResult) {
        const llmSignals = (llmResult.signals as Signal[]) || [];
        let allSignals = [...signals, ...llmSignals];
        let finalScore = Math.round(localRiskScore * 0.4 + llmResult.riskScore * 0.6);

        // Wait for logo detection result
        const logoResult = await logoDetectionPromise;
        
        // Process logo detection - CRITICAL if brand mismatch detected
        if (logoResult && logoResult.brandDetected && logoResult.isDomainMismatch) {
          const logoSignal = this.createSignal(
            "logo_domain_mismatch",
            "critical",
            `${logoResult.brandDetected} logo on unauthorized domain`,
            `CRITICAL: ${logoResult.brandDetected} brand logo detected but domain is not legitimate (expected: ${logoResult.legitimateDomains.slice(0, 3).join(", ")})`,
          );
          allSignals.push(logoSignal);
          
          // Significant score boost for visual brand spoofing
          finalScore = Math.max(finalScore, 85);
          
          console.log(`[TesterAgent] Logo detection ALERT: ${logoResult.brandDetected} on wrong domain`);
        }

        return {
          ...this.createResult(
            finalScore,
            llmResult.confidence,
            allSignals,
            llmResult.explanation,
            Date.now() - startTime,
          ),
          screenshot,
        };
      }
    } catch (error) {
      console.error("Tester Agent LLM analysis failed:", error);
    }

    // Fallback: Still check logo detection even if LLM failed
    const logoResult = await logoDetectionPromise;
    
    if (logoResult && logoResult.brandDetected && logoResult.isDomainMismatch) {
      signals.push(
        this.createSignal(
          "logo_domain_mismatch",
          "critical",
          `${logoResult.brandDetected} logo on unauthorized domain`,
          `CRITICAL: ${logoResult.brandDetected} brand logo detected but domain is not legitimate`,
        ),
      );
      localRiskScore = Math.max(localRiskScore, 85);
    }

    return {
      ...this.createResult(
        localRiskScore,
        0.5,
        signals,
        "Analysis based on browser behavior testing",
        Date.now() - startTime,
      ),
      screenshot,
    };
  }

  private async performBrowserTest(url: string): Promise<BrowserTestResult> {
    let context: BrowserContext | null = null;
    const redirectChain: string[] = [];
    const consoleErrors: string[] = [];
    const networkErrors: string[] = [];
    const permissionRequests: string[] = [];
    let hasPopups = false;
    let hasOverlays = false;
    let downloadAttempted = false;
    let safetyWarning: string | undefined;
    let screenshot = "";

    try {
      // Use singleton browser and create a new context per request
      const browser = await getBrowser();
      
      context = await browser.newContext({
        viewport: CONFIG.PLAYWRIGHT.VIEWPORT,
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      });

      // Track permission requests
      context.on("page", (page) => {
        page.on("dialog", async (dialog) => {
          permissionRequests.push(dialog.type());
          hasPopups = true;
          await dialog.dismiss();
        });
      });

      // Track downloads
      context.on("page", (page) => {
        page.on("download", () => {
          downloadAttempted = true;
        });
      });

      const page = await context.newPage();
      page.setDefaultTimeout(CONFIG.PLAYWRIGHT.TIMEOUT);

      // Track console errors
      page.on("console", (msg) => {
        if (msg.type() === "error") {
          consoleErrors.push(msg.text());
        }
      });

      // Track network errors
      page.on("requestfailed", (request) => {
        networkErrors.push(`${request.url()} - ${request.failure()?.errorText}`);
      });

      // Track redirects
      page.on("response", (response) => {
        const status = response.status();
        if (status >= 300 && status < 400) {
          redirectChain.push(response.url());
        }
      });

      const startTime = Date.now();

      // Navigate to the URL
      try {
        await page.goto(url, { waitUntil: "domcontentloaded" });
      } catch (error) {
        // Check for safety warnings
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (
          errorMessage.includes("net::ERR_") ||
          errorMessage.includes("blocked")
        ) {
          safetyWarning = errorMessage;
        }
      }

      const loadTimeMs = Date.now() - startTime;

      // Check for overlays
      try {
        hasOverlays = await page.evaluate(() => {
          const overlays = document.querySelectorAll(
            '[class*="modal"], [class*="popup"], [class*="overlay"], [role="dialog"]',
          );
          return overlays.length > 0;
        });
      } catch {
        // Ignore evaluation errors
      }

      // Take screenshot
      try {
        const screenshotBuffer = await page.screenshot({
          type: "jpeg",
          quality: 70,
        });
        screenshot = screenshotBuffer.toString("base64");
      } catch {
        // Ignore screenshot errors
      }

      const finalUrl = page.url();

      // Analyze forms for cross-origin submission (Form Hijacking Detection)
      let formAnalysis: FormAnalysis[] = [];
      try {
        formAnalysis = await page.evaluate((pageOrigin: string) => {
          const forms = document.querySelectorAll("form");
          const results: FormAnalysis[] = [];
          
          forms.forEach((form, index) => {
            const action = form.getAttribute("action") || "";
            const method = (form.getAttribute("method") || "GET").toUpperCase();
            
            // Get all input fields
            const inputs = form.querySelectorAll("input, textarea, select");
            const inputFields: string[] = [];
            let hasPasswordField = false;
            let hasCreditCardField = false;
            
            inputs.forEach((input) => {
              const type = (input.getAttribute("type") || "text").toLowerCase();
              const name = (input.getAttribute("name") || "").toLowerCase();
              const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
              
              inputFields.push(type);
              
              if (type === "password") {
                hasPasswordField = true;
              }
              
              // Detect credit card fields by name, autocomplete, or pattern
              if (
                name.includes("card") || name.includes("cc-") || name.includes("credit") ||
                autocomplete.includes("cc-") || 
                type === "tel" && (name.includes("cvv") || name.includes("cvc"))
              ) {
                hasCreditCardField = true;
              }
            });
            
            // Determine action domain
            let actionDomain = "";
            let isCrossOrigin = false;
            
            try {
              if (action && !action.startsWith("#") && !action.startsWith("javascript:")) {
                const actionUrl = new URL(action, pageOrigin);
                actionDomain = actionUrl.hostname.toLowerCase();
                
                const pageHost = new URL(pageOrigin).hostname.toLowerCase();
                
                // Normalize www prefix
                const normalizeHost = (h: string) => h.replace(/^www\./, "");
                isCrossOrigin = normalizeHost(actionDomain) !== normalizeHost(pageHost);
              }
            } catch {
              // Invalid URL, skip
            }
            
            results.push({
              formIndex: index,
              action,
              actionDomain,
              method,
              hasPasswordField,
              hasCreditCardField,
              isCrossOrigin,
              inputFields,
            });
          });
          
          return results;
        }, finalUrl);
      } catch {
        // Ignore form analysis errors
      }

      return {
        screenshot,
        finalUrl,
        redirectChain,
        hasPopups,
        hasOverlays,
        downloadAttempted,
        permissionRequests,
        consoleErrors,
        networkErrors,
        loadTimeMs,
        safetyWarning,
        formAnalysis,
      };
    } finally {
      // Close context to free resources (but keep browser running)
      if (context) {
        await context.close();
      }
    }
  }

  private analyzeTestResults(
    result: BrowserTestResult,
    signals: Signal[],
  ): number {
    let score = 0;

    // Check for redirects
    if (result.redirectChain.length > 3) {
      signals.push(
        this.createSignal(
          "excessive_redirects",
          "high",
          result.redirectChain.length,
          "Excessive number of redirects",
        ),
      );
      score += 20;
    } else if (result.redirectChain.length > 1) {
      signals.push(
        this.createSignal(
          "multiple_redirects",
          "medium",
          result.redirectChain.length,
          "Multiple redirects detected",
        ),
      );
      score += 10;
    }

    // Check for cross-domain redirects (but not www variants)
    try {
      const originalHost = new URL(result.redirectChain[0] || result.finalUrl).hostname.toLowerCase();
      const finalHost = new URL(result.finalUrl).hostname.toLowerCase();
      
      // Normalize www prefix for comparison
      const normalizeHost = (host: string) => host.replace(/^www\./, "");
      const normalizedOriginal = normalizeHost(originalHost);
      const normalizedFinal = normalizeHost(finalHost);
      
      // Only flag if it's actually a different domain (not just www variant)
      if (normalizedOriginal !== normalizedFinal) {
        signals.push(
          this.createSignal(
            "cross_domain_redirect",
            "high",
            `${originalHost} → ${finalHost}`,
            "Redirected to different domain",
          ),
        );
        score += 15;
      }
    } catch {
      // Invalid URLs, skip check
    }

    // Check for popups
    if (result.hasPopups) {
      signals.push(
        this.createSignal(
          "popups_detected",
          "medium",
          true,
          "Popup dialogs detected",
        ),
      );
      score += 15;
    }

    // Check for overlays
    if (result.hasOverlays) {
      signals.push(
        this.createSignal(
          "overlays_detected",
          "medium",
          true,
          "Modal overlays detected on page load",
        ),
      );
      score += 10;
    }

    // Check for download attempts
    if (result.downloadAttempted) {
      signals.push(
        this.createSignal(
          "download_attempted",
          "critical",
          true,
          "Automatic download attempted",
        ),
      );
      score += 30;
    }

    // Check for permission requests
    if (result.permissionRequests.length > 0) {
      signals.push(
        this.createSignal(
          "permission_requests",
          "high",
          result.permissionRequests.join(", "),
          "Browser permission requests detected",
        ),
      );
      score += 15;
    }

    // Check for safety warnings
    if (result.safetyWarning) {
      signals.push(
        this.createSignal(
          "safety_warning",
          "critical",
          result.safetyWarning,
          "Browser safety warning triggered",
        ),
      );
      score += 40;
    }

    // Check for console errors
    if (result.consoleErrors.length > 5) {
      signals.push(
        this.createSignal(
          "excessive_errors",
          "medium",
          result.consoleErrors.length,
          "Excessive console errors",
        ),
      );
      score += 10;
    }

    // Check for slow load time
    if (result.loadTimeMs > 15000) {
      signals.push(
        this.createSignal(
          "slow_load",
          "medium",
          result.loadTimeMs,
          "Unusually slow page load",
        ),
      );
      score += 10;
    }

    // Check for Form Hijacking (Cross-Origin Form Submission)
    if (result.formAnalysis && result.formAnalysis.length > 0) {
      for (const form of result.formAnalysis) {
        // Critical: Password form submitting to different domain
        if (form.isCrossOrigin && form.hasPasswordField) {
          signals.push(
            this.createSignal(
              "cross_origin_password_form",
              "critical",
              `Form submits passwords to ${form.actionDomain}`,
              "CRITICAL: Password form submits to different domain (Form Hijacking)",
            ),
          );
          score += 50;
        }
        // Critical: Credit card form submitting to different domain
        else if (form.isCrossOrigin && form.hasCreditCardField) {
          signals.push(
            this.createSignal(
              "cross_origin_credential_form",
              "critical",
              `Form submits payment data to ${form.actionDomain}`,
              "CRITICAL: Payment form submits to different domain (Form Hijacking)",
            ),
          );
          score += 50;
        }
        // High: Any cross-origin form submission
        else if (form.isCrossOrigin && form.method === "POST") {
          signals.push(
            this.createSignal(
              "cross_origin_form",
              "high",
              `POST form submits to ${form.actionDomain}`,
              "Form submits data to different domain",
            ),
          );
          score += 20;
        }
      }
    }

    return Math.min(100, score);
  }
}

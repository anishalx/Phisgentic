// Tester Agent - Simulates user interaction and checks behavioral anomalies

import { BaseAgent } from "./base-agent.js";
import type { AgentResult, Signal, BrowserTestResult } from "../types/index.js";
import { chromium, Browser, Page } from "playwright";
import { CONFIG } from "../config/index.js";

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

export class TesterAgent extends BaseAgent {
  constructor() {
    super("testerAgent", "Tester Agent", SYSTEM_PROMPT);
  }

  async analyze(url: string): Promise<AgentResult & { screenshot?: string }> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let localRiskScore = 0;
    let screenshot: string | undefined;

    // Perform browser test
    let testResult: BrowserTestResult | null = null;
    try {
      testResult = await this.performBrowserTest(url);
      screenshot = testResult.screenshot;
    } catch (error) {
      console.error("Tester Agent browser test failed:", error);
      return {
        ...this.createResult(
          50,
          0.2,
          [
            this.createSignal(
              "test_failed",
              "medium",
              true,
              "Browser test failed",
            ),
          ],
          "Unable to perform browser test",
          Date.now() - startTime,
        ),
        screenshot: undefined,
      };
    }

    // Analyze test results locally
    localRiskScore = this.analyzeTestResults(testResult, signals);

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
        const allSignals = [...signals, ...llmSignals];

        const combinedScore = Math.round(
          localRiskScore * 0.4 + llmResult.riskScore * 0.6,
        );

        return {
          ...this.createResult(
            combinedScore,
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
    let browser: Browser | null = null;
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
      browser = await chromium.launch({
        headless: CONFIG.PLAYWRIGHT.HEADLESS,
      });

      const context = await browser.newContext({
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
      };
    } finally {
      if (browser) {
        await browser.close();
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

    return Math.min(100, score);
  }
}

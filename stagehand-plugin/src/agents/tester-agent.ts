// PhishGuard Plugin - Tester Agent (Self-contained)
// Adapted from server/src/agents/tester-agent.ts
// Operates on an external Playwright Page from Stagehand.
// Performs screenshot capture, form hijacking detection, and overlay checks.
// Does NOT navigate - assumes page is already loaded.

import type { Page } from "playwright";
import type { AgentResult, Signal, FormAnalysis } from "../types.js";

function createSignal(
  type: string,
  severity: Signal["severity"],
  value: string | number | boolean,
  description: string,
): Signal {
  return { type, severity, value, description };
}

export class PluginTesterAgent {
  /**
   * Perform behavioral testing on an existing Playwright Page.
   * Does NOT navigate or manage browser lifecycle.
   */
  async analyze(page: Page, url: string): Promise<AgentResult & { screenshot?: string }> {
    const startTime = Date.now();
    const signals: Signal[] = [];
    let score = 0;
    let screenshot: string | undefined;

    // Take screenshot
    try {
      const screenshotBuffer = await page.screenshot({ type: "jpeg", quality: 70 });
      screenshot = screenshotBuffer.toString("base64");
    } catch {
      // Ignore screenshot errors
    }

    const finalUrl = page.url();

    // Check for overlays/modals
    try {
      const hasOverlays = await page.evaluate(() => {
        const overlays = document.querySelectorAll(
          '[class*="modal"], [class*="popup"], [class*="overlay"], [role="dialog"]',
        );
        return overlays.length > 0;
      });
      if (hasOverlays) {
        signals.push(createSignal("overlays_detected", "medium", true, "Modal overlays detected on page"));
        score += 10;
      }
    } catch { /* ignore */ }

    // Check for cross-domain redirect (original URL vs current URL)
    try {
      const originalHost = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
      const currentHost = new URL(finalUrl).hostname.toLowerCase().replace(/^www\./, "");
      if (originalHost !== currentHost) {
        signals.push(createSignal("cross_domain_redirect", "high",
          `${originalHost} -> ${currentHost}`, "Page redirected to different domain"));
        score += 15;
      }
    } catch { /* ignore */ }

    // Form hijacking detection
    let formAnalysis: FormAnalysis[] = [];
    try {
      formAnalysis = await page.evaluate((pageOrigin: string) => {
        const forms = document.querySelectorAll("form");
        const results: FormAnalysis[] = [];

        forms.forEach((form, index) => {
          const action = form.getAttribute("action") || "";
          const method = (form.getAttribute("method") || "GET").toUpperCase();
          const inputs = form.querySelectorAll("input, textarea, select");
          const inputFields: string[] = [];
          let hasPasswordField = false;
          let hasCreditCardField = false;

          inputs.forEach((input) => {
            const type = (input.getAttribute("type") || "text").toLowerCase();
            const name = (input.getAttribute("name") || "").toLowerCase();
            const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
            inputFields.push(type);
            if (type === "password") hasPasswordField = true;
            if (
              name.includes("card") || name.includes("cc-") || name.includes("credit") ||
              autocomplete.includes("cc-") ||
              (type === "tel" && (name.includes("cvv") || name.includes("cvc")))
            ) {
              hasCreditCardField = true;
            }
          });

          let actionDomain = "";
          let isCrossOrigin = false;
          try {
            if (action && !action.startsWith("#") && !action.startsWith("javascript:")) {
              const actionUrl = new URL(action, pageOrigin);
              actionDomain = actionUrl.hostname.toLowerCase();
              const pageHost = new URL(pageOrigin).hostname.toLowerCase();
              const normalizeHost = (h: string) => h.replace(/^www\./, "");
              isCrossOrigin = normalizeHost(actionDomain) !== normalizeHost(pageHost);
            }
          } catch { /* invalid URL */ }

          results.push({
            formIndex: index, action, actionDomain, method,
            hasPasswordField, hasCreditCardField, isCrossOrigin, inputFields,
          });
        });
        return results;
      }, finalUrl);
    } catch { /* ignore */ }

    // Score form analysis results
    for (const form of formAnalysis) {
      if (form.isCrossOrigin && form.hasPasswordField) {
        signals.push(createSignal("cross_origin_password_form", "critical",
          `Form submits passwords to ${form.actionDomain}`,
          "CRITICAL: Password form submits to different domain (Form Hijacking)"));
        score += 50;
      } else if (form.isCrossOrigin && form.hasCreditCardField) {
        signals.push(createSignal("cross_origin_credential_form", "critical",
          `Form submits payment data to ${form.actionDomain}`,
          "CRITICAL: Payment form submits to different domain"));
        score += 50;
      } else if (form.isCrossOrigin && form.method === "POST") {
        signals.push(createSignal("cross_origin_form", "high",
          `POST form submits to ${form.actionDomain}`,
          "Form submits data to different domain"));
        score += 20;
      }
    }

    // Console errors check
    const consoleErrors: string[] = [];
    try {
      // We can't retroactively get console errors, but can check page state
      const errorCount = await page.evaluate(() => {
        // Check for JavaScript error indicators in the page
        return document.querySelectorAll('[class*="error"], [id*="error"]').length;
      });
      if (errorCount > 5) {
        signals.push(createSignal("excessive_errors", "medium", errorCount, "Many error elements on page"));
        score += 10;
      }
    } catch { /* ignore */ }

    score = Math.min(100, score);

    return {
      agentId: "testerAgent",
      agentName: "Tester Agent",
      riskScore: score,
      confidence: 0.6,
      signals,
      explanation: this.generateExplanation(signals, score),
      executionTimeMs: Date.now() - startTime,
      screenshot,
    };
  }

  private generateExplanation(signals: Signal[], score: number): string {
    const critical = signals.filter((s) => s.severity === "critical");
    const high = signals.filter((s) => s.severity === "high");
    if (critical.length > 0) return `CRITICAL: ${critical.map((s) => s.description).join("; ")}`;
    if (high.length > 0) return `Behavioral flags: ${high.map((s) => s.description).join("; ")}`;
    if (score < 20) return "No behavioral anomalies detected.";
    return "Browser behavior analysis complete.";
  }
}

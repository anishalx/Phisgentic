// Severity-calibration regression tests.
//
// The README per-agent signal tables document the intended severity for
// every detection. These tests pin the code to the tables so a future
// edit can't silently drift (as ip_address, suspicious_hosting,
// external_form_action, high_urgency, excessive_errors and url_length
// had) and skew the orchestrator's allow→warn bump rule.

import { describe, it, expect } from "vitest";
import { UrlAgent } from "./url-agent.js";
import { DomainAgent } from "./domain-agent.js";
import { ContentAgent } from "./content-agent.js";
import { HeuristicAgent } from "./heuristic-agent.js";

async function findSignal(url: string, type: string, analyze: (u: string) => Promise<any>) {
  const result = await analyze(url);
  return (result.signals ?? []).find((s: any) => s.type === type);
}

describe("signal severities match the README tables", () => {
  it("url_length over 100 chars is medium (README: +5 medium)", async () => {
    const url = `https://example.com/${"a".repeat(120)}`;
    const agent = new UrlAgent();
    const signal = await findSignal(url, "url_length", (u) => agent.analyze(u));
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("medium");
    expect(signal!.value).toBeGreaterThan(100);
  });

  it("suspicious_hosting is high (README: +20 high)", async () => {
    const agent = new DomainAgent();
    const result = await agent.analyze("https://evil-login.weebly.com/account");
    const signal = (result.signals ?? []).find((s) => s.type === "suspicious_hosting");
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("high");
  });

  it("external_form_action is critical (README: +25 critical)", async () => {
    const agent = new ContentAgent();
    const result = await agent.analyze({
      url: "http://evil-site.com/login",
      pageContent: {
        title: "Sign in",
        forms: [
          {
            action: "http://capture.evil.net/harvest",
            method: "POST",
            hasPasswordField: true,
            inputTypes: ["text", "password"],
          },
        ],
        links: [],
        scripts: [],
        metaTags: {},
        textContent: "Sign in to continue",
        hasPasswordField: true,
        hasLoginForm: true,
      },
    });
    const signal = (result.signals ?? []).find((s) => s.type === "external_form_action");
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("critical");
  });

  it("high_urgency (3+ urgency matches) is critical (README: +20 critical)", async () => {
    const agent = new HeuristicAgent();
    const result = await agent.analyze({
      url: "https://example.com/login",
      pageContent: {
        title: "Action Required",
        forms: [],
        links: [],
        scripts: [],
        metaTags: {},
        textContent:
          "URGENT security alert: unusual activity detected on your account. " +
          "Action required immediately — verify now to avoid suspension.",
        hasPasswordField: false,
        hasLoginForm: false,
      },
    });
    const signal = (result.signals ?? []).find((s) => s.type === "high_urgency");
    expect(signal).toBeDefined();
    expect(signal!.severity).toBe("critical");
  });
});

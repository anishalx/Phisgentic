// Unit tests for Domain Agent
import { describe, it, expect, vi, beforeEach } from "vitest";
import { DomainAgent } from "./domain-agent.js";

// Mock the Groq client to avoid API calls during tests
vi.mock("../api/groq-client.js", () => ({
  getGroqClient: () => ({
    analyzeForAgent: vi.fn().mockResolvedValue(null),
  }),
  GroqClient: vi.fn(),
}));

// Mock the Gemini client (dual-model secondary)
vi.mock("../api/gemini-client.js", () => ({
  getGeminiClient: () => ({
    analyzeForAgent: vi.fn().mockResolvedValue(null),
    isAvailable: vi.fn().mockReturnValue(false),
  }),
  GeminiClient: vi.fn(),
}));

describe("DomainAgent", () => {
  let agent: DomainAgent;

  beforeEach(() => {
    agent = new DomainAgent();
  });

  describe("analyze", () => {
    it("should return low risk for known safe domains", async () => {
      const result = await agent.analyze("https://www.google.com");
      const safeSignal = result.signals.find((s) => s.type === "known_safe");
      expect(safeSignal).toBeDefined();
      expect(result.riskScore).toBe(0);
    });

    it("should return low risk for other known safe domains", async () => {
      const result = await agent.analyze("https://github.com/user/repo");
      const safeSignal = result.signals.find((s) => s.type === "known_safe");
      expect(safeSignal).toBeDefined();
      expect(result.riskScore).toBe(0);
    });

    it("should detect suspicious domain patterns", async () => {
      const result = await agent.analyze(
        "https://login-secure-paypal.example.com"
      );
      const patternSignals = result.signals.filter(
        (s) => s.type === "suspicious_domain_pattern"
      );
      expect(patternSignals.length).toBeGreaterThan(0);
    });

    it("should detect brand name in subdomain", async () => {
      const result = await agent.analyze(
        "https://paypal.secure-login.example.com"
      );
      const brandSignal = result.signals.find(
        (s) => s.type === "brand_in_subdomain"
      );
      expect(brandSignal).toBeDefined();
      expect(brandSignal?.severity).toBe("critical");
    });

    it("should detect long domain names", async () => {
      const longDomain = "https://" + "a".repeat(60) + ".com/login";
      const result = await agent.analyze(longDomain);
      const lengthSignal = result.signals.find((s) => s.type === "long_domain");
      expect(lengthSignal).toBeDefined();
    });

    it("should detect excessive hyphens", async () => {
      const result = await agent.analyze(
        "https://secure-login-verify-account-update.example.com"
      );
      const hyphenSignal = result.signals.find(
        (s) => s.type === "excessive_hyphens" || s.type === "multiple_hyphens"
      );
      expect(hyphenSignal).toBeDefined();
    });

    it("should detect suspicious TLDs in domain", async () => {
      const result = await agent.analyze("https://secure-banking.xyz");
      const tldSignal = result.signals.find((s) => s.type === "suspicious_tld");
      expect(tldSignal).toBeDefined();
    });

    it("should handle invalid URLs gracefully", async () => {
      const result = await agent.analyze("not-a-url");
      expect(result.riskScore).toBe(50);
      expect(result.confidence).toBe(0.1);
    });
  });

  describe("safe domain detection", () => {
    const safeDomains = [
      "https://www.microsoft.com",
      "https://www.apple.com",
      "https://www.amazon.com",
      "https://www.facebook.com",
    ];

    safeDomains.forEach((domain) => {
      it(`should mark ${new URL(domain).hostname} as safe`, async () => {
        const result = await agent.analyze(domain);
        expect(result.riskScore).toBe(0);
      });
    });
  });

  describe("result structure", () => {
    it("should return valid result structure", async () => {
      const result = await agent.analyze("https://example.com");

      expect(result).toHaveProperty("agentId", "domainAgent");
      expect(result).toHaveProperty("agentName", "Domain Intelligence Agent");
      expect(result).toHaveProperty("riskScore");
      expect(result).toHaveProperty("confidence");
      expect(result).toHaveProperty("signals");
      expect(result).toHaveProperty("explanation");
      expect(result).toHaveProperty("executionTimeMs");

      expect(typeof result.executionTimeMs).toBe("number");
      expect(result.executionTimeMs).toBeGreaterThanOrEqual(0);
    });
  });
});

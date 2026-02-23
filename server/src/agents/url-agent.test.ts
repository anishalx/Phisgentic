// Unit tests for URL Agent
import { describe, it, expect, vi, beforeEach } from "vitest";
import { UrlAgent } from "./url-agent.js";

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

describe("UrlAgent", () => {
  let agent: UrlAgent;

  beforeEach(() => {
    agent = new UrlAgent();
  });

  describe("analyze", () => {
    it("should return low risk for safe URLs", async () => {
      const result = await agent.analyze("https://www.google.com");
      expect(result.riskScore).toBeLessThan(30);
      expect(result.agentId).toBe("urlAgent");
      expect(result.agentName).toBe("URL Analysis Agent");
    });

    it("should detect IP address URLs as high risk", async () => {
      const result = await agent.analyze("http://192.168.1.1/login");
      expect(result.riskScore).toBeGreaterThan(20);
      const ipSignal = result.signals.find((s) => s.type === "ip_address");
      expect(ipSignal).toBeDefined();
      expect(ipSignal?.severity).toBe("critical");
    });

    it("should detect suspicious TLDs", async () => {
      const result = await agent.analyze("https://example.xyz/secure");
      const tldSignal = result.signals.find((s) => s.type === "suspicious_tld");
      expect(tldSignal).toBeDefined();
    });

    it("should detect URL shorteners", async () => {
      const result = await agent.analyze("https://bit.ly/abc123");
      const shortenerSignal = result.signals.find(
        (s) => s.type === "url_shortener"
      );
      expect(shortenerSignal).toBeDefined();
    });

    it("should detect long URLs", async () => {
      const longUrl =
        "https://example.com/" + "a".repeat(100) + "/login/verify";
      const result = await agent.analyze(longUrl);
      const lengthSignal = result.signals.find((s) => s.type === "url_length");
      expect(lengthSignal).toBeDefined();
    });

    it("should detect excessive subdomains", async () => {
      const result = await agent.analyze(
        "https://login.secure.account.verify.example.com/auth"
      );
      const subdomainSignal = result.signals.find(
        (s) => s.type === "subdomain_depth"
      );
      expect(subdomainSignal).toBeDefined();
    });

    it("should detect phishing keywords", async () => {
      const result = await agent.analyze(
        "https://example.com/secure-login-verify-account"
      );
      const keywordSignal = result.signals.find(
        (s) => s.type === "phishing_keywords"
      );
      expect(keywordSignal).toBeDefined();
    });

    it("should detect HTTP (non-secure) connections", async () => {
      const result = await agent.analyze("http://example.com/login");
      const httpsSignal = result.signals.find((s) => s.type === "no_https");
      expect(httpsSignal).toBeDefined();
      expect(httpsSignal?.severity).toBe("medium");
    });

    it("should detect non-standard ports", async () => {
      const result = await agent.analyze("https://example.com:8443/login");
      const portSignal = result.signals.find(
        (s) => s.type === "non_standard_port"
      );
      expect(portSignal).toBeDefined();
    });

    it("should return error result for invalid URLs", async () => {
      const result = await agent.analyze("not-a-valid-url");
      expect(result.riskScore).toBe(50); // Neutral error score
      expect(result.confidence).toBe(0.1); // Low confidence
    });

    it("should detect encoded characters", async () => {
      const result = await agent.analyze(
        "https://example.com/login%2Fverify%20account"
      );
      const encodedSignal = result.signals.find(
        (s) => s.type === "encoded_chars"
      );
      expect(encodedSignal).toBeDefined();
    });
  });

  describe("result structure", () => {
    it("should always return valid result structure", async () => {
      const result = await agent.analyze("https://www.example.com");

      expect(result).toHaveProperty("agentId");
      expect(result).toHaveProperty("agentName");
      expect(result).toHaveProperty("riskScore");
      expect(result).toHaveProperty("confidence");
      expect(result).toHaveProperty("signals");
      expect(result).toHaveProperty("explanation");
      expect(result).toHaveProperty("executionTimeMs");

      expect(typeof result.riskScore).toBe("number");
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);

      expect(typeof result.confidence).toBe("number");
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);

      expect(Array.isArray(result.signals)).toBe(true);
    });
  });
});

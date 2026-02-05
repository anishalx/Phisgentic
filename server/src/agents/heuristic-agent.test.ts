// Unit tests for Heuristic Agent
import { describe, it, expect, vi, beforeEach } from "vitest";
import { HeuristicAgent } from "./heuristic-agent.js";
import type { PageContent } from "../types/index.js";

// Mock the Groq client to avoid API calls during tests
vi.mock("../api/groq-client.js", () => ({
  getGroqClient: () => ({
    analyzeForAgent: vi.fn().mockResolvedValue(null),
  }),
  GroqClient: vi.fn(),
}));

describe("HeuristicAgent", () => {
  let agent: HeuristicAgent;

  beforeEach(() => {
    agent = new HeuristicAgent();
  });

  describe("URL heuristics", () => {
    it("should detect urgency patterns in URL", async () => {
      const result = await agent.analyze({
        url: "https://example.com/act-now-limited-time",
      });
      const urgencySignal = result.signals.find(
        (s) => s.type === "urgency_in_url"
      );
      expect(urgencySignal).toBeDefined();
    });

    it("should detect suspicious URL parameters", async () => {
      const result = await agent.analyze({
        url: "https://example.com/page?verify=1&token=abc&session=xyz",
      });
      const paramSignal = result.signals.find(
        (s) => s.type === "suspicious_params"
      );
      expect(paramSignal).toBeDefined();
    });

    it("should detect base64-like encoded data in URL", async () => {
      const result = await agent.analyze({
        url: "https://example.com/redirect?data=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=",
      });
      const encodedSignal = result.signals.find(
        (s) => s.type === "encoded_data"
      );
      expect(encodedSignal).toBeDefined();
    });
  });

  describe("content heuristics", () => {
    const createMockContent = (text: string, title = "Test Page"): PageContent => ({
      title,
      forms: [],
      links: [],
      scripts: [],
      metaTags: {},
      textContent: text,
      hasPasswordField: false,
      hasLoginForm: false,
    });

    it("should detect urgency language in content", async () => {
      const content = createMockContent(
        "Act now! This is urgent. Limited time offer expires immediately!"
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const urgencySignal = result.signals.find(
        (s) =>
          s.type === "urgency_language" || s.type === "high_urgency"
      );
      expect(urgencySignal).toBeDefined();
    });

    it("should detect threat language", async () => {
      const content = createMockContent(
        "Your account has been suspended. Unauthorized access detected. Account disabled."
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const threatSignal = result.signals.find(
        (s) => s.type === "threat_language" || s.type === "high_threat"
      );
      expect(threatSignal).toBeDefined();
    });

    it("should detect sensitive data requests", async () => {
      const content = createMockContent(
        "Please enter your social security number and credit card details"
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const sensitiveSignal = result.signals.find(
        (s) => s.type === "sensitive_data_request"
      );
      expect(sensitiveSignal).toBeDefined();
      expect(sensitiveSignal?.severity).toBe("critical");
    });

    it("should detect reward scam language", async () => {
      const content = createMockContent(
        "Congratulations! You have won a free iPhone! Claim your prize now!"
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const rewardSignal = result.signals.find((s) => s.type === "reward_scam");
      expect(rewardSignal).toBeDefined();
    });

    it("should detect manipulative page titles", async () => {
      const content = createMockContent(
        "Normal content here",
        "Verify Your Account - Secure Login"
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const titleSignal = result.signals.find(
        (s) => s.type === "manipulative_title"
      );
      expect(titleSignal).toBeDefined();
    });

    it("should detect poor grammar/typos", async () => {
      const content = createMockContent(
        "We recieve your request. Your account have been updated."
      );
      const result = await agent.analyze({
        url: "https://example.com",
        pageContent: content,
      });
      const grammarSignal = result.signals.find(
        (s) => s.type === "poor_grammar"
      );
      expect(grammarSignal).toBeDefined();
    });
  });

  describe("combined analysis", () => {
    it("should return high risk for multiple indicators", async () => {
      const content: PageContent = {
        title: "Verify Account - Urgent",
        forms: [],
        links: [],
        scripts: [],
        metaTags: {},
        textContent:
          "Your account has been suspended! Act now to verify your identity. Enter your credit card number immediately.",
        hasPasswordField: true,
        hasLoginForm: true,
      };

      const result = await agent.analyze({
        url: "https://example.com/verify?token=abc",
        pageContent: content,
      });

      expect(result.riskScore).toBeGreaterThan(30);
      expect(result.signals.length).toBeGreaterThan(2);
    });

    it("should return low risk for clean content", async () => {
      const content: PageContent = {
        title: "Welcome to Example",
        forms: [],
        links: [],
        scripts: [],
        metaTags: {},
        textContent: "Welcome to our website. We provide quality services.",
        hasPasswordField: false,
        hasLoginForm: false,
      };

      const result = await agent.analyze({
        url: "https://example.com/about",
        pageContent: content,
      });

      expect(result.riskScore).toBeLessThan(30);
    });
  });

  describe("result structure", () => {
    it("should return valid result structure", async () => {
      const result = await agent.analyze({ url: "https://example.com" });

      expect(result).toHaveProperty("agentId", "heuristicAgent");
      expect(result).toHaveProperty("agentName", "Heuristic Analysis Agent");
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(Array.isArray(result.signals)).toBe(true);
    });
  });
});

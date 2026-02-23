// Unit tests for BaseAgent — dual-model consensus logic
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LLMAnalysisResult, Signal, AgentResult } from "../types/index.js";

// We'll create a concrete subclass to test the abstract BaseAgent methods

// Mock Groq client
const mockGroqAnalyze = vi.fn();
vi.mock("../api/groq-client.js", () => ({
  getGroqClient: () => ({
    analyzeForAgent: mockGroqAnalyze,
  }),
  GroqClient: vi.fn(),
}));

// Mock Gemini client
const mockGeminiAnalyze = vi.fn();
const mockGeminiIsAvailable = vi.fn();
vi.mock("../api/gemini-client.js", () => ({
  getGeminiClient: () => ({
    analyzeForAgent: mockGeminiAnalyze,
    isAvailable: mockGeminiIsAvailable,
  }),
  GeminiClient: vi.fn(),
}));

// Mock config to control dual-model settings
vi.mock("../config/index.js", async () => {
  const actual = await vi.importActual<typeof import("../config/index.js")>("../config/index.js");
  return {
    CONFIG: {
      ...actual.CONFIG,
      DUAL_MODEL: {
        ENABLED: true,
        CONSENSUS_THRESHOLD: 15,
        DISAGREEMENT_STRATEGY: "conservative" as const,
      },
    },
  };
});

// Import after mocks
import { BaseAgent } from "./base-agent.js";

// Create a concrete test implementation
class TestAgent extends BaseAgent {
  constructor() {
    super("testAgent", "Test Agent", "You are a test agent.");
  }

  async analyze(data: unknown): Promise<AgentResult> {
    const { result, comparison } = await this.dualModelAnalyze(data as object);
    if (result) {
      return this.createResult(
        result.riskScore,
        result.confidence,
        result.signals,
        result.explanation,
        result.latencyMs,
      );
    }
    return this.createErrorResult("Both models failed", 0);
  }

  // Expose protected methods for testing
  public testDualModelAnalyze(data: object) {
    return this.dualModelAnalyze(data);
  }

  public testCreateSignal(type: string, severity: Signal["severity"], value: string | number | boolean, description: string) {
    return this.createSignal(type, severity, value, description);
  }

  public testCreateResult(riskScore: number, confidence: number, signals: Signal[], explanation: string, executionTimeMs: number) {
    return this.createResult(riskScore, confidence, signals, explanation, executionTimeMs);
  }

  public testCreateErrorResult(error: string, executionTimeMs: number) {
    return this.createErrorResult(error, executionTimeMs);
  }
}

function makeResult(overrides: Partial<LLMAnalysisResult> = {}): LLMAnalysisResult {
  return {
    riskScore: 50,
    confidence: 0.8,
    signals: [],
    explanation: "Test explanation",
    model: "test-model",
    latencyMs: 100,
    ...overrides,
  };
}

describe("BaseAgent", () => {
  let agent: TestAgent;

  beforeEach(() => {
    vi.clearAllMocks();
    agent = new TestAgent();
  });

  describe("createSignal", () => {
    it("should create a properly structured signal", () => {
      const signal = agent.testCreateSignal("test_signal", "high", "some value", "A test signal");
      expect(signal).toEqual({
        type: "test_signal",
        severity: "high",
        value: "some value",
        description: "A test signal",
      });
    });

    it("should handle boolean and numeric values", () => {
      const boolSignal = agent.testCreateSignal("bool_test", "low", true, "Boolean");
      expect(boolSignal.value).toBe(true);

      const numSignal = agent.testCreateSignal("num_test", "medium", 42, "Numeric");
      expect(numSignal.value).toBe(42);
    });
  });

  describe("createResult", () => {
    it("should clamp riskScore to 0-100", () => {
      const result = agent.testCreateResult(150, 0.5, [], "over", 10);
      expect(result.riskScore).toBe(100);

      const result2 = agent.testCreateResult(-20, 0.5, [], "under", 10);
      expect(result2.riskScore).toBe(0);
    });

    it("should clamp confidence to 0-1", () => {
      const result = agent.testCreateResult(50, 1.5, [], "over", 10);
      expect(result.confidence).toBe(1);

      const result2 = agent.testCreateResult(50, -0.5, [], "under", 10);
      expect(result2.confidence).toBe(0);
    });

    it("should include agentId and agentName", () => {
      const result = agent.testCreateResult(50, 0.8, [], "test", 100);
      expect(result.agentId).toBe("testAgent");
      expect(result.agentName).toBe("Test Agent");
      expect(result.executionTimeMs).toBe(100);
    });
  });

  describe("createErrorResult", () => {
    it("should return neutral score with low confidence", () => {
      const result = agent.testCreateErrorResult("Something failed", 200);
      expect(result.riskScore).toBe(50);
      expect(result.confidence).toBe(0.1);
      expect(result.signals).toHaveLength(1);
      expect(result.signals[0].type).toBe("error");
      expect(result.explanation).toContain("Something failed");
      expect(result.executionTimeMs).toBe(200);
    });
  });

  describe("dualModelAnalyze — single model mode", () => {
    it("should use only Groq when Gemini is unavailable", async () => {
      mockGeminiIsAvailable.mockReturnValue(false);
      const groqResult = makeResult({ riskScore: 70 });
      mockGroqAnalyze.mockResolvedValue(groqResult);

      const { result, comparison } = await agent.testDualModelAnalyze({ test: true });

      expect(result).toEqual(groqResult);
      expect(comparison).toBeUndefined();
      expect(mockGroqAnalyze).toHaveBeenCalledTimes(1);
      expect(mockGeminiAnalyze).not.toHaveBeenCalled();
    });

    it("should return null result when Groq fails in single mode", async () => {
      mockGeminiIsAvailable.mockReturnValue(false);
      mockGroqAnalyze.mockResolvedValue(null);

      const { result } = await agent.testDualModelAnalyze({ test: true });
      expect(result).toBeNull();
    });
  });

  describe("dualModelAnalyze — dual model mode", () => {
    beforeEach(() => {
      mockGeminiIsAvailable.mockReturnValue(true);
    });

    it("should run both models in parallel when both available", async () => {
      const groqResult = makeResult({ riskScore: 60, confidence: 0.8, model: "groq-llama" });
      const geminiResult = makeResult({ riskScore: 65, confidence: 0.7, model: "gemini-flash" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result, comparison } = await agent.testDualModelAnalyze({ test: true });

      expect(mockGroqAnalyze).toHaveBeenCalledTimes(1);
      expect(mockGeminiAnalyze).toHaveBeenCalledTimes(1);
      expect(result).not.toBeNull();
      expect(comparison).toBeDefined();
      expect(comparison!.agreed).toBe(true); // diff = 5, within threshold 15
      expect(comparison!.strategy).toBe("consensus-average");
    });

    it("should return null when both models fail", async () => {
      mockGroqAnalyze.mockResolvedValue(null);
      mockGeminiAnalyze.mockResolvedValue(null);

      const { result } = await agent.testDualModelAnalyze({ test: true });
      expect(result).toBeNull();
    });

    it("should use Gemini only when Groq fails", async () => {
      mockGroqAnalyze.mockResolvedValue(null);
      const geminiResult = makeResult({ riskScore: 55 });
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result, comparison } = await agent.testDualModelAnalyze({ test: true });

      expect(result).toEqual(geminiResult);
      expect(comparison).toBeDefined();
      expect(comparison!.strategy).toBe("single-model-fallback");
      expect(comparison!.agreed).toBe(true);
    });

    it("should use Groq only when Gemini fails", async () => {
      const groqResult = makeResult({ riskScore: 45 });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(null);

      const { result, comparison } = await agent.testDualModelAnalyze({ test: true });

      expect(result).toEqual(groqResult);
      expect(comparison).toBeDefined();
      expect(comparison!.strategy).toBe("single-model-fallback");
      expect(comparison!.agreed).toBe(true);
    });
  });

  describe("consensus logic", () => {
    beforeEach(() => {
      mockGeminiIsAvailable.mockReturnValue(true);
    });

    it("should use confidence-weighted average when models agree (diff <= 15)", async () => {
      // Groq: 60, conf 0.8 | Gemini: 70, conf 0.6 → diff = 10 ≤ 15 → agreed
      // Weighted avg: (60*0.8 + 70*0.6) / (0.8+0.6) = (48+42)/1.4 = 64.28 → 64
      const groqResult = makeResult({ riskScore: 60, confidence: 0.8, model: "groq" });
      const geminiResult = makeResult({ riskScore: 70, confidence: 0.6, model: "gemini" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result, comparison } = await agent.testDualModelAnalyze({});

      expect(comparison!.agreed).toBe(true);
      expect(comparison!.scoreDifference).toBe(10);
      expect(comparison!.strategy).toBe("consensus-average");
      expect(comparison!.consensusScore).toBe(64);
    });

    it("should use conservative strategy (max) when models disagree (diff > 15)", async () => {
      // Groq: 20, Gemini: 80 → diff = 60 > 15 → disagreement → conservative = max(20, 80) = 80
      const groqResult = makeResult({ riskScore: 20, confidence: 0.8, model: "groq" });
      const geminiResult = makeResult({ riskScore: 80, confidence: 0.7, model: "gemini" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result, comparison } = await agent.testDualModelAnalyze({});

      expect(comparison!.agreed).toBe(false);
      expect(comparison!.scoreDifference).toBe(60);
      expect(comparison!.strategy).toBe("disagreement-conservative");
      expect(comparison!.consensusScore).toBe(80);
    });

    it("should merge signals from both models, deduplicating by type+severity", async () => {
      const groqResult = makeResult({
        riskScore: 50,
        signals: [
          { type: "ip_address", severity: "critical", value: "192.168.1.1", description: "IP address" },
          { type: "no_https", severity: "medium", value: "http", description: "No HTTPS" },
        ],
      });
      const geminiResult = makeResult({
        riskScore: 55,
        signals: [
          { type: "ip_address", severity: "critical", value: "192.168.1.1", description: "IP from gemini" },
          { type: "phishing_keywords", severity: "high", value: "login", description: "Phishing keyword" },
        ],
      });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});

      // ip_address:critical deduplicated, unique: no_https:medium + phishing_keywords:high
      expect(result!.signals).toHaveLength(3);
      // Groq signals come first
      expect(result!.signals[0].type).toBe("ip_address");
      expect(result!.signals[0].description).toBe("IP address"); // Groq's version kept
      expect(result!.signals[1].type).toBe("no_https");
      expect(result!.signals[2].type).toBe("phishing_keywords");
    });

    it("should use max confidence from both models", async () => {
      const groqResult = makeResult({ riskScore: 50, confidence: 0.6 });
      const geminiResult = makeResult({ riskScore: 50, confidence: 0.9 });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});
      expect(result!.confidence).toBe(0.9);
    });

    it("should use max latency from both models", async () => {
      const groqResult = makeResult({ riskScore: 50, latencyMs: 200 });
      const geminiResult = makeResult({ riskScore: 50, latencyMs: 500 });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});
      expect(result!.latencyMs).toBe(500);
    });

    it("should create consensus model name", async () => {
      const groqResult = makeResult({ riskScore: 50, model: "llama-70b" });
      const geminiResult = makeResult({ riskScore: 50, model: "gemini-flash" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});
      expect(result!.model).toBe("consensus(llama-70b+gemini-flash)");
    });

    it("should show both explanations when models disagree", async () => {
      const groqResult = makeResult({ riskScore: 10, explanation: "Looks safe" });
      const geminiResult = makeResult({ riskScore: 80, explanation: "Very suspicious" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});
      expect(result!.explanation).toContain("Groq: 10/100");
      expect(result!.explanation).toContain("Gemini: 80/100");
      expect(result!.explanation).toContain("Looks safe");
      expect(result!.explanation).toContain("Very suspicious");
    });

    it("should use Groq explanation when models agree", async () => {
      const groqResult = makeResult({ riskScore: 50, explanation: "Groq says it's fine" });
      const geminiResult = makeResult({ riskScore: 55, explanation: "Gemini agrees" });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result } = await agent.testDualModelAnalyze({});
      expect(result!.explanation).toBe("Groq says it's fine");
    });

    it("should handle equal confidence zero (fallback to simple average)", async () => {
      const groqResult = makeResult({ riskScore: 40, confidence: 0 });
      const geminiResult = makeResult({ riskScore: 60, confidence: 0 });
      mockGroqAnalyze.mockResolvedValue(groqResult);
      mockGeminiAnalyze.mockResolvedValue(geminiResult);

      const { result, comparison } = await agent.testDualModelAnalyze({});
      // diff = 20 > threshold 15 → disagreed → conservative → max(40,60) = 60
      expect(comparison!.agreed).toBe(false);
      expect(comparison!.consensusScore).toBe(60);
    });
  });
});

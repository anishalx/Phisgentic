// End-to-end veto tests with BOTH LLM clients mocked (single-model mode).
//
// Proves the origin guard holds through the real orchestrator pipeline:
//   1. A locally-detected veto (typosquatting) still BLOCKS even when the
//      LLM disagrees and says the URL is safe.
//   2. An LLM hallucinating a veto-list signal (typosquatting, critical)
//      on a clean URL does NOT block — it can only bump allow→warn.
//
// URL and Domain agents run their REAL local logic; only the LLM clients
// (Groq/Gemini) and the browser-dependent agents (tester/content/heuristic)
// are mocked so the pipeline is hermetic and fast.

import { vi, describe, it, expect, beforeEach } from "vitest";

const { groqAnalyze, geminiIsAvailable } = vi.hoisted(() => ({
  groqAnalyze: vi.fn(),
  geminiIsAvailable: vi.fn(),
}));

vi.mock("../api/groq-client.js", () => ({
  getGroqClient: () => ({ analyzeForAgent: groqAnalyze }),
  GroqClient: class {},
}));
vi.mock("../api/gemini-client.js", () => ({
  getGeminiClient: () => ({
    isAvailable: geminiIsAvailable,
    analyzeForAgent: vi.fn(),
  }),
  GeminiClient: class {},
}));

vi.mock("./tester-agent.js", () => ({
  TesterAgent: class {
    async analyze() {
      return {
        agentId: "testerAgent",
        agentName: "Tester Agent",
        riskScore: 0,
        confidence: 0.1,
        signals: [],
        explanation: "mocked",
        executionTimeMs: 1,
      };
    }
  },
  closeBrowser: async () => {},
}));
vi.mock("./content-agent.js", () => ({
  ContentAgent: class {
    async analyze() {
      return {
        agentId: "contentAgent",
        agentName: "Content Analyzer",
        riskScore: 0,
        confidence: 0.1,
        signals: [],
        explanation: "mocked",
        executionTimeMs: 1,
      };
    }
  },
}));
vi.mock("./heuristic-agent.js", () => ({
  HeuristicAgent: class {
    async analyze() {
      return {
        agentId: "heuristicAgent",
        agentName: "Heuristic Agent",
        riskScore: 0,
        confidence: 0.1,
        signals: [],
        explanation: "mocked",
        executionTimeMs: 1,
      };
    }
  },
}));

import { Orchestrator } from "./orchestrator.js";

function llmOk(riskScore: number, signals: any[]) {
  return {
    riskScore,
    confidence: 0.9,
    signals,
    explanation: "mocked LLM",
    model: "mock",
    latencyMs: 5,
  };
}

describe("orchestrator vetoes vs mocked LLM output", () => {
  beforeEach(() => {
    geminiIsAvailable.mockReturnValue(false); // single-model (Groq) mode
    groqAnalyze.mockReset();
  });

  it("still BLOCKS on a local typosquatting veto even when the LLM calls it safe", async () => {
    // LLM (Groq) says the URL is perfectly safe, no signals.
    groqAnalyze.mockResolvedValue(llmOk(5, []));

    const orchestrator = new Orchestrator();
    const { verdict } = await orchestrator.analyzeUrl("https://paypa1.com/login");

    expect(verdict.action).toBe("block");
    expect(verdict.overallRiskScore).toBeGreaterThanOrEqual(85);
  });

  it("does NOT block when the LLM hallucinates a veto-list signal on a clean URL", async () => {
    // LLM insists this clean URL shows critical typosquatting.
    groqAnalyze.mockResolvedValue(
      llmOk(80, [
        {
          type: "typosquatting",
          severity: "critical",
          value: "paypal",
          description: "LLM hallucinated veto",
          origin: "llm",
        },
      ]),
    );

    const orchestrator = new Orchestrator();
    const { verdict } = await orchestrator.analyzeUrl(
      "http://legitcorp-blog.example.org/login",
    );

    // Never an instant block from an LLM-suggested veto type.
    expect(verdict.action).not.toBe("block");
    // The critical LLM signal may still bump allow→warn (conservative), which is fine.
    expect(["allow", "warn"]).toContain(verdict.action);
  });
});

// Unit tests for Orchestrator — verdict logic, safe domain detection, timeout
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AgentResult, Signal } from "../types/index.js";

// Mock all agents to avoid real API calls and browser launches
vi.mock("./url-agent.js", () => ({
  UrlAgent: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue(null),
  })),
}));
vi.mock("./domain-agent.js", () => ({
  DomainAgent: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue(null),
  })),
}));
vi.mock("./content-agent.js", () => ({
  ContentAgent: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue(null),
  })),
}));
vi.mock("./heuristic-agent.js", () => ({
  HeuristicAgent: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue(null),
  })),
}));
vi.mock("./tester-agent.js", () => ({
  TesterAgent: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue(null),
  })),
}));

// Import after mocks
import { Orchestrator } from "./orchestrator.js";
import { UrlAgent } from "./url-agent.js";
import { DomainAgent } from "./domain-agent.js";
import { ContentAgent } from "./content-agent.js";
import { HeuristicAgent } from "./heuristic-agent.js";
import { TesterAgent } from "./tester-agent.js";

function makeAgentResult(overrides: Partial<AgentResult> = {}): AgentResult {
  return {
    agentId: "testAgent",
    agentName: "Test Agent",
    riskScore: 30,
    confidence: 0.8,
    signals: [],
    explanation: "Test result",
    executionTimeMs: 100,
    ...overrides,
  };
}

function makeSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    type: "test_signal",
    severity: "medium",
    value: "test",
    description: "A test signal",
    ...overrides,
  };
}

describe("Orchestrator", () => {
  let orchestrator: Orchestrator;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = new Orchestrator();
  });

  describe("safe domain fast-track", () => {
    it("should fast-track google.com as safe", async () => {
      // Set up agents to return results (tester returns low risk, others return low risk)
      const testerMock = vi.mocked(TesterAgent).mock.results[0]?.value;
      if (testerMock) {
        testerMock.analyze.mockResolvedValue(makeAgentResult({ agentId: "testerAgent", riskScore: 5 }));
      }

      const urlMock = vi.mocked(UrlAgent).mock.results[0]?.value;
      if (urlMock) urlMock.analyze.mockResolvedValue(makeAgentResult({ agentId: "urlAgent", riskScore: 5 }));

      const domainMock = vi.mocked(DomainAgent).mock.results[0]?.value;
      if (domainMock) domainMock.analyze.mockResolvedValue(makeAgentResult({ agentId: "domainAgent", riskScore: 0 }));

      const contentMock = vi.mocked(ContentAgent).mock.results[0]?.value;
      if (contentMock) contentMock.analyze.mockResolvedValue(makeAgentResult({ agentId: "contentAgent", riskScore: 5 }));

      const heuristicMock = vi.mocked(HeuristicAgent).mock.results[0]?.value;
      if (heuristicMock) heuristicMock.analyze.mockResolvedValue(makeAgentResult({ agentId: "heuristicAgent", riskScore: 5 }));

      const result = await orchestrator.analyzeUrl("https://www.google.com/search");

      expect(result.verdict.action).toBe("allow");
      expect(result.verdict.overallRiskScore).toBe(0);
      expect(result.verdict.confidence).toBe(0.99);
      expect(result.verdict.summary).toContain("trusted domain");
    });
  });

  describe("calculateVerdictWithVeto — direct testing via analyzeUrl", () => {
    it("should return warn when all agents fail", async () => {
      // All agents return null (timeout/fail)
      const result = await orchestrator.analyzeUrl("https://suspicious-site.xyz");

      expect(result.verdict.action).toBe("warn");
      expect(result.verdict.overallRiskScore).toBe(60);
      expect(result.verdict.confidence).toBe(0.3);
    });
  });

  describe("calculateVerdictWithVeto — unit testing", () => {
    // To properly test the private calculateVerdictWithVeto method,
    // we test through the orchestrator with controlled agent results.

    it("should block when a critical veto signal is present", async () => {
      // Set tester to return critical signal
      const testerMock = vi.mocked(TesterAgent).mock.results[0]?.value;
      testerMock?.analyze.mockResolvedValue(makeAgentResult({
        agentId: "testerAgent",
        riskScore: 90,
        signals: [makeSignal({ type: "brand_impersonation", severity: "critical", description: "PayPal impersonation" })],
      }));

      // Other agents return low risk
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "urlAgent", riskScore: 20, signals: [] })
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 30, signals: [] })
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 25, signals: [] })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 15, signals: [] })
      );

      const result = await orchestrator.analyzeUrl("https://paypal-verify.xyz/login");

      expect(result.verdict.action).toBe("block");
      expect(result.verdict.overallRiskScore).toBeGreaterThanOrEqual(85);
      expect(result.verdict.summary).toContain("Critical threat");
    });

    it("should block when a single agent scores >= 75 (single agent conviction)", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "testerAgent", riskScore: 10 })
      );
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "urlAgent", riskScore: 80 }) // >= 75
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 20 })
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 15 })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 10 })
      );

      const result = await orchestrator.analyzeUrl("https://suspicion.example.xyz");
      expect(result.verdict.action).toBe("block");
      expect(result.verdict.overallRiskScore).toBe(80);
    });

    it("should block when 2+ agents have score > 50 (consensus)", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "testerAgent", riskScore: 10 })
      );
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "urlAgent", riskScore: 60 }) // > 50
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 55 }) // > 50
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 20 })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 10 })
      );

      const result = await orchestrator.analyzeUrl("https://suspicious-example.xyz");
      expect(result.verdict.action).toBe("block");
      // avgSuspiciousScore = (60+55)/2 = 57.5 → 58, max(65, 58) = 65
      expect(result.verdict.overallRiskScore).toBeGreaterThanOrEqual(65);
    });

    it("should allow when all agents report low risk", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "testerAgent", riskScore: 5, confidence: 0.9 })
      );
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "urlAgent", riskScore: 10, confidence: 0.9 })
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 5, confidence: 0.9 })
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 10, confidence: 0.9 })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 5, confidence: 0.9 })
      );

      const result = await orchestrator.analyzeUrl("https://legit-site.com");
      expect(result.verdict.action).toBe("allow");
      expect(result.verdict.overallRiskScore).toBeLessThanOrEqual(25);
    });

    it("should bump allow to warn when high-severity signal present", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "testerAgent", riskScore: 5, confidence: 0.9 })
      );
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({
          agentId: "urlAgent",
          riskScore: 15,
          confidence: 0.9,
          signals: [makeSignal({ severity: "high", type: "suspicious_tld", description: "Suspicious TLD" })],
        })
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 10, confidence: 0.9 })
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 5, confidence: 0.9 })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 5, confidence: 0.9 })
      );

      const result = await orchestrator.analyzeUrl("https://legit-site.xyz");
      // Weighted average should be ≤ 25 (allow zone), but high signal bumps to warn
      expect(result.verdict.action).toBe("warn");
    });
  });

  describe("logging", () => {
    it("should produce logs for each agent", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "testerAgent", riskScore: 10 })
      );
      vi.mocked(UrlAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "urlAgent", riskScore: 10 })
      );
      vi.mocked(DomainAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "domainAgent", riskScore: 10 })
      );
      vi.mocked(ContentAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "contentAgent", riskScore: 10 })
      );
      vi.mocked(HeuristicAgent).mock.results[0]?.value?.analyze.mockResolvedValue(
        makeAgentResult({ agentId: "heuristicAgent", riskScore: 10 })
      );

      const result = await orchestrator.analyzeUrl("https://example.com");

      expect(result.logs.length).toBeGreaterThan(0);
      // Should have orchestrator start log, agent start logs, agent completion logs, final verdict log
      const orchestratorLogs = result.logs.filter(l => l.agentId === "orchestrator");
      expect(orchestratorLogs.length).toBeGreaterThanOrEqual(2); // start + final

      const testerLogs = result.logs.filter(l => l.agentId === "testerAgent");
      expect(testerLogs.length).toBeGreaterThanOrEqual(1);
    });

    it("should call onLog callback when provided", async () => {
      const onLog = vi.fn();
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(null);

      await orchestrator.analyzeUrl("https://example.com", onLog);

      expect(onLog).toHaveBeenCalled();
      expect(onLog.mock.calls.length).toBeGreaterThan(0);
    });
  });

  describe("verdict structure", () => {
    it("should always include url and timestamp in verdict", async () => {
      vi.mocked(TesterAgent).mock.results[0]?.value?.analyze.mockResolvedValue(null);

      const result = await orchestrator.analyzeUrl("https://test.example.com");

      expect(result.verdict.url).toBe("https://test.example.com");
      expect(result.verdict.timestamp).toBeGreaterThan(0);
      expect(typeof result.verdict.summary).toBe("string");
      expect(["allow", "warn", "block"]).toContain(result.verdict.action);
    });
  });
});

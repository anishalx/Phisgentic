// PhishGuard Stagehand Plugin - Core Detector / Orchestrator
// Runs all 5 agents (full mode) or URL+Domain only (fast mode).
// Applies Critical Veto Logic and weighted scoring.

import type { Page } from "playwright";
import type { AgentResult, Signal, PhishGuardResult } from "./types.js";
import {
  PluginUrlAgent,
  PluginDomainAgent,
  PluginContentAgent,
  PluginHeuristicAgent,
  PluginTesterAgent,
} from "./agents/index.js";
import {
  SAFE_DOMAINS,
  CRITICAL_VETO_SIGNALS,
  AGENT_WEIGHTS,
  THRESHOLDS,
} from "./agents/config.js";

export class PhishGuardDetector {
  private urlAgent: PluginUrlAgent;
  private domainAgent: PluginDomainAgent;
  private contentAgent: PluginContentAgent;
  private heuristicAgent: PluginHeuristicAgent;
  private testerAgent: PluginTesterAgent;

  constructor() {
    this.urlAgent = new PluginUrlAgent();
    this.domainAgent = new PluginDomainAgent();
    this.contentAgent = new PluginContentAgent();
    this.heuristicAgent = new PluginHeuristicAgent();
    this.testerAgent = new PluginTesterAgent();
  }

  /**
   * Full scan: runs all 5 agents with the provided page.
   * URL + Domain run in parallel, then Content + Heuristic + Tester in parallel.
   */
  async scanFull(url: string, page: Page): Promise<PhishGuardResult> {
    const startTime = Date.now();

    // Safe domain fast-track
    const safeDomainResult = this.checkSafeDomain(url);
    if (safeDomainResult) {
      return {
        ...safeDomainResult,
        mode: "full",
        scanTimeMs: Date.now() - startTime,
      };
    }

    // Phase 1: URL + Domain agents (no page needed)
    const [urlResult, domainResult] = await Promise.all([
      this.safeRun(() => this.urlAgent.analyze(url), "urlAgent", "URL Analysis Agent"),
      this.safeRun(() => this.domainAgent.analyze(url), "domainAgent", "Domain Intelligence Agent"),
    ]);

    // Phase 2: Content + Heuristic + Tester agents (page needed)
    const [contentResult, heuristicResult, testerResult] = await Promise.all([
      this.safeRun(() => this.contentAgent.analyze(page, url), "contentAgent", "Content Analyzer"),
      this.safeRun(() => this.heuristicAgent.analyze(url, page), "heuristicAgent", "Heuristic Analysis Agent"),
      this.safeRun(async () => this.testerAgent.analyze(page, url), "testerAgent", "Tester Agent"),
    ]);

    const agentResults: AgentResult[] = [
      urlResult,
      domainResult,
      contentResult,
      heuristicResult,
      testerResult,
    ];

    // Extract screenshot from tester result
    const screenshot = (testerResult as AgentResult & { screenshot?: string }).screenshot;

    // Collect all signals
    const allSignals = agentResults.flatMap((r) => r.signals);

    // Apply Critical Veto Logic + weighted scoring
    const verdict = this.computeVerdict(agentResults, allSignals);

    return {
      url,
      action: verdict.action,
      riskScore: verdict.riskScore,
      confidence: verdict.confidence,
      summary: verdict.summary,
      agentResults,
      signals: allSignals,
      fromCache: false,
      mode: "full",
      scanTimeMs: Date.now() - startTime,
      timestamp: Date.now(),
      screenshot,
    };
  }

  /**
   * Fast scan: runs only URL + Domain agents (no page needed, no LLM).
   * ~200-500ms typical execution time.
   */
  async scanFast(url: string): Promise<PhishGuardResult> {
    const startTime = Date.now();

    // Safe domain fast-track
    const safeDomainResult = this.checkSafeDomain(url);
    if (safeDomainResult) {
      return {
        ...safeDomainResult,
        mode: "fast",
        scanTimeMs: Date.now() - startTime,
      };
    }

    // Run URL + Domain agents in parallel
    const [urlResult, domainResult] = await Promise.all([
      this.safeRun(() => this.urlAgent.analyze(url), "urlAgent", "URL Analysis Agent"),
      this.safeRun(() => this.domainAgent.analyze(url), "domainAgent", "Domain Intelligence Agent"),
    ]);

    const agentResults: AgentResult[] = [urlResult, domainResult];
    const allSignals = agentResults.flatMap((r) => r.signals);

    // Apply simplified verdict logic (only 2 agents)
    const verdict = this.computeVerdictFast(agentResults, allSignals);

    return {
      url,
      action: verdict.action,
      riskScore: verdict.riskScore,
      confidence: verdict.confidence,
      summary: verdict.summary,
      agentResults,
      signals: allSignals,
      fromCache: false,
      mode: "fast",
      scanTimeMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  /**
   * Check if URL is on the safe domain whitelist for instant allow.
   */
  private checkSafeDomain(url: string): Omit<PhishGuardResult, "mode" | "scanTimeMs"> | null {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      const isSafe = SAFE_DOMAINS.some(
        (safe: string) => hostname === safe || hostname.endsWith(`.${safe}`),
      );
      if (isSafe) {
        return {
          url,
          action: "allow",
          riskScore: 0,
          confidence: 0.99,
          summary: `${hostname} is a verified safe domain.`,
          agentResults: [],
          signals: [{ type: "known_safe", severity: "low", value: hostname, description: "Verified safe domain" }],
          fromCache: false,
          timestamp: Date.now(),
        };
      }
    } catch {
      // Invalid URL, proceed with analysis
    }
    return null;
  }

  /**
   * Safely run an agent, returning an error result if it fails.
   */
  private async safeRun(
    fn: () => Promise<AgentResult>,
    agentId: string,
    agentName: string,
  ): Promise<AgentResult> {
    try {
      return await fn();
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      return {
        agentId,
        agentName,
        riskScore: 0,
        confidence: 0,
        signals: [{ type: "agent_error", severity: "low", value: errorMsg, description: `${agentName} failed: ${errorMsg}` }],
        explanation: `Agent failed: ${errorMsg}`,
        executionTimeMs: 0,
      };
    }
  }

  /**
   * Full mode: Critical Veto Logic + weighted average scoring.
   *
   * Decision cascade:
   * 1. Any critical veto signal → immediate block (score ≥ 85)
   * 2. Single agent ≥ 75 → block
   * 3. 2+ agents > 50 → consensus block
   * 4. Weighted average with thresholds (allow ≤ 25, warn 26-55, block ≥ 56)
   * 5. High severity signals bump "allow" to "warn"
   */
  private computeVerdict(
    agentResults: AgentResult[],
    allSignals: Signal[],
  ): { action: "allow" | "warn" | "block"; riskScore: number; confidence: number; summary: string } {
    // 1. Critical Veto: Check for critical veto signals
    const vetoSignals = allSignals.filter(
      (s) => CRITICAL_VETO_SIGNALS.includes(s.type) && s.severity === "critical",
    );
    if (vetoSignals.length > 0) {
      const descriptions = vetoSignals.map((s) => s.description).join("; ");
      return {
        action: "block",
        riskScore: Math.max(85, this.weightedAverage(agentResults)),
        confidence: 0.95,
        summary: `BLOCKED: Critical threat detected — ${descriptions}`,
      };
    }

    // 2. Single agent ≥ 75 → block
    const highScoreAgent = agentResults.find((r) => r.riskScore >= 75 && r.confidence > 0.3);
    if (highScoreAgent) {
      return {
        action: "block",
        riskScore: Math.max(75, this.weightedAverage(agentResults)),
        confidence: highScoreAgent.confidence,
        summary: `BLOCKED: ${highScoreAgent.agentName} detected high risk (score: ${highScoreAgent.riskScore}/100)`,
      };
    }

    // 3. 2+ agents > 50 → consensus block
    const moderateAgents = agentResults.filter((r) => r.riskScore > 50 && r.confidence > 0.3);
    if (moderateAgents.length >= 2) {
      const names = moderateAgents.map((a) => a.agentName).join(", ");
      return {
        action: "block",
        riskScore: this.weightedAverage(agentResults),
        confidence: Math.max(...moderateAgents.map((a) => a.confidence)),
        summary: `BLOCKED: Multiple agents flagged risk — ${names}`,
      };
    }

    // 4. Weighted average with thresholds
    const weightedScore = this.weightedAverage(agentResults);
    const avgConfidence = agentResults.length > 0
      ? agentResults.reduce((sum, r) => sum + r.confidence, 0) / agentResults.length
      : 0;

    let action: "allow" | "warn" | "block";
    let summary: string;

    if (weightedScore >= THRESHOLDS.BLOCK_MIN) {
      action = "block";
      summary = `BLOCKED: Overall risk score ${weightedScore}/100 exceeds threshold.`;
    } else if (weightedScore > THRESHOLDS.ALLOW_MAX) {
      action = "warn";
      summary = `WARNING: Moderate risk detected (score: ${weightedScore}/100).`;
    } else {
      action = "allow";
      summary = `Safe: Low risk score (${weightedScore}/100).`;
    }

    // 5. High severity signals bump "allow" to "warn"
    if (action === "allow") {
      const highSeveritySignals = allSignals.filter(
        (s) => s.severity === "high" || s.severity === "critical",
      );
      if (highSeveritySignals.length > 0) {
        action = "warn";
        summary = `WARNING: ${highSeveritySignals[0].description}`;
      }
    }

    return { action, riskScore: weightedScore, confidence: avgConfidence, summary };
  }

  /**
   * Fast mode: simplified verdict with only URL + Domain agents.
   * Uses proportional weights (URL: 0.4, Domain: 0.6).
   */
  private computeVerdictFast(
    agentResults: AgentResult[],
    allSignals: Signal[],
  ): { action: "allow" | "warn" | "block"; riskScore: number; confidence: number; summary: string } {
    // Critical veto signals still apply
    const vetoSignals = allSignals.filter(
      (s) => CRITICAL_VETO_SIGNALS.includes(s.type) && s.severity === "critical",
    );
    if (vetoSignals.length > 0) {
      const descriptions = vetoSignals.map((s) => s.description).join("; ");
      return {
        action: "block",
        riskScore: Math.max(85, this.weightedAverageFast(agentResults)),
        confidence: 0.9,
        summary: `BLOCKED: ${descriptions}`,
      };
    }

    // Single agent ≥ 75 → block
    const highScoreAgent = agentResults.find((r) => r.riskScore >= 75 && r.confidence > 0.3);
    if (highScoreAgent) {
      return {
        action: "block",
        riskScore: Math.max(75, this.weightedAverageFast(agentResults)),
        confidence: highScoreAgent.confidence,
        summary: `BLOCKED: ${highScoreAgent.agentName} — score ${highScoreAgent.riskScore}/100`,
      };
    }

    // Weighted average
    const weightedScore = this.weightedAverageFast(agentResults);
    const avgConfidence = agentResults.length > 0
      ? agentResults.reduce((sum, r) => sum + r.confidence, 0) / agentResults.length
      : 0;

    let action: "allow" | "warn" | "block";
    let summary: string;

    if (weightedScore >= THRESHOLDS.BLOCK_MIN) {
      action = "block";
      summary = `BLOCKED: Risk score ${weightedScore}/100.`;
    } else if (weightedScore > THRESHOLDS.ALLOW_MAX) {
      action = "warn";
      summary = `WARNING: Moderate risk (score: ${weightedScore}/100).`;
    } else {
      action = "allow";
      summary = `Safe: Low risk (${weightedScore}/100).`;
    }

    // High severity bump
    if (action === "allow") {
      const highSeveritySignals = allSignals.filter(
        (s) => s.severity === "high" || s.severity === "critical",
      );
      if (highSeveritySignals.length > 0) {
        action = "warn";
        summary = `WARNING: ${highSeveritySignals[0].description}`;
      }
    }

    return { action, riskScore: weightedScore, confidence: avgConfidence, summary };
  }

  /**
   * Compute weighted average score across all 5 agents using configured weights.
   */
  private weightedAverage(agentResults: AgentResult[]): number {
    let totalWeight = 0;
    let weightedSum = 0;

    for (const result of agentResults) {
      const weight = AGENT_WEIGHTS[result.agentId] ?? 0;
      if (result.confidence > 0) {
        weightedSum += result.riskScore * weight;
        totalWeight += weight;
      }
    }

    if (totalWeight === 0) return 0;
    return Math.round(weightedSum / totalWeight);
  }

  /**
   * Compute weighted average for fast mode (URL: 0.4, Domain: 0.6).
   */
  private weightedAverageFast(agentResults: AgentResult[]): number {
    const fastWeights: Record<string, number> = {
      urlAgent: 0.4,
      domainAgent: 0.6,
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const result of agentResults) {
      const weight = fastWeights[result.agentId] ?? 0;
      if (result.confidence > 0) {
        weightedSum += result.riskScore * weight;
        totalWeight += weight;
      }
    }

    if (totalWeight === 0) return 0;
    return Math.round(weightedSum / totalWeight);
  }
}

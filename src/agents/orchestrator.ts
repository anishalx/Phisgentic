// Orchestrator - Coordinates all agents and aggregates results

import { UrlAgent } from "./url-agent";
import { DomainAgent } from "./domain-agent";
import { ContentAgent } from "./content-agent";
import { HeuristicAgent } from "./heuristic-agent";
import type { AgentResult, PageContent, FinalVerdict } from "../types";
import { CONFIG } from "../config";

export class Orchestrator {
  private urlAgent: UrlAgent;
  private domainAgent: DomainAgent;
  private contentAgent: ContentAgent;
  private heuristicAgent: HeuristicAgent;

  constructor() {
    this.urlAgent = new UrlAgent();
    this.domainAgent = new DomainAgent();
    this.contentAgent = new ContentAgent();
    this.heuristicAgent = new HeuristicAgent();
  }

  async analyzeUrl(
    url: string,
    pageContent?: PageContent,
  ): Promise<FinalVerdict> {
    const startTime = Date.now();

    // Run all agents in parallel for speed
    const agentPromises = [
      this.urlAgent.analyze(url),
      this.domainAgent.analyze(url),
      this.contentAgent.analyze({ url, pageContent: pageContent! }),
      this.heuristicAgent.analyze({ url, pageContent }),
    ];

    // Wait for all agents with timeout
    const results = await Promise.allSettled(
      agentPromises.map((p) => this.withTimeout(p, CONFIG.ANALYSIS.TIMEOUT_MS)),
    );

    // Collect successful results
    const agentResults: AgentResult[] = [];

    for (const result of results) {
      if (result.status === "fulfilled" && result.value) {
        agentResults.push(result.value);
      }
    }

    // Calculate final verdict
    const verdict = this.calculateVerdict(url, agentResults);

    console.log(
      `[Orchestrator] Analysis completed in ${Date.now() - startTime}ms`,
      verdict,
    );

    return verdict;
  }

  private calculateVerdict(
    url: string,
    agentResults: AgentResult[],
  ): FinalVerdict {
    if (agentResults.length === 0) {
      return {
        action: "warn",
        overallRiskScore: 50,
        confidence: 0.1,
        agentResults: [],
        summary: "Unable to analyze URL - all agents failed",
        url,
        timestamp: Date.now(),
      };
    }

    // Calculate weighted score
    let totalWeight = 0;
    let weightedScore = 0;
    let weightedConfidence = 0;

    for (const result of agentResults) {
      const weight = CONFIG.AGENT_WEIGHTS[result.agentId] || 0.25;
      const effectiveWeight = weight * result.confidence;

      weightedScore += result.riskScore * effectiveWeight;
      weightedConfidence += result.confidence * weight;
      totalWeight += effectiveWeight;
    }

    const overallRiskScore =
      totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 50;
    const confidence = Math.min(1, weightedConfidence);

    // Determine action based on thresholds
    let action: "allow" | "warn" | "block";
    if (overallRiskScore <= CONFIG.THRESHOLDS.ALLOW_MAX) {
      action = "allow";
    } else if (overallRiskScore >= CONFIG.THRESHOLDS.BLOCK_MIN) {
      action = "block";
    } else {
      action = "warn";
    }

    // Check for any critical signals that should override
    const hasCriticalSignal = agentResults.some((r) =>
      r.signals.some((s) => s.severity === "critical"),
    );

    if (hasCriticalSignal && action === "allow") {
      action = "warn";
    }

    // Generate summary
    const summary = this.generateSummary(
      agentResults,
      overallRiskScore,
      action,
    );

    return {
      action,
      overallRiskScore,
      confidence,
      agentResults,
      summary,
      url,
      timestamp: Date.now(),
    };
  }

  private generateSummary(
    results: AgentResult[],
    score: number,
    action: string,
  ): string {
    const allSignals = results.flatMap((r) => r.signals);
    const criticalSignals = allSignals.filter((s) => s.severity === "critical");
    const highSignals = allSignals.filter((s) => s.severity === "high");

    let summary = "";

    if (action === "block") {
      summary = `⛔ HIGH RISK (Score: ${score}/100) - `;
    } else if (action === "warn") {
      summary = `⚠️ SUSPICIOUS (Score: ${score}/100) - `;
    } else {
      summary = `✅ LOW RISK (Score: ${score}/100) - `;
    }

    if (criticalSignals.length > 0) {
      summary += `Critical issues: ${criticalSignals
        .map((s) => s.description)
        .slice(0, 2)
        .join("; ")}. `;
    } else if (highSignals.length > 0) {
      summary += `Concerns: ${highSignals
        .map((s) => s.description)
        .slice(0, 2)
        .join("; ")}. `;
    } else {
      summary += "No major concerns detected. ";
    }

    // Add agent explanations
    const explanations = results
      .filter((r) => r.riskScore > 30)
      .map((r) => r.explanation)
      .slice(0, 2);

    if (explanations.length > 0) {
      summary += explanations.join(" ");
    }

    return summary.trim();
  }

  private withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
  ): Promise<T | null> {
    return Promise.race([
      promise,
      new Promise<null>((resolve) =>
        setTimeout(() => resolve(null), timeoutMs),
      ),
    ]);
  }
}

// Export singleton
let orchestratorInstance: Orchestrator | null = null;

export function getOrchestrator(): Orchestrator {
  if (!orchestratorInstance) {
    orchestratorInstance = new Orchestrator();
  }
  return orchestratorInstance;
}

// Base Agent class - Abstract class for all analysis agents

import type { AgentResult, Signal } from "../types";
import { getGroqClient, GroqClient } from "../api/groq-client";

export abstract class BaseAgent {
  protected agentId: string;
  protected agentName: string;
  protected groqClient: GroqClient;
  protected systemPrompt: string;

  constructor(agentId: string, agentName: string, systemPrompt: string) {
    this.agentId = agentId;
    this.agentName = agentName;
    this.systemPrompt = systemPrompt;
    this.groqClient = getGroqClient();
  }

  abstract analyze(data: unknown): Promise<AgentResult>;

  protected createSignal(
    type: string,
    severity: Signal["severity"],
    value: string | number | boolean,
    description: string,
  ): Signal {
    return { type, severity, value, description };
  }

  protected createResult(
    riskScore: number,
    confidence: number,
    signals: Signal[],
    explanation: string,
    executionTimeMs: number,
  ): AgentResult {
    return {
      agentId: this.agentId,
      agentName: this.agentName,
      riskScore: Math.max(0, Math.min(100, riskScore)),
      confidence: Math.max(0, Math.min(1, confidence)),
      signals,
      explanation,
      executionTimeMs,
    };
  }

  protected createErrorResult(
    error: string,
    executionTimeMs: number,
  ): AgentResult {
    return this.createResult(
      50, // Neutral score on error
      0.1, // Low confidence
      [this.createSignal("error", "medium", error, "Analysis failed")],
      `Analysis error: ${error}`,
      executionTimeMs,
    );
  }
}

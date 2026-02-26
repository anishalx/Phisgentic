// Base Agent class - Abstract class for all analysis agents
// Supports dual-model consensus: Groq (primary) + Gemini (secondary)

import type { AgentResult, Signal, LLMAnalysisResult, ModelComparison } from "../types/index.js";
import { getGroqClient, GroqClient } from "../api/groq-client.js";
import { getGeminiClient, GeminiClient } from "../api/gemini-client.js";
import { CONFIG } from "../config/index.js";

/** Maximum characters for any single string field sent to LLM */
const MAX_LLM_STRING_LENGTH = 4000;
/** Maximum number of items in arrays sent to LLM */
const MAX_LLM_ARRAY_LENGTH = 20;

export abstract class BaseAgent {
  protected agentId: string;
  protected agentName: string;
  protected groqClient: GroqClient;
  protected geminiClient: GeminiClient;
  protected systemPrompt: string;

  constructor(agentId: string, agentName: string, systemPrompt: string) {
    this.agentId = agentId;
    this.agentName = agentName;
    this.systemPrompt = systemPrompt;
    this.groqClient = getGroqClient();
    this.geminiClient = getGeminiClient();
  }

  abstract analyze(data: unknown): Promise<AgentResult>;

  /**
   * Dual-model LLM analysis: Runs Groq and Gemini in parallel,
   * then applies consensus logic to produce a single result.
   * Falls back to single-model if Gemini is unavailable or dual-model is disabled.
   */
  protected async dualModelAnalyze(
    analysisData: object,
  ): Promise<{ result: LLMAnalysisResult | null; comparison?: ModelComparison }> {
    const dualEnabled = CONFIG.DUAL_MODEL.ENABLED && this.geminiClient.isAvailable();

    // Truncate large payloads to avoid wasting tokens
    const truncatedData = this.truncatePayload(analysisData) as object;

    // Primary: Groq analysis (always runs)
    const groqPromise = this.groqClient.analyzeForAgent(
      this.agentName,
      this.systemPrompt,
      truncatedData,
    );

    if (!dualEnabled) {
      // Single-model fallback
      const groqResult = await groqPromise;
      return { result: groqResult };
    }

    // Dual-model: Run both in parallel
    const geminiPromise = this.geminiClient.analyzeForAgent(
      this.agentName,
      this.systemPrompt,
      truncatedData,
    );

    const [groqResult, geminiResult] = await Promise.all([groqPromise, geminiPromise]);

    // If both failed, return null
    if (!groqResult && !geminiResult) {
      return { result: null };
    }

    // If only one succeeded, use it
    if (!groqResult) {
      console.log(`[${this.agentName}] Groq failed, using Gemini only`);
      return {
        result: geminiResult,
        comparison: {
          geminiResult: geminiResult!,
          consensusScore: geminiResult!.riskScore,
          scoreDifference: 0,
          strategy: "single-model-fallback",
          agreed: true,
        },
      };
    }
    if (!geminiResult) {
      console.log(`[${this.agentName}] Gemini failed, using Groq only`);
      return {
        result: groqResult,
        comparison: {
          groqResult,
          consensusScore: groqResult.riskScore,
          scoreDifference: 0,
          strategy: "single-model-fallback",
          agreed: true,
        },
      };
    }

    // Both succeeded — apply consensus logic
    const comparison = this.computeConsensus(groqResult, geminiResult);

    // Build merged result using the consensus score
    const mergedResult: LLMAnalysisResult = {
      riskScore: comparison.consensusScore,
      confidence: Math.max(groqResult.confidence, geminiResult.confidence),
      signals: this.mergeSignals(groqResult.signals, geminiResult.signals),
      explanation: this.mergeExplanations(groqResult, geminiResult, comparison),
      model: `consensus(${groqResult.model}+${geminiResult.model})`,
      latencyMs: Math.max(groqResult.latencyMs, geminiResult.latencyMs),
    };

    console.log(
      `[${this.agentName}] Dual-model consensus: Groq=${groqResult.riskScore}, Gemini=${geminiResult.riskScore}, ` +
      `Final=${comparison.consensusScore}, Diff=${comparison.scoreDifference}, Strategy=${comparison.strategy}, ` +
      `Agreed=${comparison.agreed}`
    );

    return { result: mergedResult, comparison };
  }

  /**
   * Compute consensus between two model results
   */
  private computeConsensus(groq: LLMAnalysisResult, gemini: LLMAnalysisResult): ModelComparison {
    const diff = Math.abs(groq.riskScore - gemini.riskScore);
    const threshold = CONFIG.DUAL_MODEL.CONSENSUS_THRESHOLD;
    const agreed = diff <= threshold;

    let consensusScore: number;
    let strategy: string;

    if (agreed) {
      // Models agree — average their scores (weighted by confidence)
      const totalConfidence = groq.confidence + gemini.confidence;
      if (totalConfidence > 0) {
        consensusScore = Math.round(
          (groq.riskScore * groq.confidence + gemini.riskScore * gemini.confidence) / totalConfidence
        );
      } else {
        consensusScore = Math.round((groq.riskScore + gemini.riskScore) / 2);
      }
      strategy = "consensus-average";
    } else {
      // Models disagree significantly — use configured strategy
      switch (CONFIG.DUAL_MODEL.DISAGREEMENT_STRATEGY) {
        case "conservative":
          // Take the HIGHER score (safer for phishing detection)
          consensusScore = Math.max(groq.riskScore, gemini.riskScore);
          strategy = "disagreement-conservative";
          break;
        case "average":
          consensusScore = Math.round((groq.riskScore + gemini.riskScore) / 2);
          strategy = "disagreement-average";
          break;
        case "max":
          consensusScore = Math.max(groq.riskScore, gemini.riskScore);
          strategy = "disagreement-max";
          break;
        default:
          consensusScore = Math.max(groq.riskScore, gemini.riskScore);
          strategy = "disagreement-conservative";
      }
    }

    return {
      groqResult: groq,
      geminiResult: gemini,
      consensusScore,
      scoreDifference: diff,
      strategy,
      agreed,
    };
  }

  /**
   * Merge signals from both models, deduplicating by type
   */
  private mergeSignals(groqSignals: Signal[], geminiSignals: Signal[]): Signal[] {
    const seen = new Set<string>();
    const merged: Signal[] = [];

    // Add all Groq signals first (primary)
    for (const signal of groqSignals) {
      const key = `${signal.type}:${signal.severity}`;
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(signal);
      }
    }

    // Add unique Gemini signals
    for (const signal of geminiSignals) {
      const key = `${signal.type}:${signal.severity}`;
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(signal);
      }
    }

    return merged;
  }

  /**
   * Merge explanations from both models
   */
  private mergeExplanations(
    groq: LLMAnalysisResult,
    gemini: LLMAnalysisResult,
    comparison: ModelComparison,
  ): string {
    if (comparison.agreed) {
      // Models agree — use Groq's explanation (usually more detailed)
      return groq.explanation;
    }
    // Models disagree — show both perspectives
    return `[Groq: ${groq.riskScore}/100] ${groq.explanation} | [Gemini: ${gemini.riskScore}/100] ${gemini.explanation}`;
  }

  /**
   * Truncate large payloads to avoid wasting LLM tokens.
   * Recursively limits string lengths and array sizes.
   */
  private truncatePayload(data: unknown, depth = 0): unknown {
    if (depth > 5) return "[nested]";

    if (typeof data === "string") {
      return data.length > MAX_LLM_STRING_LENGTH
        ? data.substring(0, MAX_LLM_STRING_LENGTH) + "...[truncated]"
        : data;
    }

    if (Array.isArray(data)) {
      const sliced = data.slice(0, MAX_LLM_ARRAY_LENGTH);
      return sliced.map((item) => this.truncatePayload(item, depth + 1));
    }

    if (data && typeof data === "object") {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(data)) {
        result[key] = this.truncatePayload(value, depth + 1);
      }
      return result;
    }

    return data;
  }

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
      15, // Low score — errors should not inflate risk (default-to-allow)
      0.1, // Low confidence
      [this.createSignal("error", "low", error, "Analysis failed")],
      `Analysis error: ${error}`,
      executionTimeMs,
    );
  }
}

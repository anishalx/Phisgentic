// Google Gemini API Client for secondary LLM analysis (dual-model consensus)

import { CONFIG } from "../config/index.js";
import type { LLMAnalysisResult, Signal } from "../types/index.js";
import { getGeminiRateLimiter } from "../utils/rate-limiter.js";

const REQUEST_TIMEOUT_MS = 20_000; // 20 second timeout (down from 25s to leave headroom)

interface GeminiResponse {
  candidates?: {
    content: {
      parts: { text: string }[];
    };
    finishReason: string;
  }[];
  usageMetadata?: {
    promptTokenCount: number;
    candidatesTokenCount: number;
    totalTokenCount: number;
  };
  error?: {
    code: number;
    message: string;
    status: string;
  };
}

export class GeminiClient {
  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || CONFIG.GEMINI_API_KEY;
    this.model = CONFIG.GEMINI_MODEL;
    this.baseUrl = CONFIG.GEMINI_API_URL;
  }

  /**
   * Check if Gemini is configured and available
   */
  isAvailable(): boolean {
    return Boolean(this.apiKey);
  }

  /**
   * Analyze data for phishing indicators using Gemini
   */
  async analyzeForAgent(
    agentName: string,
    systemPrompt: string,
    analysisData: object,
  ): Promise<LLMAnalysisResult | null> {
    if (!this.isAvailable()) {
      return null;
    }

    const startTime = Date.now();

    const schema = {
      type: "object",
      properties: {
        riskScore: { type: "number", description: "Risk score 0-100" },
        confidence: { type: "number", description: "Confidence 0-1" },
        signals: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string" },
              severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
              value: { type: "string" },
              description: { type: "string" },
            },
            required: ["type", "severity", "value", "description"],
          },
        },
        explanation: { type: "string" },
      },
      required: ["riskScore", "confidence", "signals", "explanation"],
    };

    const fullPrompt = `${systemPrompt}

You MUST respond with valid JSON matching this schema:
${JSON.stringify(schema, null, 2)}

Analyze the following data for phishing indicators:

${JSON.stringify(analysisData, null, 2)}`;

    const url = `${this.baseUrl}/${this.model}:generateContent?key=${this.apiKey}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      // Rate limit: wait for token before making API call
      await getGeminiRateLimiter().acquire(REQUEST_TIMEOUT_MS);

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [{ text: fullPrompt }],
            },
          ],
          generationConfig: {
            temperature: CONFIG.ANALYSIS.LLM_TEMPERATURE,
            maxOutputTokens: CONFIG.ANALYSIS.LLM_MAX_TOKENS,
            responseMimeType: "application/json",
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[GeminiClient] ${agentName} API error: ${response.status} - ${errorText}`);
        return null;
      }

      const data = (await response.json()) as GeminiResponse;

      if (data.error) {
        console.error(`[GeminiClient] ${agentName} API error:`, data.error.message);
        return null;
      }

      if (!data.candidates || data.candidates.length === 0) {
        console.error(`[GeminiClient] ${agentName}: No candidates in response`);
        return null;
      }

      const content = data.candidates[0].content.parts[0]?.text;
      if (!content) {
        console.error(`[GeminiClient] ${agentName}: Empty response content`);
        return null;
      }

      // Parse JSON response (handle potential markdown code blocks)
      let parsed: Record<string, unknown>;
      try {
        const jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/) ||
                          content.match(/```\s*([\s\S]*?)\s*```/) ||
                          [null, content];
        const jsonStr = jsonMatch[1] || content;
        parsed = JSON.parse(jsonStr.trim());
      } catch {
        console.error(`[GeminiClient] ${agentName}: Failed to parse JSON response`);
        return null;
      }

      const latencyMs = Date.now() - startTime;

      return {
        riskScore: Number(parsed.riskScore) || 0,
        confidence: Number(parsed.confidence) || 0,
        signals: ((parsed.signals as unknown[]) || []).map((s: unknown) => {
          const signal = s as Record<string, unknown>;
          return {
            type: String(signal.type || "unknown"),
            severity: (["low", "medium", "high", "critical"].includes(String(signal.severity))
              ? String(signal.severity)
              : "medium") as Signal["severity"],
            value: signal.value !== undefined ? String(signal.value) : "",
            description: String(signal.description || ""),
            origin: "llm" as const,
          };
        }),
        explanation: String(parsed.explanation || ""),
        model: this.model,
        latencyMs,
      };
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        console.error(`[GeminiClient] ${agentName}: Request timed out after ${REQUEST_TIMEOUT_MS}ms`);
        return null;
      }
      console.error(`[GeminiClient] ${agentName} analysis error:`, error);
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

// Singleton instance
let geminiInstance: GeminiClient | null = null;

export function getGeminiClient(apiKey?: string): GeminiClient {
  if (!geminiInstance || apiKey) {
    geminiInstance = new GeminiClient(apiKey);
  }
  return geminiInstance;
}

// Groq API Client for LLM-powered analysis
// NOTE: This client is NOT used by the extension at runtime.
// All LLM analysis is performed by the backend API server.
// The extension communicates with the server via REST/SSE, not directly with Groq.

import { CONFIG } from "../config";
import type { GroqRequest, GroqResponse, GroqMessage } from "../types";

// Groq API endpoint (not in CONFIG since extension doesn't call Groq directly)
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";

export class GroqClient {
  private apiUrl: string;
  private apiKey: string;
  private model: string;

  constructor(apiKey?: string) {
    this.apiUrl = GROQ_API_URL;
    this.apiKey = apiKey || "";
    this.model = CONFIG.GROQ_MODEL;
  }

  async analyze(
    systemPrompt: string,
    userPrompt: string,
    jsonSchema?: object,
  ): Promise<{ success: boolean; data?: unknown; error?: string }> {
    const messages: GroqMessage[] = [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ];

    const request: GroqRequest = {
      model: this.model,
      messages,
      temperature: CONFIG.ANALYSIS.LLM_TEMPERATURE,
      max_completion_tokens: CONFIG.ANALYSIS.LLM_MAX_TOKENS,
    };

    if (jsonSchema) {
      request.response_format = {
        type: "json_schema",
        json_schema: {
          name: "analysis_response",
          schema: jsonSchema,
        },
      };
    }

    try {
      const response = await fetch(this.apiUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorText = await response.text();
        return {
          success: false,
          error: `API error: ${response.status} - ${errorText}`,
        };
      }

      const data: GroqResponse = await response.json();

      if (!data.choices || data.choices.length === 0) {
        return { success: false, error: "No response from LLM" };
      }

      const content = data.choices[0].message.content;

      // Try to parse as JSON if schema was provided
      if (jsonSchema) {
        try {
          const parsed = JSON.parse(content);
          return { success: true, data: parsed };
        } catch {
          return { success: false, error: "Failed to parse JSON response" };
        }
      }

      return { success: true, data: content };
    } catch (error) {
      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown error occurred",
      };
    }
  }

  // Convenience method for agent analysis with structured output
  async analyzeForAgent(
    agentName: string,
    systemPrompt: string,
    analysisData: object,
  ): Promise<{
    riskScore: number;
    confidence: number;
    signals: unknown[];
    explanation: string;
  } | null> {
    const schema = {
      type: "object",
      properties: {
        riskScore: {
          type: "number",
          description:
            "Risk score from 0-100 where 0 is safe and 100 is definitely phishing",
        },
        confidence: {
          type: "number",
          description: "Confidence level from 0-1 in the assessment",
        },
        signals: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string" },
              severity: {
                type: "string",
                enum: ["low", "medium", "high", "critical"],
              },
              value: { type: "string" },
              description: { type: "string" },
            },
            required: ["type", "severity", "description"],
          },
        },
        explanation: {
          type: "string",
          description: "Brief explanation of the analysis and key findings",
        },
      },
      required: ["riskScore", "confidence", "signals", "explanation"],
    };

    const userPrompt = `Analyze the following data for phishing indicators:\n\n${JSON.stringify(analysisData, null, 2)}`;

    const result = await this.analyze(systemPrompt, userPrompt, schema);

    if (result.success && result.data) {
      return result.data as {
        riskScore: number;
        confidence: number;
        signals: unknown[];
        explanation: string;
      };
    }

    console.error(`${agentName} analysis failed:`, result.error);
    return null;
  }
}

// Singleton instance
let clientInstance: GroqClient | null = null;

export function getGroqClient(apiKey?: string): GroqClient {
  if (!clientInstance || apiKey) {
    clientInstance = new GroqClient(apiKey);
  }
  return clientInstance;
}

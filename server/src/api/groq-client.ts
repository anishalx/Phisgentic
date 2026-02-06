// Groq API Client for LLM-powered analysis

import { CONFIG } from "../config/index.js";
import type { GroqRequest, GroqResponse, GroqMessage, LogoDetectionResult } from "../types/index.js";

export class GroqClient {
  private apiUrl: string;
  private apiKey: string;
  private model: string;
  private visionModel: string;

  constructor(apiKey?: string) {
    this.apiUrl = CONFIG.GROQ_API_URL;
    this.apiKey = apiKey || CONFIG.GROQ_API_KEY;
    this.model = CONFIG.GROQ_MODEL;
    this.visionModel = CONFIG.GROQ_VISION_MODEL;
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

      const data = (await response.json()) as GroqResponse;

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

  /**
   * Analyze a screenshot for brand logos using vision model
   * Detects visual brand spoofing attacks
   */
  async analyzeLogoInScreenshot(
    screenshotBase64: string,
    pageUrl: string,
  ): Promise<LogoDetectionResult | null> {
    const pageDomain = this.extractDomain(pageUrl);
    
    const systemPrompt = `You are a cybersecurity expert specializing in visual phishing detection.
Analyze the provided screenshot to identify any brand logos or company branding visible on the page.

Your task:
1. Identify any recognizable brand logos (Microsoft, Google, PayPal, Apple, Amazon, Facebook, Netflix, banks, etc.)
2. Determine if the detected brand matches the domain of the page
3. Flag potential brand impersonation/phishing if there's a mismatch

Respond in JSON format with these fields:
- brandDetected: The brand name if a logo is detected, or null if no recognizable brand
- confidence: Your confidence level (0-1) in the brand detection
- isDomainMismatch: true if the brand doesn't match the page domain, false otherwise
- legitimateDomains: Array of legitimate domains for the detected brand
- explanation: Brief explanation of your analysis`;

    const messages: GroqMessage[] = [
      { role: "system", content: systemPrompt },
      { 
        role: "user", 
        content: [
          {
            type: "text",
            text: `Analyze this screenshot from the page at domain "${pageDomain}" (full URL: ${pageUrl}). Identify any brand logos and determine if they legitimately belong to this domain.`,
          },
          {
            type: "image_url",
            image_url: {
              url: `data:image/jpeg;base64,${screenshotBase64}`,
            },
          },
        ],
      },
    ];

    try {
      const response = await fetch(this.apiUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: this.visionModel,
          messages,
          temperature: 0.1,
          max_completion_tokens: 500,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[GroqClient] Vision API error: ${response.status} - ${errorText}`);
        return null;
      }

      const data = (await response.json()) as GroqResponse;

      if (!data.choices || data.choices.length === 0) {
        return null;
      }

      const content = data.choices[0].message.content;

      // Parse JSON from response
      try {
        // Handle potential markdown code blocks
        const jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/) || 
                          content.match(/```\s*([\s\S]*?)\s*```/) ||
                          [null, content];
        const jsonStr = jsonMatch[1] || content;
        const parsed = JSON.parse(jsonStr.trim());
        
        // Validate the brand against our known domains if detected
        if (parsed.brandDetected) {
          const brandLower = parsed.brandDetected.toLowerCase();
          const knownDomains = CONFIG.BRAND_DOMAINS[brandLower] || [];
          
          // Check if page domain matches any legitimate domain for this brand
          const isLegitimate = knownDomains.some(legitDomain => 
            pageDomain === legitDomain || pageDomain.endsWith(`.${legitDomain}`)
          );
          
          parsed.isDomainMismatch = !isLegitimate && knownDomains.length > 0;
          parsed.legitimateDomains = knownDomains;
        }

        return parsed as LogoDetectionResult;
      } catch (parseError) {
        console.error("[GroqClient] Failed to parse vision response:", parseError);
        return null;
      }
    } catch (error) {
      console.error("[GroqClient] Vision analysis error:", error);
      return null;
    }
  }

  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return "";
    }
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

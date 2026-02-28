// Google Safe Browsing API Client
// Checks URLs against Google's database of phishing, malware, social engineering, and unwanted software

import { CONFIG } from "../config/index.js";

export interface SafeBrowsingResult {
  isUnsafe: boolean;
  threatTypes: string[];
  platformTypes: string[];
  threatEntryTypes: string[];
  /** Human-readable description of threats found */
  description: string;
  /** Latency of the API call in ms */
  latencyMs: number;
}

/**
 * Google Safe Browsing Lookup API v4 client.
 * Returns threat matches for a given URL.
 * Gracefully returns safe result if API key is not configured or API fails.
 */
export class SafeBrowsingClient {
  private apiKey: string;
  private apiUrl: string;
  private enabled: boolean;
  private timeoutMs: number;

  constructor() {
    this.apiKey = CONFIG.GOOGLE_SAFE_BROWSING.API_KEY;
    this.apiUrl = CONFIG.GOOGLE_SAFE_BROWSING.API_URL;
    this.enabled = CONFIG.GOOGLE_SAFE_BROWSING.ENABLED;
    this.timeoutMs = CONFIG.GOOGLE_SAFE_BROWSING.TIMEOUT_MS;
  }

  isAvailable(): boolean {
    return this.enabled && this.apiKey.length > 0;
  }

  async checkUrl(url: string): Promise<SafeBrowsingResult> {
    const startTime = Date.now();

    if (!this.isAvailable()) {
      return {
        isUnsafe: false,
        threatTypes: [],
        platformTypes: [],
        threatEntryTypes: [],
        description: "Google Safe Browsing not configured — skipped",
        latencyMs: Date.now() - startTime,
      };
    }

    try {
      const requestBody = {
        client: {
          clientId: "phishguard-ai",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(`${this.apiUrl}?key=${this.apiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        console.error(`[SafeBrowsing] API error: ${response.status} ${response.statusText}`);
        return {
          isUnsafe: false,
          threatTypes: [],
          platformTypes: [],
          threatEntryTypes: [],
          description: `Google Safe Browsing API error: ${response.status}`,
          latencyMs: Date.now() - startTime,
        };
      }

      const data = await response.json();
      const latencyMs = Date.now() - startTime;

      // If matches is empty or absent, URL is safe
      if (!data.matches || data.matches.length === 0) {
        return {
          isUnsafe: false,
          threatTypes: [],
          platformTypes: [],
          threatEntryTypes: [],
          description: "URL not found in Google Safe Browsing threat database",
          latencyMs,
        };
      }

      // URL is flagged as unsafe
      const threatTypes = [...new Set(data.matches.map((m: any) => m.threatType))] as string[];
      const platformTypes = [...new Set(data.matches.map((m: any) => m.platformType))] as string[];
      const threatEntryTypes = [...new Set(data.matches.map((m: any) => m.threatEntryType))] as string[];

      const threatDescriptions = threatTypes.map((t: string) => {
        switch (t) {
          case "MALWARE": return "malware";
          case "SOCIAL_ENGINEERING": return "phishing/social engineering";
          case "UNWANTED_SOFTWARE": return "unwanted software";
          case "POTENTIALLY_HARMFUL_APPLICATION": return "potentially harmful application";
          default: return t.toLowerCase();
        }
      });

      console.log(`[SafeBrowsing] THREAT DETECTED for ${url}: ${threatDescriptions.join(", ")}`);

      return {
        isUnsafe: true,
        threatTypes,
        platformTypes,
        threatEntryTypes,
        description: `Google Safe Browsing: ${threatDescriptions.join(", ")} detected`,
        latencyMs,
      };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error(`[SafeBrowsing] Check failed: ${errorMsg}`);

      return {
        isUnsafe: false,
        threatTypes: [],
        platformTypes: [],
        threatEntryTypes: [],
        description: `Google Safe Browsing check failed: ${errorMsg}`,
        latencyMs: Date.now() - startTime,
      };
    }
  }
}

// Singleton
let safeBrowsingInstance: SafeBrowsingClient | null = null;

export function getSafeBrowsingClient(): SafeBrowsingClient {
  if (!safeBrowsingInstance) {
    safeBrowsingInstance = new SafeBrowsingClient();
  }
  return safeBrowsingInstance;
}

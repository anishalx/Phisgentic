// API Integration tests
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import express, { Express, Request, Response } from "express";
import { Server } from "http";

// Mock the orchestrator to avoid actual browser automation and API calls
vi.mock("./agents/orchestrator.js", () => ({
  getOrchestrator: () => ({
    analyzeUrl: vi.fn().mockImplementation(async (url: string, onLog?: (log: unknown) => void) => {
      // Simulate some logs
      if (onLog) {
        onLog({ agentId: "urlAgent", message: "Analyzing URL structure...", status: "running" });
        onLog({ agentId: "urlAgent", message: "URL analysis complete", status: "complete" });
      }

      // Return mock result based on URL
      const isPhishing = url.includes("phishing") || url.includes("malware");
      const isSuspicious = url.includes("suspicious") || url.includes("test");

      return {
        verdict: {
          overallRiskScore: isPhishing ? 85 : isSuspicious ? 55 : 15,
          overallConfidence: 0.8,
          verdict: isPhishing ? "phishing" : isSuspicious ? "suspicious" : "safe",
          summary: `Analysis of ${url}`,
          screenshot: null,
          agentResults: [],
        },
        logs: [
          { agentId: "urlAgent", message: "Analysis complete", status: "complete" },
        ],
      };
    }),
  }),
}));

// Create test app
function createTestApp(): Express {
  const app = express();
  app.use(express.json());

  // Health check endpoint
  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", timestamp: Date.now() });
  });

  // Main scan endpoint
  app.post("/api/scan", async (req: Request, res: Response) => {
    const { url } = req.body;

    if (!url) {
      res.status(400).json({
        success: false,
        error: "URL is required",
        logs: [],
      });
      return;
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      res.status(400).json({
        success: false,
        error: "Invalid URL format",
        logs: [],
      });
      return;
    }

    try {
      const { getOrchestrator } = await import("./agents/orchestrator.js");
      const orchestrator = getOrchestrator();
      const result = await orchestrator.analyzeUrl(url);

      res.json({
        success: true,
        verdict: result.verdict,
        logs: result.logs,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        logs: [],
      });
    }
  });

  return app;
}

describe("API Endpoints", () => {
  let app: Express;
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    app = createTestApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address();
        if (address && typeof address === "object") {
          baseUrl = `http://localhost:${address.port}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  describe("GET /api/health", () => {
    it("should return health status", async () => {
      const response = await fetch(`${baseUrl}/api/health`);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toHaveProperty("status", "ok");
      expect(data).toHaveProperty("timestamp");
      expect(typeof data.timestamp).toBe("number");
    });
  });

  describe("POST /api/scan", () => {
    it("should return 400 if URL is missing", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await response.json();

      expect(response.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.error).toBe("URL is required");
    });

    it("should return 400 for invalid URL format", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "not-a-valid-url" }),
      });
      const data = await response.json();

      expect(response.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.error).toBe("Invalid URL format");
    });

    it("should return safe verdict for safe URLs", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://www.google.com" }),
      });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data).toHaveProperty("verdict");
      expect(data.verdict.verdict).toBe("safe");
      expect(data.verdict.overallRiskScore).toBeLessThan(30);
    });

    it("should return phishing verdict for phishing URLs", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://phishing-site.example.com" }),
      });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.verdict.verdict).toBe("phishing");
      expect(data.verdict.overallRiskScore).toBeGreaterThan(70);
    });

    it("should return suspicious verdict for suspicious URLs", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://suspicious-link.example.com" }),
      });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.verdict.verdict).toBe("suspicious");
    });

    it("should include logs in response", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://example.com" }),
      });
      const data = await response.json();

      expect(data).toHaveProperty("logs");
      expect(Array.isArray(data.logs)).toBe(true);
    });
  });

  describe("response structure", () => {
    it("should return proper verdict structure", async () => {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://www.example.com" }),
      });
      const data = await response.json();

      expect(data.verdict).toHaveProperty("overallRiskScore");
      expect(data.verdict).toHaveProperty("overallConfidence");
      expect(data.verdict).toHaveProperty("verdict");
      expect(data.verdict).toHaveProperty("summary");
      expect(["safe", "suspicious", "phishing"]).toContain(data.verdict.verdict);
    });
  });
});

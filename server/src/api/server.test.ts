// Integration tests for PhishGuard API endpoints using supertest

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import request from "supertest";
import app from "../app.js";

// Mock external dependencies to avoid real LLM calls in tests
vi.mock("../agents/orchestrator.js", () => {
  const mockVerdict = {
    url: "https://example.com",
    riskScore: 0.2,
    riskLevel: "low" as const,
    confidence: 0.85,
    isPhishing: false,
    flags: [],
    summary: "This URL appears to be safe.",
  };

  const mockLogs = [
    { agent: "url", level: "info", message: "URL analysis complete", timestamp: Date.now() },
    { agent: "domain", level: "info", message: "Domain analysis complete", timestamp: Date.now() },
  ];

  return {
    getOrchestrator: vi.fn(() => ({
      analyzeUrl: vi.fn(async (url: string, onLog?: Function) => {
        // Simulate log events for streaming
        if (onLog) {
          onLog(mockLogs[0]);
          onLog(mockLogs[1]);
        }
        return {
          verdict: { ...mockVerdict, url },
          logs: [...mockLogs],
        };
      }),
    })),
  };
});

describe("API Endpoints", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ─── Health Check ───────────────────────────────────────────

  describe("GET /api/health", () => {
    it("should return status ok with cache stats", async () => {
      const res = await request(app).get("/api/health");

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("status", "ok");
      expect(res.body).toHaveProperty("timestamp");
      expect(typeof res.body.timestamp).toBe("number");
      expect(res.body).toHaveProperty("cache");
      expect(res.body.cache).toHaveProperty("size");
      expect(res.body.cache).toHaveProperty("maxSize");
      expect(res.body.cache).toHaveProperty("ttlMs");
    });

    it("should include security headers from helmet", async () => {
      const res = await request(app).get("/api/health");

      // Helmet adds these headers by default
      expect(res.headers).toHaveProperty("x-content-type-options", "nosniff");
      expect(res.headers).toHaveProperty("x-frame-options");
    });
  });

  // ─── POST /api/scan ─────────────────────────────────────────

  describe("POST /api/scan", () => {
    it("should scan a valid URL successfully", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "https://example.com" });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("success", true);
      expect(res.body).toHaveProperty("verdict");
      expect(res.body.verdict).toHaveProperty("url", "https://example.com");
      expect(res.body.verdict).toHaveProperty("riskScore");
      expect(res.body.verdict).toHaveProperty("riskLevel");
      expect(res.body.verdict).toHaveProperty("confidence");
      expect(res.body.verdict).toHaveProperty("isPhishing");
      expect(res.body).toHaveProperty("logs");
      expect(Array.isArray(res.body.logs)).toBe(true);
    });

    it("should return 400 when body is missing", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("success", false);
      expect(res.body).toHaveProperty("error");
      expect(res.body).toHaveProperty("logs", []);
    });

    it("should return 400 when url is not a valid URL", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "not-a-url" });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("success", false);
      expect(res.body.error).toMatch(/Invalid URL/i);
    });

    it("should return 400 when url is empty string", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "" });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("success", false);
    });

    it("should return 400 when url exceeds max length (2048)", async () => {
      const longUrl = "https://example.com/" + "a".repeat(2050);
      const res = await request(app)
        .post("/api/scan")
        .send({ url: longUrl });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("success", false);
    });

    it("should return 400 when extra body fields sent without url", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ foo: "bar", baz: 123 });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("success", false);
    });

    it("should accept a localhost URL", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "http://localhost:3000/api/test" });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("success", true);
      expect(res.body.verdict).toHaveProperty("url", "http://localhost:3000/api/test");
    });

    it("should accept a URL with port", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "https://example.com:8080/path" });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("success", true);
    });

    it("should return Content-Type application/json", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "https://example.com" });

      expect(res.headers["content-type"]).toMatch(/json/);
    });

    it("should handle request body with url only", async () => {
      const res = await request(app)
        .post("/api/scan")
        .send({ url: "https://google.com" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.verdict.url).toBe("https://google.com");
    });
  });

  // ─── GET /api/scan/stream (SSE) ─────────────────────────────

  describe("GET /api/scan/stream", () => {
    it("should return 400 when url query param is missing", async () => {
      const res = await request(app)
        .get("/api/scan/stream");

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("error");
    });

    it("should return 400 when url query param is invalid", async () => {
      const res = await request(app)
        .get("/api/scan/stream?url=not-a-url");

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("error");
    });

    it("should return SSE headers for a valid url", async () => {
      const res = await request(app)
        .get("/api/scan/stream?url=https://example.com");

      // SSE response should have these headers
      expect(res.headers["content-type"]).toMatch(/text\/event-stream/);
      expect(res.headers["cache-control"]).toMatch(/no-cache/);
      expect(res.headers["connection"]).toMatch(/keep-alive/);
    });

    it("should return SSE events with result and done", async () => {
      const res = await request(app)
        .get("/api/scan/stream?url=https://example.com");

      // The response body should contain SSE-formatted data
      expect(res.text).toContain("event: result");
      expect(res.text).toContain("event: done");
    });

    it("should include log events in SSE stream", async () => {
      const res = await request(app)
        .get("/api/scan/stream?url=https://example.com");

      expect(res.text).toContain("event: log");
    });

    it("should include verdict data in result event", async () => {
      const res = await request(app)
        .get("/api/scan/stream?url=https://example.com");

      // Parse SSE data to find result event
      const resultMatch = res.text.match(/event: result\ndata: (.+)\n/);
      expect(resultMatch).toBeTruthy();

      if (resultMatch) {
        const verdict = JSON.parse(resultMatch[1]);
        expect(verdict).toHaveProperty("url", "https://example.com");
        expect(verdict).toHaveProperty("riskScore");
        expect(verdict).toHaveProperty("riskLevel");
      }
    });

    it("should work with encoded URL query params", async () => {
      const url = "https://example.com/path?q=test&page=1";
      const res = await request(app)
        .get(`/api/scan/stream?url=${encodeURIComponent(url)}`);

      expect(res.status).toBe(200);
      expect(res.headers["content-type"]).toMatch(/text\/event-stream/);
    });
  });

  // ─── CORS ────────────────────────────────────────────────────

  describe("CORS", () => {
    it("should allow requests with no origin (server-to-server)", async () => {
      const res = await request(app)
        .get("/api/health")
        .set("Origin", "");

      expect(res.status).toBe(200);
    });

    it("should allow chrome-extension origins", async () => {
      const res = await request(app)
        .get("/api/health")
        .set("Origin", "chrome-extension://abc123");

      expect(res.status).toBe(200);
    });
  });

  // ─── Helmet Security Headers ────────────────────────────────

  describe("Security Headers", () => {
    it("should include security headers on all endpoints", async () => {
      const res = await request(app).get("/api/health");

      expect(res.headers).toHaveProperty("x-content-type-options", "nosniff");
      expect(res.headers).toHaveProperty("x-frame-options");
      // Helmet removes X-Powered-By by default
      expect(res.headers).not.toHaveProperty("x-powered-by");
    });

    it("should remove X-Powered-By header", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["x-powered-by"]).toBeUndefined();
    });
  });

  // ─── Error Handling ──────────────────────────────────────────

  describe("Error Handling", () => {
    it("should return 404 for unknown routes", async () => {
      const res = await request(app).get("/api/nonexistent");
      expect(res.status).toBe(404);
    });

    it("should handle malformed JSON body gracefully", async () => {
      const res = await request(app)
        .post("/api/scan")
        .set("Content-Type", "application/json")
        .send("{ invalid json }");

      // express.json middleware should return 400 for malformed JSON
      expect(res.status).toBe(400);
    });

    it("should return proper error response when orchestrator throws", async () => {
      const { getOrchestrator } = await import("../agents/orchestrator.js");
      const mockOrchestrator = {
        analyzeUrl: vi.fn(async () => {
          throw new Error("LLM API unavailable");
        }),
      };
      vi.mocked(getOrchestrator).mockReturnValue(mockOrchestrator as any);

      const res = await request(app)
        .post("/api/scan")
        .send({ url: "https://llm-error-test.example.com" });

      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty("success", false);
      expect(res.body).toHaveProperty("error", "LLM API unavailable");
      expect(res.body).toHaveProperty("logs", []);
    });
  });

  // ─── HTTP Methods ────────────────────────────────────────────

  describe("HTTP Methods", () => {
    it("should reject GET on /api/scan", async () => {
      const res = await request(app).get("/api/scan");
      expect(res.status).toBe(404);
    });

    it("should reject POST on /api/health", async () => {
      const res = await request(app).post("/api/health").send({});
      expect(res.status).toBe(404);
    });
  });
});

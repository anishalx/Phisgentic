// PhishGuard API Server

import express, { Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { CONFIG } from "./config/index.js";
import { getOrchestrator } from "./agents/orchestrator.js";
import { closeBrowser } from "./agents/tester-agent.js";
import type { ScanRequest, ScanResponse, AgentLog } from "./types/index.js";

const app = express();

// Security middleware
app.use(helmet());

// Rate limiting - 30 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/scan", limiter);

// CORS and JSON parsing
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Input validation schema
const scanRequestSchema = z.object({
  url: z.string().url("Invalid URL format").max(2048, "URL too long"),
});

// Health check endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: Date.now() });
});

// Main scan endpoint
app.post("/api/scan", async (req: Request, res: Response) => {
  // Validate input with Zod
  const parseResult = scanRequestSchema.safeParse(req.body);
  
  if (!parseResult.success) {
    const errorMessage = parseResult.error.issues[0]?.message || "Invalid request";
    res.status(400).json({
      success: false,
      error: errorMessage,
      logs: [],
    } as ScanResponse);
    return;
  }

  const { url } = parseResult.data;

  console.log(`[API] Scanning URL: ${url}`);

  try {
    const orchestrator = getOrchestrator();
    const result = await orchestrator.analyzeUrl(url);

    res.json({
      success: true,
      verdict: result.verdict,
      logs: result.logs,
    } as ScanResponse);
  } catch (error) {
    console.error("[API] Scan error:", error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      logs: [],
    } as ScanResponse);
  }
});

// SSE endpoint for real-time logs
app.get("/api/scan/stream", async (req: Request, res: Response) => {
  const url = req.query.url as string;

  // Validate URL with Zod
  const parseResult = scanRequestSchema.safeParse({ url });
  
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.issues[0]?.message || "Invalid URL" });
    return;
  }

  // Set up SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  console.log(`[API] Starting stream scan for: ${url}`);

  const onLog = (log: AgentLog) => {
    res.write(`event: log\ndata: ${JSON.stringify(log)}\n\n`);
  };

  try {
    const orchestrator = getOrchestrator();
    const result = await orchestrator.analyzeUrl(url, onLog);

    // Send final result
    res.write(`event: result\ndata: ${JSON.stringify(result.verdict)}\n\n`);
    res.write(`event: done\ndata: {}\n\n`);
    res.end();
  } catch (error) {
    console.error("[API] Stream scan error:", error);
    res.write(
      `event: error\ndata: ${JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" })}\n\n`,
    );
    res.end();
  }
});

// Start server
const server = app.listen(CONFIG.PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║                                                        ║
║   PhishGuard AI - Multi-Agent Phishing Detection API   ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║   Server running on port ${CONFIG.PORT}                        ║
║                                                        ║
║   Endpoints:                                           ║
║   - POST /api/scan     - Analyze a URL                 ║
║   - GET  /api/scan/stream?url=... - SSE stream scan    ║
║   - GET  /api/health   - Health check                  ║
║                                                        ║
║   Security:                                            ║
║   - Rate limiting: 30 req/min per IP                   ║
║   - Helmet security headers enabled                    ║
║   - Input validation with Zod                          ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
async function shutdown() {
  console.log("\n[API] Shutting down gracefully...");
  
  server.close(async () => {
    console.log("[API] HTTP server closed");
    await closeBrowser();
    console.log("[API] Cleanup complete, exiting");
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error("[API] Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

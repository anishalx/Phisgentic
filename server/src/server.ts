// PhishGuard API Server

import express, { Request, Response } from "express";
import cors from "cors";
import { CONFIG } from "./config/index.js";
import { getOrchestrator } from "./agents/orchestrator.js";
import type { ScanRequest, ScanResponse, AgentLog } from "./types/index.js";

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: Date.now() });
});

// Main scan endpoint
app.post("/api/scan", async (req: Request, res: Response) => {
  const { url } = req.body as ScanRequest;

  if (!url) {
    res.status(400).json({
      success: false,
      error: "URL is required",
      logs: [],
    } as ScanResponse);
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
    } as ScanResponse);
    return;
  }

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

  if (!url) {
    res.status(400).json({ error: "URL is required" });
    return;
  }

  // Validate URL format
  try {
    new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid URL format" });
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
app.listen(CONFIG.PORT, () => {
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
╚════════════════════════════════════════════════════════╝
  `);
});

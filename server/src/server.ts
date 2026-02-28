// PhishGuard API Server

import express, { Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { CONFIG } from "./config/index.js";
import { getOrchestrator } from "./agents/orchestrator.js";
import { closeBrowser } from "./agents/tester-agent.js";
import { getScanCache } from "./utils/cache.js";
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

// CORS - restrict to known origins in production
const allowedOrigins = [
  "http://localhost:3000",  // Next.js dashboard dev
  "http://localhost:3001",  // Self (for health checks)
  `http://localhost:${CONFIG.PORT}`,
  "https://phishiq.zone.id",  // Custom domain
  process.env.DASHBOARD_URL, // Production dashboard URL
].filter(Boolean) as string[];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g., curl, server-to-server, extensions)
      if (!origin) return callback(null, true);
      // Chrome extensions have chrome-extension:// origin — allow all
      if (origin.startsWith("chrome-extension://")) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      // Allow any Render-hosted origin (*.onrender.com)
      if (origin.endsWith(".onrender.com")) return callback(null, true);
      // In development, allow all origins
      if (process.env.NODE_ENV !== "production") return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: "1mb" }));

// Input validation schema
const scanRequestSchema = z.object({
  url: z.string().url("Invalid URL format").max(2048, "URL too long"),
});

// Health check endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  const cache = getScanCache();
  res.json({
    status: "ok",
    timestamp: Date.now(),
    cache: cache.stats(),
  });
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

  // Check cache first
  const cache = getScanCache();
  const cached = cache.get(url);
  if (cached) {
    console.log(`[API] Cache hit for: ${url}`);
    res.json({
      success: true,
      verdict: cached.verdict,
      logs: cached.logs,
    } as ScanResponse);
    return;
  }

  console.log(`[API] Scanning URL: ${url}`);

  try {
    const orchestrator = getOrchestrator();
    const result = await orchestrator.analyzeUrl(url);

    // Store in cache
    cache.set(url, result.verdict, result.logs);

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
  res.setHeader("X-Accel-Buffering", "no"); // Disable nginx/Render proxy buffering
  res.flushHeaders(); // Flush headers immediately so client knows SSE is open

  console.log(`[API] Starting stream scan for: ${url}`);

  // Track whether client is still connected
  let clientConnected = true;
  const abortController = new AbortController();

  req.on("close", () => {
    clientConnected = false;
    abortController.abort();
    console.log(`[API] Client disconnected from stream scan for: ${url}`);
  });

  const safeSend = (event: string, data: string) => {
    if (clientConnected && !res.writableEnded) {
      try {
        res.write(`event: ${event}\ndata: ${data}\n\n`);
      } catch {
        clientConnected = false;
      }
    }
  };

  // Keepalive ping every 20s to prevent Render/nginx proxy from closing idle SSE connections
  const keepaliveInterval = setInterval(() => {
    if (clientConnected && !res.writableEnded) {
      try {
        res.write(": keepalive\n\n"); // SSE comment line, ignored by EventSource
      } catch {
        clientConnected = false;
      }
    } else {
      clearInterval(keepaliveInterval);
    }
  }, 20_000);

  // Check cache — if cached, replay logs and result immediately
  const cache = getScanCache();
  const cached = cache.get(url);
  if (cached) {
    console.log(`[API] Stream cache hit for: ${url}`);
    for (const log of cached.logs) {
      safeSend("log", JSON.stringify(log));
    }
    safeSend("result", JSON.stringify(cached.verdict));
    safeSend("done", "{}");
    if (!res.writableEnded) res.end();
    return;
  }

  const onLog = (log: AgentLog) => {
    safeSend("log", JSON.stringify(log));
  };

  // Server-side timeout: auto-end SSE connection after 120s to prevent hanging
  const sseTimeout = setTimeout(() => {
    if (clientConnected && !res.writableEnded) {
      console.log(`[API] SSE timeout for: ${url}`);
      safeSend("error", JSON.stringify({ error: "Analysis timed out" }));
      if (!res.writableEnded) res.end();
      clientConnected = false;
    }
  }, 120_000);

  try {
    const orchestrator = getOrchestrator();
    const result = await orchestrator.analyzeUrl(url, onLog);

    // Store in cache
    cache.set(url, result.verdict, result.logs);

    // Send final result only if client is still connected
    safeSend("result", JSON.stringify(result.verdict));
    safeSend("done", "{}");
    if (!res.writableEnded) res.end();
  } catch (error) {
    if (!clientConnected) {
      // Client already disconnected — nothing to send
      console.log(`[API] Scan aborted (client disconnected): ${url}`);
      return;
    }
    console.error("[API] Stream scan error:", error);
    safeSend("error", JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }));
    if (!res.writableEnded) res.end();
  } finally {
    clearTimeout(sseTimeout);
    clearInterval(keepaliveInterval);
  }
});

// Start server
const server = app.listen(CONFIG.PORT, "0.0.0.0", () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   PhishGuard AI - Multi-Agent Phishing Detection API      ║
║   Dual-Model Consensus: Groq Llama + Google Gemini Flash  ║
║                                                           ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║   Server running on port ${String(CONFIG.PORT).padEnd(34)}║
║                                                           ║
║   Endpoints:                                              ║
║   - POST /api/scan          - Analyze a URL               ║
║   - GET  /api/scan/stream   - SSE stream scan             ║
║   - GET  /api/health        - Health check + cache stats   ║
║                                                           ║
║   Performance:                                            ║
║   - LRU scan cache (5min TTL, 100 entries)                ║
║   - LLM rate limiting (Groq 28/min, Gemini 14/min)       ║
║   - Parallel agent execution (all 5 agents)               ║
║   - Content truncation for LLM payloads                   ║
║   - SSE server-side timeout (60s)                         ║
║                                                           ║
║   Security:                                               ║
║   - Rate limiting: 30 req/min per IP                      ║
║   - Helmet security headers enabled                       ║
║   - Input validation with Zod                             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
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

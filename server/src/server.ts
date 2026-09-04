// PhishGuard API Server

import { CONFIG } from "./config/index.js";
import { closeBrowser } from "./agents/tester-agent.js";
import app from "./app.js";

// Start server
const server = app.listen(CONFIG.PORT, "0.0.0.0", () => {
  console.log(`\r\n╔═══════════════════════════════════════════════════════════╗\r\n║                                                           ║\r\n║   PhishGuard AI - Multi-Agent Phishing Detection API      ║\r\n║   Dual-Model Consensus: Groq Llama + Google Gemini Flash  ║\r\n║                                                           ║\r\n╠═══════════════════════════════════════════════════════════╣\r\n║                                                           ║\r\n║   Server running on port ${String(CONFIG.PORT).padEnd(34)}║\r\n║                                                           ║\r\n║   Endpoints:                                              ║\r\n║   - POST /api/scan          - Analyze a URL               ║\r\n║   - GET  /api/scan/stream   - SSE stream scan             ║\r\n║   - GET  /api/health        - Health check + cache stats   ║\r\n║                                                           ║\r\n║   Performance:                                            ║\r\n║   - LRU scan cache (30min TTL, 500 entries)               ║\r\n║   - LLM rate limiting (Groq 28/min, Gemini 14/min)       ║\r\n║   - Parallel agent execution (all 5 agents)               ║\r\n║   - Content truncation for LLM payloads                   ║\r\n║   - SSE server-side timeout (120s)                        ║\r\n║                                                           ║\r\n║   Security:                                               ║\r\n║   - Rate limiting: 30 req/min per IP                      ║\r\n║   - Helmet security headers enabled                       ║\r\n║   - Input validation with Zod                             ║\r\n║                                                           ║\r\n╚═══════════════════════════════════════════════════════════╝\r\n  `);
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

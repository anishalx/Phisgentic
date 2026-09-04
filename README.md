# PhishGuard AI - Multi-Agent Phishing Detection System

A comprehensive, multi-agent AI-powered phishing detection system featuring **dual-model cross-verification** with two independent LLMs (Groq Llama 3.3 70B + Google Gemini 2.0 Flash) for consensus-based analysis, plus optional **Google Safe Browsing API v4** integration for external threat intelligence. The system employs **5 specialized AI agents** that analyze URLs in parallel across multiple dimensions -- URL structure, domain reputation, page content, social engineering heuristics, and live browser behavioral testing. Delivered through three integrated platforms: a **Next.js Web Dashboard** with real-time SSE streaming, a **Node.js Backend API Server** with Playwright browser automation, and a **Chrome Browser Extension** (Manifest V3) for passive real-time protection.

![Architecture](structure.png)

---

## Table of Contents

- [Key Highlights](#key-highlights)
- [Features](#features)
  - [Dual-Model Cross-Verification](#dual-model-cross-verification)
  - [AI Agent System](#ai-agent-system)
  - [Performance Optimizations](#performance-optimizations)
  - [Platform Features](#platform-features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Start the Backend API Server](#1-start-the-backend-api-server)
  - [2. Start the Web Dashboard](#2-start-the-web-dashboard)
  - [3. Build and Load the Chrome Extension](#3-build-and-load-the-chrome-extension)
  - [4. Analyze URLs](#4-analyze-urls)
- [API Reference](#api-reference)
  - [POST /api/scan](#post-apiscan)
  - [GET /api/scan/stream](#get-apiscanstream)
  - [GET /api/health](#get-apihealth)
- [Agent Deep Dive](#agent-deep-dive)
  - [URL Agent](#1-url-agent)
  - [Domain Agent](#2-domain-agent)
  - [Content Agent](#3-content-agent)
  - [Heuristic Agent](#4-heuristic-agent)
  - [Tester Agent](#5-tester-agent)
- [Orchestrator and Scoring](#orchestrator-and-scoring)
  - [Parallel Execution Pipeline](#parallel-execution-pipeline)
  - [Weighted Scoring Formula](#weighted-scoring-formula)
  - [Critical Veto System](#critical-veto-system)
  - [Priority Cascade Decision Logic](#priority-cascade-decision-logic)
- [Dual-Model Consensus Engine](#dual-model-consensus-engine)
- [Detection Signals Reference](#detection-signals-reference)
- [Web Dashboard](#web-dashboard)
- [Chrome Extension](#chrome-extension)
- [Configuration](#configuration)
  - [Agent Weights](#agent-weights)
  - [Risk Thresholds](#risk-thresholds)
  - [Environment Variables](#environment-variables)
  - [Safe Domains Whitelist](#safe-domains-whitelist)
  - [Blocklist Domains](#blocklist-domains)
  - [Protected Brands](#protected-brands)
- [Deployment](#deployment)
  - [Render.com One-Click Deploy](#rendercom-one-click-deploy)
- [Technologies](#technologies)
- [API Response Types](#api-response-types)
- [Security Considerations](#security-considerations)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Key Highlights

- **Dual-Model AI Consensus**: Two independent LLMs (Groq Llama 3.3 70B + Google Gemini 2.0 Flash) cross-verify every analysis, reducing false negatives and increasing reliability
- **5 Specialized AI Agents**: URL, Domain, Content, Heuristic, and Tester agents analyze URLs in parallel with weighted scoring
- **Google Safe Browsing Integration**: Optional Google Safe Browsing Lookup API v4 integration provides external threat intelligence, running in parallel with agents and capable of overriding early-exit decisions
- **Critical Veto System**: Instant block on high-confidence phishing signals (typosquatting, homograph attacks, cross-origin credential forms, logo mismatches) regardless of overall score
- **Performance Optimized**: LRU caching (500 entries, 30-min TTL), parallel agent execution with deferred promises, token bucket rate limiting, content truncation, early-exit fast paths
- **Vision-Based Logo Detection**: Groq Vision model (Llama 3.2 11B Vision) identifies brand logos on suspicious domains
- **Real-Time Streaming**: Server-Sent Events (SSE) stream agent activity logs to the dashboard in real time
- **3 Delivery Platforms**: Next.js Web Dashboard, Express API Server, Chrome Extension (Manifest V3)
- **Security-First Thresholds**: Tightened scoring (allow <= 30, warn 31-69, block >= 70) with lowered conviction thresholds -- better to warn on a safe site than miss phishing
- **Deployment Ready**: Render.com blueprint for one-click cloud deployment

---

## Features

### Dual-Model Cross-Verification

Each AI agent sends the same analysis prompt to **both** Groq Llama and Google Gemini Flash independently. Results are compared using a consensus engine with configurable disagreement strategies:

| Scenario | Consensus Strategy | Outcome |
|----------|--------------------|---------|
| Both models agree (score diff <= 15) | `consensus-average` | Confidence-weighted average of both scores |
| Models disagree on risk (score diff > 15) | `conservative` / `average` / `max` | Configurable -- defaults to taking the higher (more cautious) risk score |
| One model fails | `single-model-fallback` | Gracefully falls back to the working model's result |
| Both models fail | Local heuristics only | Falls back to deterministic local analysis (no LLM) |

This dual-model approach significantly reduces false negatives (missed phishing) and increases overall reliability by requiring independent agreement from two architecturally different LLMs.

### AI Agent System

The system deploys 5 specialized agents that each focus on a different dimension of phishing detection:

| Agent | Weight | Analysis Focus | Key Detection Capabilities |
|-------|--------|----------------|----------------------------|
| **URL Agent** | 20% | URL structure analysis | IP addresses, typosquatting, homograph attacks, suspicious TLDs, URL shorteners, encoded characters, phishing keywords |
| **Domain Agent** | 25% | Domain reputation & identity | Blocklist matching, brand impersonation, DGA detection, suspicious hosting, excessive hyphens, domain length anomalies |
| **Content Agent** | 25% | Page content analysis | Cross-origin form submissions, brand mismatches, sensitive data requests, urgency language, mismatched links, hidden elements |
| **Heuristic Agent** | 15% | Social engineering patterns | Urgency/threat language, reward scams, poor grammar, manipulative titles, suspicious URL parameters, news context awareness |
| **Tester Agent** | 15% | Live browser behavioral testing | Redirects, popups, downloads, permission requests, safety warnings, form hijacking, vision-based logo detection, screenshot capture |

Each agent combines **fast local heuristic checks** (deterministic, sub-millisecond) with **dual-model LLM analysis** (deeper semantic understanding) using a configurable weighted blend (typically 40% local + 60% LLM).

### Performance Optimizations

- **Parallel Agent Execution**: All 5 agents run simultaneously using a deferred promise pattern. URL and Domain agents start immediately; Tester Agent launches a headless browser; Content and Heuristic agents await page content from Tester Agent, then run their analysis in parallel. Google Safe Browsing check runs in parallel with all agents.
- **Early-Exit Fast Path**: If both URL Agent and Domain Agent score < 5 (clearly safe) AND Google Safe Browsing does not flag the URL, the remaining 3 agents are skipped entirely, saving 5-10 seconds per scan. If Safe Browsing flags the URL, early exit is cancelled and full analysis proceeds.
- **LLM Fast Path**: Individual agents skip LLM calls when local analysis produces a score < 10 (clearly safe) or >= 80 (clearly dangerous), saving 2-4 seconds per agent.
- **LRU Scan Cache**: 500-entry cache with 30-minute TTL for instant repeat scans. URL normalization ensures consistent cache hits.
- **LLM Rate Limiting**: Token bucket algorithm prevents API quota exhaustion -- Groq at 28 req/min (below 30 RPM free tier), Gemini at 14 req/min (below 15 RPM free tier).
- **Content Truncation**: LLM payloads capped at 4,000 chars per string, 20 items per array, max recursion depth 5, preventing token overflow.
- **Browser Singleton**: Playwright Chromium instance is reused across scans (only the browser context is recycled per scan).
- **SSE Keepalive**: 20-second keepalive pings prevent proxy/CDN timeouts on long-running scans.
- **Server-Side Timeout**: 120-second auto-disconnect on SSE streams prevents hanging connections.

### Platform Features

- **Web Dashboard**: Modern Next.js 14 interface with glassmorphism design, real-time agent log streaming via SSE, animated verdict gauges, screenshot preview, and expandable per-agent breakdowns
- **Chrome Extension**: Passive real-time protection with fullscreen warning overlays, risk score ring in popup, scan history, per-domain whitelist, and one-click "Trust Site" functionality
- **Backend API**: RESTful + SSE endpoints, Zod input validation, Helmet security headers, CORS with extension support, express-rate-limit (30 req/min per IP), graceful Playwright shutdown

---

## System Architecture

```
+-----------------------+                               +-----------------------+
|    Web Dashboard      |                               |  Chrome Extension     |
|  (Next.js 14 +        |                               |  (Manifest V3)        |
|   TailwindCSS +       |                               |  Service Worker +     |
|   Framer Motion)      |                               |  Content Script +     |
+-----------+-----------+                               |  Popup UI)            |
            |                                           +-----------+-----------+
            +---------------------------+---------------------------+
                                        |
                              HTTP POST / SSE GET
                                        |
                                        v
+-----------------------------------------------------------------------+
|                          Backend API Server                            |
|                    (Express + TypeScript + Playwright)                 |
|                                                                       |
|   Middleware: Helmet | CORS | Rate Limit (30/min) | Zod Validation    |
|                                                                       |
|   +---------------------------------------------------------------+   |
|   |                        Orchestrator                            |   |
|   |  Parallel execution with deferred promise pattern              |   |
|   |  5-layer priority cascade + critical veto system               |   |
|   |  Weighted scoring + early-exit optimization                    |   |
|   |                                                                |   |
|   |  +--------+ +--------+ +---------+ +----------+ +---------+  |   |
|   |  |  URL   | | Domain | | Content | | Heuristic| | Tester  |  |   |
|   |  | Agent  | | Agent  | |  Agent  | |  Agent   | |  Agent  |  |   |
|   |  | (20%)  | | (25%)  | |  (25%)  | |  (15%)   | |  (15%)  |  |   |
|   |  +---+----+ +---+----+ +----+----+ +----+-----+ +----+----+  |   |
|   |      |          |           |            |            |       |   |
|   |      +-----+----+-----+----+------+-----+-----+------+       |   |
|   |            |          |           |            |              |   |
|   |  +---------------------------------------------------------+  |   |
|   |  | Google Safe Browsing API v4 (optional)                  |  |   |
|   |  | Runs in parallel with agents, can override early-exit   |  |   |
|   |  +---------------------------------------------------------+  |   |
|   |            |          |                                       |   |
|   +---------------------------------------------------------------+   |
|                |                                   |                  |
|    +-----------+----------+           +-----------+-----------+       |
|    v                      v           v                       v       |
|  +---------------------+  +---------------------+                    |
|  |    Groq LLM API     |  | Google Gemini API   |                    |
|  | Llama 3.3 70B (text)|  | Gemini 2.0 Flash    |                    |
|  | Llama 3.2 11B (vis.)|  | (cross-verification)|                    |
|  +---------------------+  +---------------------+                    |
|                                                                       |
|   +---------------------------------------------------------------+   |
|   |              Performance Layer                                 |   |
|   |  [LRU Cache: 500 entries, 30min TTL]                          |   |
|   |  [Rate Limiter: Groq 28/min, Gemini 14/min]                   |   |
|   |  [Content Truncation: 4000 chars, 20 items, depth 5]          |   |
|   |  [Browser Singleton: Chromium reuse across scans]             |   |
|   +---------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
```

---

## Project Structure

```
agent-browser/
├── server/                              # Backend API Server
│   ├── src/
│   │   ├── agents/
│   │   │   ├── base-agent.ts            # Abstract agent class + dual-model consensus engine
│   │   │   ├── url-agent.ts             # URL structure analysis (typosquatting, homographs)
│   │   │   ├── domain-agent.ts          # Domain reputation checks (blocklists, brand impersonation)
│   │   │   ├── content-agent.ts         # Page content analysis via Playwright
│   │   │   ├── heuristic-agent.ts       # Social engineering pattern matching
│   │   │   ├── tester-agent.ts          # Browser behavioral testing + vision logo detection
│   │   │   └── orchestrator.ts          # Parallel agent coordination, weighted scoring, veto logic
│   │   ├── api/
│   │   │   ├── groq-client.ts           # Groq LLM client (text + vision, singleton, rate-limited)
│   │   │   ├── gemini-client.ts         # Google Gemini Flash client (singleton, rate-limited)
│   │   │   └── safe-browsing-client.ts  # Google Safe Browsing Lookup API v4 client (optional)
│   │   ├── config/
│   │   │   └── index.ts                 # Weights, thresholds, blocklists, whitelists, LLM config
│   │   ├── types/
│   │   │   └── index.ts                 # TypeScript type definitions (19 interfaces + type aliases)
│   │   ├── utils/
│   │   │   ├── url-parser.ts            # URL parsing, TLD extraction, homoglyph detection, Levenshtein distance
│   │   │   ├── cache.ts                 # LRU scan cache with TTL and URL normalization
│   │   │   └── rate-limiter.ts          # Token bucket rate limiter with async queue
│   │   └── server.ts                    # Express server: endpoints, SSE streaming, middleware, graceful shutdown
│   ├── package.json                     # Dependencies: express, playwright, zod, helmet, cors
│   └── tsconfig.json                    # TypeScript config (ES2022, NodeNext modules)
│
├── web-dashboard/                       # Frontend Dashboard (Next.js 14)
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx               # Root layout with Inter font
│   │   │   ├── page.tsx                 # Main page: state management, SSE connection, component composition
│   │   │   └── globals.css              # Custom CSS: glassmorphism, gauges, signal badges, terminal theme
│   │   ├── components/
│   │   │   ├── ScanningInterface.tsx     # URL input form, validation, quick-test buttons (safe/suspicious/phishing)
│   │   │   ├── StatusFeed.tsx           # Terminal-styled real-time agent activity log viewer
│   │   │   ├── ResultCard.tsx           # Verdict display: SVG gauge, critical signals, screenshot, metadata
│   │   │   ├── AgentBreakdown.tsx       # Expandable accordion: per-agent scores, explanations, signals
│   │   │   └── index.ts                # Barrel export
│   │   ├── lib/
│   │   │   └── api.ts                  # API client: fetch-based SSE streaming, retry logic, health check
│   │   └── types/
│   │       ├── index.ts                # Dashboard TypeScript types (Signal, AgentResult, FinalVerdict, etc.)
│   │       └── framer-motion.d.ts      # Framer Motion type declarations
│   ├── package.json                    # Dependencies: next 14, react 18, framer-motion, lucide-react, tailwindcss
│   ├── tailwind.config.js              # Custom colors (safe/warning/danger), animations
│   ├── next.config.js                  # Standalone output mode for deployment
│   └── postcss.config.js              # PostCSS with Tailwind + Autoprefixer
│
├── src/                                 # Chrome Browser Extension (Manifest V3)
│   ├── background/
│   │   └── service-worker.ts            # Navigation interception, API communication, badge updates, retry logic
│   ├── content/
│   │   └── content-script.ts            # Page content extraction, fullscreen warning overlay injection, XSS-safe rendering
│   ├── ui/popup/
│   │   ├── popup.ts                     # Popup logic: status display, ring progress, agent cards, history, trust/report
│   │   ├── popup.html                   # Popup markup: header, SVG ring, agent grid, signals, quick actions, history panel
│   │   └── popup.css                    # Dark theme design system with CSS custom properties
│   ├── config/
│   │   └── index.ts                     # Extension config: API base URL, thresholds, safe domains, patterns
│   ├── types/
│   │   └── index.ts                     # Extension type system (19 interfaces + message types, storage shape)
│   ├── api/
│   │   └── groq-client.ts              # Groq client reference (not used at runtime -- backend handles LLM calls)
│   └── utils/
│       ├── url-parser.ts                # URL parsing, TLD handling, homoglyph detection, Levenshtein distance
│       └── storage.ts                   # Chrome storage wrapper: settings, whitelist, history, API key CRUD
│
├── scripts/
│   └── copy-assets.js                   # Build script: copies manifest.json, assets/, popup.html/css to dist/
│
├── assets/                              # Extension assets
│   ├── icon-16.png                      # Extension icon 16x16
│   ├── icon-48.png                      # Extension icon 48x48
│   └── icon-128.png                     # Extension icon 128x128
│
├── manifest.json                        # Chrome Extension Manifest V3 configuration
├── vite.config.ts                       # Vite build config for extension (3 entry points)
├── render.yaml                          # Render.com deployment blueprint (API + Dashboard)
├── .env.example                         # Environment variable template
├── .gitignore                           # Git ignore rules
├── tsconfig.json                        # Root TypeScript config for extension (ES2022, bundler)
├── package.json                         # Root package: extension build scripts, vite, @types/chrome
└── README.md                            # This file
```

---

## Getting Started

### Prerequisites

- **Node.js 18+** (LTS recommended)
- **npm** (included with Node.js)
- **Groq API Key** (required) -- [Get one free at console.groq.com](https://console.groq.com/)
- **Google Gemini API Key** (optional, enables dual-model consensus) -- [Get one free at aistudio.google.com](https://aistudio.google.com/apikey)

### 1. Start the Backend API Server

```bash
cd server
npm install

# Create your environment file
cp .env.example .env
```

Edit the `.env` file and add your API keys:

```env
# Required -- Primary LLM
GROQ_API_KEY=your_groq_api_key_here

# Optional -- Enables dual-model cross-verification
GEMINI_API_KEY=your_gemini_api_key_here

# Enable dual-model consensus (set to "true" if you have both keys)
DUAL_MODEL_ENABLED=true

# Optional -- Enables Google Safe Browsing external threat intelligence
GOOGLE_SAFE_BROWSING_API_KEY=your_safe_browsing_api_key_here
```

Start the server:

```bash
# Development mode (with hot reload via tsx)
npm run dev

# Production mode
npm run build
npm start
```

The API server runs on **`http://localhost:3001`** by default.

> **Note**: On first run, Playwright will download the Chromium browser binary (~150MB). This is a one-time download.

### 2. Start the Web Dashboard

```bash
cd web-dashboard
npm install
npm run dev
```

The dashboard runs on **`http://localhost:3000`** by default.

### 3. Build and Load the Chrome Extension

```bash
# From the project root (agent-browser/)
npm install
npm run build
```

Load the extension in Chrome:

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `dist/` folder that was created by the build step

> **Important**: The Chrome extension requires the backend API server to be running at `http://localhost:3001`. Make sure the server is started before using the extension.

### 4. Analyze URLs

**Via Web Dashboard:**

1. Open `http://localhost:3000` in your browser
2. Enter a URL to analyze (e.g., `https://google.com`) or click a quick-test button
3. Click **Scan URL**
4. Watch the agents analyze in real-time via the terminal-styled status feed
5. View the detailed verdict with risk score gauge, screenshot, and per-agent breakdown

**Via Chrome Extension:**

1. Simply browse the web -- the extension automatically intercepts every navigation
2. For dangerous/suspicious sites, a fullscreen warning overlay appears
3. Click the extension icon to see the risk score ring, agent breakdown, and detected signals
4. Use **Trust Site** to whitelist a domain, or **Report** to flag false positives

**Via API (curl):**

```bash
# Standard JSON response
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# SSE streaming response
curl -N "http://localhost:3001/api/scan/stream?url=https://example.com"
```

---

## API Reference

### POST /api/scan

Analyze a URL for phishing indicators. Returns the complete verdict as a single JSON response.

**Request:**

```json
{
  "url": "https://example.com"
}
```

- URL must be a valid URL (validated by Zod)
- Maximum URL length: 2,048 characters
- Rate limited: 30 requests/minute per IP

**Response (200 OK):**

```json
{
  "success": true,
  "verdict": {
    "action": "allow",
    "overallRiskScore": 0,
    "confidence": 0.99,
    "summary": "SAFE - This is a verified trusted domain.",
    "url": "https://example.com",
    "timestamp": 1709123456789,
    "screenshot": "data:image/jpeg;base64,...",
    "agentResults": [
      {
        "agentId": "urlAgent",
        "agentName": "URL Analysis Agent",
        "riskScore": 0,
        "confidence": 0.95,
        "signals": [],
        "explanation": "No suspicious URL patterns detected.",
        "executionTimeMs": 45
      }
    ]
  },
  "logs": [
    {
      "agentId": "orchestrator",
      "agentName": "Orchestrator",
      "message": "Starting parallel agent analysis...",
      "timestamp": 1709123456000,
      "type": "info"
    }
  ]
}
```

**Error Response (400/500):**

```json
{
  "success": false,
  "error": "Invalid URL format",
  "logs": []
}
```

### GET /api/scan/stream

SSE (Server-Sent Events) endpoint for real-time analysis with streaming agent logs. This is the primary endpoint used by the web dashboard.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | The URL to analyze (URL-encoded) |

**Example:**

```
GET /api/scan/stream?url=https%3A%2F%2Fexample.com
```

**SSE Event Types:**

| Event | Data Format | Description |
|-------|-------------|-------------|
| `log` | `AgentLog` JSON | Real-time agent activity update (sent multiple times) |
| `result` | `FinalVerdict` JSON | Final verdict with scores and agent results (sent once) |
| `done` | `"done"` | Analysis complete signal (sent once, last event) |
| `error` | `{ error: string }` JSON | Error occurred during analysis |

**SSE Headers Set:**

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

**Connection Behavior:**

- Keepalive pings sent every 20 seconds (SSE comment `: keepalive`)
- Server-side timeout: 120 seconds
- Cached results are replayed instantly as SSE events

### GET /api/health

Health check endpoint with cache statistics.

**Response:**

```json
{
  "status": "ok",
  "timestamp": 1709123456789,
  "cache": {
    "size": 5,
    "maxSize": 500,
    "ttlMs": 1800000
  }
}
```

---

## Agent Deep Dive

All agents extend the abstract `BaseAgent` class, which provides:
- LLM integration via both `GroqClient` and `GeminiClient`
- Dual-model consensus engine (`dualModelAnalyze()`)
- Payload truncation for LLM calls
- Signal and result factory methods
- Score clamping (0-100) and confidence clamping (0-1)

Each agent follows the same pattern:
1. **Local heuristic analysis** (fast, deterministic)
2. **Fast-path decision** (skip LLM if clearly safe or clearly dangerous)
3. **Dual-model LLM analysis** (if needed)
4. **Score blending** (weighted combination of local + LLM scores)

### 1. URL Agent

**ID:** `urlAgent` | **Weight:** 20% | **Score Blend:** 40% local + 60% LLM

Analyzes URL structure for phishing indicators without fetching the page.

| Detection Check | Condition | Score Impact | Severity |
|----------------|-----------|--------------|----------|
| URL length | > 100 characters | +5 | medium |
| URL length | > 75 characters | +3 | low |
| IP address instead of domain | Public IPv4 detected (excludes private/local) | +25 | critical |
| Subdomain depth | > 3 levels deep | +8 | medium |
| Suspicious TLD | `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.icu`, `.buzz`, `.monster`, `.rest`, `.cam`, `.uno`, `.fit`, `.pw`, `.ws`, `.su`, `.link`, `.site`, `.online`, `.live`, `.fun`, `.website` | +20 | high |
| URL shortener | `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, etc. (16 services) | +15 | medium |
| Encoded characters | `%XX` patterns in URL | +3 | low |
| Special characters | > 10 special chars in pathname | +10 | medium |
| Homograph attack | Cyrillic, Greek, or Latin Extended Unicode characters (e.g., Cyrillic "а" vs Latin "a") | +35 | critical |
| Phishing keywords | > 2 keywords (`login`, `verify`, `secure`, `password`, etc.) in path | +15 | high |
| Typosquatting | Levenshtein distance 1-2 from a protected brand name | +35 | critical |
| No HTTPS | HTTP protocol used | +10 | medium |
| Non-standard port | Port is not 80, 443, or empty | +8 | medium |

**Fast Path:** If local score < 10, returns immediately without calling the LLM (saves 2-4 seconds).

### 2. Domain Agent

**ID:** `domainAgent` | **Weight:** 25% | **Score Blend:** 40% local + 60% LLM

Analyzes domain reputation, brand impersonation, and blocklist matching. This is the most critical agent.

| Detection Check | Condition | Score Impact | Severity |
|----------------|-----------|--------------|----------|
| Safe domain | Matches 150+ trusted domains (Google, Microsoft, etc.) | **Instant score 0** | - |
| Blocklist match | `duckdns.org`, `000webhostapp.com`, `ddns.net`, etc. | **Instant score 95** | critical |
| Suspicious hosting | `000webhostapp.com`, `forms.gle`, `sites.google.com`, `vercel.app`, `netlify.app`, `web.app`, `firebaseapp.com`, `github.io`, `herokuapp.com`, `blogspot.com`, `weebly.com`, `wix.com`, `wordpress.com`, `pages.dev`, `workers.dev`, `onrender.com`, `surge.sh`, `tiiny.site`, `carrd.co`, `glitch.me`, `repl.co` | +20 | high |
| Brand impersonation | Brand name found in domain segments, not on official domain | +45 | critical |
| Brand in subdomain | Brand name in subdomain but different main domain | +40 | critical |
| Suspicious TLD | Matches suspicious TLD list | +25 | high |
| Suspicious patterns | `-login`, `-secure`, `-verify`, `-account` in hostname | +5 to +12 | medium |
| DGA detection | Consonant ratio > 0.85, vowel ratio < 0.12, 5+ consecutive consonants | +30 | high |
| Hostname length | > 50 chars: +15, > 35 chars: +8 | +8 to +15 | medium/high |
| Multiple hyphens | > 3 hyphens: +20, > 1 hyphen: +8 | +8 to +20 | medium/high |

**Brand Impersonation Logic:** Short brand names (<=3 chars like "ups", "dhl") use exact segment matching (split on dots/hyphens) to avoid false positives. For example, "setup.com" does NOT match "ups", but "ups-login.evil.com" does.

**Fast Paths:**
- Local score < 10: returns immediately, skips LLM
- Local score >= 80: returns immediately with confidence 0.95, skips LLM

### 3. Content Agent

**ID:** `contentAgent` | **Weight:** 25% | **Score Blend:** 40% local + 60% LLM

Analyzes page content using Playwright headless browser. Fetches and renders the page, then examines forms, links, meta tags, and text content.

| Detection Check | Condition | Score Impact | Severity |
|----------------|-----------|--------------|----------|
| External form action | Password form submitting to unknown external domain (skips known auth providers like auth0, okta, stripe) | +25 | critical |
| Brand impersonation in title | Brand name in page title but URL is not the brand's domain | +25 (or +10 with educational context) | high |
| Sensitive data requests | SSN, credit card, bank account, maiden name, DOB requested via forms | +10 to +30 | high/critical |
| Urgency/threat language | "account suspended", "verify now", "unauthorized access", time pressure | +10 per match (max +30) | medium/high |
| Mismatched brand links | Link text says "PayPal" but href goes to a different domain | +35 | critical |
| CAPTCHA/blocked page | Cloudflare challenge, "verify you are human" | +15 | medium |
| Empty page | Body text < 100 chars | +10 | low |

**Educational Context Detection:** Words like "review", "guide", "vs", "tutorial", "blog", "api" in the title downgrade brand-impersonation severity from +25 to +10.

**Known Auth/Payment Domains:** Cross-origin form submissions to legitimate auth providers (auth0.com, okta.com, accounts.google.com, stripe.com, paypal.com, razorpay.com, etc.) are excluded from phishing signals.

**Playwright Configuration:** Chromium headless, viewport 1280x720, Chrome 120 user agent, `domcontentloaded` wait strategy.

### 4. Heuristic Agent

**ID:** `heuristicAgent` | **Weight:** 15% | **Score Blend:** 30% local + 70% LLM

Detects social engineering patterns and behavioral manipulation tactics. Features **news context awareness** to avoid false positives on news articles that naturally contain threat-related language.

| Detection Check | Condition | Score Impact | Severity |
|----------------|-----------|--------------|----------|
| Urgency language | >= 3 matches ("urgent", "immediately", "24 hours", "verify now", "action required") | +20 | critical |
| Urgency language | 1-2 matches | +8 | medium |
| Threat language | >= 5 matches ("suspended", "locked", "unauthorized", "breach", "compromised") | +15 | high |
| Threat language | >= 3 matches | +8 | medium |
| Sensitive data requests | SSN, credit card, CVV, PIN, DOB, maiden name, bank account | +20 | critical |
| Reward/prize scams | "you have won", "congratulations", "claim your prize", "gift card", "free iPhone" | +10 | medium |
| Manipulative title | Title contains "verify", "confirm", or "secure" | +5 | low |
| Poor grammar | Common typos: "recieve", "occured", "youre account", etc. | +10 | medium |
| Urgency in URL | Urgency patterns as URL path segments | +15 | high |
| Suspicious parameters | > 2 of: `token`, `verify`, `confirm`, `secure`, `login`, `session` | +15 | high |
| Base64-like data | 30+ chars of `[A-Za-z0-9+/=]` in URL | +10 | medium |

**News Context Detection:** Returns true if the page has `og:type=article` meta tags, news-specific meta tags (`article:published_time`, `news_keywords`), news outlet names in the title (BBC, CNN, Reuters), or 2+ article markers ("published on", "staff writer", "copyright") with text > 2000 chars. In news context, urgency/threat thresholds are raised significantly to avoid false positives.

### 5. Tester Agent

**ID:** `testerAgent` | **Weight:** 15% | **Score Blend:** 40% local + 60% LLM

Performs live browser behavioral testing using Playwright. Launches a headless Chromium browser, navigates to the URL, and monitors for suspicious behaviors.

| Detection Check | Condition | Score Impact | Severity |
|----------------|-----------|--------------|----------|
| Cross-origin password form | Form with password field submitting to a different domain | +50 | critical |
| Cross-origin credit card form | Form with credit card field submitting to a different domain | +50 | critical |
| Safety warning | Browser error page or Safe Browsing block | +40 | critical |
| Download attempted | Automatic file download triggered | +30 | critical |
| Excessive redirects | > 3 redirects | +20 | high |
| Cross-domain redirect | Original domain != final domain (normalized, excludes www) | +15 | high |
| Permission requests | Browser permission dialogs (geolocation, notifications, etc.) | +15 | high |
| Popup dialogs | Alert/confirm/prompt dialogs on page load | +15 | medium |
| Overlays detected | Modal, popup, or overlay CSS elements on page load | +10 | medium |
| Slow load | > 15 seconds load time | +10 | medium |
| Console errors | > 5 JavaScript errors | +10 | low |
| Cross-origin POST form | Non-credential form posting cross-origin | +8 | medium |

**Vision-Based Logo Detection:**

1. Takes a JPEG screenshot of the page (quality 70)
2. Sends the screenshot to Groq Vision model (Llama 3.2 11B Vision)
3. The model identifies any brand logos visible on the page
4. Cross-references detected brands against a mapping of 30+ brands to their legitimate domains
5. If a brand logo is detected on a domain that does NOT belong to that brand, a `logo_domain_mismatch` critical signal is raised and the score is set to at least 85

**Browser Singleton:** The Playwright Chromium instance is created once and reused across all scans. Only the browser context is recycled per scan, preventing resource leaks and reducing startup time.

**Graceful Degradation:** If `DISABLE_TESTER_AGENT=true` is set (e.g., on hosting platforms without Playwright support), the agent returns a neutral score of 0 with confidence 0.1.

---

## Orchestrator and Scoring

The orchestrator (`orchestrator.ts`) is the central coordinator that runs all agents, applies veto logic, and produces the final verdict. It also integrates with Google Safe Browsing API v4 for external threat intelligence.

### Parallel Execution Pipeline

```
                        ┌──────────────────────────┐
                        │  URL Agent (immediate)    │──┐
                        ├──────────────────────────┤  │
                        │  Domain Agent (immediate) │──┤
                        ├──────────────────────────┤  │
                        │  Tester Agent (browser)   │──┤── Promise.allSettled()
                        ├──────────────────────────┤  │
                        │  Content Agent (awaits    │──┤
                        │  pageContent from Tester) │  │
                        ├──────────────────────────┤  │
                        │  Heuristic Agent (awaits  │──┘
                        │  pageContent from Tester) │
                        └──────────────────────────┘
                        ┌──────────────────────────┐
                        │  Google Safe Browsing     │── Runs in parallel
                        │  (external threat intel)  │   Can override early exit
                        └──────────────────────────┘

Early Exit: If URL + Domain both score < 5 AND Safe Browsing clear → skip remaining 3 agents
```

1. **URL Agent** and **Domain Agent** start immediately (no browser needed)
2. **Google Safe Browsing** check runs in parallel with all agents (if configured)
3. **Tester Agent** starts the headless browser in parallel
4. A deferred promise (`pageContentPromise`) is created
5. **Content Agent** and **Heuristic Agent** await this promise, which resolves when Tester Agent completes and provides `pageContent`
6. Once resolved, Content and Heuristic agents run their analysis in parallel
7. All results are collected via `Promise.allSettled()` with a per-agent timeout of 45 seconds
8. If Google Safe Browsing flags the URL, a synthetic `known_phishing_domain` veto signal is injected into results

### Weighted Scoring Formula

```
finalScore = Σ(agentScore × agentWeight × agentConfidence) / Σ(agentWeight × agentConfidence)
```

Where:
- `agentScore` = the agent's risk score (0-100)
- `agentWeight` = configured weight from `CONFIG.AGENT_WEIGHTS`
- `agentConfidence` = the agent's confidence level (0-1)

This confidence-weighted approach means high-confidence results have more influence on the final score than low-confidence ones.

### Critical Veto System

The following signal types trigger an **immediate block** (score >= 85) regardless of the overall weighted average:

> **Vetoes only fire on deterministic detections.** Every signal carries an `origin` (`local` | `llm` | `synthetic`). LLM-suggested signals never trigger a veto — a model can hallucinate a veto-list type name on a legitimate site — so only locally-detected signals and trusted external intel (Safe Browsing) can auto-block. LLM agreement still raises the score, it just can't hard-block by itself.

| Veto Signal | Source Agent(s) | Description |
|-------------|-----------------|-------------|
| `blocklist_match` | Domain | Domain on known phishing blocklist |
| `known_phishing_domain` | Safe Browsing (external) | URL flagged by Google Safe Browsing v4 |
| `typosquatting` | URL | Domain mimics a known brand (e.g., `paypa1.com`) |
| `homograph` | URL | Unicode lookalike characters in domain (e.g., Cyrillic "а" in "pаypal") |
| `brand_impersonation` | Domain | Brand as an exact label or glued to a credential keyword on a non-official domain (e.g., `paypal-login.com`, `paypalsecure.com`). Substring-only matches like `amazonaws.com` are excluded |
| `brand_in_subdomain` | Domain | Brand label as a subdomain of an unrelated domain (e.g., `accounts.google.com.evil-site.top`) |
| `download_attempted` | Tester | Automatic file download triggered on page load |
| `safety_warning` | Tester | Browser Safe Browsing warning detected |
| `logo_domain_mismatch` | Tester | Vision-detected brand logo on non-brand domain |
| `cross_origin_password_form` | Tester | Password form submitting to a different domain |
| `cross_origin_credential_form` | Tester | Credential form submitting to a different domain |

### Priority Cascade Decision Logic

The orchestrator uses a 5-layer priority cascade to determine the final verdict:

| Priority | Condition | Result |
|----------|-----------|--------|
| **0** | URL domain matches the safe domains whitelist (150+ domains) | **Instant ALLOW** (score 0, confidence 0.99) |
| **1** | Any agent reports a locally-detected veto signal (from the list above; LLM suggestions excluded) | **Instant BLOCK** (score >= 85) |
| **2** | Single agent conviction: any agent scores >= 75 | **BLOCK** |
| **3** | Consensus block: 2+ agents score > 55 | **BLOCK** (average of suspicious agents, minimum 65) |
| **4** | Weighted average calculation with standard thresholds | `allow` (<= 30), `warn` (31-69), `block` (>= 70) |

**Bump Rule:** If the weighted average produces an "allow" action but there are 2+ high-severity signals OR any critical-severity signal present, the verdict is bumped from "allow" to "warn".

---

## Dual-Model Consensus Engine

The dual-model consensus engine is implemented in `BaseAgent.dualModelAnalyze()` and is used by every agent:

```
                    ┌─────────────────┐
                    │  Analysis Data  │
                    │  (truncated)    │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │  Promise.all()  │
                    ├─────────────────┤
              ┌─────┴─────┐   ┌──────┴──────┐
              │   Groq    │   │   Gemini    │
              │ Llama 3.3 │   │ 2.0 Flash   │
              │   70B     │   │             │
              └─────┬─────┘   └──────┬──────┘
                    │                │
                    └────────┬───────┘
                             │
                    ┌────────┴────────┐
                    │  Consensus      │
                    │  Computation    │
                    └────────┬────────┘
                             │
             ┌───────────────┼───────────────┐
             │               │               │
         Both Agree     Disagree        One/Both Fail
         (diff <= 15)   (diff > 15)
             │               │               │
    Confidence-weighted  Configurable    Fallback to
    average score        strategy         working model
```

**Consensus Computation Details:**

1. **Agreement** (score difference <= 15 points):
   - Uses confidence-weighted average: `consensusScore = (groqScore * groqConf + geminiScore * geminiConf) / (groqConf + geminiConf)`
   - Strategy: `consensus-average`
   - Confidence is boosted since both models agree

2. **Disagreement** (score difference > 15 points):
   - Applies the configured `DISAGREEMENT_STRATEGY`:
     - `conservative`: takes the MAX (higher) score -- more cautious
     - `average`: simple average of both scores
     - `max`: takes the MAX score (same as conservative)

3. **Signal Merging**: Signals from both models are deduplicated by `type:severity` key. Groq signals take priority as the primary model.

4. **Explanation Merging**: If agreed, uses Groq's explanation. If disagreed, shows both: `[Groq: X/100] explanation | [Gemini: Y/100] explanation`.

---

## Detection Signals Reference

### Signal Severity Levels

| Severity | Color | Impact |
|----------|-------|--------|
| `critical` | Red/Purple | Can trigger immediate veto block |
| `high` | Orange | Significant risk contributor |
| `medium` | Yellow/Amber | Moderate risk indicator |
| `low` | Green | Minor indicator, rarely decisive alone |

### Signal Structure

```typescript
interface Signal {
  type: string;        // e.g., "typosquatting", "brand_impersonation"
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string; // Human-readable explanation
  origin?: "local" | "llm" | "synthetic"; // who produced it; "llm" never vetoes
}
```

### Complete Signal Catalog

**URL Agent Signals:** `url_length`, `ip_address`, `subdomain_depth`, `suspicious_tld`, `url_shortener`, `encoded_chars`, `special_chars`, `homograph`, `phishing_keywords`, `typosquatting`, `no_https`, `non_standard_port`

**Domain Agent Signals:** `known_safe`, `blocklist_match`, `suspicious_hosting`, `brand_impersonation`, `brand_in_subdomain`, `suspicious_tld`, `dga_pattern`, `long_domain`, `excessive_hyphens`, `multiple_hyphens`, `suspicious_domain_pattern`

**Content Agent Signals:** `fetch_blocked`, `content_blocked`, `no_content`, `empty_page`, `login_form_same_domain`, `login_form_suspicious_domain`, `external_form_action`, `title_brand_mismatch`, `sensitive_data_request`, `urgency_threat`, `mismatched_brand_links`, `data_uri_form_action`, `simple_password_form`, `minimal_content_with_form`, `all_external_links`

**Heuristic Agent Signals:** `urgency_in_url`, `urgency_language`, `high_urgency`, `threat_language`, `high_threat`, `sensitive_data_request`, `reward_scam`, `manipulative_title`, `poor_grammar`, `suspicious_params`, `encoded_data`

**Tester Agent Signals:** `test_skipped`, `cross_origin_password_form`, `cross_origin_credential_form`, `cross_origin_form`, `safety_warning`, `download_attempted`, `excessive_redirects`, `multiple_redirects`, `cross_domain_redirect`, `permission_requests`, `popups_detected`, `overlays_detected`, `excessive_errors`, `slow_load`, `logo_domain_mismatch`

**External/System Signals:** `known_phishing_domain` (Google Safe Browsing veto injection), `error` (agent failure fallback)

---

## Web Dashboard

### Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 14.2 | React framework with App Router |
| React | 18.3 | UI library |
| TailwindCSS | 3.4 | Utility-first CSS framework |
| Framer Motion | 11.11 | Animation library |
| Lucide React | 0.453 | Icon library |
| TypeScript | 5.6 | Type safety |

### Components

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| `ScanningInterface` | URL input and scan trigger | URL validation (auto-prepends `https://`), quick-test buttons for safe/suspicious/phishing URLs, shield icon with scanning pulse animation |
| `StatusFeed` | Real-time agent activity logs | Terminal-styled dark theme, auto-scroll, macOS traffic lights, color-coded log levels (`[INFO]` cyan, `[WARN]` amber, `[ERR!]` red, `[DONE]` green), blinking cursor |
| `ResultCard` | Final verdict display | SVG circular gauge (animated), color-coded verdict banner (SAFE/SUSPICIOUS/DANGEROUS), critical signal badges, screenshot preview (with red tint for blocks), timestamp and confidence metadata |
| `AgentBreakdown` | Per-agent detail view | Expandable accordion, agent icons (Link/Globe/FileText/Brain/TestTube), animated risk score bars, signal cards with severity icons, confidence percentage |

### Design System

- **Theme:** Cream/warm background with glassmorphism cards
- **Colors:** Safe (emerald green), Warning (amber), Danger (red)
- **Custom CSS:** Glassmorphism (`glass` class with backdrop-blur), gradient text, custom scrollbar, pulse-glow animations, terminal dark mode
- **Responsive:** Mobile-first with adjusted layouts for terminal feed, agent breakdowns, and signal displays

### SSE Streaming API Client

The dashboard uses a custom fetch-based SSE client (not native `EventSource`) with:
- Manual line-by-line SSE parsing
- `AbortController` for cancellation
- Automatic retry (up to 2 retries with 1.5s delay) for network errors
- Production URL auto-detection (falls back to `https://phishguard-api-m35d.onrender.com` when not on localhost)

---

## Chrome Extension

### Architecture

The extension operates in **API mode** -- all AI analysis is delegated to the backend server. No LLM calls are made from the browser.

```
┌─────────────┐     chrome.runtime      ┌──────────────────┐     HTTP POST      ┌──────────────┐
│  Content     │ ◄──────────────────────► │  Service Worker   │ ─────────────────► │  Backend API │
│  Script      │   PAGE_CONTENT           │  (background)     │                    │  :3001       │
│              │   SHOW_WARNING            │                   │ ◄─────────────────  │              │
│              │   USER_OVERRIDE           │                   │   JSON Response    │              │
│              │   GET_STATUS              │                   │                    │              │
└─────────────┘                           └──────────────────┘                    └──────────────┘
                                                 ▲
                                                 │ chrome.runtime
                                                 │ GET_STATUS
                                          ┌──────┴───────┐
                                          │  Popup UI    │
                                          └──────────────┘
```

### Manifest V3 Configuration

```json
{
  "manifest_version": 3,
  "permissions": ["storage", "tabs", "webNavigation", "activeTab"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background/service-worker.js", "type": "module" },
  "content_scripts": [{ "matches": ["<all_urls>"], "run_at": "document_start" }]
}
```

### Navigation Interception Flow

Every main-frame navigation goes through this decision pipeline:

1. **Internal URL filter** -- Skip `chrome://`, `chrome-extension://`, `about:` URLs
2. **Settings check** -- If extension is disabled, skip
3. **Whitelist check** -- If domain (or parent domain) is whitelisted, skip
4. **Safe domain check** -- If domain matches the 150+ trusted domains list, show green badge instantly (no API call)
5. **API analysis** -- Send URL to backend (non-blocking, navigation proceeds)
6. **Post-analysis** -- Store result, update badge, notify content script if dangerous

### Warning Overlay

For `warn` and `block` verdicts, the content script injects a fullscreen overlay:

- **z-index:** 2147483647 (maximum possible)
- **Block verdict:** Red glow, "CRITICAL RISK" badge, "This site may steal your data"
- **Warn verdict:** Amber glow, "WARNING RISK" badge, "This site looks suspicious"
- **Content:** Blocked URL display, analysis summary, agent breakdown with color-coded risk pills
- **Actions:** "Go Back to Safety" (primary), "View Details" (toggleable), "Proceed anyway (unsafe)"
- **Security:** All user-facing text is XSS-escaped via `escapeHtml()` to prevent injection from malicious URLs

### Popup UI Features

- **Risk Score Ring:** SVG circular progress indicator with animated `strokeDasharray`
- **Agent Cards:** Grid of agent results with emoji icons and color-coded score pills
- **Signal List:** First 8 detected signals with severity-colored dots
- **Quick Actions:** Trust Site (adds to whitelist), Report (feedback), History (recent scans)
- **History Panel:** Last 10 scans with relative timestamps, domain names, and color-coded scores
- **Toggle Switch:** Enable/disable the extension

### Chrome Storage

| Key | Type | Description |
|-----|------|-------------|
| `settings` | `Settings` | Enabled toggle, thresholds, notification preferences |
| `whitelist` | `string[]` | Trusted domain list (supports subdomain matching) |
| `analysisHistory` | `AnalysisHistoryEntry[]` | Last ~100 scan records |
| `apiKey` | `string` | Optional Groq API key (not used at runtime) |

### Build System

The extension is built with **Vite** using three entry points:

```typescript
// vite.config.ts
input: {
  "background/service-worker": "src/background/service-worker.ts",
  "content/content-script": "src/content/content-script.ts",
  "ui/popup/popup": "src/ui/popup/popup.ts",
}
```

A post-build script (`scripts/copy-assets.js`) copies `manifest.json`, `assets/` (icons), and `popup.html`/`popup.css` to the `dist/` folder.

---

## Configuration

### Agent Weights

Configured in `server/src/config/index.ts`:

```typescript
AGENT_WEIGHTS: {
  urlAgent: 0.20,       // 20% - URL structure analysis
  domainAgent: 0.25,    // 25% - Domain reputation (highest alongside content)
  contentAgent: 0.25,   // 25% - Page content analysis
  heuristicAgent: 0.15, // 15% - Social engineering patterns
  testerAgent: 0.15,    // 15% - Browser behavioral testing (catches what static analysis misses)
}
```

### Risk Thresholds

**Server-side** (used by orchestrator for final verdict):

```typescript
THRESHOLDS: {
  ALLOW_MAX: 30,   // 0-30: Safe (allow)
  WARN_MAX: 69,    // 31-69: Suspicious (warn)
  BLOCK_MIN: 70,   // 70-100: Dangerous (block)
}
```

**Extension-side** (used for badge/overlay display):

```typescript
THRESHOLDS: {
  ALLOW_MAX: 30,   // 0-30: Safe
  WARN_MAX: 70,    // 31-70: Suspicious
  BLOCK_MIN: 71,   // 71-100: Dangerous
}
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | Yes | - | Groq API key for Llama 3.3 70B text + Llama 3.2 11B Vision |
| `GEMINI_API_KEY` | No | - | Google Gemini API key (enables dual-model cross-verification) |
| `DUAL_MODEL_ENABLED` | No | `true` | Enable/disable dual-model consensus |
| `PORT` | No | `3001` | Backend server port |
| `NODE_ENV` | No | `development` | Environment mode (`development` / `production`) |
| `DISABLE_TESTER_AGENT` | No | `false` | Disable Playwright-based tester agent (for platforms without browser support) |
| `DISABLE_VISION_DETECTION` | No | `false` | Disable vision-based logo detection |
| `GOOGLE_SAFE_BROWSING_API_KEY` | No | - | Google Safe Browsing API key (enables external threat intelligence checks) |
| `DASHBOARD_URL` | No | - | Dashboard URL for CORS (production) |
| `NEXT_PUBLIC_API_URL` | No | `http://localhost:3001` | Dashboard's API base URL |

### Safe Domains Whitelist

Over **150 trusted domains** across categories that receive instant "allow" verdicts (no API/LLM calls):

- **Search/Tech:** google.com, microsoft.com, apple.com, github.com, gitlab.com, stackoverflow.com
- **Social Media:** facebook.com, twitter.com, x.com, reddit.com, linkedin.com, instagram.com
- **Video/Streaming:** youtube.com, netflix.com, spotify.com, twitch.tv, hulu.com
- **E-Commerce:** amazon.com, amazon.in, flipkart.com, ebay.com, walmart.com, shopify.com
- **Payments:** paypal.com, stripe.com, razorpay.com
- **News:** bbc.com, cnn.com, nytimes.com, reuters.com, theguardian.com
- **Banking:** chase.com, wellsfargo.com, bankofamerica.com, hdfc.com, sbi.co.in
- **Cloud/Dev:** aws.amazon.com, cloud.google.com, vercel.com, netlify.com, heroku.com
- **Education:** wikipedia.org, coursera.org, edx.org, khanacademy.org
- **Government/Shipping:** usps.com, fedex.com, ups.com, dhl.com
- And many more...

### Safe Domain Exclusions

Subdomains of safe domains that are commonly abused for phishing are excluded from the safe domain whitelist. These are checked **before** the whitelist, so phishing hosted on these subdomains is still detected:

```
sites.google.com, docs.google.com, drive.google.com,
storage.googleapis.com, forms.gle, s3.amazonaws.com,
blob.core.windows.net, githubusercontent.com,
raw.githubusercontent.com, gist.github.com,
notion.site, sharepoint.com, sway.office.com
```

### Blocklist Domains

Domains that receive instant "block" verdicts (score 95, critical severity):

```
# Free dynamic DNS services heavily abused for phishing
duckdns.org, ddns.net, no-ip.org, hopto.org, zapto.org,
sytes.net, serveblog.net, serveftp.com,

# Free hosting with extremely high abuse rates
000webhostapp.com, rf.gd, infinityfreeapp.com, epizy.com,
byethost.com, byet.host, awardspace.net, atwebpages.com,
mywebcommunity.org, great-site.net, is-best.net, freenom.com,
42web.io, freewebhostmost.com, 16mb.com, creatorlink.net
```

### Protected Brands

26 brands with full impersonation detection:

| Brand | Official Domain | Min Length for Detection |
|-------|----------------|------------------------|
| PayPal | paypal.com | 4 |
| Amazon | amazon.com | 4 |
| Apple | apple.com | 4 |
| Microsoft | microsoft.com | 4 |
| Google | google.com | 4 |
| Facebook | facebook.com | 4 |
| Netflix | netflix.com | 4 |
| Instagram | instagram.com | 4 |
| Chase | chase.com | 4 |
| Wells Fargo | wellsfargo.com | 4 |
| USPS | usps.com | 4 |
| FedEx | fedex.com | 4 |
| UPS | ups.com | 3 |
| DHL | dhl.com | 3 |
| Walmart | walmart.com | 4 |
| eBay | ebay.com | 4 |
| Dropbox | dropbox.com | 4 |
| Coinbase | coinbase.com | 4 |
| Binance | binance.com | 4 |
| Spotify | spotify.com | 4 |
| LinkedIn | linkedin.com | 4 |
| Twitter | twitter.com | 4 |
| Meta | meta.com | 4 |
| Outlook | outlook.com | 4 |
| iCloud | icloud.com | 4 |
| Office365 | office.com | 4 |

**Short Brand Protection:** Brands with <= 3 characters (UPS, DHL) use exact segment matching instead of substring matching to prevent false positives (e.g., "setup.com" won't match "ups").

---

## Deployment

### Render.com One-Click Deploy

The project includes a `render.yaml` blueprint for deploying both services to [Render.com](https://render.com):

1. Fork/push this repository to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com) > **Blueprints**
3. Connect your repository and select the blueprint
4. Set environment variables in the Render dashboard:
   - `GROQ_API_KEY` (required)
   - `GEMINI_API_KEY` (optional, enables dual-model)
   - `DUAL_MODEL_ENABLED` (set to `true` if using Gemini)
5. Deploy

The blueprint deploys two services:

**phishguard-api** (Backend):
- Runtime: Node.js
- Region: Oregon
- Plan: Free
- Build: `npm install --include=dev && npm run build`
- Start: `npm start`
- Tester agent disabled by default (`DISABLE_TESTER_AGENT=true`)
- Port: 10000

**phishguard-dashboard** (Frontend):
- Runtime: Node.js
- Region: Oregon
- Plan: Free
- Build: `npm install --include=dev && npm run build`
- Start: `npm start`
- Auto-configured to connect to API via `NEXT_PUBLIC_API_URL`
- Standalone output mode for efficient deployment

> **Note**: The Tester Agent (Playwright) is disabled by default on Render's free tier since it requires a headless browser environment with Chromium binaries. Set `DISABLE_TESTER_AGENT=false` if your plan supports it.

---

## Technologies

| Component | Stack | Details |
|-----------|-------|---------|
| **Backend API** | Node.js, Express, TypeScript | REST + SSE endpoints, Zod validation, Helmet security headers |
| **Browser Automation** | Playwright (Chromium) | Headless browser for content extraction, form analysis, screenshot capture |
| **AI/LLM (Primary)** | Groq API | Llama 3.3 70B Versatile (text), Llama 3.2 11B Vision Preview (logo detection) |
| **AI/LLM (Secondary)** | Google Gemini API | Gemini 2.0 Flash (cross-verification) |
| **Threat Intelligence** | Google Safe Browsing API v4 | External threat database lookup (optional, malware/phishing/social engineering) |
| **Web Dashboard** | Next.js 14, React 18, TailwindCSS | App Router, SSE streaming, Framer Motion animations, Lucide icons |
| **Chrome Extension** | Manifest V3, Vite, TypeScript | Service worker, content script, popup UI |
| **Performance** | Custom implementations | LRU cache with TTL, token bucket rate limiter, payload truncation |
| **Security** | Helmet, express-rate-limit, Zod, CORS | Input validation, rate limiting, security headers, XSS prevention |
| **Deployment** | Render.com | Blueprint YAML for one-click deployment |

---

## API Response Types

### ScanResponse

```typescript
interface ScanResponse {
  success: boolean;
  verdict?: FinalVerdict;
  error?: string;
  logs: AgentLog[];
}
```

### FinalVerdict

```typescript
interface FinalVerdict {
  action: "allow" | "warn" | "block";
  overallRiskScore: number;        // 0-100
  confidence: number;              // 0.0-1.0
  agentResults: AgentResult[];
  summary: string;
  url: string;
  timestamp: number;               // epoch milliseconds
  screenshot?: string;             // base64 JPEG
  modelComparison?: ModelComparison;
}
```

### AgentResult

```typescript
interface AgentResult {
  agentId: string;
  agentName: string;
  riskScore: number;               // 0-100
  confidence: number;              // 0.0-1.0
  signals: Signal[];
  explanation: string;
  executionTimeMs: number;
}
```

### Signal

```typescript
interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
}
```

### AgentLog

```typescript
interface AgentLog {
  agentId: string;
  agentName: string;
  message: string;
  timestamp: number;
  type: "info" | "warning" | "error" | "success";
}
```

### ModelComparison

```typescript
interface ModelComparison {
  groqResult?: LLMAnalysisResult;
  geminiResult?: LLMAnalysisResult;
  consensusScore: number;
  scoreDifference: number;
  strategy: string;                // "consensus-average", "conservative", "single-model-fallback"
  agreed: boolean;
}
```

### BrowserTestResult

```typescript
interface BrowserTestResult {
  screenshot: string;              // base64 JPEG
  finalUrl: string;
  redirectChain: string[];
  hasPopups: boolean;
  hasOverlays: boolean;
  downloadAttempted: boolean;
  permissionRequests: string[];
  consoleErrors: string[];
  networkErrors: string[];
  loadTimeMs: number;
  safetyWarning?: string;
  formAnalysis: FormAnalysis[];
  logoDetection?: LogoDetectionResult;
  pageContent?: PageContent;
}
```

---

## Security Considerations

1. **API Key Protection**: All API keys are stored in environment variables and never committed to source control. The `.env` file is in `.gitignore`.
2. **Backend Proxy**: The backend acts as a secure proxy for all LLM API calls. No API keys are exposed to the frontend or extension.
3. **Rate Limiting**: Express rate limiter at 30 req/min per IP prevents API abuse. LLM rate limiters (Groq 28/min, Gemini 14/min) prevent quota exhaustion.
4. **Input Validation**: All API endpoints validate input with Zod schemas. URLs are validated and capped at 2,048 characters.
5. **Security Headers**: Helmet middleware sets secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.).
6. **CORS**: Configured to allow only specific origins (localhost, extension, dashboard, Render domains). Non-production mode allows all origins.
7. **XSS Prevention**: The Chrome extension escapes all user-facing text (URLs, summaries, agent names) via `escapeHtml()` before rendering in the warning overlay.
8. **Content Truncation**: LLM payloads are truncated to prevent injection of excessively large content into prompts.
9. **Graceful Shutdown**: The server handles `SIGTERM`/`SIGINT` signals, properly closing the HTTP server and Playwright browser instances with a 10-second force-exit timeout.
10. **Extension Fail-Open**: If the backend is unreachable, the extension fails open (allows navigation) rather than blocking all browsing.

---

## Known Limitations

1. **Requires Internet Connectivity**: LLM analysis requires internet access to reach Groq and Gemini APIs. There is no offline analysis mode.
2. **Headless Browser Detection**: Some websites detect and block headless browsers (Playwright), which affects the Content and Tester agents. This results in lower confidence scores, not false blocks.
3. **Screenshot Failures**: Protected pages (banking, some corporate sites) may prevent screenshot capture.
4. **Playwright Hosting Requirements**: The Tester Agent requires Playwright Chromium binaries, which are not available on all hosting platforms (disabled by default on Render free tier).
5. **Vision Model Availability**: Vision-based logo detection depends on Groq's Llama 3.2 11B Vision model availability.
6. **Dual-Model Dependency**: Full dual-model consensus requires both Groq and Gemini API keys. With only Groq, the system still works but with single-model analysis.
7. **False Positives on Hosting Platforms**: Sites hosted on platforms like Weebly, Wix, or Google Sites may receive elevated risk scores due to hosting platform signals.
8. **API Rate Limits**: Free tier API limits (Groq 30 RPM, Gemini 15 RPM) may cause delays under heavy concurrent usage.
9. **Extension Backend Dependency**: The Chrome extension requires the backend API server to be running. Without it, all sites receive a "safe" fallback verdict.
10. **Cache Staleness**: Cached results (30-minute TTL) may not reflect changes to a website's content after the initial scan.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run the backend tests: `cd server && npm test`
5. Build the extension: `npm run build`
6. Build the dashboard: `cd web-dashboard && npm run build`
7. Commit your changes with a descriptive message
8. Submit a pull request

### Development Setup

```bash
# Terminal 1: Backend API (with hot reload)
cd server && npm run dev

# Terminal 2: Web Dashboard (with hot reload)
cd web-dashboard && npm run dev

# Terminal 3: Extension (with watch mode)
npm run dev
```

---

## License

MIT License - Feel free to use, modify, and distribute.

# PhishGuard AI - Multi-Agent Phishing Detection System

A comprehensive, multi-agent AI-powered phishing detection system featuring **dual-model cross-verification** with two independent LLMs (Groq Llama + Google Gemini Flash) for consensus-based analysis. Delivered through four platforms: a **Web Dashboard**, a **Backend API Server**, a **Chrome Browser Extension**, and a **Stagehand Plugin** for browser automation frameworks.

## Key Highlights

- **Dual-Model AI Consensus**: Two independent LLMs (Groq Llama 3.3 70B + Google Gemini 2.0 Flash) cross-verify every analysis for higher accuracy
- **5 Specialized AI Agents**: URL, Domain, Content, Heuristic, and Tester agents analyze URLs in parallel
- **131 Automated Tests**: Comprehensive test suite across 8 test files, all passing
- **Performance Optimized**: LRU caching, parallel agent execution, rate limiting, content truncation
- **Critical Veto System**: Instant block on high-confidence phishing signals regardless of overall score
- **4 Delivery Platforms**: Web Dashboard, API Server, Chrome Extension, Stagehand Plugin

## Features

### Dual-Model Cross-Verification

Each AI agent sends the same analysis prompt to **both** Groq Llama and Google Gemini Flash independently. Results are compared using a consensus engine:

| Scenario | Outcome |
|----------|---------|
| Both models agree | Use agreed result with boosted confidence |
| Models disagree on risk | Take the higher (more cautious) risk score |
| One model fails | Gracefully fall back to the working model |
| Both models fail | Fall back to local heuristic analysis only |

This dual-model approach significantly reduces false negatives (missed phishing) and increases reliability.

### AI Agent System

| Agent | Weight | Analysis Focus |
|-------|--------|----------------|
| **URL Agent** | 20% | URL structure, encoding, typosquatting, homograph attacks |
| **Domain Agent** | 30% | Domain reputation, blocklists, brand impersonation, DGA detection |
| **Content Agent** | 25% | Page content, forms, login fields, brand mismatches via Playwright |
| **Heuristic Agent** | 15% | Urgency language, threats, social engineering patterns |
| **Tester Agent** | 10% | Redirects, popups, downloads, browser warnings, vision-based logo detection |

### Performance Optimizations

- **Parallel Agent Execution**: All 5 agents run simultaneously using a deferred promise pattern. TesterAgent, URL, and Domain start immediately; Content and Heuristic await page content from TesterAgent, then start their analysis in parallel.
- **LRU Scan Cache**: 100-entry cache with 5-minute TTL for instant repeat scans (~150ms vs ~30s)
- **LLM Rate Limiting**: Token bucket algorithm - Groq at 28 req/min, Gemini at 14 req/min
- **Content Truncation**: LLM payloads capped at 4000 chars per string, 20 items per array, max depth 5
- **SSE Server-Side Timeout**: 60-second auto-disconnect prevents hanging connections

### Platform Features

- **Web Dashboard**: Modern Next.js 14 interface with real-time agent streaming via SSE
- **Chrome Extension**: Passive real-time protection with fullscreen warning overlays
- **Stagehand Plugin**: Drop-in phishing protection for Stagehand browser automation
- **Visual Verdicts**: Clear Safe/Suspicious/Dangerous verdicts with risk scores
- **Screenshot Capture**: See what the page looks like before visiting
- **Vision-Based Logo Detection**: Identifies brand logos on suspicious domains using Groq Vision (Llama 3.2 11B Vision)
- **Deployment Ready**: Render.com blueprint for one-click deployment

## Architecture

```
                        +---------------------------------+
                        |        Stagehand Plugin         |
                        |  (Proxy-based interception)     |
                        +---------------+-----------------+
                                        |
+-----------------------+               |               +-----------------------+
|    Web Dashboard      |               |               |  Chrome Extension     |
|  (Next.js + Tailwind) |               |               |  (Manifest V3)        |
+-----------+-----------+               |               +-----------+-----------+
            |                           |                           |
            +---------------------------+---------------------------+
                                        |
                                   HTTP / SSE
                                        |
                                        v
+-----------------------------------------------------------------------+
|                          Backend API Server                            |
|                       (Express + Playwright)                           |
|                                                                       |
|   +---------------------------------------------------------------+   |
|   |                        Orchestrator                            |   |
|   |  (Weighted scoring + Critical veto + Consensus detection)      |   |
|   |  (Parallel execution with deferred promise pattern)            |   |
|   |                                                                |   |
|   |  +--------+ +--------+ +---------+ +----------+ +---------+  |   |
|   |  |  URL   | | Domain | | Content | | Heuristic| | Tester  |  |   |
|   |  | Agent  | | Agent  | |  Agent  | |  Agent   | |  Agent  |  |   |
|   |  | (20%)  | | (30%)  | |  (25%)  | |  (15%)   | |  (10%)  |  |   |
|   |  +--------+ +--------+ +---------+ +----------+ +---------+  |   |
|   +---------------------------------------------------------------+   |
|                               |                                       |
|           +-------------------+-------------------+                   |
|           v                                       v                   |
|  +---------------------+              +---------------------+         |
|  |    Groq LLM API     |              | Google Gemini API   |         |
|  | Llama 3.3 70B (text)|              | Gemini 2.0 Flash    |         |
|  | Llama 3.2 11B (vis.)|              | (cross-verification)|         |
|  +---------------------+              +---------------------+         |
|                                                                       |
|   +---------------------------------------------------------------+   |
|   |              Performance Layer                                 |   |
|   |  [LRU Cache] [Rate Limiter] [Content Truncation]              |   |
|   +---------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
```

## Project Structure

```
agent-browser/
├── server/                          # Backend API Server
│   ├── src/
│   │   ├── agents/
│   │   │   ├── base-agent.ts        # Abstract agent + dual-model consensus engine
│   │   │   ├── url-agent.ts         # URL structure analysis
│   │   │   ├── domain-agent.ts      # Domain reputation checks
│   │   │   ├── content-agent.ts     # Page content analysis (Playwright)
│   │   │   ├── heuristic-agent.ts   # Social engineering patterns
│   │   │   ├── tester-agent.ts      # Browser behavioral testing + vision
│   │   │   ├── orchestrator.ts      # Parallel agent coordination & scoring
│   │   │   ├── base-agent.test.ts   # Dual-model consensus tests (21 tests)
│   │   │   ├── orchestrator.test.ts # Verdict logic tests (10 tests)
│   │   │   ├── url-agent.test.ts    # URL agent tests (12 tests)
│   │   │   ├── domain-agent.test.ts # Domain agent tests (13 tests)
│   │   │   └── heuristic-agent.test.ts # Heuristic agent tests (12 tests)
│   │   ├── api/
│   │   │   ├── groq-client.ts       # Groq LLM client (text + vision)
│   │   │   ├── gemini-client.ts     # Google Gemini Flash client
│   │   │   └── gemini-client.test.ts # Gemini client tests (17 tests)
│   │   ├── config/
│   │   │   └── index.ts             # Weights, thresholds, blocklists, LLM config
│   │   ├── types/
│   │   │   └── index.ts             # TypeScript type definitions
│   │   ├── utils/
│   │   │   ├── url-parser.ts        # URL parsing utilities
│   │   │   ├── url-parser.test.ts   # URL parser tests (38 tests)
│   │   │   ├── cache.ts             # LRU scan cache with TTL
│   │   │   └── rate-limiter.ts      # Token bucket rate limiter
│   │   ├── server.ts                # Express server entry point
│   │   └── api.test.ts              # API integration tests (8 tests)
│   ├── package.json
│   ├── tsconfig.json
│   └── vitest.config.ts
│
├── web-dashboard/                   # Frontend Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx           # Root layout
│   │   │   ├── page.tsx             # Main page
│   │   │   └── globals.css          # Global styles
│   │   ├── components/
│   │   │   ├── ScanningInterface.tsx # URL input & scan trigger
│   │   │   ├── StatusFeed.tsx       # Real-time agent logs
│   │   │   ├── ResultCard.tsx       # Verdict display
│   │   │   ├── AgentBreakdown.tsx   # Per-agent detail view
│   │   │   └── index.ts            # Barrel export
│   │   ├── lib/
│   │   │   └── api.ts              # API client (fetch + SSE)
│   │   └── types/
│   │       └── index.ts            # Dashboard types
│   ├── package.json
│   ├── tailwind.config.js
│   └── next.config.js
│
├── src/                             # Chrome Browser Extension
│   ├── background/
│   │   └── service-worker.ts        # Navigation interception
│   ├── content/
│   │   └── content-script.ts        # Page extraction + warning overlay
│   ├── ui/popup/
│   │   ├── popup.ts                 # Popup logic
│   │   ├── popup.html               # Popup markup
│   │   └── popup.css                # Popup styles
│   ├── config/
│   │   └── index.ts                 # Extension config
│   ├── types/
│   │   └── index.ts                 # Extension types
│   ├── api/
│   │   └── groq-client.ts           # Extension Groq client
│   └── utils/
│       ├── url-parser.ts            # URL parsing
│       └── storage.ts               # Chrome storage wrapper
│
├── stagehand-plugin/                # Stagehand Plugin
│   ├── src/
│   │   ├── index.ts                 # Public API (withPhishGuard)
│   │   ├── plugin.ts                # Core Proxy-based interception
│   │   ├── detector.ts              # Detection orchestrator (fast/full)
│   │   ├── types.ts                 # Plugin types
│   │   ├── link-scanner.ts          # Proactive page link scanning
│   │   ├── cache.ts                 # LRU cache with TTL
│   │   ├── logger.ts                # Formatted logger
│   │   └── agents/                  # Plugin agent wrappers
│   ├── package.json
│   └── tsconfig.json
│
├── manifest.json                    # Chrome Extension MV3 manifest
├── vite.config.ts                   # Vite build config for extension
├── render.yaml                      # Render.com deployment blueprint
├── .env.example                     # Environment variable template
└── README.md
```

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- A [Groq API key](https://console.groq.com/) (required)
- A [Google Gemini API key](https://aistudio.google.com/apikey) (optional, enables dual-model)

### 1. Start the Backend API

```bash
cd server
npm install
cp .env.example .env
# Edit .env and add your API keys:
#   GROQ_API_KEY=your_groq_key
#   GEMINI_API_KEY=your_gemini_key    (optional)
#   DUAL_MODEL_ENABLED=true           (optional)
npm run dev
```

The API server runs on `http://localhost:3001`.

### 2. Start the Web Dashboard

```bash
cd web-dashboard
npm install
npm run dev
```

The dashboard runs on `http://localhost:3000`.

### 3. Analyze URLs

1. Open `http://localhost:3000` in your browser
2. Enter a URL to analyze (e.g., `https://google.com`)
3. Click "Scan URL"
4. Watch the agents analyze in real-time
5. View the detailed verdict with screenshot and agent breakdown

## API Endpoints

### POST /api/scan

Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "success": true,
  "verdict": {
    "action": "allow",
    "overallRiskScore": 0,
    "confidence": 0.99,
    "summary": "SAFE - This is a verified trusted domain.",
    "screenshot": "base64...",
    "agentResults": [...]
  },
  "logs": [...]
}
```

### GET /api/scan/stream?url=...

SSE endpoint for real-time analysis with streaming agent logs.

**Events:**
- `log` - Agent activity updates
- `result` - Final verdict
- `done` - Analysis complete
- `error` - Error occurred

### GET /api/health

Health check endpoint with cache statistics.

**Response:**
```json
{
  "status": "ok",
  "timestamp": 1234567890,
  "cache": {
    "size": 5,
    "maxSize": 100,
    "ttlMs": 300000
  }
}
```

## How Scoring Works

Each agent returns:

- `riskScore`: 0-100 (0 = safe, 100 = definitely phishing)
- `confidence`: 0-1 (how confident the agent is)
- `signals`: Array of detected indicators
- `explanation`: Human-readable analysis

When dual-model is enabled, each agent's analysis includes a `modelComparison` object showing the results from both Groq and Gemini, along with the consensus method used.

The orchestrator combines scores using a weighted formula:

```
finalScore = Sum(agentScore * agentWeight * agentConfidence) / Sum(agentWeight * agentConfidence)
```

Domain and Content agents use `MAX(local, LLM)` instead of averaging for more aggressive detection.

### Orchestrator Priority Cascade

The orchestrator uses a multi-level decision system:

| Priority | Condition | Result |
|----------|-----------|--------|
| 0 | Safe domain whitelist match | Instant ALLOW |
| 1 | Critical veto signal detected | Instant BLOCK (score >= 85) |
| 2 | Any single agent score >= 75 | BLOCK |
| 3 | 2+ agents score > 50 | Consensus BLOCK |
| 4 | Weighted average | allow <= 25, warn 26-55, block >= 56 |
| 5 | High-severity signals present | Bumps "allow" to "warn" |

### Critical Veto Signals

The following signals trigger an immediate block regardless of overall score:

- `blocklist_match` - Domain on known phishing blocklist
- `brand_impersonation` - Brand name used deceptively
- `typosquatting` - Domain mimics a known brand
- `homograph` - Unicode lookalike characters in domain
- `ip_address` - IP address used instead of domain
- `external_form_action` - Login form submits to external domain
- `title_brand_mismatch` - Page title/brand does not match domain
- `logo_domain_mismatch` - Vision-detected brand logo on wrong domain
- `cross_origin_password_form` - Password submitted to different domain
- `safety_warning` - Browser safety warning detected
- And more...

## Detection Signals

### URL Agent
- Excessive URL length
- IP address instead of domain
- Multiple subdomains
- Suspicious TLDs (.tk, .xyz, .ml, etc.)
- URL shorteners (bit.ly, tinyurl.com, etc.)
- Typosquatting patterns
- Homograph attacks (Unicode lookalikes)
- Encoded characters
- Phishing keywords in path

### Domain Agent
- Known phishing blocklist match
- Brand name in subdomain
- Random-looking domain names (DGA detection)
- Suspicious patterns (-login, -secure)
- Excessive hyphens
- Suspicious hosting platforms (weebly, wix, netlify, etc.)
- Brand impersonation with improved false-positive filtering

### Content Agent
- Login forms submitting to external domains
- Brand name mismatch (page title vs URL domain)
- Sensitive data requests
- Mismatched link text
- Form hijacking detection
- Hidden element detection

### Heuristic Agent
- Urgency language ("Act now!", "24 hours")
- Threat language ("suspended", "locked")
- Reward scam patterns ("You've won!")
- Poor grammar/spelling
- Suspicious URL parameters

### Tester Agent
- Excessive redirects / cross-domain redirects
- Popup dialogs (with proper listener cleanup)
- Automatic download attempts
- Browser permission requests
- Safety warnings
- Vision-based logo detection (Groq Vision model)
- Redirect chain tracking

## Chrome Extension

The browser extension provides passive real-time protection by intercepting navigation events and scanning URLs through the backend API.

### Build Extension

```bash
npm install
npm run build
```

### Load in Chrome

1. Go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `dist` folder

### Extension Features

- Automatic scanning of every page navigation
- Fullscreen warning overlay for phishing pages
- Risk score ring with agent breakdown in popup
- Scan history tracking
- Per-domain whitelist
- Report phishing functionality

## Stagehand Plugin

The Stagehand plugin adds phishing protection to [Stagehand](https://github.com/browserbase/stagehand) browser automation workflows using a JavaScript Proxy pattern.

### Installation

```bash
cd stagehand-plugin
npm install
npm run build
```

### Usage

```typescript
import { Stagehand } from "@browserbasehq/stagehand";
import { withPhishGuard } from "./stagehand-plugin";

const stagehand = new Stagehand({ /* config */ });
await stagehand.init();

// Wrap with phishing protection
const protected = withPhishGuard(stagehand, {
  mode: "fast",       // "fast" (URL+Domain only) or "full" (all 5 agents)
  onPhishing: "warn", // "warn" (log and continue) or "block" (throw error)
});

// All navigation is now automatically scanned
await protected.page.goto("https://example.com");
```

### Plugin Features

- **Two modes**: "fast" (~200ms, URL+Domain only) and "full" (all 5 agents)
- **Proxy-based**: Transparently intercepts `page.goto()`, `page.act()`, and `agent().execute()`
- **Caching**: LRU cache with TTL to avoid re-scanning known URLs
- **Proactive scanning**: Optionally scan all links on a page
- **Stats tracking**: Track scan counts, blocks, and cache hits

## Configuration

### Agent Weights

Edit `server/src/config/index.ts`:

```typescript
AGENT_WEIGHTS: {
  urlAgent: 0.20,       // 20%
  domainAgent: 0.30,    // 30% - Domain reputation is critical
  contentAgent: 0.25,   // 25%
  heuristicAgent: 0.15, // 15%
  testerAgent: 0.10,    // 10%
}
```

### Risk Thresholds

```typescript
THRESHOLDS: {
  ALLOW_MAX: 25,   // 0-25: Safe
  WARN_MAX: 55,    // 26-55: Suspicious
  BLOCK_MIN: 56,   // 56-100: Dangerous
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key (required) | - |
| `GEMINI_API_KEY` | Google Gemini API key (enables dual-model) | - |
| `DUAL_MODEL_ENABLED` | Enable dual-model cross-verification | `false` |
| `PORT` | Backend server port | `3001` |
| `DISABLE_TESTER_AGENT` | Disable Playwright-based tester agent | `false` |
| `DISABLE_VISION_DETECTION` | Disable vision-based logo detection | `false` |
| `NEXT_PUBLIC_API_URL` | Dashboard API base URL | `http://localhost:3001` |
| `NODE_ENV` | Environment (development/production) | `development` |

## Testing

The project uses [Vitest](https://vitest.dev/) for testing. Tests mock the LLM API clients to avoid external API calls.

```bash
cd server
npm test
```

### Test Suite (131 tests, 8 files)

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `url-parser.test.ts` | 38 | URL parsing, TLD detection, brand similarity, encoding |
| `base-agent.test.ts` | 21 | Dual-model consensus engine, fallback logic, payload truncation |
| `gemini-client.test.ts` | 17 | Gemini API client, error handling, timeouts, JSON parsing |
| `domain-agent.test.ts` | 13 | Safe domains, brand impersonation, suspicious patterns, TLDs |
| `url-agent.test.ts` | 12 | Safe URLs, IP detection, suspicious TLDs, shorteners, keywords |
| `heuristic-agent.test.ts` | 12 | Urgency language, threats, sensitive data, reward scams |
| `orchestrator.test.ts` | 10 | Verdict logic, veto signals, weighted scoring, consensus |
| `api.test.ts` | 8 | Endpoint routing, error handling, input validation |

## Deployment

### Render.com (One-Click)

The project includes a `render.yaml` blueprint for deploying both the API server and web dashboard to [Render.com](https://render.com):

1. Fork/push this repository to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com) > **Blueprints**
3. Connect your repository and select the blueprint
4. Set environment variables in the Render dashboard:
   - `GROQ_API_KEY` (required)
   - `GEMINI_API_KEY` (optional, enables dual-model)
   - `DUAL_MODEL_ENABLED` (set to `true` if using Gemini)
5. Deploy

The blueprint deploys:
- **phishguard-api**: Backend API server (tester agent disabled by default on free tier)
- **phishguard-dashboard**: Next.js web dashboard (auto-connects to API)

> **Note**: The tester agent (Playwright) is disabled by default on Render's free tier since it requires a headless browser environment. Set `DISABLE_TESTER_AGENT=false` if your plan supports it.

## Technologies

| Component | Stack |
|-----------|-------|
| **Backend** | Node.js, Express, TypeScript, Playwright, Zod, Helmet |
| **AI/LLM** | Groq API (Llama 3.3 70B text + Llama 3.2 11B Vision), Google Gemini API (Gemini 2.0 Flash) |
| **Dashboard** | Next.js 14, React 18, TailwindCSS, Framer Motion, Lucide React |
| **Extension** | Chrome Extension Manifest V3, Vite, TypeScript |
| **Plugin** | TypeScript, ES Proxy pattern, Playwright peer dependency |
| **Testing** | Vitest (131 tests across 8 files) |
| **Performance** | LRU caching, token bucket rate limiting, parallel execution |
| **Deployment** | Render.com |

## Security Notes

- API keys must be stored in environment variables -- never commit them to source control
- The backend acts as a secure proxy for all LLM API calls
- Never expose API keys in frontend or extension code
- The extension communicates with the local backend server; no API keys are embedded
- Rate limiting (30 req/min per IP) and Helmet security headers are enabled on the API server
- LLM rate limiting prevents API quota exhaustion (Groq 28/min, Gemini 14/min)
- Input validation with Zod on all API endpoints

## Known Limitations

- Requires internet connectivity for LLM analysis (no offline mode)
- Some sites may block headless browser access (affects Content and Tester agents)
- Screenshot capture may fail on some protected pages
- Tester agent requires Playwright browser binaries (not available on all hosting platforms)
- Vision-based logo detection depends on Groq Vision model availability
- Dual-model consensus requires both Groq and Gemini API keys for full functionality

## License

MIT License - Feel free to use and modify.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run the tests (`cd server && npm test`)
4. Commit your changes
5. Submit a pull request

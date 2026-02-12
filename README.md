# PhishGuard AI - Multi-Agent Phishing Detection System

A comprehensive, multi-agent AI-powered phishing detection system with four delivery mechanisms: a **Web Dashboard**, a **Backend API Server**, a **Chrome Browser Extension**, and a **Stagehand Plugin** for browser automation frameworks. Powered by 5 specialized AI agents and Groq's ultra-fast LLM inference.

## Features

- **Multi-Agent AI Analysis**: 5 specialized AI agents analyze URLs in parallel
  - **URL Agent** (20%): Analyzes URL structure, encoding, typosquatting, homograph attacks
  - **Domain Agent** (30%): Checks domain reputation, blocklists, brand impersonation, DGA detection
  - **Content Agent** (25%): Examines page content, forms, login fields, brand mismatches via Playwright
  - **Heuristic Agent** (15%): Detects urgency language, threats, social engineering patterns
  - **Tester Agent** (10%): Simulates user behavior, detects redirects, popups, downloads, and uses vision-based logo detection

- **Web Dashboard**: Modern Next.js interface for URL analysis with real-time agent streaming
- **Chrome Extension**: Passive real-time protection with fullscreen warning overlays
- **Stagehand Plugin**: Drop-in phishing protection for Stagehand browser automation
- **Real-time Logging**: Watch agents work in real-time via SSE streaming
- **Visual Verdicts**: Clear Safe/Suspicious/Dangerous verdicts with risk scores
- **Screenshot Capture**: See what the page looks like before visiting
- **Vision-Based Logo Detection**: Identifies brand logos on suspicious domains using Groq Vision (Llama 3.2 11B Vision)
- **Critical Veto System**: Instant block on high-confidence phishing signals regardless of overall score
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
|   |                                                                |   |
|   |  +--------+ +--------+ +---------+ +----------+ +---------+  |   |
|   |  |  URL   | | Domain | | Content | | Heuristic| | Tester  |  |   |
|   |  | Agent  | | Agent  | |  Agent  | |  Agent   | |  Agent  |  |   |
|   |  | (20%)  | | (30%)  | |  (25%)  | |  (15%)   | |  (10%)  |  |   |
|   |  +--------+ +--------+ +---------+ +----------+ +---------+  |   |
|   +---------------------------------------------------------------+   |
|                               |                                       |
|                               v                                       |
|                    +---------------------+                            |
|                    |    Groq LLM API     |                            |
|                    | Llama 3.3 70B (text)|                            |
|                    | Llama 3.2 11B (vis.)|                            |
|                    +---------------------+                            |
+-----------------------------------------------------------------------+
```

## Project Structure

```
agent-browser/
├── server/                          # Backend API Server
│   ├── src/
│   │   ├── agents/
│   │   │   ├── base-agent.ts        # Abstract agent class
│   │   │   ├── url-agent.ts         # URL structure analysis
│   │   │   ├── domain-agent.ts      # Domain reputation checks
│   │   │   ├── content-agent.ts     # Page content analysis (Playwright)
│   │   │   ├── heuristic-agent.ts   # Social engineering patterns
│   │   │   ├── tester-agent.ts      # Browser behavioral testing + vision
│   │   │   ├── orchestrator.ts      # Agent coordination & scoring
│   │   │   ├── url-agent.test.ts    # URL agent tests
│   │   │   ├── domain-agent.test.ts # Domain agent tests
│   │   │   └── heuristic-agent.test.ts # Heuristic agent tests
│   │   ├── api/
│   │   │   └── groq-client.ts       # Groq LLM client (text + vision)
│   │   ├── config/
│   │   │   └── index.ts             # Weights, thresholds, blocklists
│   │   ├── types/
│   │   │   └── index.ts             # TypeScript type definitions
│   │   ├── utils/
│   │   │   └── url-parser.ts        # URL parsing utilities
│   │   ├── server.ts                # Express server entry point
│   │   └── api.test.ts              # API integration tests
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
├── planning.md                      # Development plan
├── explain.md                       # Technical documentation
└── README.md
```

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- A [Groq API key](https://console.groq.com/)

### 1. Start the Backend API

```bash
cd server
npm install
cp ../.env.example .env
# Edit .env and add your GROQ_API_KEY
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
    "overallRiskScore": 15,
    "confidence": 0.85,
    "summary": "LOW RISK (Score: 15/100) - No major concerns detected.",
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

Health check endpoint.

## How Scoring Works

Each agent returns:

- `riskScore`: 0-100 (0 = safe, 100 = definitely phishing)
- `confidence`: 0-1 (how confident the agent is)
- `signals`: Array of detected indicators
- `explanation`: Human-readable analysis

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
- Brand impersonation

### Content Agent
- Login forms submitting to external domains
- Brand name mismatch (page title vs URL domain)
- Sensitive data requests
- Mismatched link text
- Form hijacking detection

### Heuristic Agent
- Urgency language ("Act now!", "24 hours")
- Threat language ("suspended", "locked")
- Reward scam patterns ("You've won!")
- Poor grammar/spelling
- Suspicious URL parameters

### Tester Agent
- Excessive redirects / cross-domain redirects
- Popup dialogs
- Automatic download attempts
- Browser permission requests
- Safety warnings
- Vision-based logo detection (Groq Vision model)

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
| `PORT` | Backend server port | `3001` |
| `DISABLE_TESTER_AGENT` | Disable Playwright-based tester agent | `false` |
| `DISABLE_VISION_DETECTION` | Disable vision-based logo detection | `false` |
| `NEXT_PUBLIC_API_URL` | Dashboard API base URL | `http://localhost:3001` |
| `NODE_ENV` | Environment (development/production) | `development` |

## Testing

The project uses [Vitest](https://vitest.dev/) for testing. Tests mock the Groq API client to avoid external API calls.

```bash
cd server
npm test
```

### Test Coverage

- **URL Agent**: 10 tests - safe URLs, IP detection, suspicious TLDs, shorteners, long URLs, subdomains, keywords, HTTPS, ports, encoded characters
- **Domain Agent**: 9 tests - safe domains, suspicious patterns, brand impersonation, long domains, hyphens, TLDs
- **Heuristic Agent**: 10 tests - urgency language, threat detection, sensitive data, reward scams, grammar, combined analysis
- **API Integration**: 8 tests - endpoint routing, error handling, mocked orchestrator

## Deployment

### Render.com (One-Click)

The project includes a `render.yaml` blueprint for deploying both the API server and web dashboard to [Render.com](https://render.com):

1. Fork/push this repository to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com) > **Blueprints**
3. Connect your repository and select the blueprint
4. Set the `GROQ_API_KEY` environment variable in the Render dashboard
5. Deploy

The blueprint deploys:
- **phishguard-api**: Backend API server (tester agent disabled by default on free tier)
- **phishguard-dashboard**: Next.js web dashboard (auto-connects to API)

> **Note**: The tester agent (Playwright) is disabled by default on Render's free tier since it requires a headless browser environment. Set `DISABLE_TESTER_AGENT=false` if your plan supports it.

## Technologies

| Component | Stack |
|-----------|-------|
| **Backend** | Node.js, Express, TypeScript, Playwright, Zod, Helmet |
| **AI/LLM** | Groq API - Llama 3.3 70B (text), Llama 3.2 11B Vision (logo detection) |
| **Dashboard** | Next.js 14, React 18, TailwindCSS, Framer Motion, Lucide React |
| **Extension** | Chrome Extension Manifest V3, Vite, TypeScript |
| **Plugin** | TypeScript, ES Proxy pattern, Playwright peer dependency |
| **Testing** | Vitest |
| **Deployment** | Render.com |

## Security Notes

- The Groq API key must be stored in environment variables -- never commit it to source control
- The backend acts as a secure proxy for all LLM API calls
- Never expose API keys in frontend or extension code
- The extension communicates with the local backend server; no API keys are embedded
- Rate limiting and Helmet security headers are enabled on the API server

## Known Limitations

- Requires internet connectivity for LLM analysis (no offline mode)
- Some sites may block headless browser access (affects Content and Tester agents)
- Screenshot capture may fail on some protected pages
- Tester agent requires Playwright browser binaries (not available on all hosting platforms)
- Vision-based logo detection depends on Groq Vision model availability

## License

MIT License - Feel free to use and modify.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run the tests (`cd server && npm test`)
4. Commit your changes
5. Submit a pull request

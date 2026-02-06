# PhishGuard AI - Complete Project Documentation

## Overview

**PhishGuard AI** is a sophisticated multi-agent phishing detection system that combines multiple AI-powered analysis techniques to protect users from malicious websites. The project consists of three main components:

1. **Backend API Server** - Express.js server with 5 specialized AI agents
2. **Web Dashboard** - Next.js frontend for URL analysis
3. **Browser Extension** - Chrome/Firefox extension for real-time protection

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Web Dashboard                                │
│                    (Next.js + TailwindCSS)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Scanning   │  │   Status    │  │   Result    │  │   Agent    │ │
│  │  Interface  │  │    Feed     │  │    Card     │  │  Breakdown │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTP/SSE
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Backend API                                  │
│                    (Express + Playwright)                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Orchestrator                            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────┐│   │
│  │  │   URL    │ │  Domain  │ │ Content  │ │Heuristic │ │Test││   │
│  │  │  Agent   │ │  Agent   │ │  Agent   │ │  Agent   │ │Agent│   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └────┘│   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│                    ┌─────────────────┐                              │
│                    │   Groq LLM API  │                              │
│                    │ (Llama 3.3 70B) │                              │
│                    └─────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
agent browser/
├── server/                      # Backend API
│   ├── src/
│   │   ├── agents/
│   │   │   ├── base-agent.ts    # Abstract agent class
│   │   │   ├── url-agent.ts     # URL analysis
│   │   │   ├── domain-agent.ts  # Domain reputation
│   │   │   ├── content-agent.ts # Page content (Playwright)
│   │   │   ├── heuristic-agent.ts # Pattern matching
│   │   │   ├── tester-agent.ts  # Browser testing
│   │   │   └── orchestrator.ts  # Agent coordination
│   │   ├── api/
│   │   │   └── groq-client.ts   # Groq LLM client
│   │   ├── config/
│   │   │   └── index.ts         # Configuration
│   │   ├── types/
│   │   │   └── index.ts         # TypeScript types
│   │   ├── utils/
│   │   │   └── url-parser.ts    # URL utilities
│   │   └── server.ts            # Express server
│   ├── package.json
│   └── tsconfig.json
│
├── web-dashboard/               # Frontend Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx       # Root layout
│   │   │   ├── page.tsx         # Main page
│   │   │   └── globals.css      # Global styles
│   │   ├── components/
│   │   │   ├── ScanningInterface.tsx  # URL input
│   │   │   ├── StatusFeed.tsx         # Agent logs
│   │   │   ├── ResultCard.tsx         # Verdict display
│   │   │   └── AgentBreakdown.tsx     # Agent details
│   │   ├── lib/
│   │   │   └── api.ts           # API client
│   │   └── types/
│   │       └── index.ts         # TypeScript types
│   ├── package.json
│   └── tailwind.config.js
│
├── src/                         # Browser Extension
│   ├── agents/                  # Client-side agents
│   ├── background/              # Service worker
│   ├── content/                 # Content script
│   └── ui/                      # Extension popup
│
├── manifest.json                # Chrome Extension MV3 manifest
├── render.yaml                  # Render.com deployment config
└── README.md
```

---

## Backend API - Deep Dive

### Server (`server/src/server.ts`)

The Express.js server provides:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Analyze a URL (returns JSON) |
| `/api/scan/stream` | GET | SSE endpoint for real-time logs |
| `/api/health` | GET | Health check |

**Security Features:**
- **Helmet** - Security headers
- **Rate Limiting** - 30 requests/minute per IP
- **Zod Validation** - Input sanitization
- **CORS** - Cross-origin resource sharing

### The Agent System

All agents extend the `BaseAgent` class, which provides:
- LLM integration via `GroqClient`
- Result standardization
- Signal creation helpers

---

## Agent Breakdown

### 1. URL Agent (`url-agent.ts`)

**Purpose:** Analyzes URL structure for phishing indicators

**Detection Signals:**
| Signal | Severity | Score Impact |
|--------|----------|--------------|
| IP address instead of domain | Critical | +30 |
| Homograph attack (Пaypal vs PayPal) | Critical | +35 |
| Typosquatting (paypa1.com) | Critical | +35 |
| Suspicious TLD (.tk, .xyz) | High | +20 |
| URL shorteners | Medium | +15 |
| Excessive length (>100 chars) | High | +15 |
| Multiple subdomains | Medium | +8-15 |
| Non-standard port | High | +15 |

**Analysis Flow:**
1. Parse URL into components
2. Run local pattern checks
3. Use LLM for deeper analysis
4. Combine scores: 40% local + 60% LLM

---

### 2. Domain Agent (`domain-agent.ts`)

**Purpose:** Domain reputation and blocklist checking

**Detection Signals:**
| Signal | Severity | Score Impact |
|--------|----------|--------------|
| Blocklist match | Critical | 95 (instant) |
| Suspicious hosting (weebly, wix) | Critical | +50 |
| Brand impersonation | Critical | +45 |
| Brand name in subdomain | Critical | +40 |
| DGA-style random domain | High | +30 |
| Suspicious patterns (-login, -secure) | Medium | +10-15 |

**Protected Brands:**
PayPal, Amazon, Apple, Microsoft, Google, Facebook, Netflix, Instagram, Chase, Wells Fargo, USPS, FedEx, UPS, DHL, eBay, Dropbox, Coinbase, Binance, and more.

**Logic:** Takes MAXIMUM of local and LLM scores (not average) for aggressive detection.

---

### 3. Content Agent (`content-agent.ts`)

**Purpose:** Page content analysis using Playwright

**Detection Signals:**
| Signal | Severity | Score Impact |
|--------|----------|--------------|
| External form action (credentials) | Critical | +45 |
| Title/brand mismatch | Critical | +40 |
| Sensitive data requests (SSN, CC) | Critical | +35 |
| Mismatched brand links | Critical | +35 |
| Login form on unknown domain | High | +25 |
| CAPTCHA/blocked page | High | +40 |
| Urgency/threat language | High | +10-30 |

**Playwright Features:**
- Headless browser rendering
- Form detection and analysis
- External link enumeration
- Hidden element detection
- Meta tag extraction

---

### 4. Heuristic Agent (`heuristic-agent.ts`)

**Purpose:** Behavioral pattern matching and social engineering detection

**Detection Signals:**
| Signal | Severity | Score Impact |
|--------|----------|--------------|
| Multiple urgency indicators (3+) | Critical | +25 |
| Multiple threat indicators (3+) | Critical | +25 |
| Sensitive data requests | Critical | +20 |
| Reward/prize scam language | High | +20 |
| Urgency language | High | +12 |
| Threat language | High | +12 |
| Manipulative title | Medium | +10 |
| Poor grammar/spelling | Medium | +10 |

**Urgency Patterns:** "urgent", "immediately", "24 hours", "suspended", "verify now", "action required"

**Threat Patterns:** "suspended", "terminated", "locked", "unauthorized", "breach", "compromised"

---

### 5. Tester Agent (`tester-agent.ts`)

**Purpose:** Browser behavioral testing with Playwright

**Detection Signals:**
| Signal | Severity | Score Impact |
|--------|----------|--------------|
| Password form → external domain | Critical | +50 |
| Credit card form → external domain | Critical | +50 |
| Safety warning triggered | Critical | +40 |
| Automatic download attempted | Critical | +30 |
| Cross-origin POST form | High | +20 |
| Excessive redirects (>3) | High | +20 |
| Browser permission requests | High | +15 |
| Popup dialogs | Medium | +15 |
| Cross-domain redirect | High | +15 |
| Modal overlays on load | Medium | +10 |

**Advanced Features:**
- **Logo Detection:** Uses Groq Vision model to detect brand logos and verify domain authenticity
- **Form Hijacking Detection:** Analyzes where form data is submitted
- **Screenshot Capture:** JPEG screenshot for visual review
- **Redirect Chain Tracking:** Records all redirects

---

## Orchestrator (`orchestrator.ts`)

The orchestrator coordinates all agents and implements the **Critical Veto Logic**:

### Scoring Flow

```
1. Run Tester Agent first (needs screenshot for visual analysis)
2. Run URL, Domain, Content, Heuristic agents in parallel
3. Apply Critical Veto Logic
4. Calculate final weighted score
5. Return verdict
```

### Critical Veto Logic

```
Priority Order:
0. Safe domain whitelist → Instant ALLOW
1. Critical signal detected → Instant BLOCK
2. Any agent score ≥ 75 → BLOCK (single agent conviction)
3. Two+ agents score > 50 → BLOCK (consensus)
4. Otherwise → Weighted average with thresholds
```

### Agent Weights

| Agent | Weight | Description |
|-------|--------|-------------|
| Domain Agent | 30% | Most critical - domain reputation |
| Content Agent | 25% | Page content analysis |
| URL Agent | 20% | URL structure patterns |
| Heuristic Agent | 15% | Social engineering detection |
| Tester Agent | 10% | Browser behavioral testing |

### Risk Thresholds

| Score Range | Verdict | Description |
|-------------|---------|-------------|
| 0-25 | `allow` | Safe to visit |
| 26-55 | `warn` | Suspicious - proceed with caution |
| 56-100 | `block` | Dangerous - do not visit |

---

## Groq LLM Integration (`groq-client.ts`)

### Models Used

| Model | Purpose |
|-------|---------|
| `llama-3.3-70b-versatile` | Text analysis for all agents |
| `llama-3.2-11b-vision-preview` | Logo detection from screenshots |

### API Configuration

```typescript
GROQ_API_URL: "https://api.groq.com/openai/v1/chat/completions"
LLM_TEMPERATURE: 0.1  // Low = more deterministic
LLM_MAX_TOKENS: 1000
```

### Vision Analysis

The `analyzeLogoInScreenshot()` method:
1. Takes base64 screenshot + page URL
2. Sends to vision model
3. Detects brand logos
4. Compares against legitimate domain list
5. Flags domain mismatches as CRITICAL

---

## Web Dashboard

### Technology Stack
- **Framework:** Next.js 14
- **Styling:** TailwindCSS
- **Animations:** Framer Motion
- **API Client:** Native fetch with SSE support

### Components

| Component | Purpose |
|-----------|---------|
| `ScanningInterface` | URL input with scan button |
| `StatusFeed` | Real-time agent activity logs |
| `ResultCard` | Verdict display with screenshot |
| `AgentBreakdown` | Detailed per-agent results |

### State Management

```typescript
status: "idle" | "scanning" | "complete" | "error"
logs: AgentLog[]
verdict: FinalVerdict | null
error: string | null
```

---

## Browser Extension

### Manifest V3 Structure

| Component | File | Purpose |
|-----------|------|---------|
| Service Worker | `background/service-worker.js` | Background processing |
| Content Script | `content/content-script.js` | Page injection |
| Popup UI | `ui/popup/popup.html` | Extension popup |

### Permissions

- `storage` - Save settings and scan history
- `tabs` - Access tab information
- `webNavigation` - Monitor navigation events
- `scripting` - Inject content scripts
- `activeTab` - Access current tab
- `<all_urls>` - Analyze any website

---

## Configuration (`config/index.ts`)

### Key Settings

| Setting | Value | Description |
|---------|-------|-------------|
| `PORT` | 3001 | API server port |
| `TIMEOUT_MS` | 30000 | Analysis timeout |
| `ALLOW_MAX` | 25 | Max score for "allow" |
| `BLOCK_MIN` | 56 | Min score for "block" |

### Blocklisted Domains

Free hosting services commonly abused:
- 000webhostapp.com, weebly.com, wixsite.com
- blogspot.com, netlify.app, vercel.app
- herokuapp.com, glitch.me, firebaseapp.com

### Safe Domains (Whitelist)

Instant allow for verified domains:
- google.com, microsoft.com, apple.com
- github.com, amazon.com, facebook.com
- paypal.com, netflix.com, youtube.com

---

## API Response Types

### ScanResponse

```typescript
interface ScanResponse {
  success: boolean;
  verdict?: {
    action: "allow" | "warn" | "block";
    overallRiskScore: number;
    confidence: number;
    agentResults: AgentResult[];
    summary: string;
    url: string;
    timestamp: number;
    screenshot?: string;  // Base64
  };
  error?: string;
  logs: AgentLog[];
}
```

### AgentResult

```typescript
interface AgentResult {
  agentId: string;
  agentName: string;
  riskScore: number;      // 0-100
  confidence: number;     // 0-1
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

---

## Deployment

### Render.com Configuration (`render.yaml`)

Two services deployed:

**1. phishguard-api (Backend)**
- Runtime: Node.js
- Build: `npm install && npm run build`
- Start: `npm start`
- Env: `GROQ_API_KEY`, `DISABLE_TESTER_AGENT=true`

**2. phishguard-dashboard (Frontend)**
- Runtime: Node.js
- Build: `npm install && npm run build`
- Start: `npm start`
- Env: `NEXT_PUBLIC_API_URL` (auto-linked to API)

> **Note:** Tester Agent is disabled on Render because Playwright browser automation isn't available in the free tier.

---

## How to Run Locally

### Prerequisites
- Node.js 18+
- Groq API key

### Backend Setup

```bash
cd server
npm install
# Create .env with GROQ_API_KEY
npm run dev
# Runs on http://localhost:3001
```

### Dashboard Setup

```bash
cd web-dashboard
npm install
npm run dev
# Runs on http://localhost:3000
```

### Extension Build

```bash
npm install
npm run build
# Load dist/ folder in chrome://extensions
```

---

## Security Considerations

1. **API Key Protection:** Groq key stored in environment variables
2. **Rate Limiting:** 30 requests/minute per IP prevents abuse
3. **Input Validation:** Zod validates all incoming URLs
4. **Timeout Protection:** 30-second max analysis time
5. **Graceful Shutdown:** Proper cleanup of browser instances

---

## Known Limitations

1. **No Offline Mode:** Requires internet for LLM analysis
2. **Headless Detection:** Some sites block Playwright
3. **Screenshot Failures:** Protected pages may not capture
4. **Render Limitations:** Tester Agent disabled on free tier
5. **False Positives:** Aggressive detection may flag legitimate sites

---

## Summary

PhishGuard AI is a comprehensive phishing detection system that uses:

- **5 Specialized AI Agents** analyzing different aspects
- **Groq LLM Integration** for intelligent analysis
- **Playwright Automation** for behavioral testing
- **Vision AI** for brand logo detection
- **Critical Veto Logic** for aggressive threat detection
- **Real-time SSE Streaming** for live updates

The system prioritizes security over convenience, preferring false positives to missing actual phishing attempts.

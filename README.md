# PhishGuard AI - Multi-Agent Phishing Detection System

A comprehensive phishing detection system featuring a **Web Dashboard** and **Backend API** powered by multiple AI agents and Groq's ultra-fast LLM. Also includes a Chrome/Firefox browser extension for real-time protection.

## Features

- **Multi-Agent AI Analysis**: 5 specialized AI agents analyze URLs in parallel
  - **URL Agent**: Analyzes URL structure, encoding, typosquatting, homograph attacks
  - **Domain Agent**: Checks domain reputation, suspicious patterns, brand impersonation
  - **Content Agent**: Examines page content, forms, login fields, brand mismatches (uses Playwright)
  - **Heuristic Agent**: Detects urgency language, threats, social engineering patterns
  - **Tester Agent** (NEW): Simulates user behavior, captures screenshots, detects popups/downloads

- **Web Dashboard**: Modern React-based interface for URL analysis
- **Real-time Logging**: Watch agents work in real-time with SSE streaming
- **Visual Verdicts**: Clear Safe/Suspicious/Dangerous verdicts with risk scores
- **Screenshot Capture**: See what the page looks like before visiting
- **Browser Extension**: Optional Chrome/Firefox extension for passive protection

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
│   │   │   ├── tester-agent.ts  # Browser testing (NEW)
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
├── src/                         # Browser Extension (original)
│   ├── background/
│   ├── content/
│   ├── agents/
│   └── ...
│
├── manifest.json                # Extension manifest
└── README.md
```

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn

### 1. Start the Backend API

```bash
cd server
npm install
npm run dev
```

The API server runs on `http://localhost:3001`

### 2. Start the Web Dashboard

```bash
cd web-dashboard
npm install
npm run dev
```

The dashboard runs on `http://localhost:3000`

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

SSE endpoint for real-time analysis logs.

**Events:**
- `log` - Agent activity updates
- `result` - Final verdict
- `done` - Analysis complete
- `error` - Error occurred

### GET /api/health

Health check endpoint.

## Configuration

### Risk Thresholds

Edit `server/src/config/index.ts`:

```typescript
THRESHOLDS: {
  ALLOW_MAX: 30,    // 0-30: Safe
  WARN_MAX: 70,     // 31-70: Suspicious
  BLOCK_MIN: 71     // 71-100: Dangerous
}
```

### Agent Weights

```typescript
AGENT_WEIGHTS: {
  urlAgent: 0.20,       // 20%
  domainAgent: 0.25,    // 25%
  contentAgent: 0.25,   // 25%
  heuristicAgent: 0.15, // 15%
  testerAgent: 0.15     // 15%
}
```

### Environment Variables

Create `.env` in the server directory:

```env
PORT=3001
GROQ_API_KEY=your_groq_api_key_here
```

## How Scoring Works

Each agent returns:

- `riskScore`: 0-100 (0 = safe, 100 = definitely phishing)
- `confidence`: 0-1 (how confident the agent is)
- `signals`: Array of detected indicators

The orchestrator combines scores using:

```
finalScore = Σ(agentScore × agentWeight × agentConfidence) / Σ(agentWeight × agentConfidence)
```

## Detection Signals

### URL Agent
- Excessive URL length
- IP address instead of domain
- Multiple subdomains
- Suspicious TLDs (.tk, .xyz, etc.)
- URL shorteners
- Typosquatting patterns
- Homograph attacks (Unicode lookalikes)

### Domain Agent
- Brand name in subdomain
- Random-looking domain names
- Suspicious patterns (-login, -secure)
- Excessive hyphens

### Content Agent
- Login forms submitting to external domains
- Brand name mismatch (title vs URL)
- Sensitive data requests
- Mismatched link text

### Heuristic Agent
- Urgency language ("Act now!", "24 hours")
- Threat language ("suspended", "locked")
- Reward scam patterns
- Poor grammar/spelling

### Tester Agent (NEW)
- Excessive redirects
- Cross-domain redirects
- Popup dialogs
- Automatic download attempts
- Browser permission requests
- Safety warnings

## Technologies

- **Backend**: Node.js, Express, TypeScript
- **Browser Automation**: Playwright
- **Frontend**: Next.js 14, React, TailwindCSS, Framer Motion
- **AI/LLM**: Groq API (Llama 3.3 70B)
- **Browser Extension**: Chrome Extension MV3, Vite

## Browser Extension (Optional)

The original browser extension is still available for real-time passive protection.

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

## Security Notes

- The Groq API key should be stored in environment variables for production
- The backend acts as a secure proxy for API calls
- Never expose API keys in frontend code

## License

MIT License - Feel free to use and modify.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Known Limitations

- Requires internet for LLM analysis (no offline mode)
- Some sites may block headless browsers
- Screenshot capture may fail on some protected pages

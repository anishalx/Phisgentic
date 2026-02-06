// Configuration constants for the extension

export const CONFIG = {
  // Local Backend API Configuration
  API_BASE_URL: "http://localhost:3001",
  API_SCAN_ENDPOINT: "/api/scan",

  // Groq API Configuration (kept for reference, not used in extension)
  GROQ_API_URL: "https://api.groq.com/openai/v1/chat/completions",
  GROQ_API_KEY: process.env.GROQ_API_KEY || "YOUR_GROQ_API_KEY_HERE",
  GROQ_MODEL: "llama-3.3-70b-versatile",

  // Agent weights for final scoring
  AGENT_WEIGHTS: {
    urlAgent: 0.25,
    domainAgent: 0.3,
    contentAgent: 0.25,
    heuristicAgent: 0.2,
  } as Record<string, number>,

  // Risk thresholds
  THRESHOLDS: {
    ALLOW_MAX: 30, // 0-30: Allow
    WARN_MAX: 70, // 31-70: Warn
    BLOCK_MIN: 71, // 71-100: Block
  },

  // Analysis settings
  ANALYSIS: {
    TIMEOUT_MS: 10000,
    MAX_CONTENT_LENGTH: 50000,
    LLM_TEMPERATURE: 0.2,
    LLM_MAX_TOKENS: 800,
  },

  // Known safe domains (won't be analyzed)
  SAFE_DOMAINS: [
    "google.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "stackoverflow.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "youtube.com",
  ],

  // Suspicious TLDs
  SUSPICIOUS_TLDS: [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".work",
    ".click",
    ".link",
    ".info",
    ".biz",
    ".online",
    ".site",
  ],

  // URL shortener domains
  URL_SHORTENERS: [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "short.link",
  ],

  // Phishing keywords in URLs
  PHISHING_KEYWORDS: [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "instagram",
    "netflix",
  ],

  // Urgency language patterns
  URGENCY_PATTERNS: [
    "urgent",
    "immediately",
    "suspended",
    "locked",
    "expire",
    "verify now",
    "confirm now",
    "24 hours",
    "limited time",
    "act now",
    "action required",
    "account will be",
  ],
} as const;

export const DEFAULT_SETTINGS = {
  enabled: true,
  blockThreshold: 70,
  warnThreshold: 30,
  showNotifications: true,
  autoBlock: false,
};

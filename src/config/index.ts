// Configuration constants for the extension

export const CONFIG = {
  // Local Backend API Configuration
  API_BASE_URL: "http://localhost:3001",
  API_SCAN_ENDPOINT: "/api/scan",

  // NOTE: Groq API is NOT used directly by the extension.
  // All LLM calls go through the backend API server.
  // These are kept for reference only.
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

  // Known safe domains (won't be analyzed - instant skip)
  SAFE_DOMAINS: [
    // Search & Tech
    "google.com", "google.co.in", "google.co.uk", "google.co.jp", "google.de",
    "google.fr", "google.com.br", "google.ca", "google.com.au",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "bing.com", "yahoo.com", "duckduckgo.com",
    // Social Media
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "whatsapp.com", "reddit.com", "pinterest.com", "tiktok.com",
    "snapchat.com", "discord.com", "telegram.org",
    // Video & Streaming
    "youtube.com", "netflix.com", "twitch.tv", "spotify.com",
    "disneyplus.com", "hulu.com", "primevideo.com", "hotstar.com",
    // E-Commerce & Payments
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
    "flipkart.com", "myntra.com", "meesho.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    "etsy.com", "shopify.com", "aliexpress.com",
    "paypal.com", "stripe.com", "razorpay.com",
    // News & Media
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com",
    "theguardian.com", "forbes.com", "bloomberg.com", "cnbc.com",
    "ndtv.com", "timesofindia.indiatimes.com", "hindustantimes.com",
    "indianexpress.com", "thehindu.com", "news18.com",
    "techcrunch.com", "theverge.com", "wired.com", "cnet.com",
    "washingtonpost.com", "foxnews.com", "nbcnews.com",
    "moneycontrol.com", "livemint.com", "economictimes.indiatimes.com",
    // Banking & Finance
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "coinbase.com", "binance.com", "robinhood.com",
    // Cloud & Dev Tools
    "gitlab.com", "bitbucket.org", "npmjs.com",
    "vercel.com", "netlify.com", "cloudflare.com",
    "figma.com", "canva.com", "notion.so", "slack.com", "zoom.us",
    // Education & Reference
    "wikipedia.org", "medium.com", "quora.com",
    "coursera.org", "udemy.com", "khanacademy.org",
    // Email & Productivity
    "gmail.com", "outlook.com", "live.com", "office.com",
    "protonmail.com", "dropbox.com",
    // Services
    "usps.com", "fedex.com", "ups.com", "dhl.com",
    "booking.com", "airbnb.com", "uber.com",
    "imdb.com", "yelp.com", "weather.com", "adobe.com",
    "openai.com", "chatgpt.com", "anthropic.com",
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

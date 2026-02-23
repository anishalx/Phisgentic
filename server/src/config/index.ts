// Configuration constants for the API server

import dotenv from "dotenv";
dotenv.config();

export const CONFIG = {
  // Server Configuration
  PORT: parseInt(process.env.PORT || "3001", 10),
  
  // Groq API Configuration (Primary LLM)
  GROQ_API_URL: "https://api.groq.com/openai/v1/chat/completions",
  GROQ_API_KEY: process.env.GROQ_API_KEY || "",
  GROQ_MODEL: "llama-3.3-70b-versatile",
  GROQ_VISION_MODEL: "llama-3.2-11b-vision-preview", // Vision-capable model for logo detection

  // Gemini API Configuration (Secondary LLM for dual-model consensus)
  GEMINI_API_URL: "https://generativelanguage.googleapis.com/v1beta/models",
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || "",
  GEMINI_MODEL: "gemini-2.0-flash",

  // Dual-Model Consensus Settings
  DUAL_MODEL: {
    ENABLED: process.env.DUAL_MODEL_ENABLED !== "false", // Enabled by default
    CONSENSUS_THRESHOLD: 15, // Max score difference for auto-consensus
    DISAGREEMENT_STRATEGY: "conservative" as "conservative" | "average" | "max",
    // "conservative" = take higher score when models disagree significantly
    // "average" = average both scores
    // "max" = take the maximum score
  },

  // Agent weights for final scoring (higher = more influence)
  AGENT_WEIGHTS: {
    urlAgent: 0.20,
    domainAgent: 0.30, // Increased - domain reputation is critical
    contentAgent: 0.25,
    heuristicAgent: 0.15,
    testerAgent: 0.10,
  } as Record<string, number>,

  // Risk thresholds - LOWERED for more aggressive detection
  THRESHOLDS: {
    ALLOW_MAX: 25,   // 0-25: Allow (was 30)
    WARN_MAX: 55,    // 26-55: Warn (was 70)
    BLOCK_MIN: 56,   // 56-100: Block (was 71)
  },

  // Critical signal types that trigger immediate BLOCK verdict
  CRITICAL_VETO_SIGNALS: [
    "blocklist_match",
    "known_phishing_domain",
    "brand_impersonation",
    "typosquatting",
    "homograph",
    "ip_address",
    "external_form_action",
    "title_brand_mismatch",
    "download_attempted",
    "safety_warning",
    "sensitive_data_request",
    "brand_in_subdomain",
    // New: Advanced Detection
    "logo_domain_mismatch",      // Vision-detected brand logo on wrong domain
    "cross_origin_password_form", // Form hijacking: password submitted to different domain
    "cross_origin_credential_form", // Form hijacking: credentials to different domain
  ],

  // Analysis settings
  ANALYSIS: {
    TIMEOUT_MS: 45000, // 45s per-agent timeout (up from 30s; LLM timeout is 20s)
    MAX_CONTENT_LENGTH: 50000,
    LLM_TEMPERATURE: 0.1, // Lower = more deterministic
    LLM_MAX_TOKENS: 1000,
  },

  // Known safe domains (instant allow)
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
    "netflix.com",
    "paypal.com",
    "instagram.com",
    "whatsapp.com",
    "reddit.com",
    "wikipedia.org",
  ],

  // Known phishing/malware domains (instant block)
  // IMPORTANT: Only include domains that are EXCLUSIVELY used for malicious purposes.
  // Do NOT include legitimate hosting platforms (Vercel, Netlify, Heroku, etc.)
  // Those belong in SUSPICIOUS_HOSTING_PATTERNS with a lower score.
  BLOCKLIST_DOMAINS: [
    // Free dynamic DNS services heavily abused for phishing
    "duckdns.org",
    "ddns.net",
    "no-ip.org",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "serveblog.net",
    "serveftp.com",
    // Free hosting with extremely high abuse rates
    "000webhostapp.com",
  ],

  // Suspicious TLDs (high-risk) - Expanded list
  SUSPICIOUS_TLDS: [
    ".tk", ".ml", ".ga", ".cf", ".gq",  // Free TLDs
    ".xyz", ".top", ".work", ".click", ".link",
    ".info", ".biz", ".online", ".site", ".club",
    ".icu", ".buzz", ".monster", ".rest", ".cam",
    ".uno", ".fit", ".life", ".live", ".space",
    ".fun", ".website", ".tech", ".store", ".shop",
    ".pw", ".cc", ".ws", ".su", ".ru",  // High abuse regions
  ],

  // Phishing-associated free hosting patterns
  SUSPICIOUS_HOSTING_PATTERNS: [
    "000webhostapp.com",
    "weebly.com", 
    "wix.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
    "forms.gle",
    "docs.google.com/forms",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "glitch.me",
    "repl.co",
    "github.io", // When impersonating brands
    "gitlab.io",
    "web.app",
    "firebaseapp.com",
    "azurewebsites.net",
    "cloudfront.net",
  ],

  // URL shortener domains
  URL_SHORTENERS: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "short.link", "cutt.ly", "shorturl.at", "rb.gy",
    "trib.al", "x.co", "soo.gd", "s.id",
  ],

  // Phishing keywords in URLs - Expanded
  PHISHING_KEYWORDS: [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "secure", "security", "protect",
    "account", "myaccount", "my-account",
    "update", "upgrade", "renew",
    "confirm", "confirmation",
    "password", "passwd", "pwd",
    "banking", "bank", "wallet",
    "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "instagram", "netflix",
    "support", "help", "customer",
    "suspend", "locked", "disabled",
    "unusual", "activity", "alert",
    "recover", "recovery", "restore",
    "webscr", "cgi-bin", "cmd=",
  ],

  // Brand names for impersonation detection
  // NOTE: Brands with names <= 3 chars (ups, dhl, meta) need exact-match logic
  // in domain-agent.ts to avoid false positives (e.g., "setup.com" matching "ups").
  PROTECTED_BRANDS: [
    { name: "paypal", domain: "paypal.com", minLength: 4 },
    { name: "amazon", domain: "amazon.com", minLength: 4 },
    { name: "apple", domain: "apple.com", minLength: 4 },
    { name: "microsoft", domain: "microsoft.com", minLength: 4 },
    { name: "google", domain: "google.com", minLength: 4 },
    { name: "facebook", domain: "facebook.com", minLength: 4 },
    { name: "meta", domain: "meta.com", minLength: 4 },
    { name: "instagram", domain: "instagram.com", minLength: 4 },
    { name: "netflix", domain: "netflix.com", minLength: 4 },
    { name: "spotify", domain: "spotify.com", minLength: 4 },
    { name: "linkedin", domain: "linkedin.com", minLength: 4 },
    { name: "twitter", domain: "twitter.com", minLength: 4 },
    { name: "chase", domain: "chase.com", minLength: 4 },
    { name: "wellsfargo", domain: "wellsfargo.com", minLength: 4 },
    { name: "bankofamerica", domain: "bankofamerica.com", minLength: 4 },
    { name: "usps", domain: "usps.com", minLength: 4 },
    { name: "fedex", domain: "fedex.com", minLength: 4 },
    { name: "ups", domain: "ups.com", minLength: 3 },
    { name: "dhl", domain: "dhl.com", minLength: 3 },
    { name: "walmart", domain: "walmart.com", minLength: 4 },
    { name: "ebay", domain: "ebay.com", minLength: 4 },
    { name: "dropbox", domain: "dropbox.com", minLength: 4 },
    { name: "outlook", domain: "outlook.com", minLength: 4 },
    { name: "office365", domain: "office.com", minLength: 4 },
    { name: "icloud", domain: "icloud.com", minLength: 4 },
    { name: "coinbase", domain: "coinbase.com", minLength: 4 },
    { name: "binance", domain: "binance.com", minLength: 4 },
  ],

  // Brand to legitimate domains mapping for logo detection
  // Maps brand names to all their legitimate domains
  BRAND_DOMAINS: {
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "azure.com", "windows.com", "xbox.com", "bing.com", "skype.com", "linkedin.com", "github.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "google.co.uk", "google.co.in", "android.com", "chromium.org"],
    "apple": ["apple.com", "icloud.com", "itunes.com", "apple.co"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com", "primevideo.com", "audible.com", "twitch.tv"],
    "facebook": ["facebook.com", "fb.com", "messenger.com", "meta.com", "instagram.com", "whatsapp.com", "oculus.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "oculus.com"],
    "instagram": ["instagram.com", "facebook.com", "meta.com"],
    "paypal": ["paypal.com", "paypal.me", "braintreepayments.com", "venmo.com"],
    "netflix": ["netflix.com", "nflxvideo.net"],
    "spotify": ["spotify.com", "spotifycdn.com"],
    "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
    "x": ["x.com", "twitter.com", "t.co", "twimg.com"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "chase": ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
    "bank of america": ["bankofamerica.com", "bofa.com", "mbna.com", "merrilledge.com"],
    "wells fargo": ["wellsfargo.com", "wf.com"],
    "citibank": ["citi.com", "citibank.com", "citicards.com"],
    "usps": ["usps.com", "usps.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "walmart": ["walmart.com", "samsclub.com"],
    "ebay": ["ebay.com", "ebay.co.uk", "ebay.de"],
    "dropbox": ["dropbox.com", "dropboxstatic.com"],
    "coinbase": ["coinbase.com", "coinbase.pro"],
    "binance": ["binance.com", "binance.us"],
    "steam": ["steampowered.com", "steamcommunity.com", "valve.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com"],
    "adobe": ["adobe.com", "adobelogin.com", "behance.net", "creativecloud.com"],
    "docusign": ["docusign.com", "docusign.net"],
  } as Record<string, string[]>,

  // Urgency language patterns
  URGENCY_PATTERNS: [
    "urgent", "immediately", "right away",
    "suspended", "locked", "disabled", "terminated",
    "expire", "expiring", "expires in",
    "verify now", "confirm now", "update now",
    "24 hours", "48 hours", "within hours",
    "limited time", "act now", "action required",
    "account will be", "will be suspended",
    "unauthorized", "unusual activity",
    "security alert", "important notice",
  ],

  // Playwright settings
  PLAYWRIGHT: {
    HEADLESS: true,
    TIMEOUT: 20000,
    VIEWPORT: { width: 1280, height: 720 },
  },
} as const;

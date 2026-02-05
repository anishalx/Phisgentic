// Configuration constants for the API server

import dotenv from "dotenv";
dotenv.config();

export const CONFIG = {
  // Server Configuration
  PORT: parseInt(process.env.PORT || "3001", 10),
  
  // Groq API Configuration
  GROQ_API_URL: "https://api.groq.com/openai/v1/chat/completions",
  GROQ_API_KEY: process.env.GROQ_API_KEY || "",
  GROQ_MODEL: "llama-3.3-70b-versatile",

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
  ],

  // Analysis settings
  ANALYSIS: {
    TIMEOUT_MS: 30000,
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

  // Known phishing/malware domains (instant block) - Sample from OpenPhish/PhishTank
  BLOCKLIST_DOMAINS: [
    // Common phishing hosting
    "000webhostapp.com",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "sites.google.com",
    "forms.gle",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "glitch.me",
    "repl.co",
    "firebaseapp.com",
    // Free subdomain services abused for phishing
    "duckdns.org",
    "ddns.net",
    "no-ip.org",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "serveblog.net",
    "serveftp.com",
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
  PROTECTED_BRANDS: [
    { name: "paypal", domain: "paypal.com" },
    { name: "amazon", domain: "amazon.com" },
    { name: "apple", domain: "apple.com" },
    { name: "microsoft", domain: "microsoft.com" },
    { name: "google", domain: "google.com" },
    { name: "facebook", domain: "facebook.com" },
    { name: "meta", domain: "meta.com" },
    { name: "instagram", domain: "instagram.com" },
    { name: "netflix", domain: "netflix.com" },
    { name: "spotify", domain: "spotify.com" },
    { name: "linkedin", domain: "linkedin.com" },
    { name: "twitter", domain: "twitter.com" },
    { name: "chase", domain: "chase.com" },
    { name: "wellsfargo", domain: "wellsfargo.com" },
    { name: "bankofamerica", domain: "bankofamerica.com" },
    { name: "usps", domain: "usps.com" },
    { name: "fedex", domain: "fedex.com" },
    { name: "ups", domain: "ups.com" },
    { name: "dhl", domain: "dhl.com" },
    { name: "walmart", domain: "walmart.com" },
    { name: "ebay", domain: "ebay.com" },
    { name: "dropbox", domain: "dropbox.com" },
    { name: "outlook", domain: "outlook.com" },
    { name: "office365", domain: "office.com" },
    { name: "icloud", domain: "icloud.com" },
    { name: "coinbase", domain: "coinbase.com" },
    { name: "binance", domain: "binance.com" },
  ],

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

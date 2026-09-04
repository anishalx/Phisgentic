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
    // "conservative" = take HIGHER score when models disagree (SAFER — missing phishing is worse than a false alarm)
    // "average" = average both scores (prevents single LLM hallucination from dominating)
    // "max" = take the maximum score
  },

  // Agent weights for final scoring (higher = more influence)
  AGENT_WEIGHTS: {
    urlAgent: 0.20,
    domainAgent: 0.25,
    contentAgent: 0.25,
    heuristicAgent: 0.15,
    testerAgent: 0.15, // Increased — browser testing catches what static analysis misses
  } as Record<string, number>,

  // Risk thresholds — Security-first: better to warn on a safe site than miss phishing
  THRESHOLDS: {
    ALLOW_MAX: 30,   // 0-30: Allow  (tightened from 45 — narrower safe zone)
    WARN_MAX: 69,    // 31-69: Warn
    BLOCK_MIN: 70,   // 70-100: Block (lowered from 80 — easier to block confirmed threats)
  },

  // Critical signal types that trigger immediate BLOCK verdict
  // IMPORTANT: Only include signals that are UNAMBIGUOUSLY phishing.
  // Signals removed from this list still contribute to scoring but don't auto-block.
  CRITICAL_VETO_SIGNALS: [
    "blocklist_match",
    "known_phishing_domain",
    "typosquatting",
    "homograph",
    "brand_impersonation",
    "brand_in_subdomain",
    "download_attempted",
    "safety_warning",
    // Advanced Detection
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
  // Comprehensive list to prevent false positives on legitimate websites
  SAFE_DOMAINS: [
    // Search & Tech Giants
    "google.com", "google.co.in", "google.co.uk", "google.co.jp", "google.de",
    "google.fr", "google.com.br", "google.ca", "google.com.au",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "bing.com", "yahoo.com", "yahoo.co.jp", "duckduckgo.com", "baidu.com",
    // Social Media
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "whatsapp.com", "reddit.com", "pinterest.com", "tumblr.com", "tiktok.com",
    "snapchat.com", "discord.com", "discord.gg", "telegram.org", "signal.org",
    "threads.net", "mastodon.social",
    // Video & Streaming
    "youtube.com", "netflix.com", "twitch.tv", "vimeo.com", "dailymotion.com",
    "disneyplus.com", "hulu.com", "hbomax.com", "max.com", "peacocktv.com",
    "primevideo.com", "crunchyroll.com", "spotify.com", "soundcloud.com",
    "hotstar.com",
    // E-Commerce & Payments
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazon.ca", "amazon.com.au", "amazon.fr", "amazon.es", "amazon.it",
    "flipkart.com", "myntra.com", "meesho.com", "ajio.com",
    "ebay.com", "ebay.co.uk", "ebay.de",
    "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "etsy.com", "shopify.com", "aliexpress.com", "alibaba.com",
    "paypal.com", "paypal.me", "stripe.com", "razorpay.com",
    "venmo.com", "squareup.com", "wise.com",
    // News & Media
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "washingtonpost.com",
    "reuters.com", "apnews.com", "theguardian.com", "forbes.com",
    "bloomberg.com", "cnbc.com", "foxnews.com", "nbcnews.com", "abcnews.go.com",
    "usatoday.com", "wsj.com", "economist.com", "time.com", "newsweek.com",
    "huffpost.com", "buzzfeed.com", "vice.com", "vox.com", "theatlantic.com",
    "ndtv.com", "timesofindia.indiatimes.com", "hindustantimes.com",
    "indianexpress.com", "thehindu.com", "news18.com", "aajtak.in",
    "moneycontrol.com", "livemint.com", "economictimes.indiatimes.com",
    "techcrunch.com", "theverge.com", "wired.com", "arstechnica.com",
    "engadget.com", "mashable.com", "gizmodo.com", "cnet.com", "zdnet.com",
    "tomsguide.com", "tomshardware.com",
    // Banking & Finance
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "capitalone.com", "usbank.com", "pnc.com", "tdbank.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.sbi",
    "axisbank.com", "kotak.com", "yesbank.in",
    "hsbc.com", "barclays.co.uk", "natwest.com", "lloydsbank.com",
    "americanexpress.com", "discover.com",
    "fidelity.com", "schwab.com", "vanguard.com", "robinhood.com",
    "coinbase.com", "binance.com", "kraken.com",
    // Cloud & Developer Tools
    "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
    "docker.com", "hub.docker.com", "aws.amazon.com", "azure.microsoft.com",
    "cloud.google.com", "digitalocean.com", "heroku.com",
    "vercel.com", "netlify.com", "cloudflare.com",
    "figma.com", "canva.com", "notion.so", "trello.com",
    "atlassian.com", "slack.com", "zoom.us", "zoom.com",
    "webex.com",
    // Education & Reference
    "wikipedia.org", "wikimedia.org", "medium.com", "substack.com",
    "quora.com", "researchgate.net", "academia.edu",
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "codecademy.com", "freecodecamp.org",
    // Email & Productivity
    "gmail.com", "outlook.com", "outlook.live.com", "live.com",
    "office.com", "office365.com", "protonmail.com", "proton.me",
    "docs.google.com", "drive.google.com",
    "dropbox.com", "box.com", "onedrive.live.com",
    // Government & Shipping
    "usps.com", "fedex.com", "ups.com", "dhl.com",
    // Travel & Services
    "tripadvisor.com", "booking.com", "airbnb.com", "expedia.com",
    "uber.com", "lyft.com", "doordash.com",
    // Other Popular Sites
    "imdb.com", "yelp.com", "zillow.com", "weather.com",
    "archive.org", "adobe.com", "samsung.com",
    "openai.com", "chatgpt.com", "anthropic.com", "huggingface.co",
    "kaggle.com", "leetcode.com", "hackerrank.com",
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
    // Additional high-abuse free hosting/DNS services
    "rf.gd",
    "infinityfreeapp.com",
    "epizy.com",
    "byethost.com",
    "byet.host",
    "awardspace.net",
    "atwebpages.com",
    "mywebcommunity.org",
    "great-site.net",
    "is-best.net",
    "freenom.com",
    "42web.io",
    "freewebhostmost.com",
    "16mb.com",
    "creatorlink.net",
  ],

  // Suspicious TLDs — Only truly high-abuse TLDs
  // Removed: .tech, .store, .shop, .site, .online, .live, .space, .life,
  //          .info, .biz, .link, .fun, .website, .cc (all used by legit businesses)
  SUSPICIOUS_TLDS: [
    ".tk", ".ml", ".ga", ".cf", ".gq",  // Free TLDs (heavily abused)
    ".xyz", ".top", ".click",
    ".icu", ".buzz", ".monster", ".rest", ".cam",
    ".uno", ".fit",
    ".pw", ".ws", ".su",  // High abuse
    // Restored: additional high-abuse TLDs
    ".link", ".site", ".online", ".live",
    ".fun", ".website",
  ],

  // Suspicious hosting — platforms with significant phishing abuse rates
  // These won't auto-block but contribute to scoring when combined with other signals
  SUSPICIOUS_HOSTING_PATTERNS: [
    "000webhostapp.com",
    "forms.gle",
    "docs.google.com/forms",
    "glitch.me",
    "repl.co",
    "sites.google.com",
    // Restored: legitimate platforms that are also heavily abused for phishing
    // Having a site on these is a moderate signal, not proof of phishing
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "github.io",
    "herokuapp.com",
    "blogspot.com",
    "weebly.com",
    "wix.com",
    "wordpress.com",
    "pages.dev",       // Cloudflare Pages
    "workers.dev",     // Cloudflare Workers
    "onrender.com",    // Render
    "surge.sh",
    "tiiny.site",
    "carrd.co",
  ],

  // URL shortener domains
  URL_SHORTENERS: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "short.link", "cutt.ly", "shorturl.at", "rb.gy",
    "trib.al", "x.co", "soo.gd", "s.id",
  ],

  // Phishing keywords in URLs — Only structural/action keywords
  // Removed brand names (paypal, amazon, apple, etc.) — already caught by brand impersonation checks
  PHISHING_KEYWORDS: [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "secure", "security",
    "account", "myaccount", "my-account",
    "update", "upgrade", "renew",
    "confirm", "confirmation",
    "password", "passwd", "pwd",
    "banking", "wallet",
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

  // Known legitimate authentication/payment domains
  // Cross-origin form submissions TO these domains are NOT phishing
  KNOWN_AUTH_PAYMENT_DOMAINS: [
    // Authentication providers
    "auth0.com", "okta.com", "onelogin.com", "duo.com",
    "login.microsoftonline.com", "accounts.google.com",
    "appleid.apple.com", "id.apple.com",
    "cognito-idp.amazonaws.com", "amazoncognito.com",
    "firebase.google.com", "firebaseapp.com",
    "auth.firebase.com", "identitytoolkit.googleapis.com",
    "login.salesforce.com", "login.live.com",
    "github.com", "gitlab.com",
    // Payment processors
    "stripe.com", "js.stripe.com", "checkout.stripe.com",
    "paypal.com", "paypalobjects.com",
    "razorpay.com", "api.razorpay.com",
    "checkout.shopify.com", "shop.app",
    "square.com", "squareup.com",
    "braintreegateway.com", "braintree-api.com",
    "adyen.com", "checkout.adyen.com",
    "2checkout.com", "paddle.com",
    "chargebee.com", "recurly.com",
    // Form services
    "formspree.io", "getform.io", "formsubmit.co",
    "mailchimp.com", "list-manage.com",
    "convertkit.com", "sendinblue.com",
    "hubspot.com", "forms.hubspot.com",
    "typeform.com",
  ],

  // Urgency language patterns
  // Removed common legitimate words: "suspended", "locked", "disabled", "terminated"
  // (these appear naturally in ToS, status pages, account management, and news)
  URGENCY_PATTERNS: [
    "urgent", "immediately", "right away",
    "expire", "expiring", "expires in",
    "verify now", "confirm now", "update now",
    "24 hours", "48 hours", "within hours",
    "limited time", "act now", "action required",
    "account will be", "will be suspended",
    "unauthorized", "unusual activity",
    "security alert", "important notice",
  ],

  // Safe domain exclusions — subdomains of safe domains that are commonly abused for phishing
  // These are checked BEFORE the safe domain whitelist, so phishing on these is still detected
  SAFE_DOMAIN_EXCLUSIONS: [
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "storage.googleapis.com",
    "forms.gle",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "notion.site",
    "sharepoint.com",
    "sway.office.com",
  ],

  // Google Safe Browsing API Configuration
  GOOGLE_SAFE_BROWSING: {
    API_KEY: process.env.GOOGLE_SAFE_BROWSING_API_KEY || "",
    API_URL: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    ENABLED: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
    TIMEOUT_MS: 5000, // 5s timeout — don't block analysis if API is slow
  },

  // Playwright settings
  PLAYWRIGHT: {
    HEADLESS: true,
    TIMEOUT: 20000,
    VIEWPORT: { width: 1280, height: 720 },
  },
} as const;

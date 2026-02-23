// PhishGuard Plugin - Shared Configuration Constants
// Extracted from server/src/config/index.ts for self-contained plugin use.

export const SAFE_DOMAINS = [
  "google.com", "microsoft.com", "apple.com", "github.com",
  "stackoverflow.com", "amazon.com", "facebook.com", "twitter.com",
  "linkedin.com", "youtube.com", "netflix.com", "paypal.com",
  "instagram.com", "whatsapp.com", "reddit.com", "wikipedia.org",
];

export const BLOCKLIST_DOMAINS = [
  "000webhostapp.com", "weebly.com", "wixsite.com",
  "duckdns.org", "ddns.net", "no-ip.org", "hopto.org",
  "zapto.org", "sytes.net", "serveblog.net", "serveftp.com",
];

export const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq",
  ".xyz", ".top", ".work", ".click", ".link",
  ".info", ".biz", ".online", ".site", ".club",
  ".icu", ".buzz", ".monster", ".rest", ".cam",
  ".uno", ".fit", ".life", ".live", ".space",
  ".fun", ".website", ".tech", ".store", ".shop",
  ".pw", ".cc", ".ws", ".su", ".ru",
];

export const SUSPICIOUS_HOSTING_PATTERNS = [
  "000webhostapp.com", "weebly.com", "wix.com", "blogspot.com",
  "wordpress.com", "sites.google.com", "forms.gle", "docs.google.com",  // M12 fix: removed /forms (never matches hostname)
  "netlify.app", "vercel.app", "herokuapp.com", "glitch.me",
  "repl.co", "github.io", "gitlab.io", "web.app",
  "firebaseapp.com", "azurewebsites.net", "cloudfront.net",
];

export const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl",
  "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "short.link", "cutt.ly", "shorturl.at", "rb.gy",
  "trib.al", "x.co", "soo.gd", "s.id",
];

export const PHISHING_KEYWORDS = [
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
];

// NOTE: Brands with names <= 3 chars (ups, dhl) need exact-match logic
// in domain-agent.ts to avoid false positives (e.g., "setup.com" matching "ups").
// minLength controls the minimum hostname segment length for includes() matching.
export const PROTECTED_BRANDS = [
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
];

export const URGENCY_PATTERNS = [
  "urgent", "immediately", "right away",
  "suspended", "locked", "disabled", "terminated",
  "expire", "expiring", "expires in",
  "verify now", "confirm now", "update now",
  "24 hours", "48 hours", "within hours",
  "limited time", "act now", "action required",
  "account will be", "will be suspended",
  "unauthorized", "unusual activity",
  "security alert", "important notice",
];

export const CRITICAL_VETO_SIGNALS = [
  "blocklist_match",
  // M5 fix: removed "known_phishing_domain" — no agent emits this
  "brand_impersonation",
  "typosquatting",
  "homograph",
  // M10 fix: removed "ip_address" — too aggressive, blocks legitimate internal tools
  "external_form_action",
  "title_brand_mismatch",
  // M5 fix: removed "download_attempted", "safety_warning", "logo_domain_mismatch" — no agent emits these
  "sensitive_data_request",
  "brand_in_subdomain",
  "cross_origin_password_form",
  "cross_origin_credential_form",
];

export const AGENT_WEIGHTS: Record<string, number> = {
  urlAgent: 0.20,
  domainAgent: 0.30,
  contentAgent: 0.25,
  heuristicAgent: 0.15,
  testerAgent: 0.10,
};

export const THRESHOLDS = {
  ALLOW_MAX: 25,
  BLOCK_MIN: 56,
};

export const BRAND_DOMAINS: Record<string, string[]> = {
  "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "azure.com", "windows.com", "xbox.com", "bing.com", "skype.com", "linkedin.com", "github.com"],
  "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "android.com", "chromium.org"],
  "apple": ["apple.com", "icloud.com", "itunes.com", "apple.co"],
  "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com", "primevideo.com", "audible.com", "twitch.tv"],
  "facebook": ["facebook.com", "fb.com", "messenger.com", "meta.com", "instagram.com", "whatsapp.com", "oculus.com"],
  "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "oculus.com"],
  "instagram": ["instagram.com", "facebook.com", "meta.com"],
  "paypal": ["paypal.com", "paypal.me", "braintreepayments.com", "venmo.com"],
  "netflix": ["netflix.com", "nflxvideo.net"],
  "spotify": ["spotify.com", "spotifycdn.com"],
  "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
  "linkedin": ["linkedin.com", "licdn.com"],
  "chase": ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
  "wells fargo": ["wellsfargo.com", "wf.com"],
  "usps": ["usps.com", "usps.gov"],
  "fedex": ["fedex.com"],
  "ups": ["ups.com"],
  "dhl": ["dhl.com", "dhl.de"],
  "walmart": ["walmart.com", "samsclub.com"],
  "ebay": ["ebay.com", "ebay.co.uk", "ebay.de"],
  "dropbox": ["dropbox.com", "dropboxstatic.com"],
  "coinbase": ["coinbase.com", "coinbase.pro"],
  "binance": ["binance.com", "binance.us"],
};

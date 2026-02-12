// PhishGuard Stagehand Plugin - Type Definitions
// These mirror the server types to avoid cross-project rootDir issues.
// The agent wrappers import the actual server classes at runtime.

// ─── Shared Types (mirrored from server/src/types) ─────────────────────

export interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
}

export interface AgentResult {
  agentId: string;
  agentName: string;
  riskScore: number;
  confidence: number;
  signals: Signal[];
  explanation: string;
  executionTimeMs: number;
}

export interface FinalVerdict {
  action: "allow" | "warn" | "block";
  overallRiskScore: number;
  confidence: number;
  agentResults: AgentResult[];
  summary: string;
  url: string;
  timestamp: number;
  screenshot?: string;
}

export interface PageContent {
  title: string;
  forms: FormData[];
  links: LinkData[];
  scripts: string[];
  metaTags: Record<string, string>;
  textContent: string;
  hasPasswordField: boolean;
  hasLoginForm: boolean;
}

export interface FormData {
  action: string;
  method: string;
  hasPasswordField: boolean;
  inputTypes: string[];
}

export interface LinkData {
  href: string;
  text: string;
  isExternal: boolean;
}

export interface FormAnalysis {
  formIndex: number;
  action: string;
  actionDomain: string;
  method: string;
  hasPasswordField: boolean;
  hasCreditCardField: boolean;
  isCrossOrigin: boolean;
  inputFields: string[];
}

export interface LogoDetectionResult {
  brandDetected: string | null;
  confidence: number;
  isDomainMismatch: boolean;
  legitimateDomains: string[];
  explanation: string;
}

export interface BrowserTestResult {
  screenshot: string;
  finalUrl: string;
  redirectChain: string[];
  hasPopups: boolean;
  hasOverlays: boolean;
  downloadAttempted: boolean;
  permissionRequests: string[];
  consoleErrors: string[];
  networkErrors: string[];
  loadTimeMs: number;
  safetyWarning?: string;
  formAnalysis: FormAnalysis[];
  logoDetection?: LogoDetectionResult;
}

// ─── Plugin Configuration ──────────────────────────────────────────────

export interface PhishGuardOptions {
  /** Groq API key — reserved for future LLM integration. Currently unused by plugin agents. */
  groqApiKey?: string;

  /** Detection mode: "full" runs all 5 agents, "fast" runs URL+Domain only (no LLM) */
  mode?: "full" | "fast";

  /** Scan all links on the page after navigation (default: true) */
  scanPageLinks?: boolean;

  /** Maximum number of links to scan per page (default: 50) */
  maxLinksToScan?: number;

  /** Concurrent link scan limit (default: 5) */
  linkScanConcurrency?: number;

  /** Callback when phishing is detected (warn or block verdict) */
  onPhishingDetected?: (result: PhishGuardResult) => void;

  /** Callback when link scanning completes for a page */
  onLinksScanComplete?: (report: LinkScanReport) => void;

  /** Callback when a scan starts */
  onScanStart?: (url: string) => void;

  /** Callback when a scan completes */
  onScanComplete?: (url: string, result: PhishGuardResult) => void;

  /** Maximum cache entries (default: 500) */
  cacheMaxSize?: number;

  /** Cache TTL in milliseconds (default: 1800000 = 30 min) */
  cacheTTLMs?: number;

  /** Enable verbose logging (default: true) */
  verbose?: boolean;
}

// ─── Resolved Configuration (with defaults applied) ────────────────────

export interface ResolvedOptions {
  groqApiKey?: string;
  mode: "full" | "fast";
  scanPageLinks: boolean;
  maxLinksToScan: number;
  linkScanConcurrency: number;
  onPhishingDetected?: (result: PhishGuardResult) => void;
  onLinksScanComplete?: (report: LinkScanReport) => void;
  onScanStart?: (url: string) => void;
  onScanComplete?: (url: string, result: PhishGuardResult) => void;
  cacheMaxSize: number;
  cacheTTLMs: number;
  verbose: boolean;
}

// ─── Scan Results ──────────────────────────────────────────────────────

export interface PhishGuardResult {
  /** The URL that was scanned */
  url: string;

  /** Final action recommendation */
  action: "allow" | "warn" | "block";

  /** Overall risk score 0-100 */
  riskScore: number;

  /** Confidence in the assessment 0-1 */
  confidence: number;

  /** Human-readable summary */
  summary: string;

  /** Per-agent results (only in full mode) */
  agentResults: AgentResult[];

  /** All detected signals across agents */
  signals: Signal[];

  /** Whether this result came from cache */
  fromCache: boolean;

  /** Detection mode used */
  mode: "full" | "fast";

  /** Total scan time in ms */
  scanTimeMs: number;

  /** Timestamp of the scan */
  timestamp: number;

  /** Base64 screenshot if available (full mode with tester agent) */
  screenshot?: string;
}

// ─── Link Scanning ─────────────────────────────────────────────────────

export interface SuspiciousLink {
  /** The link URL */
  url: string;

  /** The link text shown on the page */
  text: string;

  /** Risk score from fast scan */
  riskScore: number;

  /** Why it was flagged */
  reason: string;

  /** Signals detected */
  signals: Signal[];
}

export interface LinkScanReport {
  /** The page URL where links were found */
  pageUrl: string;

  /** Total links found on the page */
  totalLinks: number;

  /** Links that were actually scanned (external, non-safe) */
  scannedLinks: number;

  /** Links flagged as suspicious */
  suspiciousLinks: SuspiciousLink[];

  /** Total time to scan all links */
  scanTimeMs: number;

  /** Timestamp */
  timestamp: number;
}

// ─── Scanner Stats ─────────────────────────────────────────────────────

export interface ScannerStats {
  /** Total URLs scanned */
  totalScans: number;

  /** URLs flagged as dangerous (block) */
  blockedCount: number;

  /** URLs flagged as suspicious (warn) */
  warnedCount: number;

  /** URLs allowed */
  allowedCount: number;

  /** Cache hits */
  cacheHits: number;

  /** Cache size */
  cacheSize: number;

  /** Total suspicious links found across all pages */
  suspiciousLinksFound: number;

  /** Average scan time in ms */
  avgScanTimeMs: number;
}

// ─── Manual Scanner Interface ──────────────────────────────────────────

export interface PhishGuardScanner {
  /** Scan a single URL. Pass a Playwright Page for full-mode analysis. */
  scan(url: string, page?: unknown): Promise<PhishGuardResult>;

  /** Scan a URL in fast mode (URL+Domain only, no LLM) */
  fastScan(url: string): Promise<PhishGuardResult>;

  /** Get scanner statistics */
  getStats(): ScannerStats;

  /** Clear the result cache */
  clearCache(): void;
}

// ─── Default Option Values ─────────────────────────────────────────────

export const DEFAULT_OPTIONS: Omit<ResolvedOptions, "groqApiKey"> = {
  mode: "full",
  scanPageLinks: true,
  maxLinksToScan: 50,
  linkScanConcurrency: 5,
  cacheMaxSize: 500,
  cacheTTLMs: 30 * 60 * 1000, // 30 minutes
  verbose: true,
};

export function resolveOptions(options: PhishGuardOptions): ResolvedOptions {
  return {
    ...DEFAULT_OPTIONS,
    ...options,
    mode: options.mode ?? DEFAULT_OPTIONS.mode,
    scanPageLinks: options.scanPageLinks ?? DEFAULT_OPTIONS.scanPageLinks,
    maxLinksToScan: options.maxLinksToScan ?? DEFAULT_OPTIONS.maxLinksToScan,
    linkScanConcurrency: options.linkScanConcurrency ?? DEFAULT_OPTIONS.linkScanConcurrency,
    cacheMaxSize: options.cacheMaxSize ?? DEFAULT_OPTIONS.cacheMaxSize,
    cacheTTLMs: options.cacheTTLMs ?? DEFAULT_OPTIONS.cacheTTLMs,
    verbose: options.verbose ?? DEFAULT_OPTIONS.verbose,
  };
}

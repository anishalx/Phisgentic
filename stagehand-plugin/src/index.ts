// PhishGuard Stagehand Plugin - Public API
//
// Two usage modes:
//
// 1. Auto-hook mode (recommended):
//    const guardedStagehand = withPhishGuard(stagehand, { groqApiKey: "..." });
//    // Now all navigation is automatically scanned
//
// 2. Manual scanner mode:
//    const scanner = createPhishGuardScanner({ groqApiKey: "..." });
//    const result = await scanner.scan("https://suspicious-site.com");

import type { PhishGuardOptions, PhishGuardScanner } from "./types.js";
import { PhishGuardPlugin } from "./plugin.js";

/**
 * Wrap a Stagehand instance with PhishGuard phishing detection.
 *
 * Returns the same Stagehand instance wrapped in a Proxy that
 * automatically scans URLs during navigation. The original instance
 * is not modified.
 *
 * Intercepted methods:
 * - `stagehand.page.goto(url)` — scans URL after navigation
 * - `stagehand.page.act(action)` — monitors for URL changes after action
 * - `stagehand.agent().execute(task)` — monitors for URL changes after task
 *
 * Detection behavior: Warn but continue (never blocks navigation).
 *
 * @example
 * ```typescript
 * import { Stagehand } from "@browserbasehq/stagehand";
 * import { withPhishGuard } from "phishguard-stagehand-plugin";
 *
 * const stagehand = new Stagehand({ env: "LOCAL" });
 * await stagehand.init();
 *
 * const guarded = withPhishGuard(stagehand, {
 *   groqApiKey: process.env.GROQ_API_KEY!,
 *   mode: "full",
 *   onPhishingDetected: (result) => {
 *     console.error(`Phishing detected: ${result.url}`);
 *   },
 * });
 *
 * // All navigation is now automatically scanned
 * await guarded.page.goto("https://example.com");
 * ```
 */
export function withPhishGuard<T extends Record<string, unknown>>(
  stagehand: T,
  options: PhishGuardOptions,
): T {
  const plugin = new PhishGuardPlugin(options);
  return plugin.wrap(stagehand);
}

/**
 * Create a standalone PhishGuard scanner for manual URL scanning.
 *
 * Use this when you want control over when and what to scan,
 * rather than automatic interception.
 *
 * @example
 * ```typescript
 * import { createPhishGuardScanner } from "phishguard-stagehand-plugin";
 *
 * const scanner = createPhishGuardScanner({
 *   groqApiKey: process.env.GROQ_API_KEY!,
 * });
 *
 * // Fast scan (URL + Domain only, ~200ms)
 * const fastResult = await scanner.fastScan("https://suspicious-site.com");
 *
 * // Full scan (all 5 agents, needs page)
 * const fullResult = await scanner.scan("https://suspicious-site.com");
 *
 * // Check stats
 * console.log(scanner.getStats());
 * ```
 */
export function createPhishGuardScanner(options: PhishGuardOptions): PhishGuardScanner {
  const plugin = new PhishGuardPlugin(options);

  return {
    scan: (url: string) => plugin.scan(url),
    fastScan: (url: string) => plugin.fastScan(url),
    getStats: () => plugin.getStats(),
    clearCache: () => plugin.clearCache(),
  };
}

// ─── Re-exports ────────────────────────────────────────────────────────

// Core types
export type {
  PhishGuardOptions,
  ResolvedOptions,
  PhishGuardResult,
  PhishGuardScanner,
  ScannerStats,
  SuspiciousLink,
  LinkScanReport,
  Signal,
  AgentResult,
  FinalVerdict,
} from "./types.js";

// Plugin internals (for advanced use)
export { PhishGuardPlugin } from "./plugin.js";
export { PhishGuardDetector } from "./detector.js";
export { PhishGuardCache } from "./cache.js";
export { PhishGuardLogger } from "./logger.js";
export { LinkScanner } from "./link-scanner.js";

// Agent classes (for custom pipelines)
export {
  PluginUrlAgent,
  PluginDomainAgent,
  PluginContentAgent,
  PluginHeuristicAgent,
  PluginTesterAgent,
} from "./agents/index.js";

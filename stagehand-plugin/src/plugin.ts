// PhishGuard Stagehand Plugin - Core Plugin with Proxy Pattern
// Wraps Stagehand instance to intercept navigation and run phishing detection.
// Intercepts: page.goto(), page.act(), agent.execute()
// Behavior: Warn but continue — never blocks navigation.

import type { PhishGuardOptions, PhishGuardResult, ResolvedOptions, ScannerStats } from "./types.js";
import { resolveOptions } from "./types.js";
import { PhishGuardDetector } from "./detector.js";
import { LinkScanner } from "./link-scanner.js";
import { PhishGuardCache } from "./cache.js";
import { PhishGuardLogger } from "./logger.js";

// We use Stagehand's types via imports at the type level only.
// At runtime, we operate on whatever object is passed in.
// This avoids requiring Stagehand as a hard dependency for compilation.

/** Stats tracking for scan history */
interface InternalStats {
  totalScans: number;
  blockedCount: number;
  warnedCount: number;
  allowedCount: number;
  suspiciousLinksFound: number;
  totalScanTimeMs: number;
}

/** Queued navigation for processing when current scan completes (C1 fix) */
interface PendingNavigation {
  url: string;
  page: Record<string, unknown>;
}

export class PhishGuardPlugin {
  private options: ResolvedOptions;
  private detector: PhishGuardDetector;
  private linkScanner: LinkScanner;
  private cache: PhishGuardCache;
  private logger: PhishGuardLogger;
  private stats: InternalStats;
  private scanning: boolean = false;
  private pendingNavigations: PendingNavigation[] = []; // C1: queue instead of dropping
  private wrappedPageCache: WeakMap<object, object> = new WeakMap(); // M3: cache wrapped pages

  constructor(options: PhishGuardOptions) {
    this.options = resolveOptions(options);
    this.detector = new PhishGuardDetector();
    this.linkScanner = new LinkScanner();
    this.cache = new PhishGuardCache(this.options.cacheMaxSize, this.options.cacheTTLMs);
    this.logger = new PhishGuardLogger(this.options.verbose);
    this.stats = {
      totalScans: 0,
      blockedCount: 0,
      warnedCount: 0,
      allowedCount: 0,
      suspiciousLinksFound: 0,
      totalScanTimeMs: 0,
    };
  }

  /**
   * Wrap a Stagehand instance with PhishGuard protection.
   * Returns a Proxy that intercepts navigation-related methods.
   *
   * Intercepted:
   * - stagehand.page.goto(url) — scans URL after navigation
   * - stagehand.page.act(action) — monitors URL changes after action
   * - stagehand.agent().execute(task) — monitors URL changes after agent task
   */
  wrap<T extends Record<string, unknown>>(stagehand: T): T {
    const plugin = this;

    return new Proxy(stagehand, {
      get(target: T, prop: string | symbol, receiver: unknown) {
        const value = Reflect.get(target, prop, receiver);

        // Intercept .page getter to wrap the page object
        if (prop === "page" && value && typeof value === "object") {
          return plugin.wrapPage(value as Record<string, unknown>);
        }

        // Intercept .agent() method to wrap the returned agent
        if (prop === "agent" && typeof value === "function") {
          return function (this: unknown, ...args: unknown[]) {
            const agentInstance = (value as Function).apply(target, args);
            return plugin.wrapAgent(agentInstance, target as Record<string, unknown>);
          };
        }

        return value;
      },
    });
  }

  /**
   * Wrap the Stagehand Page to intercept goto() and act().
   * M3 fix: Uses WeakMap cache to return the same Proxy for the same underlying page.
   */
  private wrapPage(page: Record<string, unknown>): Record<string, unknown> {
    // M3: Return cached wrapped page if available
    const cached = this.wrappedPageCache.get(page);
    if (cached) {
      return cached as Record<string, unknown>;
    }

    const plugin = this;

    const wrapped = new Proxy(page, {
      get(target: Record<string, unknown>, prop: string | symbol, receiver: unknown) {
        const value = Reflect.get(target, prop, receiver);

        // Intercept goto()
        if (prop === "goto" && typeof value === "function") {
          return async function (this: unknown, url: string, ...args: unknown[]) {
            // Navigate first (warn but continue)
            const result = await (value as Function).apply(target, [url, ...args]);

            // C2 fix: Scan the FINAL URL after redirects, not the requested URL
            const finalUrl = plugin.getPageUrl(target) || url;
            await plugin.handleNavigation(finalUrl, target);

            return result;
          };
        }

        // Intercept act()
        if (prop === "act" && typeof value === "function") {
          return async function (this: unknown, ...args: unknown[]) {
            // Capture URL before action
            const urlBefore = plugin.getPageUrl(target);

            // Execute the action
            const result = await (value as Function).apply(target, args);

            // Check if URL changed
            const urlAfter = plugin.getPageUrl(target);
            if (urlAfter && urlAfter !== urlBefore) {
              await plugin.handleNavigation(urlAfter, target);
            }

            return result;
          };
        }

        // Return bound functions to preserve context
        if (typeof value === "function") {
          return (value as Function).bind(target);
        }

        return value;
      },
    });

    // M3: Cache the wrapped page
    this.wrappedPageCache.set(page, wrapped);
    return wrapped;
  }

  /**
   * Wrap a Stagehand agent instance to intercept execute().
   */
  private wrapAgent(
    agentInstance: Record<string, unknown>,
    stagehand: Record<string, unknown>,
  ): Record<string, unknown> {
    const plugin = this;

    return new Proxy(agentInstance, {
      get(target: Record<string, unknown>, prop: string | symbol, receiver: unknown) {
        const value = Reflect.get(target, prop, receiver);

        // Intercept execute()
        if (prop === "execute" && typeof value === "function") {
          return async function (this: unknown, ...args: unknown[]) {
            // Capture URL before execution
            const pageBefore = stagehand.page as Record<string, unknown> | undefined;
            const urlBefore = pageBefore ? plugin.getPageUrl(pageBefore) : null;

            // Execute the agent task
            const result = await (value as Function).apply(target, args);

            // M2 fix: Re-read stagehand.page after execute() — agent may have opened new tabs
            const pageAfter = stagehand.page as Record<string, unknown> | undefined;
            if (pageAfter) {
              const urlAfter = plugin.getPageUrl(pageAfter);
              if (urlAfter && urlAfter !== urlBefore) {
                await plugin.handleNavigation(urlAfter, pageAfter);
              }
            }

            return result;
          };
        }

        if (typeof value === "function") {
          return (value as Function).bind(target);
        }

        return value;
      },
    });
  }

  /**
   * Handle a navigation event: scan the URL, log results, trigger callbacks.
   * C1 fix: Uses a queue to handle concurrent navigations instead of dropping them.
   */
  private async handleNavigation(url: string, page: Record<string, unknown>): Promise<void> {
    // Skip non-http URLs (about:blank, chrome://, etc.)
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // C1 fix: If a scan is in progress, queue this navigation instead of dropping it
    if (this.scanning) {
      // M1 fix: Log when scans are queued
      this.logger.warn(`Scan queued (another in progress): ${url}`);
      this.pendingNavigations.push({ url, page });
      return;
    }
    this.scanning = true;

    try {
      await this.executeScan(url, page);
    } finally {
      this.scanning = false;

      // C1 fix: Drain the pending queue
      await this.drainPendingNavigations();
    }
  }

  /**
   * C1 fix: Process any navigations that were queued while a scan was in progress.
   */
  private async drainPendingNavigations(): Promise<void> {
    while (this.pendingNavigations.length > 0) {
      const next = this.pendingNavigations.shift()!;

      // Skip non-http URLs
      if (!next.url.startsWith("http://") && !next.url.startsWith("https://")) continue;

      this.scanning = true;
      try {
        await this.executeScan(next.url, next.page);
      } finally {
        this.scanning = false;
      }
    }
  }

  /**
   * Execute the actual scan logic for a single URL.
   * Extracted from handleNavigation to support the queue pattern.
   */
  private async executeScan(url: string, page: Record<string, unknown>): Promise<void> {
    try {
      // Notify scan start
      this.options.onScanStart?.(url);
      this.logger.scanStart(url);

      // Check cache first
      const cached = this.cache.get(url);
      if (cached) {
        // M4 fix: Update stats for cached results too (with scanTimeMs: 0)
        this.updateStats({ ...cached, scanTimeMs: 0 });

        this.logger.scanResult(cached);
        this.options.onScanComplete?.(url, cached);

        if (cached.action !== "allow") {
          this.logger.phishingDetected(cached);
          this.options.onPhishingDetected?.(cached);
        }
        return;
      }

      // Run detection
      let result: PhishGuardResult;

      if (this.options.mode === "fast") {
        result = await this.detector.scanFast(url);
      } else {
        // Full mode: cast page to Playwright Page for agent use
        result = await this.detector.scanFull(url, page as unknown as import("playwright").Page);
      }

      // Cache the result
      this.cache.set(url, result);

      // Update stats
      this.updateStats(result);

      // Log result
      this.logger.scanResult(result);

      // Trigger callbacks
      this.options.onScanComplete?.(url, result);

      if (result.action !== "allow") {
        this.logger.phishingDetected(result);
        this.options.onPhishingDetected?.(result);
      }

      // Proactive link scanning (async, non-blocking)
      if (this.options.scanPageLinks) {
        this.scanLinksInBackground(page, url);
      }
    } catch (error) {
      this.logger.error("Scan failed", error);
    }
  }

  /**
   * Scan page links in the background (does not block navigation).
   */
  private scanLinksInBackground(page: Record<string, unknown>, pageUrl: string): void {
    // Fire and forget — don't block the main flow
    this.linkScanner
      .scanPageLinks(
        page as unknown as import("playwright").Page,
        pageUrl,
        this.options,
      )
      .then((report) => {
        if (report.suspiciousLinks.length > 0) {
          this.stats.suspiciousLinksFound += report.suspiciousLinks.length;
          this.logger.linkScanReport(report);
        }
        this.options.onLinksScanComplete?.(report);
      })
      .catch((error) => {
        this.logger.error("Link scan failed", error);
      });
  }

  /**
   * Get the current URL from a page object.
   */
  private getPageUrl(page: Record<string, unknown>): string | null {
    try {
      if (typeof page.url === "function") {
        return (page.url as () => string)();
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Update internal stats.
   */
  private updateStats(result: PhishGuardResult): void {
    this.stats.totalScans++;
    this.stats.totalScanTimeMs += result.scanTimeMs;

    switch (result.action) {
      case "allow":
        this.stats.allowedCount++;
        break;
      case "warn":
        this.stats.warnedCount++;
        break;
      case "block":
        this.stats.blockedCount++;
        break;
    }
  }

  /**
   * Get scanner statistics.
   */
  getStats(): ScannerStats {
    return {
      totalScans: this.stats.totalScans,
      blockedCount: this.stats.blockedCount,
      warnedCount: this.stats.warnedCount,
      allowedCount: this.stats.allowedCount,
      cacheHits: this.cache.totalHits,
      cacheSize: this.cache.size,
      suspiciousLinksFound: this.stats.suspiciousLinksFound,
      avgScanTimeMs: this.stats.totalScans > 0
        ? Math.round(this.stats.totalScanTimeMs / this.stats.totalScans)
        : 0,
    };
  }

  /**
   * Manually scan a URL (full or fast based on configured mode).
   * C3 fix: Accepts optional page parameter for full-mode scanning.
   */
  async scan(url: string, page?: unknown): Promise<PhishGuardResult> {
    // Check cache
    const cached = this.cache.get(url);
    if (cached) {
      // M4 fix: Update stats for cached results
      this.updateStats({ ...cached, scanTimeMs: 0 });
      return cached;
    }

    let result: PhishGuardResult;

    if (this.options.mode === "fast" || !page) {
      // C3 fix: Log warning when user configured full mode but no page provided
      if (this.options.mode === "full" && !page) {
        this.logger.warn("Full mode requested but no page provided — falling back to fast mode");
      }
      result = await this.detector.scanFast(url);
    } else {
      result = await this.detector.scanFull(url, page as import("playwright").Page);
    }

    this.cache.set(url, result);
    this.updateStats(result);
    return result;
  }

  /**
   * Manually fast-scan a URL (URL+Domain only, no page needed).
   */
  async fastScan(url: string): Promise<PhishGuardResult> {
    const cached = this.cache.get(url);
    if (cached) {
      // M4 fix: Update stats for cached results
      this.updateStats({ ...cached, scanTimeMs: 0 });
      return cached;
    }

    const result = await this.detector.scanFast(url);
    this.cache.set(url, result);
    this.updateStats(result);
    return result;
  }

  /**
   * Clear the result cache.
   */
  clearCache(): void {
    this.cache.clear();
  }
}

// PhishGuard Stagehand Plugin - Proactive Link Scanner
// After each navigation, extracts all <a> links from the page,
// filters to external links, and fast-scans them in parallel.

import type { Page } from "playwright";
import type { LinkScanReport, SuspiciousLink, ResolvedOptions } from "./types.js";
import { PluginUrlAgent, PluginDomainAgent } from "./agents/index.js";
import { SAFE_DOMAINS, THRESHOLDS } from "./agents/config.js";

interface ExtractedLink {
  href: string;
  text: string;
}

export class LinkScanner {
  private urlAgent: PluginUrlAgent;
  private domainAgent: PluginDomainAgent;

  constructor() {
    this.urlAgent = new PluginUrlAgent();
    this.domainAgent = new PluginDomainAgent();
  }

  /**
   * Scan all links on the current page for phishing indicators.
   * Extracts <a href> links, deduplicates, filters out same-domain and safe domains,
   * then fast-scans external links using URL + Domain agents with concurrency control.
   */
  async scanPageLinks(
    page: Page,
    pageUrl: string,
    options: ResolvedOptions,
  ): Promise<LinkScanReport> {
    const startTime = Date.now();

    // Extract all links from page
    let extractedLinks: ExtractedLink[] = [];
    try {
      extractedLinks = await page.evaluate(() => {
        const anchors = document.querySelectorAll("a[href]");
        const links: { href: string; text: string }[] = [];
        anchors.forEach((a) => {
          const anchor = a as HTMLAnchorElement;
          const href = anchor.href;
          if (href && href.startsWith("http")) {
            links.push({
              href,
              text: (anchor.textContent?.trim() || "").substring(0, 100),
            });
          }
        });
        return links;
      });
    } catch {
      // Page evaluation failed
      return {
        pageUrl,
        totalLinks: 0,
        scannedLinks: 0,
        suspiciousLinks: [],
        scanTimeMs: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }

    const totalLinks = extractedLinks.length;

    // Deduplicate by URL
    const seen = new Set<string>();
    const uniqueLinks: ExtractedLink[] = [];
    for (const link of extractedLinks) {
      const normalized = this.normalizeUrl(link.href);
      if (!seen.has(normalized)) {
        seen.add(normalized);
        uniqueLinks.push(link);
      }
    }

    // Filter: remove same-domain links and known safe domains
    let pageHostname: string;
    try {
      pageHostname = new URL(pageUrl).hostname.toLowerCase();
    } catch {
      pageHostname = "";
    }

    const externalLinks = uniqueLinks.filter((link) => {
      try {
        const linkHostname = new URL(link.href).hostname.toLowerCase();

        // Skip same-domain links
        if (linkHostname === pageHostname) return false;
        if (linkHostname.endsWith(`.${pageHostname}`)) return false;
        if (pageHostname.endsWith(`.${linkHostname}`)) return false;

        // Skip known safe domains
        const isSafe = SAFE_DOMAINS.some(
          (safe: string) => linkHostname === safe || linkHostname.endsWith(`.${safe}`),
        );
        if (isSafe) return false;

        return true;
      } catch {
        return false;
      }
    });

    // Limit number of links to scan
    const linksToScan = externalLinks.slice(0, options.maxLinksToScan);

    // Fast-scan with concurrency control
    const suspiciousLinks = await this.scanLinksWithConcurrency(
      linksToScan,
      options.linkScanConcurrency,
    );

    return {
      pageUrl,
      totalLinks,
      scannedLinks: linksToScan.length,
      suspiciousLinks,
      scanTimeMs: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  /**
   * Scan links in parallel with a concurrency limit.
   */
  private async scanLinksWithConcurrency(
    links: ExtractedLink[],
    concurrency: number,
  ): Promise<SuspiciousLink[]> {
    // C5 fix: Guard against concurrency <= 0 which would cause infinite loop
    const effectiveConcurrency = Math.max(1, concurrency);
    const suspicious: SuspiciousLink[] = [];
    const queue = [...links];
    const inFlight: Promise<void>[] = [];

    const processLink = async (link: ExtractedLink): Promise<void> => {
      try {
        const result = await this.fastScanLink(link);
        if (result) {
          suspicious.push(result);
        }
      } catch {
        // Skip failed scans
      }
    };

    while (queue.length > 0 || inFlight.length > 0) {
      // Fill up to concurrency limit
      while (queue.length > 0 && inFlight.length < effectiveConcurrency) {
        const link = queue.shift()!;
        const promise = processLink(link).then(() => {
          const index = inFlight.indexOf(promise);
          if (index !== -1) inFlight.splice(index, 1);
        });
        inFlight.push(promise);
      }

      // Wait for at least one to complete
      if (inFlight.length > 0) {
        await Promise.race(inFlight);
      }
    }

    return suspicious;
  }

  /**
   * Fast-scan a single link using URL + Domain agents.
   * Returns SuspiciousLink if risk score > 25, null otherwise.
   */
  private async fastScanLink(link: ExtractedLink): Promise<SuspiciousLink | null> {
    const [urlResult, domainResult] = await Promise.all([
      this.urlAgent.analyze(link.href),
      this.domainAgent.analyze(link.href),
    ]);

    // Weighted score: URL 40%, Domain 60%
    const riskScore = Math.round(
      urlResult.riskScore * 0.4 + domainResult.riskScore * 0.6,
    );

    // M14 fix: Use config threshold instead of hardcoded value
    if (riskScore <= THRESHOLDS.ALLOW_MAX) return null;

    const allSignals = [...urlResult.signals, ...domainResult.signals];
    const criticalSignals = allSignals.filter(
      (s) => s.severity === "critical" || s.severity === "high",
    );

    const reason = criticalSignals.length > 0
      ? criticalSignals.map((s) => s.description).join("; ")
      : `Risk score: ${riskScore}/100`;

    return {
      url: link.href,
      text: link.text,
      riskScore,
      reason,
      signals: allSignals,
    };
  }

  /**
   * Normalize URL for deduplication.
   */
  private normalizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      let normalized = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}`;
      if (normalized.endsWith("/") && parsed.pathname !== "/") {
        normalized = normalized.slice(0, -1);
      }
      return normalized;
    } catch {
      return url.toLowerCase();
    }
  }
}

// LRU Cache with TTL for scan result caching
// Avoids repeated scans of the same URL and saves API credits

import type { FinalVerdict, AgentLog } from "../types/index.js";

interface CacheEntry {
  verdict: FinalVerdict;
  logs: AgentLog[];
  createdAt: number;
}

export class ScanCache {
  private cache: Map<string, CacheEntry>;
  private maxSize: number;
  private ttlMs: number;

  constructor(maxSize = 500, ttlMs = 30 * 60 * 1000) {
    // Default: 500 entries, 30 minute TTL
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  /**
   * Normalize URL for cache key (strip trailing slash, lowercase host)
   */
  private normalizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      // Lowercase host, keep path case, remove trailing slash
      const normalized = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname.replace(/\/$/, "")}${parsed.search}${parsed.hash}`;
      return normalized;
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Get cached result for a URL (returns null if not found or expired)
   */
  get(url: string): { verdict: FinalVerdict; logs: AgentLog[] } | null {
    const key = this.normalizeUrl(url);
    const entry = this.cache.get(key);

    if (!entry) return null;

    // Check TTL
    if (Date.now() - entry.createdAt > this.ttlMs) {
      this.cache.delete(key);
      return null;
    }

    // Move to end (most recently accessed) for LRU ordering
    this.cache.delete(key);
    this.cache.set(key, entry);

    return { verdict: entry.verdict, logs: entry.logs };
  }

  /**
   * Store a scan result in cache
   */
  set(url: string, verdict: FinalVerdict, logs: AgentLog[]): void {
    const key = this.normalizeUrl(url);

    // Evict oldest entry if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      verdict,
      logs,
      createdAt: Date.now(),
    });
  }

  /**
   * Check if URL is cached (and not expired)
   */
  has(url: string): boolean {
    return this.get(url) !== null;
  }

  /**
   * Clear all cached entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  stats(): { size: number; maxSize: number; ttlMs: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      ttlMs: this.ttlMs,
    };
  }
}

// Singleton cache instance
let cacheInstance: ScanCache | null = null;

export function getScanCache(): ScanCache {
  if (!cacheInstance) {
    cacheInstance = new ScanCache();
  }
  return cacheInstance;
}

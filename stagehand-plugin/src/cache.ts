// PhishGuard Stagehand Plugin - LRU Cache with TTL

import type { PhishGuardResult } from "./types.js";

interface CacheEntry {
  result: PhishGuardResult;
  timestamp: number;
  expiresAt: number;
}

export class PhishGuardCache {
  private cache: Map<string, CacheEntry>;
  private maxSize: number;
  private ttlMs: number;
  private hits: number = 0;

  constructor(maxSize: number = 500, ttlMs: number = 30 * 60 * 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  /** Normalize URL to use as cache key */
  private normalizeKey(url: string): string {
    try {
      const parsed = new URL(url);
      // Normalize: lowercase host, remove trailing slash, remove fragment
      let normalized = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}`;
      if (normalized.endsWith("/") && parsed.pathname !== "/") {
        normalized = normalized.slice(0, -1);
      }
      // Include search params (sorted for consistency)
      if (parsed.search) {
        const params = new URLSearchParams(parsed.search);
        params.sort();
        normalized += `?${params.toString()}`;
      }
      return normalized;
    } catch {
      return url.toLowerCase();
    }
  }

  /** Get a cached result (returns null if expired or not found) */
  get(url: string): PhishGuardResult | null {
    const key = this.normalizeKey(url);
    const entry = this.cache.get(key);

    if (!entry) return null;

    // Check TTL
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Move to end (most recently used) by re-inserting
    this.cache.delete(key);
    this.cache.set(key, entry);

    this.hits++;

    // Mark as cached when returning
    return {
      ...entry.result,
      fromCache: true,
    };
  }

  /** Set a result in cache */
  set(url: string, result: PhishGuardResult): void {
    const key = this.normalizeKey(url);

    // If key already exists, delete to refresh position
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    // Evict oldest entries if at capacity
    while (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      result: { ...result, fromCache: false },
      timestamp: Date.now(),
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /** Check if URL is in cache (not expired) — without side effects */
  has(url: string): boolean {
    const key = this.normalizeKey(url);
    const entry = this.cache.get(key);
    if (!entry) return false;
    // Check TTL without reordering LRU or incrementing hits
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  /** Clear all cache entries */
  clear(): void {
    this.cache.clear();
    this.hits = 0;
  }

  /** Get cache statistics */
  get size(): number {
    return this.cache.size;
  }

  get totalHits(): number {
    return this.hits;
  }

  /** Remove expired entries (housekeeping) */
  prune(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [key, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
}

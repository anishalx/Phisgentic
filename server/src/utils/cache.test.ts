// Tests for LRU Cache with TTL

import { describe, it, expect, beforeEach } from "vitest";
import { ScanCache } from "./cache.js";

function createMockVerdict(url: string, score: number = 10) {
  return {
    action: "allow" as const,
    overallRiskScore: score,
    confidence: 0.9,
    agentResults: [],
    summary: "Test",
    url,
    timestamp: Date.now(),
  };
}

describe("ScanCache", () => {
  let cache: ScanCache;

  beforeEach(() => {
    cache = new ScanCache(5, 60_000); // 5 entries, 60s TTL
  });

  describe("get/set", () => {
    it("stores and retrieves entries", () => {
      const verdict = createMockVerdict("https://example.com");
      cache.set("https://example.com", verdict, []);

      const result = cache.get("https://example.com");
      expect(result).not.toBeNull();
      expect(result!.verdict.url).toBe("https://example.com");
    });

    it("returns null for missing entries", () => {
      expect(cache.get("https://missing.com")).toBeNull();
    });

    it("normalizes URLs for cache keys", () => {
      const verdict = createMockVerdict("https://Example.COM/page");
      cache.set("https://Example.COM/page", verdict, []);

      // Same URL with different case should hit cache
      const result = cache.get("https://example.com/page");
      expect(result).not.toBeNull();
    });

    it("strips trailing slashes for normalization", () => {
      const verdict = createMockVerdict("https://example.com/path");
      cache.set("https://example.com/path/", verdict, []);

      const result = cache.get("https://example.com/path");
      expect(result).not.toBeNull();
    });
  });

  describe("LRU eviction", () => {
    it("evicts oldest entry when at capacity", () => {
      // Fill cache to capacity
      for (let i = 0; i < 5; i++) {
        cache.set(`https://site${i}.com`, createMockVerdict(`https://site${i}.com`), []);
      }

      // Adding one more should evict the oldest
      cache.set("https://new.com", createMockVerdict("https://new.com"), []);

      expect(cache.get("https://site0.com")).toBeNull(); // Evicted
      expect(cache.get("https://site1.com")).not.toBeNull(); // Still there
      expect(cache.get("https://new.com")).not.toBeNull();
    });

    it("refreshes access order on get", () => {
      for (let i = 0; i < 5; i++) {
        cache.set(`https://site${i}.com`, createMockVerdict(`https://site${i}.com`), []);
      }

      // Access site0 to refresh it
      cache.get("https://site0.com");

      // Adding new entry should evict site1 (now oldest)
      cache.set("https://new.com", createMockVerdict("https://new.com"), []);

      expect(cache.get("https://site0.com")).not.toBeNull(); // Refreshed, still there
      expect(cache.get("https://site1.com")).toBeNull(); // Evicted
    });
  });

  describe("TTL expiration", () => {
    it("expires entries after TTL", () => {
      const shortTtlCache = new ScanCache(5, 1); // 1ms TTL
      shortTtlCache.set("https://example.com", createMockVerdict("https://example.com"), []);

      // Wait for TTL to expire
      return new Promise((resolve) => setTimeout(resolve, 10));

      const result = shortTtlCache.get("https://example.com");
      expect(result).toBeNull();
    });
  });

  describe("has", () => {
    it("returns true for cached entries", () => {
      cache.set("https://example.com", createMockVerdict("https://example.com"), []);
      expect(cache.has("https://example.com")).toBe(true);
    });

    it("returns false for missing entries", () => {
      expect(cache.has("https://missing.com")).toBe(false);
    });
  });

  describe("clear", () => {
    it("removes all entries", () => {
      cache.set("https://a.com", createMockVerdict("https://a.com"), []);
      cache.set("https://b.com", createMockVerdict("https://b.com"), []);

      cache.clear();

      expect(cache.get("https://a.com")).toBeNull();
      expect(cache.get("https://b.com")).toBeNull();
    });
  });

  describe("stats", () => {
    it("reports correct statistics", () => {
      cache.set("https://a.com", createMockVerdict("https://a.com"), []);
      cache.set("https://b.com", createMockVerdict("https://b.com"), []);

      const stats = cache.stats();
      expect(stats.size).toBe(2);
      expect(stats.maxSize).toBe(5);
    });
  });
});

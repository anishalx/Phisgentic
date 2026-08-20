// Tests for Token Bucket Rate Limiter

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { RateLimiter } from "./rate-limiter.js";

describe("RateLimiter", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter(3, 1000); // 3 tokens per second
  });

  afterEach(() => {
    limiter.destroy();
  });

  describe("acquire", () => {
    it("acquires tokens immediately when available", async () => {
      await limiter.acquire(1000);
      const status = limiter.status();
      expect(status.availableTokens).toBe(2);
    });

    it("acquires multiple tokens sequentially", async () => {
      await limiter.acquire(1000);
      await limiter.acquire(1000);
      await limiter.acquire(1000);

      const status = limiter.status();
      expect(status.availableTokens).toBe(0);
    });

    it("queues when no tokens available", async () => {
      // Exhaust tokens
      await limiter.acquire(1000);
      await limiter.acquire(1000);
      await limiter.acquire(1000);

      // This should queue and wait
      const acquirePromise = limiter.acquire(2000);

      const status = limiter.status();
      expect(status.queueLength).toBe(1);

      // Wait for token to be available
      await acquirePromise;
    });
  });

  describe("status", () => {
    it("reports correct token count", async () => {
      const status = limiter.status();
      expect(status.availableTokens).toBe(3);
      expect(status.maxTokens).toBe(3);
      expect(status.queueLength).toBe(0);
    });

    it("decrements tokens on acquire", async () => {
      await limiter.acquire(1000);
      const status = limiter.status();
      expect(status.availableTokens).toBe(2);
    });
  });

  describe("refill", () => {
    it("refills tokens over time", async () => {
      // Exhaust all tokens
      await limiter.acquire(1000);
      await limiter.acquire(1000);
      await limiter.acquire(1000);

      // Wait for refill
      await new Promise((resolve) => setTimeout(resolve, 500));

      const status = limiter.status();
      expect(status.availableTokens).toBeGreaterThanOrEqual(1);
    });
  });

  describe("destroy", () => {
    it("rejects queued requests on destroy", async () => {
      // Exhaust tokens
      await limiter.acquire(1000);
      await limiter.acquire(1000);
      await limiter.acquire(1000);

      // Queue a request
      const promise = limiter.acquire(5000);

      // Destroy should reject it
      limiter.destroy();

      await expect(promise).rejects.toThrow("Rate limiter destroyed");
    });
  });
});

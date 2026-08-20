// Tests for Retry utility

import { describe, it, expect, vi } from "vitest";
import { withRetry, isRetryableError } from "./retry.js";

describe("withRetry", () => {
  it("succeeds on first attempt without retrying", async () => {
    const fn = vi.fn().mockResolvedValue("success");
    const result = await withRetry(fn, { maxRetries: 3, baseDelayMs: 10 });

    expect(result).toBe("success");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on failure and eventually succeeds", async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error("fail1"))
      .mockRejectedValueOnce(new Error("fail2"))
      .mockResolvedValue("success");

    const result = await withRetry(fn, { maxRetries: 3, baseDelayMs: 10 });

    expect(result).toBe("success");
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("throws after exhausting all retries", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("always fails"));

    await expect(
      withRetry(fn, { maxRetries: 2, baseDelayMs: 10 })
    ).rejects.toThrow("always fails");

    expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it("respects maxRetries = 0 (no retries)", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("fail"));

    await expect(
      withRetry(fn, { maxRetries: 0 })
    ).rejects.toThrow("fail");

    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe("isRetryableError", () => {
  it("identifies retryable network errors", () => {
    expect(isRetryableError(new Error("ECONNRESET"))).toBe(true);
    expect(isRetryableError(new Error("ETIMEDOUT"))).toBe(true);
    expect(isRetryableError(new Error("fetch failed"))).toBe(true);
  });

  it("identifies retryable rate limit errors", () => {
    expect(isRetryableError(new Error("429 Too Many Requests"))).toBe(true);
    expect(isRetryableError(new Error("rate limit exceeded"))).toBe(true);
  });

  it("identifies retryable server errors", () => {
    expect(isRetryableError(new Error("500 Internal Server Error"))).toBe(true);
    expect(isRetryableError(new Error("502 Bad Gateway"))).toBe(true);
    expect(isRetryableError(new Error("503 Service Unavailable"))).toBe(true);
  });

  it("identifies retryable timeout errors", () => {
    expect(isRetryableError(new Error("request timed out"))).toBe(true);
    expect(isRetryableError(new Error("timeout"))).toBe(true);
  });

  it("identifies non-retryable client errors", () => {
    expect(isRetryableError(new Error("400 Bad Request"))).toBe(false);
    expect(isRetryableError(new Error("401 Unauthorized"))).toBe(false);
    expect(isRetryableError(new Error("403 Forbidden"))).toBe(false);
  });

  it("returns false for unknown errors by default", () => {
    expect(isRetryableError(new Error("something weird"))).toBe(false);
  });
});

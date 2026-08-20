// Tests for Request Deduplication

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RequestDeduplicator } from "./dedup.js";

describe("RequestDeduplicator", () => {
  let dedup: RequestDeduplicator;

  beforeEach(() => {
    dedup = new RequestDeduplicator();
  });

  afterEach(() => {
    dedup.destroy();
  });

  it("executes function on first call", async () => {
    const fn = vi.fn().mockResolvedValue("result");
    const result = await dedup.dedup("key1", fn);

    expect(result).toBe("result");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("deduplicates concurrent requests for same key", async () => {
    const fn = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve("result"), 50))
    );

    // Launch two concurrent requests with same key
    const [result1, result2] = await Promise.all([
      dedup.dedup("key1", fn),
      dedup.dedup("key1", fn),
    ]);

    expect(result1).toBe("result");
    expect(result2).toBe("result");
    expect(fn).toHaveBeenCalledTimes(1); // Only executed once
  });

  it("allows different keys to execute independently", async () => {
    const fn1 = vi.fn().mockResolvedValue("result1");
    const fn2 = vi.fn().mockResolvedValue("result2");

    const [result1, result2] = await Promise.all([
      dedup.dedup("key1", fn1),
      dedup.dedup("key2", fn2),
    ]);

    expect(result1).toBe("result1");
    expect(result2).toBe("result2");
    expect(fn1).toHaveBeenCalledTimes(1);
    expect(fn2).toHaveBeenCalledTimes(1);
  });

  it("propagates errors to all waiters", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("fail"));

    const [result1, result2] = await Promise.allSettled([
      dedup.dedup("key1", fn),
      dedup.dedup("key1", fn),
    ]);

    expect(result1.status).toBe("rejected");
    expect(result2.status).toBe("rejected");
  });

  it("cleans up after completion", async () => {
    await dedup.dedup("key1", () => Promise.resolve("ok"));

    expect(dedup.has("key1")).toBe(false);
    expect(dedup.size).toBe(0);
  });

  it("tracks pending requests", async () => {
    const fn = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve("ok"), 50))
    );

    const promise = dedup.dedup("key1", fn);

    expect(dedup.has("key1")).toBe(true);
    expect(dedup.size).toBe(1);

    await promise;

    expect(dedup.has("key1")).toBe(false);
    expect(dedup.size).toBe(0);
  });

  it("allows same key after previous request completes", async () => {
    const fn = vi.fn()
      .mockResolvedValueOnce("first")
      .mockResolvedValueOnce("second");

    const result1 = await dedup.dedup("key1", fn);
    expect(result1).toBe("first");

    const result2 = await dedup.dedup("key1", fn);
    expect(result2).toBe("second");

    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("destroy cleans up state", async () => {
    const fn = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve("ok"), 5000))
    );

    // Suppress unhandled rejections from destroy
    const p1 = dedup.dedup("key1", fn).catch(() => {});
    const p2 = dedup.dedup("key2", fn).catch(() => {});

    expect(dedup.size).toBe(2);

    dedup.destroy();

    expect(dedup.size).toBe(0);
    await Promise.all([p1, p2]);
  });
});

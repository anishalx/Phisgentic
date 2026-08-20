// Tests for Circuit Breaker

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { CircuitBreaker } from "./circuit-breaker.js";

describe("CircuitBreaker", () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    breaker = new CircuitBreaker("test", {
      failureThreshold: 3,
      resetTimeoutMs: 100,
      successThreshold: 2,
    });
  });

  it("starts in closed state", () => {
    expect(breaker.getState()).toBe("closed");
  });

  it("opens after consecutive failures exceed threshold", async () => {
    const failingFn = () => Promise.reject(new Error("fail"));

    await breaker.execute(failingFn).catch(() => {});
    await breaker.execute(failingFn).catch(() => {});
    await breaker.execute(failingFn).catch(() => {});

    expect(breaker.getState()).toBe("open");
  });

  it("rejects calls when circuit is open", async () => {
    // Open the circuit
    for (let i = 0; i < 3; i++) {
      await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }

    await expect(
      breaker.execute(() => Promise.resolve("ok"))
    ).rejects.toThrow("Circuit is OPEN");
  });

  it("transitions to half-open after reset timeout", async () => {
    // Open the circuit
    for (let i = 0; i < 3; i++) {
      await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }

    expect(breaker.getState()).toBe("open");

    // Wait for reset timeout
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(breaker.getState()).toBe("half-open");
  });

  it("closes circuit after successful half-open calls", async () => {
    // Open the circuit
    for (let i = 0; i < 3; i++) {
      await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }

    // Wait for half-open
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Succeed twice (successThreshold = 2)
    await breaker.execute(() => Promise.resolve("ok"));
    await breaker.execute(() => Promise.resolve("ok"));

    expect(breaker.getState()).toBe("closed");
  });

  it("reopens circuit if half-open call fails", async () => {
    // Open the circuit
    for (let i = 0; i < 3; i++) {
      await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }

    // Wait for half-open
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Fail once
    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    expect(breaker.getState()).toBe("open");
  });

  it("resets failure count on success", async () => {
    // Two failures (below threshold)
    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    // Success resets count
    await breaker.execute(() => Promise.resolve("ok"));

    // Two more failures should NOT open circuit (count was reset)
    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    expect(breaker.getState()).toBe("closed");
  });

  it("manually resets circuit", async () => {
    for (let i = 0; i < 3; i++) {
      await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});
    }

    expect(breaker.getState()).toBe("open");

    breaker.reset();
    expect(breaker.getState()).toBe("closed");
  });

  it("reports stats correctly", async () => {
    const stats = breaker.stats();
    expect(stats.state).toBe("closed");
    expect(stats.failureCount).toBe(0);

    await breaker.execute(() => Promise.reject(new Error("fail"))).catch(() => {});

    const statsAfter = breaker.stats();
    expect(statsAfter.failureCount).toBe(1);
  });
});

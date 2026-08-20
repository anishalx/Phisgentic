// Circuit Breaker pattern for LLM API calls
// Prevents cascading failures when an API is consistently failing

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerOptions {
  /** Number of consecutive failures before opening the circuit */
  failureThreshold: number;
  /** Time in ms to wait before trying again (half-open) */
  resetTimeoutMs: number;
  /** Number of successful calls in half-open state before closing */
  successThreshold: number;
}

const DEFAULT_OPTIONS: CircuitBreakerOptions = {
  failureThreshold: 5,
  resetTimeoutMs: 30_000, // 30 seconds
  successThreshold: 2,
};

export class CircuitBreaker {
  private state: CircuitState = "closed";
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private options: CircuitBreakerOptions;
  private name: string;

  constructor(name: string, options?: Partial<CircuitBreakerOptions>) {
    this.name = name;
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  getState(): CircuitState {
    if (this.state === "open") {
      // Check if reset timeout has elapsed
      if (Date.now() - this.lastFailureTime >= this.options.resetTimeoutMs) {
        this.state = "half-open";
        this.successCount = 0;
        console.log(`[CircuitBreaker:${this.name}] Transitioning to HALF-OPEN`);
      }
    }
    return this.state;
  }

  /**
   * Execute a function with circuit breaker protection.
   * If circuit is open, throws immediately without calling the function.
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const state = this.getState();

    if (state === "open") {
      throw new Error(
        `[CircuitBreaker:${this.name}] Circuit is OPEN — ${this.failureCount} consecutive failures. ` +
        `Will retry after ${this.options.resetTimeoutMs}ms`
      );
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;

    if (this.state === "half-open") {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold) {
        this.state = "closed";
        console.log(`[CircuitBreaker:${this.name}] Circuit CLOSED — API recovered`);
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === "half-open") {
      // Failed during half-open — reopen the circuit
      this.state = "open";
      console.log(
        `[CircuitBreaker:${this.name}] Circuit REOPENED — failed during half-open`
      );
    } else if (this.failureCount >= this.options.failureThreshold) {
      this.state = "open";
      console.log(
        `[CircuitBreaker:${this.name}] Circuit OPEN — ${this.failureCount} consecutive failures`
      );
    }
  }

  /** Reset circuit to closed state (for manual recovery) */
  reset(): void {
    this.state = "closed";
    this.failureCount = 0;
    this.successCount = 0;
    console.log(`[CircuitBreaker:${this.name}] Circuit manually RESET`);
  }

  /** Get current stats for monitoring */
  stats(): {
    state: CircuitState;
    failureCount: number;
    successCount: number;
    lastFailureTime: number;
  } {
    return {
      state: this.getState(),
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime,
    };
  }
}

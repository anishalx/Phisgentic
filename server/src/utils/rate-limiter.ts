// Token Bucket Rate Limiter for LLM API calls
// Prevents hitting Groq free tier limits (30 RPM)

export class RateLimiter {
  private tokens: number;
  private maxTokens: number;
  private refillRate: number; // tokens per second
  private lastRefill: number;
  private queue: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  private drainTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * @param maxRequests Maximum requests allowed in the window
   * @param windowMs Time window in milliseconds
   */
  constructor(maxRequests = 30, windowMs = 60_000) {
    this.maxTokens = maxRequests;
    this.tokens = maxRequests;
    this.refillRate = maxRequests / (windowMs / 1000); // tokens per second
    this.lastRefill = Date.now();
  }

  /**
   * Refill tokens based on elapsed time
   */
  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000; // seconds
    const newTokens = elapsed * this.refillRate;
    this.tokens = Math.min(this.maxTokens, this.tokens + newTokens);
    this.lastRefill = now;
  }

  /**
   * Acquire a token. Resolves immediately if available, or waits in queue.
   * Rejects after waitTimeoutMs if token not available.
   */
  async acquire(waitTimeoutMs = 10_000): Promise<void> {
    this.refill();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }

    // Queue the request and wait for a token
    return new Promise<void>((resolve, reject) => {
      const entry = { resolve, reject };
      this.queue.push(entry);

      // Timeout: reject if waiting too long
      const timeout = setTimeout(() => {
        const idx = this.queue.indexOf(entry);
        if (idx !== -1) {
          this.queue.splice(idx, 1);
          reject(new Error(`Rate limiter: timed out after ${waitTimeoutMs}ms waiting for token`));
        }
      }, waitTimeoutMs);

      // Attach cleanup
      const originalResolve = entry.resolve;
      entry.resolve = () => {
        clearTimeout(timeout);
        originalResolve();
      };

      // Start drain timer if not running
      this.scheduleDrain();
    });
  }

  /**
   * Schedule periodic drain of queued requests
   */
  private scheduleDrain(): void {
    if (this.drainTimer) return;

    this.drainTimer = setTimeout(() => {
      this.drainTimer = null;
      this.refill();

      while (this.queue.length > 0 && this.tokens >= 1) {
        this.tokens -= 1;
        const entry = this.queue.shift()!;
        entry.resolve();
      }

      // Continue draining if queue not empty
      if (this.queue.length > 0) {
        this.scheduleDrain();
      }
    }, 1000 / this.refillRate); // Check every token-refill interval
  }

  /**
   * Get current status
   */
  status(): { availableTokens: number; queueLength: number; maxTokens: number } {
    this.refill();
    return {
      availableTokens: Math.floor(this.tokens),
      queueLength: this.queue.length,
      maxTokens: this.maxTokens,
    };
  }

  /**
   * Cleanup timers
   */
  destroy(): void {
    if (this.drainTimer) {
      clearTimeout(this.drainTimer);
      this.drainTimer = null;
    }
    // Reject all queued requests
    for (const entry of this.queue) {
      entry.reject(new Error("Rate limiter destroyed"));
    }
    this.queue = [];
  }
}

// Singleton rate limiters for each LLM provider
let groqLimiter: RateLimiter | null = null;
let geminiLimiter: RateLimiter | null = null;

export function getGroqRateLimiter(): RateLimiter {
  if (!groqLimiter) {
    // Groq free tier: 30 requests per minute
    groqLimiter = new RateLimiter(28, 60_000); // 28 to leave headroom
  }
  return groqLimiter;
}

export function getGeminiRateLimiter(): RateLimiter {
  if (!geminiLimiter) {
    // Gemini free tier: 15 requests per minute
    geminiLimiter = new RateLimiter(14, 60_000); // 14 to leave headroom
  }
  return geminiLimiter;
}

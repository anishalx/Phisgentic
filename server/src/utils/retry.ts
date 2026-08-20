// Retry utility with exponential backoff and jitter

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitterFactor: number; // 0-1, amount of random jitter
}

const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 10_000,
  jitterFactor: 0.3,
};

/**
 * Execute a function with retry logic and exponential backoff.
 * Useful for transient LLM API failures (rate limits, network errors).
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: Partial<RetryOptions>,
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry on the last attempt
      if (attempt === opts.maxRetries) break;

      // Calculate delay with exponential backoff + jitter
      const exponentialDelay = Math.min(
        opts.baseDelayMs * Math.pow(2, attempt),
        opts.maxDelayMs,
      );
      const jitter = exponentialDelay * opts.jitterFactor * Math.random();
      const delay = Math.round(exponentialDelay + jitter);

      console.log(
        `[Retry] Attempt ${attempt + 1}/${opts.maxRetries} failed: ${lastError.message}. ` +
        `Retrying in ${delay}ms...`
      );

      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}

/**
 * Check if an error is retryable (transient failures).
 * Non-retryable errors: 4xx client errors (except 429), auth errors, etc.
 */
export function isRetryableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);

  // Network errors — always retry
  if (message.includes("ECONNRESET") || message.includes("ETIMEDOUT")) return true;
  if (message.includes("fetch failed") || message.includes("network")) return true;

  // Rate limiting (429) — retryable
  if (message.includes("429") || message.includes("rate limit")) return true;

  // Server errors (5xx) — retryable
  if (message.includes("500") || message.includes("502") || message.includes("503")) return true;

  // Timeout — retryable
  if (message.includes("timeout") || message.includes("timed out")) return true;

  // 400/401/403/404 — NOT retryable (client errors)
  if (message.includes("400") || message.includes("401") || message.includes("403")) return false;

  return false; // Default: don't retry unknown errors
}

// Request Deduplication
// Prevents multiple concurrent requests for the same URL from triggering duplicate LLM calls

interface PendingRequest<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
  timestamp: number;
}

const STALE_TIMEOUT_MS = 120_000; // 2 minutes

export class RequestDeduplicator {
  private pending = new Map<string, PendingRequest<unknown>>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Cleanup stale entries every 30 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 30_000);
  }

  /**
   * Deduplicate a request. If a request for the same key is already in-flight,
   * returns the same promise. Otherwise, executes the function and stores the result.
   *
   * @param key - Deduplication key (e.g., normalized URL)
   * @param fn - The async function to execute if not deduplicated
   */
  async dedup<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.pending.get(key);

    if (existing) {
      // Another request for this key is already in-flight
      console.log(`[Dedup] Reusing in-flight request for: ${key}`);
      return existing.promise as Promise<T>;
    }

    // Create new pending request
    let resolve!: (value: T) => void;
    let reject!: (reason: unknown) => void;

    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    const entry: PendingRequest<T> = {
      promise,
      resolve,
      reject,
      timestamp: Date.now(),
    };

    this.pending.set(key, entry as PendingRequest<unknown>);

    // Execute the work in the background and settle the shared promise exactly
    // once. The promise stored in `pending` is the SAME promise returned to
    // every caller (owner and deduplicated waiters alike), so a rejection from
    // `destroy()` or the stale-entry cleanup is observable and catchable by
    // everyone who called `dedup()` -- no unhandled rejections.
    fn().then(
      (result) => resolve(result),
      (error) => reject(error),
    ).finally(() => {
      this.pending.delete(key);
    });

    return promise;
  }

  /**
   * Check if a request is currently in-flight for the given key
   */
  has(key: string): boolean {
    return this.pending.has(key);
  }

  /**
   * Get the number of pending requests
   */
  get size(): number {
    return this.pending.size;
  }

  /**
   * Remove stale entries that have been pending too long
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.pending) {
      if (now - entry.timestamp > STALE_TIMEOUT_MS) {
        console.warn(`[Dedup] Cleaning stale request for: ${key}`);
        entry.reject(new Error("Request timed out (dedup cleanup)"));
        this.pending.delete(key);
      }
    }
  }

  /**
   * Destroy the deduplicator and clean up
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    // Reject all pending requests
    for (const [key, entry] of this.pending) {
      entry.reject(new Error("Deduplicator destroyed"));
    }
    this.pending.clear();
  }
}

// Singleton for the API server
let dedupInstance: RequestDeduplicator | null = null;

export function getScanDeduplicator(): RequestDeduplicator {
  if (!dedupInstance) {
    dedupInstance = new RequestDeduplicator();
  }
  return dedupInstance;
}

// API client for the PhishGuard backend

import type { ScanResponse, AgentLog, FinalVerdict } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

export async function scanUrl(url: string): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Scan failed");
  }

  return response.json();
}

/**
 * Connects to the SSE stream using fetch (not native EventSource).
 * Native EventSource fires onerror with no data for ANY connection issue
 * (including Render's proxy dropping idle connections), causing the
 * "Connection to server lost" message. fetch-based SSE lets us read the
 * stream line-by-line and handle real errors vs. clean stream ends properly.
 */
export function scanUrlWithStream(
  url: string,
  onLog: (log: AgentLog) => void,
  onResult: (verdict: FinalVerdict) => void,
  onError: (error: string) => void,
  onComplete: () => void,
): () => void {
  const encodedUrl = encodeURIComponent(url);
  const streamUrl = `${API_BASE}/api/scan/stream?url=${encodedUrl}`;
  const abortController = new AbortController();
  let done = false;

  async function connect(retryCount: number) {
    try {
      const response = await fetch(streamUrl, {
        signal: abortController.signal,
        headers: { Accept: "text/event-stream" },
      });

      if (!response.ok) {
        onError(`Server error: ${response.status} ${response.statusText}`);
        return;
      }

      if (!response.body) {
        onError("No response body from server");
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let currentEvent = "message";

      while (true) {
        const { value, done: streamDone } = await reader.read();

        if (streamDone) {
          // Stream ended cleanly — done event should have already fired
          if (!done) {
            onComplete();
            done = true;
          }
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith(":")) {
            // SSE comment (keepalive ping) — ignore
            continue;
          }

          if (line.startsWith("event:")) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            const data = line.slice(5).trim();

            if (currentEvent === "log") {
              try {
                onLog(JSON.parse(data) as AgentLog);
              } catch { /* ignore malformed log */ }
            } else if (currentEvent === "result") {
              try {
                onResult(JSON.parse(data) as FinalVerdict);
              } catch { /* ignore malformed result */ }
            } else if (currentEvent === "error") {
              try {
                const parsed = JSON.parse(data);
                onError(parsed.error || "Unknown server error");
              } catch {
                onError("Unknown server error");
              }
              done = true;
              return;
            } else if (currentEvent === "done") {
              if (!done) {
                onComplete();
                done = true;
              }
              return;
            }
          } else if (line === "") {
            // Blank line resets the event type
            currentEvent = "message";
          }
        }
      }
    } catch (err) {
      if (abortController.signal.aborted) return; // User cancelled

      const isNetworkError =
        err instanceof TypeError && err.message.toLowerCase().includes("fetch");

      if (isNetworkError && retryCount < 2) {
        // Brief pause then retry (handles transient Render proxy drops)
        await new Promise((r) => setTimeout(r, 1500));
        if (!abortController.signal.aborted) {
          connect(retryCount + 1);
        }
      } else {
        onError(
          err instanceof Error
            ? err.message
            : "Connection to server failed",
        );
      }
    }
  }

  connect(0);

  // Return cleanup function
  return () => {
    done = true;
    abortController.abort();
  };
}

export async function checkHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE}/api/health`);
    return response.ok;
  } catch {
    return false;
  }
}

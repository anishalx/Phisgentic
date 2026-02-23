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

export function scanUrlWithStream(
  url: string,
  onLog: (log: AgentLog) => void,
  onResult: (verdict: FinalVerdict) => void,
  onError: (error: string) => void,
  onComplete: () => void,
): () => void {
  const encodedUrl = encodeURIComponent(url);
  const eventSource = new EventSource(
    `${API_BASE}/api/scan/stream?url=${encodedUrl}`,
  );

  eventSource.addEventListener("log", (event) => {
    const log = JSON.parse(event.data) as AgentLog;
    onLog(log);
  });

  eventSource.addEventListener("result", (event) => {
    const verdict = JSON.parse(event.data) as FinalVerdict;
    onResult(verdict);
  });

  eventSource.addEventListener("error", (event) => {
    try {
      const messageEvent = event as MessageEvent;
      if (messageEvent.data) {
        const data = JSON.parse(messageEvent.data);
        onError(data.error || "Unknown error");
      } else {
        // Native EventSource error (connection lost, etc.)
        onError("Connection to server lost");
      }
    } catch {
      onError("Connection error");
    }
    eventSource.close();
  });

  eventSource.addEventListener("done", () => {
    onComplete();
    eventSource.close();
  });

  // Return cleanup function
  return () => {
    eventSource.close();
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

// Background Service Worker - Main entry point for the extension
// Refactored to use local API instead of in-browser AI agents

import { isWhitelisted, addToHistory, getSettings } from "../utils/storage";
import { extractDomain } from "../utils/url-parser";
import { CONFIG } from "../config";
import type { FinalVerdict, PageContent, Message } from "../types";

// API endpoint
const API_URL = `${CONFIG.API_BASE_URL}${CONFIG.API_SCAN_ENDPOINT}`;

// Store pending analyses
const pendingAnalyses = new Map<number, Promise<FinalVerdict | null>>();
const analysisResults = new Map<number, FinalVerdict>();
// Track which tabs have already been analyzed for deduplication
const analyzedUrls = new Map<number, string>();

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard AI] Extension installed - Using API mode");
  console.log(`[PhishGuard AI] API Endpoint: ${API_URL}`);
});

// Log startup
console.log("[PhishGuard AI] =================================");
console.log("[PhishGuard AI] Service Worker Starting...");
console.log(`[PhishGuard AI] API URL: ${API_URL}`);
console.log("[PhishGuard AI] =================================");

// Listen for navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only analyze main frame navigations
  if (details.frameId !== 0) return;

  const { tabId, url } = details;

  // Skip internal URLs
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:")
  ) {
    return;
  }

  console.log(`[PhishGuard AI] Analyzing URL: ${url}`);
  console.log(`[PhishGuard AI] Tab ID: ${tabId}`);

  // Check settings
  const settings = await getSettings();
  if (!settings.enabled) {
    console.log("[PhishGuard AI] Extension disabled");
    return;
  }

  // Check whitelist
  const domain = extractDomain(url);
  if (await isWhitelisted(domain)) {
    console.log(`[PhishGuard AI] Domain ${domain} is whitelisted`);
    return;
  }

  // Check if it's a known safe domain
  if (
    CONFIG.SAFE_DOMAINS.some(
      (safe) => domain === safe || domain.endsWith(`.${safe}`)
    )
  ) {
    console.log(`[PhishGuard AI] Domain ${domain} is in safe list`);
    return;
  }

  // Start analysis (don't block navigation, analyze in background)
  analyzedUrls.set(tabId, url);
  const analysisPromise = analyzeUrlViaAPI(tabId, url);
  pendingAnalyses.set(tabId, analysisPromise);

  // Handle result
  analysisPromise
    .then((verdict) => {
      if (verdict) {
        analysisResults.set(tabId, verdict);
        pendingAnalyses.delete(tabId);

        // If page is dangerous, notify the content script to show warning
        if (verdict.action === "warn" || verdict.action === "block") {
          notifyContentScript(tabId, verdict);
        }

        // Update badge
        updateBadge(tabId, verdict);

        // Log to history
        addToHistory(url, verdict);
      }
    })
    .catch((error) => {
      console.error("[PhishGuard AI] Analysis error:", error);
      pendingAnalyses.delete(tabId);
    });
});

// Listen for page content from content script
chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse) => {
    const tabId = sender.tab?.id;

    switch (message.type) {
      case "PAGE_CONTENT":
        if (tabId && sender.tab?.url) {
          handlePageContent(
            tabId,
            sender.tab.url,
            message.payload as PageContent
          );
        }
        sendResponse({ received: true });
        break;

      case "GET_STATUS":
        // Get tabId from sender.tab (content script) or from payload (popup)
        const statusTabId = tabId || (message.payload as { tabId?: number })?.tabId;
        if (statusTabId) {
          const result = analysisResults.get(statusTabId);
          const pending = pendingAnalyses.has(statusTabId);
          console.log(`[PhishGuard AI] GET_STATUS for tab ${statusTabId}:`, { result: !!result, pending });
          sendResponse({ result, pending });
        } else {
          console.log("[PhishGuard AI] GET_STATUS: No tabId provided");
          sendResponse({ result: null, pending: false });
        }
        break;

      case "USER_OVERRIDE":
        if (tabId) {
          const result = analysisResults.get(tabId);
          if (result) {
            addToHistory(result.url, result, "proceeded");
          }
        }
        sendResponse({ received: true });
        break;

      default:
        sendResponse({ error: "Unknown message type" });
    }

    return true; // Keep channel open for async response
  }
);

/**
 * Send URL to local API for analysis
 */
async function analyzeUrlViaAPI(
  tabId: number,
  url: string,
  pageContent?: PageContent
): Promise<FinalVerdict | null> {
  try {
    console.log(`[PhishGuard AI] Sending to API: ${url}`);

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
        pageContent: pageContent || null,
      }),
    });

    if (!response.ok) {
      console.error(
        `[PhishGuard AI] API error: ${response.status} ${response.statusText}`
      );
      return createFallbackVerdict(url, "API error");
    }

    const data = await response.json();

    console.log("[PhishGuard AI] Raw API response:", JSON.stringify(data, null, 2));

    // Extract verdict from nested structure (API returns { success, verdict, logs })
    const apiVerdict = data.verdict || data;

    // Map API response to FinalVerdict format
    const verdict: FinalVerdict = {
      url: apiVerdict.url || url,
      overallRiskScore: apiVerdict.overallRiskScore ?? apiVerdict.riskScore ?? 0,
      confidence: apiVerdict.confidence ?? 0.5,
      action: apiVerdict.action || mapRiskToAction(apiVerdict.overallRiskScore ?? apiVerdict.riskScore ?? 0),
      summary: apiVerdict.summary || apiVerdict.explanation || "Analysis complete",
      agentResults: apiVerdict.agentResults || apiVerdict.agents || [],
      timestamp: Date.now(),
    };

    console.log(`[PhishGuard AI] -------- VERDICT --------`);
    console.log(`[PhishGuard AI] URL: ${verdict.url}`);
    console.log(`[PhishGuard AI] Risk Score: ${verdict.overallRiskScore}`);
    console.log(`[PhishGuard AI] Action: ${verdict.action}`);
    console.log(`[PhishGuard AI] Confidence: ${verdict.confidence}`);
    console.log(`[PhishGuard AI] Summary: ${verdict.summary}`);
    console.log(`[PhishGuard AI] -------------------------`);

    return verdict;
  } catch (error) {
    console.error("[PhishGuard AI] Failed to reach API:", error);
    return createFallbackVerdict(url, "Cannot reach server");
  }
}

/**
 * Handle page content received from content script.
 * Skip re-analysis if the URL was already analyzed by onBeforeNavigate.
 */
async function handlePageContent(
  tabId: number,
  url: string,
  pageContent: PageContent
): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled) return;

  // Deduplicate: if we already analyzed this exact URL for this tab, skip
  if (analyzedUrls.get(tabId) === url && analysisResults.has(tabId)) {
    console.log(`[PhishGuard AI] Skipping duplicate analysis for tab ${tabId}: ${url}`);
    return;
  }

  // Only re-analyze if we have new page content and haven't analyzed yet
  const verdict = await analyzeUrlViaAPI(tabId, url, pageContent);

  if (verdict) {
    analysisResults.set(tabId, verdict);

    // If page is dangerous, notify the content script
    if (verdict.action === "warn" || verdict.action === "block") {
      notifyContentScript(tabId, verdict);
    }

    // Update badge
    updateBadge(tabId, verdict);

    // Update history
    addToHistory(url, verdict);
  }
}

/**
 * Map risk score to action
 */
function mapRiskToAction(riskScore: number): "allow" | "warn" | "block" {
  if (riskScore >= CONFIG.THRESHOLDS.BLOCK_MIN) return "block";
  if (riskScore > CONFIG.THRESHOLDS.ALLOW_MAX) return "warn";
  return "allow";
}

/**
 * Create a fallback verdict when API is unavailable
 */
function createFallbackVerdict(url: string, reason: string): FinalVerdict {
  return {
    url,
    overallRiskScore: 0,
    confidence: 0,
    action: "allow",
    summary: `Could not analyze: ${reason}. Proceeding with caution.`,
    agentResults: [],
    timestamp: Date.now(),
  };
}

/**
 * Notify content script to show warning overlay with retry logic
 */
function notifyContentScript(
  tabId: number,
  verdict: FinalVerdict,
  retryCount = 0
): void {
  const MAX_RETRIES = 10;
  const RETRY_DELAY_MS = 500;

  chrome.tabs
    .sendMessage(tabId, {
      type: "SHOW_WARNING",
      payload: verdict,
    })
    .then((response) => {
      if (response?.received) {
        console.log(
          `[PhishGuard AI] Warning displayed successfully on tab ${tabId}`
        );
      }
    })
    .catch((error) => {
      console.log(
        `[PhishGuard AI] Message attempt ${retryCount + 1}/${MAX_RETRIES} failed:`,
        error.message
      );

      // Retry if content script isn't ready yet
      if (retryCount < MAX_RETRIES) {
        setTimeout(() => {
          notifyContentScript(tabId, verdict, retryCount + 1);
        }, RETRY_DELAY_MS);
      } else {
        console.error(
          `[PhishGuard AI] Failed to notify content script after ${MAX_RETRIES} attempts`
        );
      }
    });
}

/**
 * Update badge based on analysis result
 */
function updateBadge(tabId: number, verdict: FinalVerdict): void {
  let color: string;
  let text: string;

  switch (verdict.action) {
    case "block":
      color = "#dc2626"; // Red
      text = "!";
      break;
    case "warn":
      color = "#f59e0b"; // Yellow/Orange
      text = "?";
      break;
    default:
      color = "#22c55e"; // Green
      text = "";
  }

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

// Update badge and re-send warning when tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    const result = analysisResults.get(tabId);
    if (result) {
      updateBadge(tabId, result);

      // Re-send warning when page is fully loaded (content script is now ready)
      if (result.action === "warn" || result.action === "block") {
        console.log(
          `[PhishGuard AI] Tab ${tabId} complete, re-sending warning for ${result.action}`
        );
        notifyContentScript(tabId, result);
      }
    }
  }
});

// Clear results when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  analysisResults.delete(tabId);
  pendingAnalyses.delete(tabId);
  analyzedUrls.delete(tabId);
});

console.log("[PhishGuard AI] Service worker initialized (API mode)");

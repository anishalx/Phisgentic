// Background Service Worker - Main entry point for the extension

import { getOrchestrator } from "../agents/orchestrator";
import { isWhitelisted, addToHistory, getSettings } from "../utils/storage";
import { extractDomain } from "../utils/url-parser";
import { CONFIG } from "../config";
import type { FinalVerdict, PageContent, Message } from "../types";

// Store pending analyses
const pendingAnalyses = new Map<number, Promise<FinalVerdict>>();
const analysisResults = new Map<number, FinalVerdict>();

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard AI] Extension installed");
});

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
      (safe) => domain === safe || domain.endsWith(`.${safe}`),
    )
  ) {
    console.log(`[PhishGuard AI] Domain ${domain} is in safe list`);
    return;
  }

  // Start analysis (don't block navigation, analyze in background)
  const analysisPromise = analyzeUrl(tabId, url);
  pendingAnalyses.set(tabId, analysisPromise);

  // Handle result
  analysisPromise
    .then((verdict) => {
      analysisResults.set(tabId, verdict);
      pendingAnalyses.delete(tabId);

      // If page is dangerous, notify the content script to show warning
      if (verdict.action === "warn" || verdict.action === "block") {
        notifyContentScript(tabId, verdict);
      }

      // Log to history
      addToHistory(url, verdict);
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
            message.payload as PageContent,
          );
        }
        sendResponse({ received: true });
        break;

      case "GET_STATUS":
        if (tabId) {
          const result = analysisResults.get(tabId);
          const pending = pendingAnalyses.has(tabId);
          sendResponse({ result, pending });
        } else {
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
  },
);

async function analyzeUrl(tabId: number, url: string): Promise<FinalVerdict> {
  const orchestrator = getOrchestrator();

  // Initial analysis without page content
  const verdict = await orchestrator.analyzeUrl(url);

  return verdict;
}

async function handlePageContent(
  tabId: number,
  url: string,
  pageContent: PageContent,
): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled) return;

  const orchestrator = getOrchestrator();

  // Re-analyze with page content
  const verdict = await orchestrator.analyzeUrl(url, pageContent);
  analysisResults.set(tabId, verdict);

  // If page is dangerous, notify the content script
  if (verdict.action === "warn" || verdict.action === "block") {
    notifyContentScript(tabId, verdict);
  }

  // Update history
  addToHistory(url, verdict);
}

function notifyContentScript(tabId: number, verdict: FinalVerdict): void {
  chrome.tabs
    .sendMessage(tabId, {
      type: "SHOW_WARNING",
      payload: verdict,
    })
    .catch((error) => {
      console.log("[PhishGuard AI] Could not send message to tab:", error);
    });
}

// Update badge based on analysis
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    const result = analysisResults.get(tabId);
    if (result) {
      updateBadge(tabId, result);
    }
  }
});

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
      text = "✓";
  }

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

// Clear results when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  analysisResults.delete(tabId);
  pendingAnalyses.delete(tabId);
});

console.log("[PhishGuard AI] Service worker initialized");

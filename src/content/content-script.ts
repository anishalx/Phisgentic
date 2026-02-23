// Content Script - Extracts page content and shows warnings

import type { PageContent, FinalVerdict, Message } from "../types";

// Track if warning is shown
let warningOverlay: HTMLElement | null = null;

// Escape HTML to prevent XSS from malicious URLs/content
function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

// Extract page content when DOM is ready
function extractPageContent(): PageContent {
  const forms = Array.from(document.querySelectorAll("form")).map((form) => {
    const inputs = Array.from(form.querySelectorAll("input"));
    const hasPasswordField = inputs.some((input) => input.type === "password");
    const inputTypes = inputs.map((input) => input.type);

    return {
      action: form.action || "",
      method: form.method || "get",
      hasPasswordField,
      inputTypes,
    };
  });

  const links = Array.from(document.querySelectorAll("a[href]"))
    .slice(0, 100)
    .map((anchor) => {
      const a = anchor as HTMLAnchorElement;
      const href = a.href;
      const isExternal = a.hostname !== window.location.hostname;

      return {
        href,
        text: a.textContent?.trim().substring(0, 100) || "",
        isExternal,
      };
    });

  const scripts = Array.from(document.querySelectorAll("script[src]"))
    .map((s) => (s as HTMLScriptElement).src)
    .filter((src) => src);

  const metaTags: Record<string, string> = {};
  document.querySelectorAll("meta").forEach((meta) => {
    const name =
      meta.getAttribute("name") || meta.getAttribute("property") || "";
    const content = meta.getAttribute("content") || "";
    if (name && content) {
      metaTags[name] = content.substring(0, 200);
    }
  });

  const hasPasswordField =
    document.querySelector('input[type="password"]') !== null;
  const hasLoginForm =
    hasPasswordField &&
    document.querySelector(
      'input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"]',
    ) !== null;

  // Get text content (limited)
  const bodyText = document.body?.innerText || "";
  const textContent = bodyText.substring(0, 10000);

  return {
    title: document.title,
    forms,
    links,
    scripts,
    metaTags,
    textContent,
    hasPasswordField,
    hasLoginForm,
  };
}

// Send page content to background script
function sendPageContent(): void {
  const content = extractPageContent();

  chrome.runtime
    .sendMessage({
      type: "PAGE_CONTENT",
      payload: content,
    } as Message)
    .catch(() => {
      // Extension might not be ready yet
    });
}

// Show warning overlay
function showWarning(verdict: FinalVerdict): void {
  // Remove existing overlay
  if (warningOverlay) {
    warningOverlay.remove();
  }

  const isBlock = verdict.action === "block";
  const riskLevel = isBlock ? "CRITICAL" : "WARNING";
  const riskColor = isBlock ? "#ef4444" : "#f59e0b";

  warningOverlay = document.createElement("div");
  warningOverlay.id = "phishguard-warning-overlay";
  warningOverlay.innerHTML = `
    <style>
      #phishguard-warning-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.85);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        padding: 20px;
      }
      
      .pg-card {
        background: #111827;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        max-width: 480px;
        width: 100%;
        overflow: hidden;
        box-shadow: 0 0 80px ${isBlock ? "rgba(239, 68, 68, 0.3)" : "rgba(245, 158, 11, 0.2)"};
      }
      
      .pg-header {
        padding: 32px 32px 24px;
        text-align: center;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      }
      
      .pg-shield {
        width: 64px;
        height: 64px;
        margin: 0 auto 16px;
        background: ${isBlock ? "rgba(239, 68, 68, 0.15)" : "rgba(245, 158, 11, 0.15)"};
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .pg-shield svg {
        width: 32px;
        height: 32px;
        color: ${riskColor};
      }
      
      .pg-badge {
        display: inline-block;
        padding: 4px 12px;
        background: ${isBlock ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)"};
        color: ${riskColor};
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 1px;
        border-radius: 4px;
        margin-bottom: 12px;
      }
      
      .pg-title {
        font-size: 22px;
        font-weight: 600;
        color: #f9fafb;
        margin: 0 0 8px;
        line-height: 1.3;
      }
      
      .pg-subtitle {
        font-size: 14px;
        color: #9ca3af;
        margin: 0;
        line-height: 1.5;
      }
      
      .pg-body {
        padding: 24px 32px;
      }
      
      .pg-url-box {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 20px;
      }
      
      .pg-url-label {
        font-size: 11px;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
      }
      
      .pg-url-text {
        font-size: 13px;
        color: #d1d5db;
        word-break: break-all;
        line-height: 1.4;
      }
      
      .pg-reason {
        font-size: 14px;
        color: #d1d5db;
        line-height: 1.6;
        margin-bottom: 20px;
        padding: 16px;
        background: rgba(255, 255, 255, 0.02);
        border-left: 3px solid ${riskColor};
        border-radius: 0 8px 8px 0;
      }
      
      .pg-actions {
        display: flex;
        gap: 12px;
      }
      
      .pg-btn {
        flex: 1;
        padding: 14px 20px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
        text-align: center;
      }
      
      .pg-btn-primary {
        background: #3b82f6;
        color: white;
      }
      
      .pg-btn-primary:hover {
        background: #2563eb;
      }
      
      .pg-btn-ghost {
        background: transparent;
        color: #6b7280;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      
      .pg-btn-ghost:hover {
        background: rgba(255, 255, 255, 0.05);
        color: #9ca3af;
      }
      
      .pg-footer {
        padding: 16px 32px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      
      .pg-brand {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        color: #6b7280;
      }
      
      .pg-brand-logo {
        width: 16px;
        height: 16px;
        color: #3b82f6;
      }
      
      .pg-proceed-link {
        font-size: 12px;
        color: #4b5563;
        background: none;
        border: none;
        cursor: pointer;
        padding: 0;
        text-decoration: underline;
        text-underline-offset: 2px;
      }
      
      .pg-proceed-link:hover {
        color: #6b7280;
      }
      
      .pg-details {
        margin-top: 16px;
        padding-top: 16px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        display: none;
      }
      
      .pg-details.open {
        display: block;
      }
      
      .pg-details-title {
        font-size: 12px;
        color: #6b7280;
        margin-bottom: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .pg-agent {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      }
      
      .pg-agent:last-child {
        border-bottom: none;
      }
      
      .pg-agent-name {
        font-size: 13px;
        color: #9ca3af;
      }
      
      .pg-agent-score {
        font-size: 12px;
        font-weight: 600;
        padding: 3px 10px;
        border-radius: 12px;
      }
      
      .pg-score-low { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
      .pg-score-medium { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
      .pg-score-high { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
      
      .pg-toggle-details {
        font-size: 12px;
        color: #6b7280;
        background: none;
        border: none;
        cursor: pointer;
        padding: 8px 0;
        width: 100%;
        text-align: center;
        margin-top: 8px;
      }
      
      .pg-toggle-details:hover {
        color: #9ca3af;
      }
    </style>
    
    <div class="pg-card">
      <div class="pg-header">
        <div class="pg-shield">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M12 8v4M12 16h.01"/>
          </svg>
        </div>
        <span class="pg-badge">${escapeHtml(riskLevel)} RISK</span>
        <h1 class="pg-title">${isBlock ? "This site may steal your data" : "This site looks suspicious"}</h1>
        <p class="pg-subtitle">PhishGuard detected potential phishing indicators on this page.</p>
      </div>
      
      <div class="pg-body">
        <div class="pg-url-box">
          <div class="pg-url-label">Blocked URL</div>
          <div class="pg-url-text">${escapeHtml(verdict.url)}</div>
        </div>
        
        <div class="pg-reason">
          ${escapeHtml(verdict.summary)}
        </div>
        
        <div class="pg-actions">
          <button class="pg-btn pg-btn-primary" id="phishguard-go-back">
            Go Back to Safety
          </button>
          <button class="pg-btn pg-btn-ghost" id="phishguard-toggle-details">
            View Details
          </button>
        </div>
        
        <div class="pg-details" id="phishguard-details">
          <div class="pg-details-title">Analysis Breakdown</div>
          ${verdict.agentResults
            .map(
              (agent) => `
            <div class="pg-agent">
              <span class="pg-agent-name">${escapeHtml(agent.agentName)}</span>
              <span class="pg-agent-score ${getScoreClass(agent.riskScore)}">
                ${escapeHtml(String(agent.riskScore))}
              </span>
            </div>
          `,
            )
            .join("")}
        </div>
      </div>
      
      <div class="pg-footer">
        <div class="pg-brand">
          <svg class="pg-brand-logo" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
          </svg>
          PhishGuard AI
        </div>
        <button class="pg-proceed-link" id="phishguard-proceed">
          Proceed anyway (unsafe)
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(warningOverlay);

  // Event: Go back
  document.getElementById("phishguard-go-back")?.addEventListener("click", () => {
    window.history.back();
    setTimeout(() => {
      window.location.href = "about:blank";
    }, 100);
  });

  // Event: Toggle details
  document.getElementById("phishguard-toggle-details")?.addEventListener("click", () => {
    const details = document.getElementById("phishguard-details");
    if (details) {
      details.classList.toggle("open");
      const btn = document.getElementById("phishguard-toggle-details");
      if (btn) {
        btn.textContent = details.classList.contains("open") ? "Hide Details" : "View Details";
      }
    }
  });

  // Event: Proceed anyway
  document.getElementById("phishguard-proceed")?.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "USER_OVERRIDE",
      payload: { url: verdict.url },
    } as Message);
    warningOverlay?.remove();
    warningOverlay = null;
  });
}

function getScoreClass(score: number): string {
  if (score <= 30) return "pg-score-low";
  if (score <= 70) return "pg-score-medium";
  return "pg-score-high";
}

// Listen for messages from background
chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse) => {
    console.log("[PhishGuard AI] Content script received message:", message.type);
    
    if (message.type === "SHOW_WARNING") {
      const verdict = message.payload as FinalVerdict;
      console.log(`[PhishGuard AI] Showing warning overlay - Action: ${verdict.action}, Score: ${verdict.overallRiskScore}`);
      showWarning(verdict);
      sendResponse({ received: true });
    }
    return true;
  },
);

// Initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    setTimeout(sendPageContent, 500); // Small delay to ensure page is loaded
  });
} else {
  setTimeout(sendPageContent, 500);
}

console.log("[PhishGuard AI] Content script loaded on:", window.location.href);

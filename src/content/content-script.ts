// Content Script - Extracts page content and shows warnings

import type { PageContent, FinalVerdict, Message } from "../types";

// Track if warning is shown
let warningOverlay: HTMLElement | null = null;

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
        background: ${isBlock ? "rgba(220, 38, 38, 0.95)" : "rgba(245, 158, 11, 0.95)"};
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      
      .phishguard-modal {
        background: white;
        border-radius: 16px;
        padding: 40px;
        max-width: 600px;
        width: 90%;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        text-align: center;
      }
      
      .phishguard-icon {
        font-size: 72px;
        margin-bottom: 20px;
      }
      
      .phishguard-title {
        font-size: 28px;
        font-weight: 700;
        color: ${isBlock ? "#dc2626" : "#f59e0b"};
        margin-bottom: 16px;
      }
      
      .phishguard-score {
        font-size: 18px;
        color: #6b7280;
        margin-bottom: 20px;
      }
      
      .phishguard-summary {
        font-size: 16px;
        color: #374151;
        line-height: 1.6;
        margin-bottom: 24px;
        text-align: left;
        padding: 16px;
        background: #f3f4f6;
        border-radius: 8px;
      }
      
      .phishguard-url {
        font-size: 14px;
        color: #6b7280;
        word-break: break-all;
        margin-bottom: 24px;
        padding: 12px;
        background: #fef2f2;
        border-radius: 8px;
        border: 1px solid #fecaca;
      }
      
      .phishguard-buttons {
        display: flex;
        gap: 16px;
        justify-content: center;
      }
      
      .phishguard-btn {
        padding: 14px 28px;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        border: none;
        transition: all 0.2s;
      }
      
      .phishguard-btn-safe {
        background: #22c55e;
        color: white;
      }
      
      .phishguard-btn-safe:hover {
        background: #16a34a;
      }
      
      .phishguard-btn-proceed {
        background: transparent;
        color: #6b7280;
        border: 2px solid #d1d5db;
      }
      
      .phishguard-btn-proceed:hover {
        background: #f3f4f6;
      }
      
      .phishguard-agents {
        margin-top: 24px;
        padding-top: 24px;
        border-top: 1px solid #e5e7eb;
        text-align: left;
      }
      
      .phishguard-agents-title {
        font-size: 14px;
        font-weight: 600;
        color: #374151;
        margin-bottom: 12px;
      }
      
      .phishguard-agent {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid #f3f4f6;
      }
      
      .phishguard-agent-name {
        font-size: 14px;
        color: #6b7280;
      }
      
      .phishguard-agent-score {
        font-size: 14px;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
      }
      
      .score-low { background: #dcfce7; color: #166534; }
      .score-medium { background: #fef3c7; color: #92400e; }
      .score-high { background: #fee2e2; color: #dc2626; }
    </style>
    
    <div class="phishguard-modal">
      <div class="phishguard-icon">${isBlock ? "🛑" : "⚠️"}</div>
      <h1 class="phishguard-title">
        ${isBlock ? "Phishing Site Detected!" : "Suspicious Site Detected"}
      </h1>
      <div class="phishguard-score">
        Risk Score: ${verdict.overallRiskScore}/100 | Confidence: ${Math.round(verdict.confidence * 100)}%
      </div>
      <div class="phishguard-summary">
        ${verdict.summary}
      </div>
      <div class="phishguard-url">
        <strong>URL:</strong> ${verdict.url}
      </div>
      <div class="phishguard-buttons">
        <button class="phishguard-btn phishguard-btn-safe" id="phishguard-go-back">
          ← Go Back to Safety
        </button>
        <button class="phishguard-btn phishguard-btn-proceed" id="phishguard-proceed">
          Proceed Anyway (Not Recommended)
        </button>
      </div>
      
      <div class="phishguard-agents">
        <div class="phishguard-agents-title">Analysis by AI Agents:</div>
        ${verdict.agentResults
          .map(
            (agent) => `
          <div class="phishguard-agent">
            <span class="phishguard-agent-name">${agent.agentName}</span>
            <span class="phishguard-agent-score ${getScoreClass(agent.riskScore)}">
              ${agent.riskScore}/100
            </span>
          </div>
        `,
          )
          .join("")}
      </div>
    </div>
  `;

  document.body.appendChild(warningOverlay);

  // Add event listeners
  document
    .getElementById("phishguard-go-back")
    ?.addEventListener("click", () => {
      window.history.back();
      setTimeout(() => {
        // If can't go back, go to a safe page
        window.location.href = "about:blank";
      }, 100);
    });

  document
    .getElementById("phishguard-proceed")
    ?.addEventListener("click", () => {
      // Notify background that user proceeded
      chrome.runtime.sendMessage({
        type: "USER_OVERRIDE",
        payload: { url: verdict.url },
      } as Message);

      // Remove overlay
      warningOverlay?.remove();
      warningOverlay = null;
    });
}

function getScoreClass(score: number): string {
  if (score <= 30) return "score-low";
  if (score <= 70) return "score-medium";
  return "score-high";
}

// Listen for messages from background
chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse) => {
    if (message.type === "SHOW_WARNING") {
      showWarning(message.payload as FinalVerdict);
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

console.log("[PhishGuard AI] Content script loaded");

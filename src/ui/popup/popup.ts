// Popup Script - Handles popup UI interactions

import type { FinalVerdict, AnalysisHistoryEntry } from "../../types";
import {
  getSettings,
  saveSettings,
  addToWhitelist,
  getAnalysisHistory,
} from "../../utils/storage";
import { extractDomain } from "../../utils/url-parser";

// DOM Elements
const enabledToggle = document.getElementById(
  "enabled-toggle",
) as HTMLInputElement;
const statusCard = document.getElementById("status-card") as HTMLElement;
const statusIcon = document.getElementById("status-icon") as HTMLElement;
const statusTitle = document.getElementById("status-title") as HTMLElement;
const statusSubtitle = document.getElementById(
  "status-subtitle",
) as HTMLElement;
const statusScore = document.getElementById("status-score") as HTMLElement;
const detailsSection = document.getElementById(
  "details-section",
) as HTMLElement;
const agentsList = document.getElementById("agents-list") as HTMLElement;
const signalsSection = document.getElementById(
  "signals-section",
) as HTMLElement;
const signalsList = document.getElementById("signals-list") as HTMLElement;
const historyList = document.getElementById("history-list") as HTMLElement;
const whitelistBtn = document.getElementById(
  "whitelist-btn",
) as HTMLButtonElement;
const reportBtn = document.getElementById("report-btn") as HTMLButtonElement;

let currentUrl = "";
let currentVerdict: FinalVerdict | null = null;

// Initialize popup
async function initialize() {
  // Load settings
  const settings = await getSettings();
  enabledToggle.checked = settings.enabled;

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url) {
    currentUrl = tab.url;

    // Skip chrome:// URLs
    if (
      currentUrl.startsWith("chrome://") ||
      currentUrl.startsWith("chrome-extension://")
    ) {
      showNotApplicable();
      return;
    }

    // Request status from background
    const response = await chrome.runtime.sendMessage({ type: "GET_STATUS" });

    if (response?.result) {
      currentVerdict = response.result;
      showResult(response.result);
    } else if (response?.pending) {
      showAnalyzing();
    } else {
      showNoAnalysis();
    }
  } else {
    showNotApplicable();
  }

  // Load history
  await loadHistory();

  // Setup event listeners
  setupEventListeners();
}

function setupEventListeners() {
  // Toggle enabled state
  enabledToggle.addEventListener("change", async () => {
    const settings = await getSettings();
    settings.enabled = enabledToggle.checked;
    await saveSettings(settings);
  });

  // Whitelist current domain
  whitelistBtn.addEventListener("click", async () => {
    if (currentUrl) {
      const domain = extractDomain(currentUrl);
      if (domain) {
        await addToWhitelist(domain);
        whitelistBtn.textContent = "✓ Whitelisted!";
        whitelistBtn.disabled = true;
        setTimeout(() => {
          whitelistBtn.innerHTML = "<span>✓</span> Whitelist Domain";
          whitelistBtn.disabled = false;
        }, 2000);
      }
    }
  });

  // Report false positive
  reportBtn.addEventListener("click", () => {
    // In a real implementation, this would send a report
    alert("Thank you for your feedback! This will help improve our detection.");
  });
}

function showAnalyzing() {
  statusCard.className = "status-card";
  statusIcon.textContent = "⏳";
  statusTitle.textContent = "Analyzing...";
  statusSubtitle.textContent = "AI agents are examining this page";
  statusScore.textContent = "--";
  detailsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showNotApplicable() {
  statusCard.className = "status-card";
  statusIcon.textContent = "➖";
  statusTitle.textContent = "Not Applicable";
  statusSubtitle.textContent = "This page cannot be analyzed";
  statusScore.textContent = "--";
  detailsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showNoAnalysis() {
  statusCard.className = "status-card safe";
  statusIcon.textContent = "✅";
  statusTitle.textContent = "No Issues Detected";
  statusSubtitle.textContent = "Page appears safe";
  statusScore.textContent = "0";
  detailsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showResult(verdict: FinalVerdict) {
  // Update status card
  if (verdict.action === "block") {
    statusCard.className = "status-card danger";
    statusIcon.textContent = "🛑";
    statusTitle.textContent = "High Risk Detected!";
  } else if (verdict.action === "warn") {
    statusCard.className = "status-card warn";
    statusIcon.textContent = "⚠️";
    statusTitle.textContent = "Suspicious Activity";
  } else {
    statusCard.className = "status-card safe";
    statusIcon.textContent = "✅";
    statusTitle.textContent = "Page Appears Safe";
  }

  statusSubtitle.textContent = `Confidence: ${Math.round(verdict.confidence * 100)}%`;
  statusScore.textContent = verdict.overallRiskScore.toString();

  // Show agent details
  if (verdict.agentResults.length > 0) {
    detailsSection.style.display = "block";
    agentsList.innerHTML = verdict.agentResults
      .map(
        (agent) => `
      <div class="agent-item">
        <span class="agent-name">${agent.agentName}</span>
        <span class="agent-score ${getScoreClass(agent.riskScore)}">${agent.riskScore}/100</span>
      </div>
    `,
      )
      .join("");
  }

  // Show signals
  const allSignals = verdict.agentResults.flatMap((r) => r.signals);
  if (allSignals.length > 0) {
    signalsSection.style.display = "block";
    signalsList.innerHTML = allSignals
      .slice(0, 10)
      .map(
        (signal) => `
      <div class="signal-item">
        <div class="signal-severity ${signal.severity}"></div>
        <div class="signal-text">${signal.description}</div>
      </div>
    `,
      )
      .join("");
  }
}

async function loadHistory() {
  const history = await getAnalysisHistory(5);

  if (history.length === 0) {
    historyList.innerHTML = '<div class="history-empty">No recent scans</div>';
    return;
  }

  historyList.innerHTML = history
    .reverse()
    .map((entry) => {
      const icon =
        entry.verdict.action === "block"
          ? "🛑"
          : entry.verdict.action === "warn"
            ? "⚠️"
            : "✅";
      const scoreClass = getScoreClass(entry.verdict.overallRiskScore);
      const time = formatTime(entry.timestamp);
      const domain = extractDomain(entry.url);

      return `
      <div class="history-item">
        <span class="history-icon">${icon}</span>
        <div class="history-details">
          <div class="history-url">${domain}</div>
          <div class="history-time">${time}</div>
        </div>
        <span class="history-score agent-score ${scoreClass}">${entry.verdict.overallRiskScore}</span>
      </div>
    `;
    })
    .join("");
}

function getScoreClass(score: number): string {
  if (score <= 30) return "low";
  if (score <= 70) return "medium";
  return "high";
}

function formatTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return "Just now";
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", initialize);

// Popup Script - Handles popup UI interactions

import type { FinalVerdict } from "../../types";
import {
  getSettings,
  saveSettings,
  addToWhitelist,
  getAnalysisHistory,
} from "../../utils/storage";
import { extractDomain } from "../../utils/url-parser";

// DOM Elements
const enabledToggle = document.getElementById("enabled-toggle") as HTMLInputElement;
const statusHero = document.getElementById("status-hero") as HTMLElement;
const statusGlow = document.getElementById("status-glow") as HTMLElement;
const ringProgress = document.getElementById("ring-progress") as unknown as SVGCircleElement;
const scoreValue = document.getElementById("score-value") as HTMLElement;
const statusTitle = document.getElementById("status-title") as HTMLElement;
const statusSubtitle = document.getElementById("status-subtitle") as HTMLElement;
const statusUrl = document.getElementById("status-url") as HTMLElement;

const agentsSection = document.getElementById("agents-section") as HTMLElement;
const agentsList = document.getElementById("agents-list") as HTMLElement;
const signalsSection = document.getElementById("signals-section") as HTMLElement;
const signalsList = document.getElementById("signals-list") as HTMLElement;

const historyPanel = document.getElementById("history-panel") as HTMLElement;
const historyList = document.getElementById("history-list") as HTMLElement;
const historyBtn = document.getElementById("history-btn") as HTMLButtonElement;

const whitelistBtn = document.getElementById("whitelist-btn") as HTMLButtonElement;
const reportBtn = document.getElementById("report-btn") as HTMLButtonElement;

let currentUrl = "";
let currentVerdict: FinalVerdict | null = null;
let historyVisible = false;

// Ring circumference for progress calculation
const RING_CIRCUMFERENCE = 2 * Math.PI * 52; // radius = 52

// Initialize popup
async function initialize() {
  // Load settings
  const settings = await getSettings();
  enabledToggle.checked = settings.enabled;

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url) {
    currentUrl = tab.url;
    const domain = extractDomain(currentUrl);
    statusUrl.textContent = domain || currentUrl;

    // Skip chrome:// URLs
    if (
      currentUrl.startsWith("chrome://") ||
      currentUrl.startsWith("chrome-extension://") ||
      currentUrl.startsWith("about:")
    ) {
      showNotApplicable();
      return;
    }

    // Request status from background (include tabId since popup messages don't have sender.tab)
    const response = await chrome.runtime.sendMessage({ 
      type: "GET_STATUS",
      payload: { tabId: tab.id }
    });

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
        whitelistBtn.innerHTML = `
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
          </svg>
          Trusted!
        `;
        whitelistBtn.disabled = true;
        setTimeout(() => {
          whitelistBtn.innerHTML = `
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
            Trust Site
          `;
          whitelistBtn.disabled = false;
        }, 2000);
      }
    }
  });

  // Report false positive
  reportBtn.addEventListener("click", () => {
    alert("Thank you for your feedback! This will help improve our detection.");
  });

  // Toggle history panel
  historyBtn.addEventListener("click", async () => {
    historyVisible = !historyVisible;
    historyBtn.classList.toggle("active", historyVisible);
    
    if (historyVisible) {
      await loadHistory();
      historyPanel.style.display = "block";
    } else {
      historyPanel.style.display = "none";
    }
  });
}

function setRingProgress(score: number) {
  const progress = (score / 100) * RING_CIRCUMFERENCE;
  const offset = RING_CIRCUMFERENCE - progress;
  ringProgress.style.strokeDashoffset = offset.toString();
}

function showAnalyzing() {
  statusHero.className = "status-hero analyzing";
  scoreValue.textContent = "--";
  statusTitle.textContent = "Analyzing...";
  statusSubtitle.textContent = "AI agents are examining this page";
  setRingProgress(0);
  agentsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showNotApplicable() {
  statusHero.className = "status-hero";
  scoreValue.textContent = "--";
  statusTitle.textContent = "Not Applicable";
  statusSubtitle.textContent = "This page cannot be analyzed";
  setRingProgress(0);
  agentsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showNoAnalysis() {
  statusHero.className = "status-hero safe";
  scoreValue.textContent = "0";
  statusTitle.textContent = "No Threats Detected";
  statusSubtitle.textContent = "This page appears to be safe";
  setRingProgress(0);
  agentsSection.style.display = "none";
  signalsSection.style.display = "none";
}

function showResult(verdict: FinalVerdict) {
  // Update status hero class based on action
  if (verdict.action === "block") {
    statusHero.className = "status-hero danger";
    statusTitle.textContent = "High Risk Detected!";
  } else if (verdict.action === "warn") {
    statusHero.className = "status-hero warn";
    statusTitle.textContent = "Suspicious Site";
  } else {
    statusHero.className = "status-hero safe";
    statusTitle.textContent = "Site Appears Safe";
  }

  // Update score display
  scoreValue.textContent = verdict.overallRiskScore.toString();
  setRingProgress(verdict.overallRiskScore);
  
  // Update subtitle with confidence
  statusSubtitle.textContent = `Confidence: ${Math.round(verdict.confidence * 100)}%`;

  // Show agent details
  if (verdict.agentResults && verdict.agentResults.length > 0) {
    agentsSection.style.display = "block";
    agentsList.innerHTML = verdict.agentResults
      .map((agent) => {
        const icon = getAgentIcon(agent.agentName);
        const scoreClass = getScoreClass(agent.riskScore);
        return `
          <div class="agent-card">
            <div class="agent-icon">${icon}</div>
            <div class="agent-info">
              <div class="agent-name">${agent.agentName}</div>
              <div class="agent-detail">${agent.signals.length} signal${agent.signals.length !== 1 ? 's' : ''} detected</div>
            </div>
            <span class="agent-score ${scoreClass}">${agent.riskScore}</span>
          </div>
        `;
      })
      .join("");
  } else {
    agentsSection.style.display = "none";
  }

  // Show signals
  const allSignals = verdict.agentResults?.flatMap((r) => r.signals) || [];
  if (allSignals.length > 0) {
    signalsSection.style.display = "block";
    signalsList.innerHTML = allSignals
      .slice(0, 8)
      .map((signal) => `
        <div class="signal-item">
          <div class="signal-dot ${signal.severity}"></div>
          <div class="signal-text">${signal.description}</div>
        </div>
      `)
      .join("");
  } else {
    signalsSection.style.display = "none";
  }
}

function getAgentIcon(agentName: string): string {
  const name = agentName.toLowerCase();
  if (name.includes("url")) return "🔗";
  if (name.includes("domain")) return "🌐";
  if (name.includes("content")) return "📄";
  if (name.includes("heuristic")) return "🧠";
  return "🤖";
}

async function loadHistory() {
  const history = await getAnalysisHistory(10);

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

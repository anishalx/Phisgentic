// Orchestrator - Coordinates all agents and aggregates results with Critical Veto Logic

import { UrlAgent } from "./url-agent.js";
import { DomainAgent } from "./domain-agent.js";
import { ContentAgent } from "./content-agent.js";
import { HeuristicAgent } from "./heuristic-agent.js";
import { TesterAgent } from "./tester-agent.js";
import type { AgentResult, PageContent, FinalVerdict, AgentLog, Signal } from "../types/index.js";
import { CONFIG } from "../config/index.js";
import type { Page } from "playwright";

export interface OrchestratorResult {
  verdict: FinalVerdict;
  logs: AgentLog[];
}

export class Orchestrator {
  private urlAgent: UrlAgent;
  private domainAgent: DomainAgent;
  private contentAgent: ContentAgent;
  private heuristicAgent: HeuristicAgent;
  private testerAgent: TesterAgent;

  constructor() {
    this.urlAgent = new UrlAgent();
    this.domainAgent = new DomainAgent();
    this.contentAgent = new ContentAgent();
    this.heuristicAgent = new HeuristicAgent();
    this.testerAgent = new TesterAgent();
  }

  async analyzeUrl(
    url: string,
    onLog?: (log: AgentLog) => void,
    /** Optional: Provide an existing Playwright Page to reuse */
    externalPage?: Page,
  ): Promise<OrchestratorResult> {
    const startTime = Date.now();
    // Use local logs array per request to prevent race conditions
    const logs: AgentLog[] = [];

    const addLog = (agentId: string, agentName: string, message: string, type: AgentLog["type"] = "info") => {
      const log: AgentLog = {
        agentId,
        agentName,
        message,
        timestamp: Date.now(),
        type,
      };
      logs.push(log);
      if (onLog) {
        onLog(log);
      }
    };

    addLog("orchestrator", "Orchestrator", `Initiating multi-agent analysis of ${url}`, "info");

    // PERFORMANCE: Run ALL agents in parallel instead of waiting for TesterAgent first.
    // URL and Domain agents don't need browser data — they start immediately.
    // Content and Heuristic agents receive pageContent via a deferred promise
    // that resolves when TesterAgent completes.
    addLog("testerAgent", "Browser Tester", "Launching headless browser...", "info");
    addLog("urlAgent", "URL Scanner", "Analyzing URL structure and patterns...", "info");
    addLog("domainAgent", "Domain Intelligence", "Checking domain reputation and blocklists...", "info");
    addLog("contentAgent", "Content Analyzer", "Scanning page content for threats...", "info");
    addLog("heuristicAgent", "Behavior Detector", "Detecting social engineering patterns...", "info");

    // Create a deferred promise for pageContent so Content/Heuristic agents
    // can await it while URL/Domain agents run independently
    let resolvePageContent: (value: PageContent | undefined) => void;
    const pageContentPromise = new Promise<PageContent | undefined>((resolve) => {
      resolvePageContent = resolve;
    });

    let screenshot: string | undefined;
    let testerResult: (AgentResult & { screenshot?: string; pageContent?: PageContent }) | null = null;

    // Tester Agent promise — resolves the pageContent deferred when done
    const testerPromise = this.withTimeout(
      this.testerAgent.analyze(url, externalPage),
      CONFIG.ANALYSIS.TIMEOUT_MS,
    ).then((result) => {
      testerResult = result;
      if (result) {
        screenshot = result.screenshot;
        resolvePageContent!(result.pageContent);
        addLog("testerAgent", "Browser Tester",
          `Browser test complete - Risk: ${result.riskScore}/100`,
          result.riskScore > 50 ? "warning" : "success"
        );
      } else {
        resolvePageContent!(undefined);
      }
      return result;
    }).catch((error) => {
      resolvePageContent!(undefined);
      addLog("testerAgent", "Browser Tester", `Browser automation failed: ${error}`, "error");
      return null;
    });

    // EARLY EXIT: Run URL + Domain agents first (they are fast, no browser needed).
    // If both score very low (<10), the site is clearly safe — skip Content,
    // Heuristic, and Tester agents entirely (saves 5-10 seconds).
    const [urlResult, domainResult] = await Promise.all([
      this.withTimeout(this.urlAgent.analyze(url), CONFIG.ANALYSIS.TIMEOUT_MS).catch(() => null),
      this.withTimeout(this.domainAgent.analyze(url), CONFIG.ANALYSIS.TIMEOUT_MS).catch(() => null),
    ]);

    if (urlResult) {
      addLog("urlAgent", "URL Scanner",
        `Analysis complete - Risk: ${urlResult.riskScore}/100`,
        urlResult.riskScore > 60 ? "warning" : "success"
      );
    } else {
      addLog("urlAgent", "URL Scanner", "Analysis failed or timed out", "error");
    }

    if (domainResult) {
      addLog("domainAgent", "Domain Intelligence",
        `Analysis complete - Risk: ${domainResult.riskScore}/100`,
        domainResult.riskScore > 60 ? "warning" : "success"
      );
    } else {
      addLog("domainAgent", "Domain Intelligence", "Analysis failed or timed out", "error");
    }

    const urlScore = urlResult?.riskScore ?? 15;
    const domainScore = domainResult?.riskScore ?? 15;

    if (urlScore < 10 && domainScore < 10) {
      // Both fast agents agree: site looks safe. Skip heavy agents.
      addLog("orchestrator", "Orchestrator", "Early exit: URL + Domain both low-risk, skipping remaining agents", "info");
      // Cancel the tester if it's still running (we don't await it)
      resolvePageContent!(undefined);

      const earlyResults: AgentResult[] = [];
      if (urlResult) earlyResults.push(urlResult);
      if (domainResult) earlyResults.push(domainResult);

      const verdict = this.calculateVerdictWithVeto(url, earlyResults, undefined);

      addLog(
        "orchestrator",
        "Orchestrator",
        `Final verdict: ${verdict.action.toUpperCase()} (Score: ${verdict.overallRiskScore}/100) - ${Date.now() - startTime}ms [FAST]`,
        "success",
      );

      return { verdict, logs };
    }

    // Full analysis: run remaining agents in parallel
    const contentPromise = pageContentPromise.then((pageContent) =>
      this.contentAgent.analyze({ url, pageContent, externalPage })
    );

    const heuristicPromise = pageContentPromise.then((pageContent) =>
      this.heuristicAgent.analyze({ url, pageContent })
    );

    const remainingResults = await Promise.allSettled([
      testerPromise,
      contentPromise.then(r => this.withTimeout(Promise.resolve(r), CONFIG.ANALYSIS.TIMEOUT_MS)),
      heuristicPromise.then(r => this.withTimeout(Promise.resolve(r), CONFIG.ANALYSIS.TIMEOUT_MS)),
    ]);

    // Collect all results
    const agentResults: AgentResult[] = [];
    if (urlResult) agentResults.push(urlResult);
    if (domainResult) agentResults.push(domainResult);

    const remainingNames = ["Browser Tester", "Content Analyzer", "Behavior Detector"];
    const remainingIds = ["testerAgent", "contentAgent", "heuristicAgent"];

    for (let i = 0; i < remainingResults.length; i++) {
      const result = remainingResults[i];
      if (result.status === "fulfilled" && result.value) {
        agentResults.push(result.value);
        if (i > 0) { // Skip tester log (already logged above)
          const riskLevel = result.value.riskScore > 60 ? "warning" : "success";
          addLog(remainingIds[i], remainingNames[i],
            `Analysis complete - Risk: ${result.value.riskScore}/100`,
            riskLevel
          );
        }
      } else if (i > 0) {
        addLog(remainingIds[i], remainingNames[i], "Analysis failed or timed out", "error");
      }
    }

    // Calculate final verdict using Critical Veto Logic
    const verdict = this.calculateVerdictWithVeto(url, agentResults, screenshot);

    addLog(
      "orchestrator",
      "Orchestrator",
      `Final verdict: ${verdict.action.toUpperCase()} (Score: ${verdict.overallRiskScore}/100) - ${Date.now() - startTime}ms`,
      verdict.action === "block" ? "warning" : verdict.action === "warn" ? "warning" : "success",
    );

    console.log(
      `[Orchestrator] Analysis completed in ${Date.now() - startTime}ms`,
      verdict,
    );

    return {
      verdict,
      logs,
    };
  }

  /**
   * Check if URL belongs to a known safe domain
   */
  private isSafeDomain(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      return CONFIG.SAFE_DOMAINS.some(safe => 
        hostname === safe || hostname.endsWith(`.${safe}`)
      );
    } catch {
      return false;
    }
  }

  /**
   * CRITICAL VETO LOGIC:
   * 0. Known safe domains get fast-tracked (but still analyzed for informational purposes)
   * 1. If ANY agent detects a critical/veto signal → Immediate BLOCK
   * 2. If highest agent score > 70 → BLOCK (single agent conviction)
   * 3. If 2+ agents have score > 50 → BLOCK (consensus)
   * 4. Otherwise, use weighted average with lowered thresholds
   */
  private calculateVerdictWithVeto(
    url: string,
    agentResults: AgentResult[],
    screenshot?: string,
  ): FinalVerdict {
    if (agentResults.length === 0) {
      return {
        action: "warn",
        overallRiskScore: 60,
        confidence: 0.3,
        agentResults: [],
        summary: "Unable to analyze URL - all agents failed. Treat with caution.",
        url,
        timestamp: Date.now(),
        screenshot,
      };
    }

    // FAST-TRACK: Known safe domains get allow verdict
    if (this.isSafeDomain(url)) {
      return {
        action: "allow",
        overallRiskScore: 0,
        confidence: 0.99,
        agentResults,
        summary: "SAFE - This is a verified trusted domain.",
        url,
        timestamp: Date.now(),
        screenshot,
      };
    }

    // Collect all signals
    const allSignals = agentResults.flatMap((r) => r.signals);
    
    // VETO CHECK 1: Only NAMED critical signal types trigger immediate block.
    // We no longer veto on s.severity === "critical" because LLMs can hallucinate
    // critical severity on legitimate sites. Only the explicitly listed types
    // (blocklist, typosquatting, homograph, etc.) are unambiguous enough to auto-block.
    const criticalTypes = CONFIG.CRITICAL_VETO_SIGNALS as readonly string[];
    const vetoSignals = allSignals.filter(
      (s) => criticalTypes.includes(s.type)
    );
    
    if (vetoSignals.length > 0) {
      const maxScore = Math.max(...agentResults.map(r => r.riskScore));
      const vetoScore = Math.max(85, maxScore);
      
      return {
        action: "block",
        overallRiskScore: vetoScore,
        confidence: 0.95,
        agentResults,
        summary: this.generateVetoSummary(vetoSignals),
        url,
        timestamp: Date.now(),
        screenshot,
      };
    }

    // VETO CHECK 2: Single agent conviction (one agent very sure)
    const maxAgentScore = Math.max(...agentResults.map(r => r.riskScore));
    const maxScoreAgent = agentResults.find(r => r.riskScore === maxAgentScore);
    
    if (maxAgentScore >= 85) {
      return {
        action: "block",
        overallRiskScore: maxAgentScore,
        confidence: maxScoreAgent?.confidence || 0.8,
        agentResults,
        summary: this.generateHighRiskSummary(agentResults, maxAgentScore),
        url,
        timestamp: Date.now(),
        screenshot,
      };
    }

    // VETO CHECK 3: Consensus block (multiple agents highly suspicious)
    const suspiciousAgents = agentResults.filter(r => r.riskScore > 70);
    if (suspiciousAgents.length >= 2) {
      const avgSuspiciousScore = Math.round(
        suspiciousAgents.reduce((sum, r) => sum + r.riskScore, 0) / suspiciousAgents.length
      );
      
      return {
        action: "block",
        overallRiskScore: Math.max(65, avgSuspiciousScore),
        confidence: 0.85,
        agentResults,
        summary: this.generateConsensusSummary(suspiciousAgents),
        url,
        timestamp: Date.now(),
        screenshot,
      };
    }

    // Standard weighted average calculation for lower-risk URLs
    let totalWeight = 0;
    let weightedScore = 0;
    let weightedConfidence = 0;

    for (const result of agentResults) {
      const weight = CONFIG.AGENT_WEIGHTS[result.agentId] || 0.2;
      const effectiveWeight = weight * result.confidence;

      weightedScore += result.riskScore * effectiveWeight;
      weightedConfidence += result.confidence * weight;
      totalWeight += effectiveWeight;
    }

    const overallRiskScore = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 50;
    const confidence = Math.min(1, weightedConfidence);

    // Determine action based on thresholds
    let action: "allow" | "warn" | "block";
    if (overallRiskScore <= CONFIG.THRESHOLDS.ALLOW_MAX) {
      action = "allow";
    } else if (overallRiskScore >= CONFIG.THRESHOLDS.BLOCK_MIN) {
      action = "block";
    } else {
      action = "warn";
    }

    // High severity signals bump "allow" to "warn" — but ONLY if there are
    // multiple high signals OR at least one critical signal.
    // A single "high" signal (e.g., a login form on a legitimate site) is not
    // enough to override an otherwise-safe weighted score.
    const highSignalCount = allSignals.filter(s => s.severity === "high").length;
    const hasCriticalSignal = allSignals.some(s => s.severity === "critical");
    if ((highSignalCount >= 3 || hasCriticalSignal) && action === "allow") {
      action = "warn";
    }

    return {
      action,
      overallRiskScore,
      confidence,
      agentResults,
      summary: this.generateSummary(agentResults, overallRiskScore, action),
      url,
      timestamp: Date.now(),
      screenshot,
    };
  }

  private generateVetoSummary(vetoSignals: Signal[]): string {
    const reasons = vetoSignals
      .slice(0, 3)
      .map(s => s.description)
      .join("; ");
    
    return `BLOCKED - Critical threat detected: ${reasons}. This URL exhibits characteristics of phishing/malware.`;
  }

  private generateHighRiskSummary(results: AgentResult[], maxScore: number): string {
    const highestAgent = results.find(r => r.riskScore === maxScore);
    const explanation = highestAgent?.explanation || "Multiple risk factors detected";
    
    return `HIGH RISK (Score: ${maxScore}/100) - ${explanation}`;
  }

  private generateConsensusSummary(suspiciousAgents: AgentResult[]): string {
    const agentNames = suspiciousAgents.map(a => a.agentName).join(", ");
    const topConcerns = suspiciousAgents
      .flatMap(a => a.signals)
      .filter(s => s.severity === "high" || s.severity === "critical")
      .slice(0, 2)
      .map(s => s.description)
      .join("; ");
    
    return `BLOCKED - Multiple detection systems flagged this URL (${agentNames}). Concerns: ${topConcerns || "Suspicious patterns detected"}.`;
  }

  private generateSummary(
    results: AgentResult[],
    score: number,
    action: string,
  ): string {
    const allSignals = results.flatMap((r) => r.signals);
    const criticalSignals = allSignals.filter((s) => s.severity === "critical");
    const highSignals = allSignals.filter((s) => s.severity === "high");

    let summary = "";

    if (action === "block") {
      summary = `DANGEROUS (Score: ${score}/100) - `;
    } else if (action === "warn") {
      summary = `SUSPICIOUS (Score: ${score}/100) - `;
    } else {
      summary = `SAFE (Score: ${score}/100) - `;
    }

    if (criticalSignals.length > 0) {
      summary += `Critical issues: ${criticalSignals
        .map((s) => s.description)
        .slice(0, 2)
        .join("; ")}. `;
    } else if (highSignals.length > 0) {
      summary += `Concerns: ${highSignals
        .map((s) => s.description)
        .slice(0, 2)
        .join("; ")}. `;
    } else if (action === "allow") {
      summary += "No threats detected. This URL appears safe to visit.";
    } else {
      summary += "Some concerns detected. Proceed with caution.";
    }

    return summary.trim();
  }

  /**
   * FIXED: Timer leak — the setTimeout was never cleared if the promise resolved first.
   * Now properly clears the timeout in all cases.
   */
  private withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
  ): Promise<T | null> {
    let timeoutId: ReturnType<typeof setTimeout>;
    
    const timeoutPromise = new Promise<null>((resolve) => {
      timeoutId = setTimeout(() => resolve(null), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]).then((result) => {
      clearTimeout(timeoutId);
      return result;
    });
  }
}

// Export singleton
let orchestratorInstance: Orchestrator | null = null;

export function getOrchestrator(): Orchestrator {
  if (!orchestratorInstance) {
    orchestratorInstance = new Orchestrator();
  }
  return orchestratorInstance;
}

// Type definitions for the PhishGuard Dashboard

export interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
}

export interface AgentResult {
  agentId: string;
  agentName: string;
  riskScore: number;
  confidence: number;
  signals: Signal[];
  explanation: string;
  executionTimeMs: number;
}

export interface FinalVerdict {
  action: "allow" | "warn" | "block";
  overallRiskScore: number;
  confidence: number;
  agentResults: AgentResult[];
  summary: string;
  url: string;
  timestamp: number;
  screenshot?: string;
}

export interface AgentLog {
  agentId: string;
  agentName: string;
  message: string;
  timestamp: number;
  type: "info" | "warning" | "error" | "success";
}

export interface ScanResponse {
  success: boolean;
  verdict?: FinalVerdict;
  error?: string;
  logs: AgentLog[];
}

export type ScanStatus = "idle" | "scanning" | "complete" | "error";

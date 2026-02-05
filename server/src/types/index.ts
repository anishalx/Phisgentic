// Type definitions for the Multi-Agent Phishing Detection API

export interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
}

export interface AgentResult {
  agentId: string;
  agentName: string;
  riskScore: number; // 0-100
  confidence: number; // 0-1
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
  screenshot?: string; // Base64 encoded screenshot from Tester Agent
}

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  success: boolean;
  verdict?: FinalVerdict;
  error?: string;
  logs: AgentLog[];
}

export interface AgentLog {
  agentId: string;
  agentName: string;
  message: string;
  timestamp: number;
  type: "info" | "warning" | "error" | "success";
}

export interface PageContent {
  title: string;
  forms: FormData[];
  links: LinkData[];
  scripts: string[];
  metaTags: Record<string, string>;
  textContent: string;
  hasPasswordField: boolean;
  hasLoginForm: boolean;
}

export interface FormData {
  action: string;
  method: string;
  hasPasswordField: boolean;
  inputTypes: string[];
}

export interface LinkData {
  href: string;
  text: string;
  isExternal: boolean;
}

// Groq API types
export interface GroqMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface GroqRequest {
  model: string;
  messages: GroqMessage[];
  temperature?: number;
  max_completion_tokens?: number;
  response_format?: {
    type: "json_schema";
    json_schema: {
      name: string;
      schema: object;
    };
  };
}

export interface GroqResponse {
  id: string;
  choices: {
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }[];
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

// Tester Agent specific types
export interface BrowserTestResult {
  screenshot: string; // Base64 encoded
  finalUrl: string;
  redirectChain: string[];
  hasPopups: boolean;
  hasOverlays: boolean;
  downloadAttempted: boolean;
  permissionRequests: string[];
  consoleErrors: string[];
  networkErrors: string[];
  loadTimeMs: number;
  safetyWarning?: string;
}

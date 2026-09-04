// Type definitions for the Multi-Agent Phishing Detection System

export interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
  origin?: "local" | "llm" | "synthetic"; // server-side provenance; "llm" never vetoes
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
}

export interface AnalysisRequest {
  url: string;
  pageContent?: PageContent;
  tabId?: number;
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

export type MessageType =
  | "ANALYZE_URL"
  | "PAGE_CONTENT"
  | "ANALYSIS_RESULT"
  | "SHOW_WARNING"
  | "USER_OVERRIDE"
  | "GET_STATUS";

export interface Message {
  type: MessageType;
  payload: unknown;
}

export interface AnalyzeUrlMessage extends Message {
  type: "ANALYZE_URL";
  payload: {
    url: string;
    tabId: number;
  };
}

export interface PageContentMessage extends Message {
  type: "PAGE_CONTENT";
  payload: PageContent;
}

export interface AnalysisResultMessage extends Message {
  type: "ANALYSIS_RESULT";
  payload: FinalVerdict;
}

export interface ShowWarningMessage extends Message {
  type: "SHOW_WARNING";
  payload: FinalVerdict;
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

// Storage types
export interface StorageData {
  apiKey?: string;
  settings: Settings;
  analysisHistory: AnalysisHistoryEntry[];
  whitelist: string[];
}

export interface Settings {
  enabled: boolean;
  blockThreshold: number;
  warnThreshold: number;
  showNotifications: boolean;
  autoBlock: boolean;
}

export interface AnalysisHistoryEntry {
  url: string;
  verdict: FinalVerdict;
  timestamp: number;
  userAction?: "proceeded" | "blocked";
}

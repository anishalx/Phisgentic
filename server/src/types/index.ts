// Type definitions for the Multi-Agent Phishing Detection API

export interface Signal {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  value: string | number | boolean;
  description: string;
  /**
   * Who produced this signal:
   * - "local": deterministic code detection (trusted)
   * - "llm":   suggested by Groq/Gemini (never triggers a veto block)
   * - "synthetic": injected by external intel like Google Safe Browsing (trusted)
   * Absent on legacy/inline signals, which are treated as local.
   */
  origin?: "local" | "llm" | "synthetic";
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
  modelComparison?: ModelComparison; // Dual-model consensus info
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
  forms: PageFormData[];
  links: LinkData[];
  scripts: string[];
  metaTags: Record<string, string>;
  textContent: string;
  hasPasswordField: boolean;
  hasLoginForm: boolean;
}

// Renamed from FormData to PageFormData to avoid shadowing the global FormData
export interface PageFormData {
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
export interface GroqTextContent {
  type: "text";
  text: string;
}

export interface GroqImageContent {
  type: "image_url";
  image_url: {
    url: string; // Base64 data URL or HTTP URL
  };
}

export type GroqContentPart = GroqTextContent | GroqImageContent;

export interface GroqMessage {
  role: "system" | "user" | "assistant";
  content: string | GroqContentPart[];
}

export interface GroqRequest {
  model: string;
  messages: GroqMessage[];
  temperature?: number;
  max_completion_tokens?: number;
  response_format?: {
    type: "json_object"; // Groq Llama models support json_object, NOT json_schema
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

// Form Hijacking Detection types
export interface FormAnalysis {
  formIndex: number;
  action: string;
  actionDomain: string;
  method: string;
  hasPasswordField: boolean;
  hasCreditCardField: boolean;
  isCrossOrigin: boolean;
  inputFields: string[];
}

// Vision/Logo Detection types
export interface LogoDetectionResult {
  brandDetected: string | null;
  confidence: number;
  isDomainMismatch: boolean;
  legitimateDomains: string[];
  explanation: string;
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
  // New: Form Hijacking Detection
  formAnalysis: FormAnalysis[];
  // New: Logo Detection
  logoDetection?: LogoDetectionResult;
  // Page content extracted during browser test (passed to Content/Heuristic agents)
  pageContent?: PageContent;
}

// Dual-Model Consensus types
export interface LLMAnalysisResult {
  riskScore: number;
  confidence: number;
  signals: Signal[];
  explanation: string;
  model: string; // Which model produced this result
  latencyMs: number;
}

export interface ModelComparison {
  groqResult?: LLMAnalysisResult;
  geminiResult?: LLMAnalysisResult;
  consensusScore: number;
  scoreDifference: number;
  strategy: string; // Which consensus strategy was used
  agreed: boolean; // Whether models agreed within threshold
}

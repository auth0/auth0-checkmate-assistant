export type EvidenceBasis = "checkmate_report" | "auth0_live";

export interface ChatHistoryMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ChatAnswerItem {
  text: string;
  basis: EvidenceBasis;
  findingIds: string[];
}

export interface ChatAnswerSection {
  title: string;
  items: ChatAnswerItem[];
}

export interface ChatActionConfirmation {
  question: string;
  findingIds: string[];
}

export interface ChatSuggestedQuestion {
  question: string;
  findingIds: string[];
}

export interface ChatAnswer {
  headline: string;
  headlineFindingIds: string[];
  sections: ChatAnswerSection[];
  evidenceGaps: string[];
  suggestedQuestions: ChatSuggestedQuestion[];
  actionConfirmations: ChatActionConfirmation[];
}

export interface ReportReference {
  reportId: string;
  tenant?: string;
  generatedAt?: string;
  totalFindings?: number;
  findingsOnly?: boolean;
  stale?: boolean;
}

export interface ToolUseRecord {
  server: "checkmate" | "auth0";
  tool: string;
  status: "succeeded" | "failed";
  retrievedAt: string;
  findingIds: string[];
  error?: string;
}

export interface ChatResult {
  answer: ChatAnswer;
  evidence: {
    report?: ReportReference;
    findingIds: string[];
    tools: ToolUseRecord[];
  };
  remediation?: {
    profile: "dev";
    actions: Array<{
      question: string;
      available: boolean;
      recommendationId?: string;
    }>;
  };
}

export interface McpToolDefinition {
  server: "checkmate" | "auth0";
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface McpCallResult {
  server: "checkmate" | "auth0";
  tool: string;
  isError: boolean;
  value: unknown;
}

export interface McpServerStatus {
  enabled: boolean;
  connected: boolean;
  readOnly: true;
  error?: string;
}

export interface ChatStatus {
  aiProvider: "openai" | "anthropic" | "google";
  model: string;
  remediationUrl: string;
  checkmate: McpServerStatus;
  auth0: McpServerStatus;
  devRemediation: {
    enabled: boolean;
    planningEnabled: boolean;
    profile: "dev";
    tenantDomain?: string;
    disabledReason?: string;
    confirmationRequired: true;
  };
  scanTargets: Record<
    "dev" | "prod",
    {
      configured: boolean;
      tenantDomain?: string;
      changesSupported: boolean;
    }
  >;
  scanInProgress: boolean;
  activeEnvironment?: {
    profile: "dev" | "prod";
    tenantDomain: string;
    reportId: string;
    changesSupported: boolean;
  };
  report?: ReportReference & {
    counts?: {
      passed: number;
      failed: number;
      warning: number;
      unknown: number;
    };
  };
}

export interface DevPlanChange {
  actionId: string;
  findingId: string;
  resourceName: string;
  configPath: string;
  currentValue: unknown;
  targetValue: unknown;
  description: string;
}

export interface DevApiCallPreview {
  id: string;
  method: "PATCH";
  url: string;
  endpoint: string;
  resourceName: string;
  status: "ready" | "already_applied";
  changes: DevPlanChange[];
  body?: Record<string, unknown>;
  sensitiveValuesRedacted: boolean;
}

export interface DevPlanPreview {
  planId: string;
  profile: "dev";
  tenantDomain: string;
  sourceReport: string;
  generatedAt: string;
  expiresAt: string;
  planSha256: string;
  executionEnabled: boolean;
  calls: DevApiCallPreview[];
}

export type AiProvider = "openai" | "anthropic" | "google";

export type AiReasoningEffort = "low" | "medium" | "high";

export interface ModelMessage {
  role: "user" | "assistant" | "developer";
  content: string;
}

export interface ModelTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface ModelToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ModelToolResult {
  callId: string;
  name: string;
  output: unknown;
  isError?: boolean;
}

export interface ModelRequest {
  instructions: string;
  messages: ModelMessage[];
  tools: ModelTool[];
  toolResults?: ModelToolResult[];
  continuation?: unknown;
}

export interface ModelTurn {
  toolCalls: ModelToolCall[];
  outputParsed: unknown;
  outputText: string;
  continuation?: unknown;
}

export interface ChatModel {
  create(request: ModelRequest): Promise<ModelTurn>;
}

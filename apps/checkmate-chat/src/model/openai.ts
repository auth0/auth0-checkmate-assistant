import OpenAI from "openai";
import { zodTextFormat } from "openai/helpers/zod";
import type {
  FunctionTool,
  ResponseInput,
  ResponseOutputItem,
} from "openai/resources/responses/responses";
import { chatAnswerSchema } from "../schema.js";
import type {
  AiReasoningEffort,
  ChatModel,
  ModelRequest,
  ModelTool,
  ModelTurn,
} from "./contracts.js";

interface OpenAiContinuation {
  provider: "openai";
  input: ResponseInput;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseArguments(value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(value);
  if (!isObject(parsed)) {
    throw new Error("The OpenAI tool arguments were not an object.");
  }
  return parsed;
}

function jsonText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value) ?? "null";
}

function toOpenAiTool(tool: ModelTool): FunctionTool {
  return {
    type: "function",
    name: tool.name,
    ...(tool.description ? { description: tool.description } : {}),
    parameters: tool.inputSchema,
    strict: false,
  };
}

function stripSdkParserMetadata(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) stripSdkParserMetadata(item);
    return;
  }
  if (!isObject(value)) return;
  delete value.parsed;
  delete value.parsed_arguments;
  for (const item of Object.values(value)) stripSdkParserMetadata(item);
}

function responseOutputForInput(output: ResponseOutputItem[]): ResponseInput {
  const copy: unknown = structuredClone(output);
  stripSdkParserMetadata(copy);
  return copy as ResponseInput;
}

function continuationInput(
  continuation: unknown,
  request: ModelRequest,
): ResponseInput {
  const previous = continuation as OpenAiContinuation | undefined;
  const input: ResponseInput =
    previous?.provider === "openai"
      ? structuredClone(previous.input)
      : request.messages.map((message) => ({
          type: "message" as const,
          role: message.role,
          content: message.content,
        }));

  for (const result of request.toolResults ?? []) {
    input.push({
      type: "function_call_output",
      call_id: result.callId,
      output: jsonText(result.output),
    });
  }
  return input;
}

export class OpenAiChatModel implements ChatModel {
  private readonly client: OpenAI;

  constructor(
    apiKey: string,
    private readonly model: string,
    private readonly reasoningEffort: AiReasoningEffort,
    timeoutMs: number,
    client?: OpenAI,
  ) {
    this.client =
      client ?? new OpenAI({ apiKey, timeout: timeoutMs, maxRetries: 2 });
  }

  async create(request: ModelRequest): Promise<ModelTurn> {
    const input = continuationInput(request.continuation, request);
    const response = await this.client.responses.parse({
      model: this.model,
      instructions: request.instructions,
      input,
      tools: request.tools.map(toOpenAiTool),
      tool_choice: "auto",
      parallel_tool_calls: false,
      reasoning: { effort: this.reasoningEffort },
      text: {
        format: zodTextFormat(chatAnswerSchema, "checkmate_chat_answer"),
        verbosity: "low",
      },
      include: ["reasoning.encrypted_content"],
      max_output_tokens: 4_000,
      store: false,
    });
    return {
      toolCalls: response.output
        .filter((item) => item.type === "function_call")
        .map((call) => ({
          id: call.call_id,
          name: call.name,
          arguments: parseArguments(call.arguments),
        })),
      outputParsed: response.output_parsed,
      outputText: response.output_text,
      continuation: {
        provider: "openai",
        input: [...input, ...responseOutputForInput(response.output)],
      } satisfies OpenAiContinuation,
    };
  }
}

import Anthropic from "@anthropic-ai/sdk";
import { jsonSchemaOutputFormat } from "@anthropic-ai/sdk/helpers/json-schema";
import type {
  ContentBlockParam,
  MessageParam,
  Tool,
} from "@anthropic-ai/sdk/resources/messages/messages";
import { zodToJsonSchema } from "zod-to-json-schema";
import { chatAnswerSchema } from "../schema.js";
import type {
  AiReasoningEffort,
  ChatModel,
  ModelRequest,
  ModelTool,
  ModelTurn,
} from "./contracts.js";

interface AnthropicContinuation {
  provider: "anthropic";
  messages: MessageParam[];
}

function jsonText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value) ?? "null";
}

function toolArguments(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("The Anthropic tool arguments were not an object.");
  }
  return value as Record<string, unknown>;
}

function toAnthropicTool(tool: ModelTool): Tool {
  return {
    name: tool.name,
    ...(tool.description ? { description: tool.description } : {}),
    input_schema: tool.inputSchema as Tool.InputSchema,
    strict: false,
  };
}

function initialMessages(request: ModelRequest): MessageParam[] {
  return request.messages
    .filter((message) => message.role !== "developer")
    .map((message) => {
      const role: "user" | "assistant" =
        message.role === "assistant" ? "assistant" : "user";
      return { role, content: message.content };
    });
}

function systemInstructions(request: ModelRequest): string {
  const developerContext = request.messages
    .filter((message) => message.role === "developer")
    .map((message) => message.content);
  return [request.instructions, ...developerContext].join("\n\n");
}

function continuationMessages(
  continuation: unknown,
  request: ModelRequest,
): MessageParam[] {
  const previous = continuation as AnthropicContinuation | undefined;
  const messages =
    previous?.provider === "anthropic"
      ? structuredClone(previous.messages)
      : initialMessages(request);
  if ((request.toolResults?.length ?? 0) > 0) {
    messages.push({
      role: "user",
      content: (request.toolResults ?? []).map((result) => ({
        type: "tool_result" as const,
        tool_use_id: result.callId,
        content: jsonText(result.output),
        ...(result.isError ? { is_error: true } : {}),
      })),
    });
  }
  return messages;
}

export class AnthropicChatModel implements ChatModel {
  private readonly client: Anthropic;

  constructor(
    apiKey: string,
    private readonly model: string,
    private readonly reasoningEffort: AiReasoningEffort,
    timeoutMs: number,
    client?: Anthropic,
  ) {
    this.client =
      client ?? new Anthropic({ apiKey, timeout: timeoutMs, maxRetries: 2 });
  }

  async create(request: ModelRequest): Promise<ModelTurn> {
    const messages = continuationMessages(request.continuation, request);
    const response = await this.client.messages.parse({
      model: this.model,
      max_tokens: 4_000,
      system: systemInstructions(request),
      messages,
      tools: request.tools.map(toAnthropicTool),
      tool_choice: { type: "auto", disable_parallel_tool_use: true },
      output_config: {
        effort: this.reasoningEffort,
        format: jsonSchemaOutputFormat(
          zodToJsonSchema(chatAnswerSchema, {
            target: "openApi3",
            $refStrategy: "none",
          }) as Parameters<typeof jsonSchemaOutputFormat>[0],
        ),
      },
    });
    const responseContent = structuredClone(
      response.content,
    ) as ContentBlockParam[];
    return {
      toolCalls: response.content
        .filter((block) => block.type === "tool_use")
        .map((call) => ({
          id: call.id,
          name: call.name,
          arguments: toolArguments(call.input),
        })),
      outputParsed: response.parsed_output,
      outputText: response.content
        .filter((block) => block.type === "text")
        .map((block) => block.text)
        .join("\n"),
      continuation: {
        provider: "anthropic",
        messages: [
          ...messages,
          { role: "assistant", content: responseContent },
        ],
      } satisfies AnthropicContinuation,
    };
  }
}

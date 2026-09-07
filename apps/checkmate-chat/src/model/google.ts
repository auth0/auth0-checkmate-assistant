import { GoogleGenAI, type Interactions } from "@google/genai";
import { zodToJsonSchema } from "zod-to-json-schema";
import { chatAnswerSchema } from "../schema.js";
import type {
  AiReasoningEffort,
  ChatModel,
  ModelMessage,
  ModelRequest,
  ModelTurn,
} from "./contracts.js";

type InteractionStep = Interactions.Step;

interface GoogleContinuation {
  provider: "google";
  steps: InteractionStep[];
}

const GOOGLE_SCHEMA_CONSTRAINTS = new Set([
  "additionalProperties",
  "minItems",
  "maxItems",
  "minLength",
  "maxLength",
]);

function googleResponseSchema(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(googleResponseSchema);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !GOOGLE_SCHEMA_CONSTRAINTS.has(key))
      .map(([key, nested]) => [key, googleResponseSchema(nested)]),
  );
}

const responseSchema = googleResponseSchema(
  zodToJsonSchema(chatAnswerSchema, {
    target: "openApi3",
    $refStrategy: "none",
  }),
);

function boundedText(value: unknown, maximum: number): unknown {
  return typeof value === "string" ? value.slice(0, maximum) : value;
}

function boundedArray(
  value: unknown,
  maximum: number,
  normalize: (item: unknown) => unknown,
): unknown {
  return Array.isArray(value) ? value.slice(0, maximum).map(normalize) : value;
}

function boundedTextArray(
  value: unknown,
  maximum: number,
  textMaximum: number,
): unknown {
  return boundedArray(value, maximum, (item) => boundedText(item, textMaximum));
}

function normalizedRecord(
  value: unknown,
  normalize: (record: Record<string, unknown>) => void,
): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return value;
  }
  const record = { ...(value as Record<string, unknown>) };
  normalize(record);
  return record;
}

function normalizeGoogleAnswer(value: unknown): unknown {
  return normalizedRecord(value, (answer) => {
    answer.headline = boundedText(answer.headline, 240);
    answer.headlineFindingIds = boundedTextArray(
      answer.headlineFindingIds,
      4,
      200,
    );
    answer.sections = boundedArray(answer.sections, 6, (section) =>
      normalizedRecord(section, (sectionRecord) => {
        sectionRecord.title = boundedText(sectionRecord.title, 120);
        sectionRecord.items = boundedArray(sectionRecord.items, 8, (item) =>
          normalizedRecord(item, (itemRecord) => {
            itemRecord.text = boundedText(itemRecord.text, 800);
            itemRecord.findingIds = boundedTextArray(
              itemRecord.findingIds,
              4,
              200,
            );
          }),
        );
      }),
    );
    answer.evidenceGaps = boundedTextArray(answer.evidenceGaps, 6, 400);
    answer.suggestedQuestions = boundedArray(
      answer.suggestedQuestions,
      4,
      (question) =>
        normalizedRecord(question, (questionRecord) => {
          questionRecord.question = boundedText(questionRecord.question, 180);
          questionRecord.findingIds = boundedTextArray(
            questionRecord.findingIds,
            4,
            200,
          );
        }),
    );
    answer.actionConfirmations = boundedArray(
      answer.actionConfirmations,
      1,
      (confirmation) =>
        normalizedRecord(confirmation, (confirmationRecord) => {
          confirmationRecord.question = boundedText(
            confirmationRecord.question,
            220,
          );
          confirmationRecord.findingIds = boundedTextArray(
            confirmationRecord.findingIds,
            4,
            200,
          );
        }),
    );
  });
}

function textContent(text: string): { type: "text"; text: string } {
  return { type: "text", text };
}

function messageStep(message: ModelMessage): InteractionStep | undefined {
  if (message.role === "developer") return undefined;
  return message.role === "user"
    ? { type: "user_input", content: [textContent(message.content)] }
    : { type: "model_output", content: [textContent(message.content)] };
}

function systemInstructions(request: ModelRequest): string {
  const developerContext = request.messages
    .filter((message) => message.role === "developer")
    .map((message) => message.content);
  return [request.instructions, ...developerContext].join("\n\n");
}

function interactionSteps(
  continuation: unknown,
  request: ModelRequest,
): InteractionStep[] {
  const previous = continuation as GoogleContinuation | undefined;
  const steps =
    previous?.provider === "google"
      ? structuredClone(previous.steps)
      : request.messages
          .map(messageStep)
          .filter((step): step is InteractionStep => Boolean(step));
  for (const result of request.toolResults ?? []) {
    steps.push({
      type: "function_result",
      call_id: result.callId,
      name: result.name,
      ...(result.isError ? { is_error: true } : {}),
      result: [textContent(JSON.stringify(result.output) ?? "null")],
    });
  }
  return steps;
}

function parseOutput(text: string | undefined): unknown {
  if (!text) return null;
  try {
    return normalizeGoogleAnswer(JSON.parse(text) as unknown);
  } catch {
    return null;
  }
}

function toolArguments(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("The Gemini tool arguments were not an object.");
  }
  return value as Record<string, unknown>;
}

export class GoogleChatModel implements ChatModel {
  private readonly client: GoogleGenAI;

  constructor(
    apiKey: string,
    private readonly model: string,
    private readonly reasoningEffort: AiReasoningEffort,
    private readonly timeoutMs: number,
    client?: GoogleGenAI,
  ) {
    this.client = client ?? new GoogleGenAI({ apiKey });
  }

  async create(request: ModelRequest): Promise<ModelTurn> {
    const steps = interactionSteps(request.continuation, request);
    const interaction = await this.client.interactions.create(
      {
        model: this.model,
        store: false,
        system_instruction: systemInstructions(request),
        input: steps,
        tools: request.tools.map((tool) => ({
          type: "function" as const,
          name: tool.name,
          ...(tool.description ? { description: tool.description } : {}),
          parameters: tool.inputSchema,
        })),
        response_format: {
          type: "text",
          mime_type: "application/json",
          // Gemini can reject deeply nested schemas when every Zod bound is
          // represented in the provider grammar. Keep the provider schema to
          // the required shape and enforce all bounds locally with Zod.
          schema: responseSchema,
        },
        generation_config: {
          max_output_tokens: 4_000,
          thinking_level: this.reasoningEffort,
          tool_choice: "auto",
        },
      },
      { timeout: this.timeoutMs },
    );
    const responseSteps = interaction.steps;
    return {
      toolCalls: responseSteps
        .filter((step) => step.type === "function_call")
        .map((call) => ({
          id: call.id,
          name: call.name,
          arguments: toolArguments(call.arguments),
        })),
      outputParsed: parseOutput(interaction.output_text),
      outputText: interaction.output_text ?? "",
      continuation: {
        provider: "google",
        steps: [...steps, ...structuredClone(responseSteps)],
      } satisfies GoogleContinuation,
    };
  }
}

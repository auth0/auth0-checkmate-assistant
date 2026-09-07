import type Anthropic from "@anthropic-ai/sdk";
import type { GoogleGenAI } from "@google/genai";
import type OpenAI from "openai";
import { describe, expect, it, vi } from "vitest";
import { AnthropicChatModel } from "../apps/checkmate-chat/src/model/anthropic.js";
import type { ModelRequest } from "../apps/checkmate-chat/src/model/contracts.js";
import { GoogleChatModel } from "../apps/checkmate-chat/src/model/google.js";
import { OpenAiChatModel } from "../apps/checkmate-chat/src/model/openai.js";
import { chatAnswerSchema } from "../apps/checkmate-chat/src/schema.js";

const parsedAnswer = {
  headline: "Enable breached-password detection.",
  headlineFindingIds: ["finding-1"],
  sections: [
    {
      title: "Recommendation",
      items: [
        {
          text: "Enable the control.",
          basis: "checkmate_report",
          findingIds: ["finding-1"],
        },
      ],
    },
  ],
  evidenceGaps: [],
  suggestedQuestions: [],
  actionConfirmations: [],
};

const initialRequest: ModelRequest = {
  instructions: "Use only CheckMate evidence.",
  messages: [
    { role: "developer", content: '{"reportId":"report.json"}' },
    { role: "user", content: "What should I do first?" },
  ],
  tools: [
    {
      name: "checkmate_get_security_topic_context",
      description: "Read bounded report evidence.",
      inputSchema: {
        type: "object",
        properties: { topic: { type: "string" } },
        required: ["topic"],
      },
    },
  ],
};

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Expected an object in the mocked provider request.");
  }
  return value as Record<string, unknown>;
}

function mockRequest(
  calls: unknown[][],
  index: number,
): Record<string, unknown> {
  return asObject(calls[index]?.[0]);
}

function collectKeys(node: unknown, keys: Set<string>): void {
  if (Array.isArray(node)) {
    for (const item of node) collectKeys(item, keys);
  } else if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      keys.add(key);
      collectKeys(value, keys);
    }
  }
}

describe("chat model provider adapters", () => {
  it("translates the neutral tool loop to OpenAI Responses without storage", async () => {
    const parse = vi
      .fn()
      .mockResolvedValueOnce({
        output: [
          {
            type: "function_call",
            call_id: "openai-call",
            name: "checkmate_get_security_topic_context",
            arguments: '{"topic":"credential_stuffing"}',
          },
        ],
        output_parsed: null,
        output_text: "",
      })
      .mockResolvedValueOnce({
        output: [],
        output_parsed: parsedAnswer,
        output_text: JSON.stringify(parsedAnswer),
      });
    const client = { responses: { parse } } as unknown as OpenAI;
    const model = new OpenAiChatModel(
      "openai-secret",
      "gpt-test",
      "high",
      180_000,
      client,
    );

    const first = await model.create(initialRequest);
    expect(first.toolCalls).toEqual([
      {
        id: "openai-call",
        name: "checkmate_get_security_topic_context",
        arguments: { topic: "credential_stuffing" },
      },
    ]);
    expect(parse.mock.calls[0]?.[0]).toEqual(
      expect.objectContaining({
        model: "gpt-test",
        store: false,
        parallel_tool_calls: false,
        reasoning: { effort: "high" },
      }),
    );

    const second = await model.create({
      ...initialRequest,
      continuation: first.continuation,
      toolResults: [
        {
          callId: "openai-call",
          name: "checkmate_get_security_topic_context",
          output: { findings: [{ findingId: "finding-1" }] },
        },
      ],
    });
    expect(second.outputParsed).toEqual(parsedAnswer);
    expect(
      mockRequest(parse.mock.calls as unknown[][], 1).input,
    ).toContainEqual(
      expect.objectContaining({
        type: "function_call_output",
        call_id: "openai-call",
      }),
    );
  });

  it("translates the neutral tool loop to Claude tool-use blocks", async () => {
    const parse = vi
      .fn()
      .mockResolvedValueOnce({
        content: [
          {
            type: "tool_use",
            id: "claude-call",
            name: "checkmate_get_security_topic_context",
            input: { topic: "credential_stuffing" },
          },
        ],
        parsed_output: null,
      })
      .mockResolvedValueOnce({
        content: [{ type: "text", text: JSON.stringify(parsedAnswer) }],
        parsed_output: parsedAnswer,
      });
    const client = { messages: { parse } } as unknown as Anthropic;
    const model = new AnthropicChatModel(
      "anthropic-secret",
      "claude-test",
      "high",
      180_000,
      client,
    );

    const first = await model.create(initialRequest);
    expect(first.toolCalls).toEqual([
      {
        id: "claude-call",
        name: "checkmate_get_security_topic_context",
        arguments: { topic: "credential_stuffing" },
      },
    ]);
    const firstRequest = mockRequest(parse.mock.calls as unknown[][], 0);
    expect(firstRequest.model).toBe("claude-test");
    expect(firstRequest.system).toContain("report.json");
    expect(firstRequest.tool_choice).toEqual({
      type: "auto",
      disable_parallel_tool_use: true,
    });
    expect(asObject(firstRequest.output_config).effort).toBe("high");

    const second = await model.create({
      ...initialRequest,
      continuation: first.continuation,
      toolResults: [
        {
          callId: "claude-call",
          name: "checkmate_get_security_topic_context",
          output: { findings: [{ findingId: "finding-1" }] },
        },
      ],
    });
    const messages = mockRequest(parse.mock.calls as unknown[][], 1).messages;
    expect(Array.isArray(messages)).toBe(true);
    const lastMessage = Array.isArray(messages)
      ? (messages as unknown[]).at(-1)
      : undefined;
    expect(lastMessage).toEqual(
      expect.objectContaining({
        role: "user",
        content: [
          expect.objectContaining({
            type: "tool_result",
            tool_use_id: "claude-call",
          }),
        ],
      }),
    );
    expect(second.outputParsed).toEqual(parsedAnswer);
  });

  it("rejects malformed Claude tool arguments", async () => {
    const parse = vi.fn().mockResolvedValue({
      content: [
        {
          type: "tool_use",
          id: "claude-call",
          name: "checkmate_get_security_topic_context",
          input: ["not", "an", "object"],
        },
      ],
      parsed_output: null,
    });
    const client = { messages: { parse } } as unknown as Anthropic;
    const model = new AnthropicChatModel(
      "anthropic-secret",
      "claude-test",
      "high",
      180_000,
      client,
    );

    await expect(model.create(initialRequest)).rejects.toThrow(
      "The Anthropic tool arguments were not an object.",
    );
  });

  it("translates the neutral tool loop to stateless Gemini interactions", async () => {
    const create = vi
      .fn()
      .mockResolvedValueOnce({
        steps: [
          { type: "thought", signature: "opaque-thought" },
          {
            type: "function_call",
            id: "gemini-call",
            name: "checkmate_get_security_topic_context",
            arguments: { topic: "credential_stuffing" },
          },
        ],
        output_text: "",
      })
      .mockResolvedValueOnce({
        steps: [
          {
            type: "model_output",
            content: [{ type: "text", text: JSON.stringify(parsedAnswer) }],
          },
        ],
        output_text: JSON.stringify(parsedAnswer),
      });
    const client = { interactions: { create } } as unknown as GoogleGenAI;
    const model = new GoogleChatModel(
      "gemini-secret",
      "gemini-test",
      "high",
      180_000,
      client,
    );

    const first = await model.create(initialRequest);
    expect(first.toolCalls).toEqual([
      {
        id: "gemini-call",
        name: "checkmate_get_security_topic_context",
        arguments: { topic: "credential_stuffing" },
      },
    ]);
    const firstRequest = mockRequest(create.mock.calls as unknown[][], 0);
    expect(firstRequest.model).toBe("gemini-test");
    expect(firstRequest.store).toBe(false);
    expect(firstRequest.system_instruction).toContain("report.json");
    const responseFormat = asObject(firstRequest.response_format);
    expect(responseFormat.type).toBe("text");
    expect(responseFormat.mime_type).toBe("application/json");
    expect(asObject(responseFormat.schema)).not.toEqual({});
    expect(firstRequest.generation_config).toEqual(
      expect.objectContaining({
        thinking_level: "high",
        tool_choice: "auto",
      }),
    );
    expect((create.mock.calls as unknown[][])[0]?.[1]).toEqual({
      timeout: 180_000,
    });

    const second = await model.create({
      ...initialRequest,
      continuation: first.continuation,
      toolResults: [
        {
          callId: "gemini-call",
          name: "checkmate_get_security_topic_context",
          output: { findings: [{ findingId: "finding-1" }] },
        },
      ],
    });
    expect(
      mockRequest(create.mock.calls as unknown[][], 1).input,
    ).toContainEqual(
      expect.objectContaining({
        type: "function_result",
        call_id: "gemini-call",
      }),
    );
    expect(second.outputParsed).toEqual(parsedAnswer);
  });

  it("rejects malformed Gemini tool arguments", async () => {
    const create = vi.fn().mockResolvedValue({
      steps: [
        {
          type: "function_call",
          id: "gemini-call",
          name: "checkmate_get_security_topic_context",
          arguments: "not-an-object",
        },
      ],
      output_text: "",
    });
    const client = { interactions: { create } } as unknown as GoogleGenAI;
    const model = new GoogleChatModel(
      "gemini-secret",
      "gemini-test",
      "high",
      180_000,
      client,
    );

    await expect(model.create(initialRequest)).rejects.toThrow(
      "The Gemini tool arguments were not an object.",
    );
  });

  it("strips unsupported JSON Schema keywords from the Gemini response schema", async () => {
    const create = vi.fn().mockResolvedValue({
      steps: [
        {
          type: "model_output",
          content: [{ type: "text", text: JSON.stringify(parsedAnswer) }],
        },
      ],
      output_text: JSON.stringify(parsedAnswer),
    });
    const client = { interactions: { create } } as unknown as GoogleGenAI;
    const model = new GoogleChatModel(
      "gemini-secret",
      "gemini-test",
      "high",
      180_000,
      client,
    );

    await model.create(initialRequest);

    const responseFormat = asObject(
      mockRequest(create.mock.calls as unknown[][], 0).response_format,
    );
    const keys = new Set<string>();
    collectKeys(responseFormat.schema, keys);
    for (const forbidden of [
      "minItems",
      "maxItems",
      "minLength",
      "maxLength",
      "pattern",
      "additionalProperties",
      "$schema",
    ]) {
      expect(keys.has(forbidden)).toBe(false);
    }
    // Structural keywords the validator accepts are preserved.
    expect(keys.has("enum")).toBe(true);
    expect(keys.has("required")).toBe(true);
  });

  it("forwards tool parameter schemas to Gemini unchanged", async () => {
    const create = vi.fn().mockResolvedValue({
      steps: [
        {
          type: "model_output",
          content: [{ type: "text", text: JSON.stringify(parsedAnswer) }],
        },
      ],
      output_text: JSON.stringify(parsedAnswer),
    });
    const client = { interactions: { create } } as unknown as GoogleGenAI;
    const model = new GoogleChatModel(
      "gemini-secret",
      "gemini-test",
      "high",
      180_000,
      client,
    );

    const inputSchema = {
      type: "object",
      properties: {
        findingId: { type: "string", minLength: 1, maxLength: 200 },
        query: { type: "string", pattern: "^[a-z]+$" },
      },
      required: ["findingId"],
    };
    await model.create({
      ...initialRequest,
      tools: [
        {
          name: "checkmate_get_finding",
          description: "Get one finding.",
          inputSchema,
        },
      ],
    });

    // Only the response schema is sanitized for Gemini; tool (function-
    // declaration) parameters are forwarded as-is. Bounds on tool arguments
    // are enforced by each tool's own validation after the model calls it.
    const sentTools = mockRequest(create.mock.calls as unknown[][], 0)
      .tools as Array<{ parameters: unknown }>;
    expect(sentTools[0]?.parameters).toEqual(inputSchema);
  });

  it("clamps oversized Gemini answers back to the safety schema limits", async () => {
    const overLimitAnswer = {
      headline: "x".repeat(300),
      headlineFindingIds: ["a", "b", "c", "d", "e", "f"],
      sections: Array.from({ length: 9 }, () => ({
        title: "t".repeat(200),
        items: Array.from({ length: 12 }, () => ({
          text: "y".repeat(1_000),
          basis: "checkmate_report",
          findingIds: ["a", "b", "c", "d", "e", "f"],
        })),
      })),
      evidenceGaps: Array.from({ length: 9 }, () => "z".repeat(500)),
      suggestedQuestions: Array.from({ length: 7 }, () => ({
        question: "q".repeat(200),
        findingIds: ["a", "b", "c", "d", "e"],
      })),
      actionConfirmations: Array.from({ length: 3 }, () => ({
        question: "c".repeat(300),
        findingIds: ["a", "b", "c", "d", "e"],
      })),
    };
    const create = vi.fn().mockResolvedValue({
      steps: [
        {
          type: "model_output",
          content: [{ type: "text", text: JSON.stringify(overLimitAnswer) }],
        },
      ],
      output_text: JSON.stringify(overLimitAnswer),
    });
    const client = { interactions: { create } } as unknown as GoogleGenAI;
    const model = new GoogleChatModel(
      "gemini-secret",
      "gemini-test",
      "high",
      180_000,
      client,
    );

    const turn = await model.create(initialRequest);

    // The clamped answer must satisfy the strict downstream safety schema.
    const validated = chatAnswerSchema.safeParse(turn.outputParsed);
    expect(validated.success).toBe(true);
    if (!validated.success) return;
    const answer = validated.data;
    expect(answer.headline).toHaveLength(240);
    expect(answer.headlineFindingIds).toHaveLength(4);
    expect(answer.sections).toHaveLength(6);
    expect(answer.sections[0]?.title).toHaveLength(120);
    expect(answer.sections[0]?.items).toHaveLength(8);
    expect(answer.sections[0]?.items[0]?.text).toHaveLength(800);
    expect(answer.sections[0]?.items[0]?.findingIds).toHaveLength(4);
    expect(answer.evidenceGaps).toHaveLength(6);
    expect(answer.suggestedQuestions).toHaveLength(4);
    expect(answer.actionConfirmations).toHaveLength(1);
  });
});

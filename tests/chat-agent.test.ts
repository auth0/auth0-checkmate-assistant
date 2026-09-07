import { describe, expect, it, vi } from "vitest";
import {
  CheckmateChatAgent,
  type ChatModel,
  type ModelRequest,
} from "../apps/checkmate-chat/src/chat-agent.js";
import type { ChatConfig } from "../apps/checkmate-chat/src/config.js";
import type { ToolHubLike } from "../apps/checkmate-chat/src/tool-hub.js";
import { sanitizeToolResult } from "../apps/checkmate-chat/src/sanitize.js";
import type {
  McpCallResult,
  McpToolDefinition,
} from "../apps/checkmate-chat/src/types.js";

const config: ChatConfig = {
  projectRoot: "/project",
  publicDirectory: "/project/public",
  reportsDirectory: "/project/reports",
  host: "127.0.0.1",
  port: 4320,
  aiProvider: "openai",
  model: "gpt-5.4-mini",
  reasoningEffort: "low",
  aiApiKey: "test-key",
  aiTimeoutMs: 180_000,
  remediationUrl: "http://127.0.0.1:4317",
  auth0Enabled: false,
  auth0Command: process.execPath,
  auth0Arguments: [],
  scanTargets: {
    dev: { configured: false },
    prod: { configured: false },
  },
  devPlanningEnabled: false,
  devRemediationEnabled: false,
};

const toolDefinitions: McpToolDefinition[] = [
  {
    server: "checkmate",
    name: "checkmate_get_report_summary",
    description: "Get report summary.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    server: "checkmate",
    name: "checkmate_get_security_topic_context",
    description: "Get topic context.",
    inputSchema: {
      type: "object",
      properties: { topic: { type: "string" } },
    },
  },
];

class FakeHub implements ToolHubLike {
  constructor(private readonly findingPriority = "red") {}

  readonly callTool = vi.fn((name: string): Promise<McpCallResult> => {
    if (name === "checkmate_get_report_summary") {
      return Promise.resolve({
        server: "checkmate",
        tool: name,
        isError: false,
        value: {
          report: {
            reportId: "latest-report.json",
            tenant: "example.auth0.com",
            totalFindings: 74,
            findingsOnly: true,
            stale: false,
          },
        },
      });
    }
    return Promise.resolve({
      server: "checkmate",
      tool: name,
      isError: false,
      value: {
        report: { reportId: "latest-report.json" },
        findings: [
          {
            findingId: "check-breached-password-detection",
            title: "Breached Password Detection",
            status: "failed",
            priority: this.findingPriority,
            autoRemediable: true,
          },
        ],
      },
    });
  });

  initialize(): Promise<void> {
    return Promise.resolve();
  }

  close(): Promise<void> {
    return Promise.resolve();
  }

  getTools(): McpToolDefinition[] {
    return toolDefinitions;
  }

  getStatus() {
    return {
      checkmate: { enabled: true, connected: true, readOnly: true as const },
      auth0: { enabled: false, connected: false, readOnly: true as const },
    };
  }
}

describe("CheckMate chatbot agent", () => {
  it("binds every MCP lookup to the selected report and records evidence", async () => {
    const requests: ModelRequest[] = [];
    const model: ChatModel = {
      create: vi.fn((request: ModelRequest) => {
        requests.push(request);
        if (requests.length === 1) {
          return Promise.resolve({
            toolCalls: [
              {
                id: "call-1",
                name: "checkmate_get_security_topic_context",
                arguments: { topic: "credential_stuffing" },
              },
            ],
            outputParsed: null,
            outputText: "",
          });
        }
        return Promise.resolve({
          toolCalls: [],
          outputParsed: {
            headline: "Strengthen credential-stuffing controls first.",
            headlineFindingIds: ["check-breached-password-detection"],
            sections: [
              {
                title: "Recommended first step",
                items: [
                  {
                    text: "Enable breached-password detection. Finding: check-breached-password-detection.",
                    basis: "checkmate_report",
                    findingIds: ["check-breached-password-detection"],
                  },
                ],
              },
            ],
            evidenceGaps: ["Confirm the current live protection settings."],
            suggestedQuestions: [
              {
                question: "Would you like more detail about this control?",
                findingIds: ["check-breached-password-detection"],
              },
            ],
            actionConfirmations: [
              {
                question:
                  "Would you like me to prepare breached-password detection for dev?",
                findingIds: ["check-breached-password-detection"],
              },
            ],
          },
          outputText: "",
        });
      }),
    };
    const hub = new FakeHub();
    const agent = new CheckmateChatAgent(hub, config, model);

    const result = await agent.answer(
      "I experienced credential stuffing. What should I do?",
      [],
      {
        profile: "dev",
        reportId: "latest-report.json",
        tenantDomain: "example.auth0.com",
      },
    );

    expect(hub.callTool).toHaveBeenNthCalledWith(
      1,
      "checkmate_get_report_summary",
      { reportId: "latest-report.json" },
    );
    expect(hub.callTool).toHaveBeenNthCalledWith(
      2,
      "checkmate_get_security_topic_context",
      {
        topic: "credential_stuffing",
        reportId: "latest-report.json",
      },
    );
    expect(requests[1]?.toolResults).toContainEqual(
      expect.objectContaining({
        callId: "call-1",
        name: "checkmate_get_security_topic_context",
      }),
    );
    expect(requests[1]?.tools.map((tool) => tool.name)).not.toContain(
      "checkmate_get_security_topic_context",
    );
    expect(result.evidence.report?.reportId).toBe("latest-report.json");
    expect(result.evidence.findingIds).toEqual([
      "check-breached-password-detection",
    ]);
    expect(result.evidence.tools).toHaveLength(2);
    expect(result.answer.sections[0]?.items[0]?.basis).toBe("checkmate_report");
    expect(result.answer.sections[0]?.items[0]?.text).toBe(
      "Enable breached-password detection.",
    );
    expect(result.answer.actionConfirmations).toEqual([
      {
        question:
          "Would you like me to prepare breached-password detection for dev?",
        findingIds: ["check-breached-password-detection"],
      },
    ]);
  });

  it("removes change confirmations from production conversations", async () => {
    const model: ChatModel = {
      create: vi.fn().mockResolvedValue({
        toolCalls: [],
        outputParsed: {
          headline: "Review the production finding.",
          headlineFindingIds: ["check-breached-password-detection"],
          sections: [
            {
              title: "Recommendation",
              items: [
                {
                  text: "Plan the change through production governance.",
                  basis: "checkmate_report",
                  findingIds: ["check-breached-password-detection"],
                },
              ],
            },
          ],
          evidenceGaps: [],
          suggestedQuestions: [],
          actionConfirmations: [
            {
              question: "Would you like me to prepare this change?",
              findingIds: ["check-breached-password-detection"],
            },
          ],
        },
        outputText: "",
      }),
    };
    const agent = new CheckmateChatAgent(new FakeHub(), config, model);

    const result = await agent.answer("What should production change?", [], {
      profile: "prod",
      reportId: "latest-report.json",
      tenantDomain: "example.auth0.com",
    });

    expect(result.answer.actionConfirmations).toEqual([]);
  });

  it("does not display a recommendation invented outside the selected report", async () => {
    let turn = 0;
    const model: ChatModel = {
      create: vi.fn(() => {
        turn += 1;
        if (turn === 1) {
          return Promise.resolve({
            toolCalls: [
              {
                id: "call-ungrounded",
                name: "checkmate_get_security_topic_context",
                arguments: { topic: "credential_stuffing" },
              },
            ],
            outputParsed: null,
            outputText: "",
          });
        }
        return Promise.resolve({
          toolCalls: [],
          outputParsed: {
            headline: "Deploy an unrelated network appliance.",
            headlineFindingIds: ["invented-finding"],
            sections: [
              {
                title: "Invented recommendation",
                items: [
                  {
                    text: "Buy and deploy a control that CheckMate did not report.",
                    basis: "checkmate_report",
                    findingIds: ["invented-finding"],
                  },
                ],
              },
            ],
            evidenceGaps: [],
            suggestedQuestions: [
              {
                question: "Would you like another unrelated suggestion?",
                findingIds: ["invented-finding"],
              },
            ],
            actionConfirmations: [
              {
                question: "Would you like me to prepare it?",
                findingIds: ["invented-finding"],
              },
            ],
          },
          outputText: "",
        });
      }),
    };
    const agent = new CheckmateChatAgent(new FakeHub(), config, model);

    const result = await agent.answer("What else should I deploy?", [], {
      profile: "dev",
      reportId: "latest-report.json",
      tenantDomain: "example.auth0.com",
    });

    expect(result.answer.headline).toBe(
      "No matching CheckMate recommendation was found.",
    );
    expect(result.answer.sections[0]?.items[0]?.text).toContain(
      "does not contain an open red, yellow, or green finding",
    );
    expect(JSON.stringify(result.answer)).not.toContain("network appliance");
    expect(result.answer.suggestedQuestions).toEqual([]);
    expect(result.answer.actionConfirmations).toEqual([]);
  });

  it("does not recommend informational findings that cannot improve the posture score", async () => {
    let turn = 0;
    const model: ChatModel = {
      create: vi.fn(() => {
        turn += 1;
        if (turn === 1) {
          return Promise.resolve({
            toolCalls: [
              {
                id: "call-informational",
                name: "checkmate_get_security_topic_context",
                arguments: { topic: "credential_stuffing" },
              },
            ],
            outputParsed: null,
            outputText: "",
          });
        }
        return Promise.resolve({
          toolCalls: [],
          outputParsed: {
            headline: "Treat the informational result as a recommendation.",
            headlineFindingIds: ["check-breached-password-detection"],
            sections: [
              {
                title: "Informational result",
                items: [
                  {
                    text: "Change this informational item.",
                    basis: "checkmate_report",
                    findingIds: ["check-breached-password-detection"],
                  },
                ],
              },
            ],
            evidenceGaps: [],
            suggestedQuestions: [],
            actionConfirmations: [],
          },
          outputText: "",
        });
      }),
    };
    const agent = new CheckmateChatAgent(new FakeHub("blue"), config, model);

    const result = await agent.answer("What should I improve?", [], {
      profile: "dev",
      reportId: "latest-report.json",
      tenantDomain: "example.auth0.com",
    });

    expect(result.answer.headline).toBe(
      "No matching CheckMate recommendation was found.",
    );
    expect(JSON.stringify(result.answer)).not.toContain(
      "Change this informational item",
    );
  });

  it("redacts secrets while preserving security configuration names", () => {
    const sanitized = sanitizeToolResult(
      {
        client_secret: "do-not-send",
        access_token: "do-not-send-either",
        options: {
          password_complexity_options: { min_length: 12 },
          token_lifetime: 3600,
        },
        actor: "admin@example.com",
        source: "203.0.113.42",
      },
      { maskPersonalData: true },
    );

    expect(sanitized).toEqual({
      client_secret: "[REDACTED]",
      access_token: "[REDACTED]",
      options: {
        password_complexity_options: { min_length: 12 },
        token_lifetime: 3600,
      },
      actor: "[EMAIL]@example.com",
      source: "203.0.113.x",
    });
  });
});

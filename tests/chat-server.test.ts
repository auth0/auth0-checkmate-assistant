import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatConfig } from "../apps/checkmate-chat/src/config.js";
import type { CheckmateScanLike } from "../apps/checkmate-chat/src/checkmate-scan.js";
import type {
  DevRemediationLike,
  PreparedDevPlanState,
} from "../apps/checkmate-chat/src/dev-remediation.js";
import type { ToolHubLike } from "../apps/checkmate-chat/src/tool-hub.js";
import { createChatServer } from "../apps/checkmate-chat/src/server.js";

const servers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
});

interface TestResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

function request(
  port: number,
  method: "GET" | "POST",
  pathname: string,
  options: {
    cookie?: string;
    csrf?: string;
    body?: Record<string, unknown>;
  } = {},
): Promise<TestResponse> {
  return new Promise((resolve, reject) => {
    const body = options.body ? JSON.stringify(options.body) : undefined;
    const headers: Record<string, string> = { host: "127.0.0.1:4320" };
    if (body) {
      headers["content-type"] = "application/json";
      headers.origin = "http://127.0.0.1:4320";
      headers["content-length"] = String(Buffer.byteLength(body));
    }
    if (options.cookie) headers.cookie = options.cookie;
    if (options.csrf) headers["x-csrf-token"] = options.csrf;
    const outgoing = http.request(
      { host: "127.0.0.1", port, method, path: pathname, headers },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
          });
        });
      },
    );
    outgoing.on("error", reject);
    if (body) outgoing.write(body);
    outgoing.end();
  });
}

describe("chat dev confirmation workflow", () => {
  it("previews a session-bound dev call and requires exact confirmation", async () => {
    const config: ChatConfig = {
      projectRoot: "/project",
      publicDirectory: "/project/public",
      reportsDirectory: "/project/reports",
      host: "127.0.0.1",
      port: 4320,
      aiProvider: "openai",
      model: "gpt-5.5",
      reasoningEffort: "high",
      aiApiKey: "test-key",
      aiTimeoutMs: 180_000,
      remediationUrl: "http://127.0.0.1:4317",
      auth0Enabled: false,
      auth0Command: process.execPath,
      auth0Arguments: [],
      scanTargets: {
        dev: { configured: true, tenantDomain: "dev-tenant.auth0.com" },
        prod: { configured: true, tenantDomain: "prod-tenant.auth0.com" },
      },
      devTenantDomain: "dev-tenant.auth0.com",
      devPlanningEnabled: true,
      devRemediationEnabled: true,
    };
    const hub: ToolHubLike = {
      initialize: () => Promise.resolve(),
      close: () => Promise.resolve(),
      getTools: () => [],
      getStatus: () => ({
        checkmate: { enabled: true, connected: true, readOnly: true },
        auth0: { enabled: false, connected: false, readOnly: true },
      }),
      callTool: () =>
        Promise.resolve({
          server: "checkmate",
          tool: "checkmate_get_report_summary",
          isError: false,
          value: {
            report: {
              reportId: "latest-report.json",
              totalFindings: 1,
              counts: { passed: 0, failed: 1, warning: 0, unknown: 0 },
            },
          },
        }),
    };
    const answerPayload = () => ({
      answer: {
        headline: "Remove the implicit grant from GrantMate.",
        headlineFindingIds: ["finding-1"],
        sections: [
          {
            title: "Recommended change",
            items: [
              {
                text: "Remove implicit.",
                basis: "checkmate_report",
                findingIds: ["finding-1"],
              },
            ],
          },
        ],
        evidenceGaps: ["This internal limitation should not be displayed."],
        suggestedQuestions: [],
        actionConfirmations: [
          {
            question:
              "Would you like me to prepare removal of the Implicit grant for dev?",
            findingIds: ["finding-1"],
          },
        ],
      },
      evidence: {
        report: { reportId: "latest-report.json" },
        findingIds: ["finding-1"],
        tools: [],
      },
    });
    const agent = {
      answer: vi
        .fn()
        .mockImplementation(() => Promise.resolve(answerPayload())),
    };
    const prepared: PreparedDevPlanState = {
      plan: { profile: "dev" },
      approvedRequestDigests: { "api-call-1": "a".repeat(64) },
      preview: {
        profile: "dev",
        tenantDomain: "dev-tenant.auth0.com",
        sourceReport: "latest-report.json",
        generatedAt: "2026-07-14T14:00:00.000Z",
        planSha256: "b".repeat(64),
        calls: [
          {
            id: "api-call-1",
            method: "PATCH",
            url: "https://dev-tenant.auth0.com/api/v2/clients/client-1",
            endpoint: "/api/v2/clients/client-1",
            resourceName: "GrantMate",
            status: "ready",
            changes: [],
            body: { grant_types: ["authorization_code"] },
            sensitiveValuesRedacted: false,
          },
        ],
      },
    };
    const execute = vi.fn().mockResolvedValue({
      validation: {
        valid: true,
        validatedAt: "2026-07-14T14:01:00.000Z",
        calls: [],
      },
      execution: {
        status: "succeeded",
        startedAt: "2026-07-14T14:01:01.000Z",
        completedAt: "2026-07-14T14:01:02.000Z",
        profile: "dev",
        calls: [],
      },
    });
    const writeAudit = vi.fn().mockResolvedValue("/audit/plan.json");
    const remediation: DevRemediationLike = {
      prepare: vi.fn().mockResolvedValue(prepared),
      execute,
      writeAudit,
    };
    const scanner: CheckmateScanLike = {
      run: vi.fn((profile: "dev" | "prod") =>
        Promise.resolve({
          profile,
          tenantDomain:
            profile === "dev"
              ? "dev-tenant.auth0.com"
              : "prod-tenant.auth0.com",
          reportId: "latest-report.json",
          startedAt: "2026-07-14T13:59:00.000Z",
          finishedAt: "2026-07-14T14:00:00.000Z",
          checkmateVersion: "1.8.4",
        }),
      ),
    };
    const server = createChatServer({
      config,
      hub,
      agent,
      remediation,
      scanner,
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No address");

    const status = await request(address.port, "GET", "/api/status");
    const cookie = status.headers["set-cookie"]?.[0]?.split(";")[0];
    const csrf = status.body.csrfToken;
    expect(cookie).toBeTruthy();
    expect(typeof csrf).toBe("string");
    if (!cookie || typeof csrf !== "string") {
      throw new Error("The test session was not created.");
    }

    const chatBeforeScan = await request(address.port, "POST", "/api/chat", {
      cookie,
      csrf,
      body: { question: "Harden GrantMate", history: [] },
    });
    expect(chatBeforeScan.status).toBe(409);
    expect(agent.answer).not.toHaveBeenCalled();

    const scan = await request(address.port, "POST", "/api/scan", {
      cookie,
      csrf,
      body: { profile: "dev" },
    });
    expect(scan.status).toBe(200);

    const chat = await request(address.port, "POST", "/api/chat", {
      cookie,
      csrf,
      body: { question: "Harden GrantMate", history: [] },
    });
    expect(chat.status).toBe(200);
    expect(chat.body.answer).not.toHaveProperty("actionConfirmations");
    expect(
      (chat.body.answer as { evidenceGaps: unknown }).evidenceGaps,
    ).toEqual([]);
    const remediationOffer = chat.body.remediation as {
      actions: Array<{ recommendationId: string; question: string }>;
    };
    expect(remediationOffer.actions).toHaveLength(1);
    expect(remediationOffer.actions[0]?.question).toContain(
      "Would you like me",
    );
    const recommendation = remediationOffer.actions[0];
    if (!recommendation) throw new Error("No recommendation was offered");

    const repeatChat = await request(address.port, "POST", "/api/chat", {
      cookie,
      csrf,
      body: { question: "What should I do first?", history: [] },
    });
    expect(repeatChat.status).toBe(200);
    expect(repeatChat.body).not.toHaveProperty("remediation");
    expect(agent.answer).toHaveBeenLastCalledWith(
      "What should I do first?",
      [],
      expect.objectContaining({
        alreadySuggestedFindingIds: ["finding-1"],
      }),
    );

    const plan = await request(address.port, "POST", "/api/dev-plan", {
      cookie,
      csrf,
      body: { recommendationId: recommendation.recommendationId },
    });
    expect(plan.status).toBe(200);
    const preview = plan.body.plan as {
      planId: string;
      planSha256: string;
      tenantDomain: string;
      executionEnabled: boolean;
    };
    expect(preview.executionEnabled).toBe(true);

    const rejected = await request(address.port, "POST", "/api/dev-execute", {
      cookie,
      csrf,
      body: {
        planId: preview.planId,
        planSha256: preview.planSha256,
        confirmed: true,
        tenantDomain: preview.tenantDomain,
        confirmationText: "NO",
      },
    });
    expect(rejected.status).toBe(400);
    expect(execute).not.toHaveBeenCalled();

    const executed = await request(address.port, "POST", "/api/dev-execute", {
      cookie,
      csrf,
      body: {
        planId: preview.planId,
        planSha256: preview.planSha256,
        confirmed: true,
        tenantDomain: preview.tenantDomain,
        confirmationText: "EXECUTE DEV",
      },
    });
    expect(executed.status).toBe(200);
    expect(executed.body).toMatchObject({
      executed: true,
      profile: "dev",
      tenantDomain: "dev-tenant.auth0.com",
    });
    expect(execute).toHaveBeenCalledOnce();
    expect(writeAudit).toHaveBeenCalledTimes(3);

    const prodScan = await request(address.port, "POST", "/api/scan", {
      cookie,
      csrf,
      body: { profile: "prod" },
    });
    expect(prodScan.status).toBe(200);
    expect(prodScan.body.activeEnvironment).toMatchObject({
      profile: "prod",
      tenantDomain: "prod-tenant.auth0.com",
      changesSupported: false,
    });

    const prodChat = await request(address.port, "POST", "/api/chat", {
      cookie,
      csrf,
      body: { question: "Harden production", history: [] },
    });
    expect(prodChat.status).toBe(200);
    expect(prodChat.body).not.toHaveProperty("remediation");
    expect(agent.answer).toHaveBeenLastCalledWith(
      "Harden production",
      [],
      expect.objectContaining({
        profile: "prod",
        tenantDomain: "prod-tenant.auth0.com",
        reportId: "latest-report.json",
      }),
    );
  });
});

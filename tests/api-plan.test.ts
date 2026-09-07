import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { buildApiPlan, apiPlanSchema } from "../src/remediation/api-plan.js";
import {
  readApiPlan,
  writeApiPlan,
} from "../src/remediation/api-plan-writer.js";
import type { ReviewSession } from "../src/remediation/review-schema.js";
import { finalizeValidatedApiPlan } from "../src/remediation/validated-api-plan.js";

const analysis = {
  whatItMeans: ["The current setting needs improvement."],
  whyItMatters: ["The proposed setting reduces risk."],
  remediationConsiderations: ["Apply the proposed setting."],
};

function session(): ReviewSession {
  return {
    schemaVersion: 1,
    report: { sourceReport: "/reports/tenant-report.json" },
    review: {
      guidanceEngine: "deterministic-test",
      startedAt: "2026-07-10T10:00:00.000Z",
      lastUpdatedAt: "2026-07-10T10:05:00.000Z",
      completedAt: "2026-07-10T10:05:00.000Z",
    },
    decisions: [
      {
        checkmateFindingId: "password-policy",
        checkmateTitle: "Password policy",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-policy",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.passwordPolicy",
            currentValue: "fair",
            targetValue: "good",
          },
        ],
        decision: {
          status: "approved",
          rationale: "Accept the stronger policy.",
          decidedAt: "2026-07-10T10:03:00.000Z",
        },
      },
      {
        checkmateFindingId: "password-history",
        checkmateTitle: "Password history",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-history",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.password_history.enable",
            currentValue: false,
            targetValue: true,
          },
        ],
        decision: {
          status: "approved",
          rationale: "Prevent password reuse.",
          decidedAt: "2026-07-10T10:04:00.000Z",
        },
      },
      {
        checkmateFindingId: "passkey",
        checkmateTitle: "Passkeys",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-passkey",
        actionableChanges: [
          {
            resourceType: "connection",
            resourceId: "con_database",
            resourceName: "Username-Password-Authentication",
            configPath: "options.authentication_methods.passkey.enabled",
            currentValue: false,
            targetValue: true,
          },
        ],
        decision: {
          status: "accepted_risk",
          rationale: "Remain unchanged.",
          decidedAt: "2026-07-10T10:05:00.000Z",
        },
      },
    ],
  };
}

describe("Auth0 API plan", () => {
  it("groups approved changes and excludes unchanged decisions", () => {
    const plan = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");

    expect(plan.calls).toHaveLength(1);
    expect(plan.calls[0]).toMatchObject({
      method: "PATCH",
      endpoint: "/api/v2/connections/con_database",
      bodyStrategy: "merge_live_connection_options",
      actionIds: ["action-policy", "action-history"],
      preconditions: [
        { path: "options.passwordPolicy", expectedValue: "fair" },
        {
          path: "options.password_history.enable",
          expectedValue: false,
        },
      ],
      body: {
        options: {
          passwordPolicy: "good",
          password_history: { enable: true },
        },
      },
    });
    expect(plan.unchangedActionIds).toEqual(["action-passkey"]);
  });

  it("writes a validated .yml file", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-plan-"));
    const outputPath = path.join(directory, "api-plan.yml");
    const plan = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");

    await writeApiPlan(outputPath, plan);

    expect(
      apiPlanSchema.parse(parse(await readFile(outputPath, "utf8"))),
    ).toEqual(plan);
    const artifact = await readApiPlan(outputPath);
    expect(artifact.plan).toEqual(plan);
    expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("stamps every PATCH call with its live validation digest", () => {
    const draft = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");
    const finalized = finalizeValidatedApiPlan(
      draft,
      {
        valid: true,
        profile: "dev",
        validatedAt: "2026-07-10T10:07:00.000Z",
        calls: [
          {
            id: "api-call-1",
            endpoint: "/api/v2/connections/con_database",
            method: "PATCH",
            resourceName: "Username-Password-Authentication",
            status: "ready",
            requestSha256: "a".repeat(64),
          },
        ],
      },
      "tenant.auth0.com",
    );

    expect(finalized).toMatchObject({
      tenantDomain: "tenant.auth0.com",
      validatedAt: "2026-07-10T10:07:00.000Z",
      calls: [
        {
          validatedRequestSha256: "a".repeat(64),
          curl: {
            shell: "bash",
            requiredEnvironmentVariables: [
              "AUTH0CHECKMATE_DEV_DOMAIN",
              "AUTH0CHECKMATE_DEV_CLIENT_ID",
              "AUTH0CHECKMATE_DEV_CLIENT_SECRET",
            ],
          },
        },
      ],
    });
    expect(finalized.calls[0]?.curl?.script).toContain("--request PATCH");
  });

  it("refuses to finalize an API plan with incomplete validation coverage", () => {
    const draft = buildApiPlan(session(), "dev", "2026-07-10T10:06:00.000Z");

    expect(() =>
      finalizeValidatedApiPlan(
        draft,
        {
          valid: true,
          profile: "dev",
          validatedAt: "2026-07-10T10:07:00.000Z",
          calls: [],
        },
        "tenant.auth0.com",
      ),
    ).toThrow("did not cover Username-Password-Authentication");
  });

  it("creates a partial client PATCH for application settings", () => {
    const review = session();
    review.decisions = [
      {
        checkmateFindingId: "implicit-grant",
        checkmateTitle: "Application grant types",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-implicit",
        actionableChanges: [
          {
            resourceType: "client",
            resourceId: "client_12345678",
            resourceName: "Test App",
            configPath: "grant_types",
            currentValue: ["authorization_code", "implicit", "refresh_token"],
            targetValue: ["authorization_code", "refresh_token"],
          },
        ],
        decision: {
          status: "approved",
          rationale: "Remove the deprecated flow.",
          decidedAt: "2026-07-10T10:05:00.000Z",
        },
      },
    ];

    const plan = buildApiPlan(review, "dev", "2026-07-10T10:06:00.000Z");

    expect(plan.calls).toEqual([
      expect.objectContaining({
        endpoint: "/api/v2/clients/client_12345678",
        resourceType: "client",
        bodyStrategy: "merge_live_nested_objects",
        body: { grant_types: ["authorization_code", "refresh_token"] },
      }),
    ]);
  });

  it("merges selected callback removals into one client PATCH", () => {
    const review = session();
    const currentCallbacks = [
      "http://localhost:3000/auth/callback",
      "http://localhost:4000/auth/callback",
      "https://assistant.example.com/auth/callback",
    ];
    review.decisions = [
      {
        checkmateFindingId: "callback-3000",
        checkmateTitle: "Application Allowed Callbacks",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-callback-3000",
        actionableChanges: [
          {
            resourceType: "client",
            resourceId: "client_assistant0",
            resourceName: "Assistant0",
            configPath: "callbacks",
            currentValue: currentCallbacks,
            targetValue: currentCallbacks.filter(
              (callback) => !callback.includes("localhost:3000"),
            ),
          },
        ],
        decision: {
          status: "approved",
          rationale: "Remove the local callback.",
          decidedAt: "2026-07-25T10:00:00.000Z",
        },
      },
      {
        checkmateFindingId: "callback-4000",
        checkmateTitle: "Application Allowed Callbacks",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-callback-4000",
        actionableChanges: [
          {
            resourceType: "client",
            resourceId: "client_assistant0",
            resourceName: "Assistant0",
            configPath: "callbacks",
            currentValue: currentCallbacks,
            targetValue: currentCallbacks.filter(
              (callback) => !callback.includes("localhost:4000"),
            ),
          },
        ],
        decision: {
          status: "approved",
          rationale: "Remove the local callback.",
          decidedAt: "2026-07-25T10:00:00.000Z",
        },
      },
    ];

    const plan = buildApiPlan(review, "dev", "2026-07-25T10:01:00.000Z");

    expect(plan.calls).toEqual([
      expect.objectContaining({
        endpoint: "/api/v2/clients/client_assistant0",
        actionIds: ["action-callback-3000", "action-callback-4000"],
        body: {
          callbacks: ["https://assistant.example.com/auth/callback"],
        },
      }),
    ]);
  });
});

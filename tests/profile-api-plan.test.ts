import { describe, expect, it } from "vitest";
import type { ActionableConfigurationMap } from "../src/auth0/configuration-reader.js";
import {
  buildProfileApiPlan,
  targetIsSatisfied,
} from "../src/remediation/profile-api-plan.js";
import type { ReviewSession } from "../src/remediation/review-schema.js";

const analysis = {
  whatItMeans: ["The current setting needs improvement."],
  whyItMatters: ["The proposed setting reduces risk."],
  remediationConsiderations: ["Apply the proposed setting."],
};

function reviewSession(): ReviewSession {
  const decision = (
    id: string,
    configPath: string,
    currentValue: number | boolean,
    targetValue: number | boolean,
  ): ReviewSession["decisions"][number] => ({
    checkmateFindingId: id,
    checkmateTitle: id,
    checkmateStatus: "failed",
    analysis,
    actionableChangeId: `action-${id}`,
    actionableChanges: [
      {
        resourceType: "connection",
        resourceId: "con_dev",
        resourceName: "Username-Password-Authentication",
        configPath,
        currentValue,
        targetValue,
      },
    ],
    decision: {
      status: "approved",
      rationale: "Approved.",
      decidedAt: "2026-07-14T01:00:00.000Z",
    },
  });
  return {
    schemaVersion: 1,
    report: { sourceReport: "/reports/dev.json" },
    review: {
      guidanceEngine: "deterministic-test",
      startedAt: "2026-07-14T00:00:00.000Z",
      lastUpdatedAt: "2026-07-14T01:00:00.000Z",
      completedAt: "2026-07-14T01:00:00.000Z",
    },
    decisions: [
      decision(
        "length",
        "options.password_complexity_options.min_length",
        8,
        12,
      ),
      decision("history", "options.password_history.enable", false, true),
    ],
  };
}

describe("profile API plans", () => {
  it("does not treat a grant list containing implicit as already compliant", () => {
    expect(
      targetIsSatisfied(
        "grant_types",
        ["authorization_code", "implicit", "refresh_token"],
        ["authorization_code", "refresh_token"],
      ),
    ).toBe(false);
  });

  it("maps resource IDs per tenant and omits settings that are already stronger", () => {
    const configuration: ActionableConfigurationMap = new Map([
      [
        "prod-length",
        [
          {
            resourceType: "connection",
            resourceId: "con_prod",
            resourceName: "Username-Password-Authentication",
            configPath: "options.password_complexity_options.min_length",
            currentValue: 15,
            targetValue: 12,
          },
        ],
      ],
      [
        "prod-history",
        [
          {
            resourceType: "connection",
            resourceId: "con_prod",
            resourceName: "Username-Password-Authentication",
            configPath: "options.password_history.enable",
            currentValue: false,
            targetValue: true,
          },
        ],
      ],
    ]);

    const plan = buildProfileApiPlan(
      reviewSession(),
      configuration,
      "prod",
      "2026-07-14T02:00:00.000Z",
    );

    expect(plan.profile).toBe("prod");
    expect(plan.alreadyCompliantActionIds).toEqual(["action-length"]);
    expect(plan.calls).toHaveLength(1);
    expect(plan.calls[0]).toMatchObject({
      endpoint: "/api/v2/connections/con_prod",
      actionIds: ["action-history"],
      body: { options: { password_history: { enable: true } } },
    });
  });

  it("preserves environment-specific grants while removing implicit", () => {
    const session = reviewSession();
    session.decisions = [
      {
        checkmateFindingId: "implicit",
        checkmateTitle: "Application grant types",
        checkmateStatus: "failed",
        analysis,
        actionableChangeId: "action-implicit",
        actionableChanges: [
          {
            resourceType: "client",
            resourceId: "client_dev",
            resourceName: "Test App",
            configPath: "grant_types",
            currentValue: ["authorization_code", "implicit"],
            targetValue: ["authorization_code"],
          },
        ],
        decision: {
          status: "approved",
          rationale: "Remove implicit.",
          decidedAt: "2026-07-14T01:00:00.000Z",
        },
      },
    ];
    const configuration: ActionableConfigurationMap = new Map([
      [
        "prod-implicit",
        [
          {
            resourceType: "client",
            resourceId: "client_prod",
            resourceName: "Test App",
            configPath: "grant_types",
            currentValue: ["authorization_code", "implicit", "refresh_token"],
            targetValue: ["authorization_code", "refresh_token"],
          },
        ],
      ],
    ]);

    const plan = buildProfileApiPlan(
      session,
      configuration,
      "prod",
      "2026-07-14T02:00:00.000Z",
    );

    expect(plan.calls[0]).toMatchObject({
      endpoint: "/api/v2/clients/client_prod",
      body: { grant_types: ["authorization_code", "refresh_token"] },
    });
  });

  it("refuses to guess a missing production resource mapping", () => {
    expect(() =>
      buildProfileApiPlan(
        reviewSession(),
        new Map(),
        "prod",
        "2026-07-14T02:00:00.000Z",
      ),
    ).toThrow("Unable to map");
  });
});

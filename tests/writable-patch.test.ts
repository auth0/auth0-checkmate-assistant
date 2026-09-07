import { describe, expect, it } from "vitest";
import {
  assertSupportedApiPlanCall,
  buildWritablePatchBody,
} from "../src/auth0/writable-patch.js";
import type { ApiPlanCall } from "../src/remediation/api-plan.js";

interface Case {
  resourceType: ApiPlanCall["resourceType"];
  resourceId: string;
  resourceName: string;
  endpoint: string;
  path: string;
  current: unknown;
  target: unknown;
}

const cases: Case[] = [
  {
    resourceType: "client",
    resourceId: "client_1",
    resourceName: "Application",
    endpoint: "/api/v2/clients/client_1",
    path: "callbacks",
    current: ["https://app.example/callback", "http://localhost:3000"],
    target: ["https://app.example/callback"],
  },
  {
    resourceType: "client",
    resourceId: "client_1",
    resourceName: "Application",
    endpoint: "/api/v2/clients/client_1",
    path: "grant_types",
    current: ["authorization_code", "implicit"],
    target: ["authorization_code"],
  },
  {
    resourceType: "client",
    resourceId: "client_1",
    resourceName: "Application",
    endpoint: "/api/v2/clients/client_1",
    path: "cross_origin_authentication",
    current: true,
    target: false,
  },
  {
    resourceType: "client",
    resourceId: "client_1",
    resourceName: "Application",
    endpoint: "/api/v2/clients/client_1",
    path: "jwt_configuration.alg",
    current: "HS256",
    target: "RS256",
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.passwordPolicy",
    current: "fair",
    target: "good",
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.password_complexity_options.min_length",
    current: 8,
    target: 12,
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.password_history.enable",
    current: false,
    target: true,
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.password_no_personal_info.enable",
    current: false,
    target: true,
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.authentication_methods.passkey.enabled",
    current: false,
    target: true,
  },
  {
    resourceType: "connection",
    resourceId: "con_1",
    resourceName: "Database",
    endpoint: "/api/v2/connections/con_1",
    path: "options.attributes.email.verification_method",
    current: "link",
    target: "otp",
  },
  {
    resourceType: "attack_protection",
    resourceId: "brute-force",
    resourceName: "Brute Force Protection",
    endpoint: "/api/v2/attack-protection/brute-force-protection",
    path: "enabled",
    current: false,
    target: true,
  },
  {
    resourceType: "attack_protection",
    resourceId: "brute-force",
    resourceName: "Brute Force Protection",
    endpoint: "/api/v2/attack-protection/brute-force-protection",
    path: "shields",
    current: [],
    target: ["block", "user_notification"],
  },
  {
    resourceType: "attack_protection",
    resourceId: "brute-force",
    resourceName: "Brute Force Protection",
    endpoint: "/api/v2/attack-protection/brute-force-protection",
    path: "mode",
    current: "count_per_identifier_and_ip",
    target: "count_per_identifier",
  },
  {
    resourceType: "attack_protection",
    resourceId: "breached-password",
    resourceName: "Breached Password Detection",
    endpoint: "/api/v2/attack-protection/breached-password-detection",
    path: "enabled",
    current: false,
    target: true,
  },
  {
    resourceType: "attack_protection",
    resourceId: "breached-password",
    resourceName: "Breached Password Detection",
    endpoint: "/api/v2/attack-protection/breached-password-detection",
    path: "shields",
    current: [],
    target: ["block"],
  },
  {
    resourceType: "attack_protection",
    resourceId: "breached-password",
    resourceName: "Breached Password Detection",
    endpoint: "/api/v2/attack-protection/breached-password-detection",
    path: "stage.pre-user-registration.shields",
    current: [],
    target: ["block"],
  },
  {
    resourceType: "attack_protection",
    resourceId: "breached-password",
    resourceName: "Breached Password Detection",
    endpoint: "/api/v2/attack-protection/breached-password-detection",
    path: "stage.pre-change-password.shields",
    current: [],
    target: ["block"],
  },
];

function setPath(path: string, value: unknown): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let current = root;
  const segments = path.split(".");
  for (const segment of segments.slice(0, -1)) {
    const nested: Record<string, unknown> = {};
    current[segment] = nested;
    current = nested;
  }
  current[segments.at(-1)!] = value;
  return root;
}

function callFor(testCase: Case): ApiPlanCall {
  return {
    id: `call-${testCase.path}`,
    method: "PATCH",
    endpoint: testCase.endpoint,
    resourceType: testCase.resourceType,
    resourceId: testCase.resourceId,
    resourceName: testCase.resourceName,
    bodyStrategy:
      testCase.resourceType === "connection"
        ? "merge_live_connection_options"
        : "merge_live_nested_objects",
    actionIds: ["action"],
    preconditions: [{ path: testCase.path, expectedValue: testCase.current }],
    body: setPath(testCase.path, testCase.target),
  };
}

describe("Auth0 writable PATCH policy", () => {
  it.each(cases)("accepts the supported $path change", (testCase) => {
    expect(() => assertSupportedApiPlanCall(callFor(testCase))).not.toThrow();
  });

  it("rejects fields outside the supported CheckMate write surface", () => {
    const call = callFor(cases[0]!);
    call.preconditions = [{ path: "client_secret", expectedValue: "old" }];
    call.body = { client_secret: "new" };

    expect(() => assertSupportedApiPlanCall(call)).toThrow(
      "unsupported writable setting: client_secret",
    );
  });

  it("rejects a resource ID that does not match the endpoint", () => {
    const call = callFor(cases[0]!);
    call.endpoint = "/api/v2/clients/a-different-client";

    expect(() => assertSupportedApiPlanCall(call)).toThrow(
      "invalid client endpoint",
    );
  });

  it("sends only writable client JWT settings from the GET response", () => {
    const call = callFor(
      cases.find((item) => item.path === "jwt_configuration.alg")!,
    );

    expect(
      buildWritablePatchBody(call, {
        jwt_configuration: {
          alg: "HS256",
          lifetime_in_seconds: 36000,
          scopes: {},
          secret_encoded: true,
          future_read_only_field: "must-not-be-patched",
        },
      }),
    ).toEqual({
      jwt_configuration: {
        alg: "RS256",
        lifetime_in_seconds: 36000,
        scopes: {},
      },
    });
  });

  it("sends only documented writable breached-password stage settings", () => {
    const call = callFor(
      cases.find(
        (item) => item.path === "stage.pre-user-registration.shields",
      )!,
    );

    expect(
      buildWritablePatchBody(call, {
        stage: {
          "pre-user-registration": {
            shields: [],
            future_read_only_field: true,
          },
          "pre-change-password": {
            shields: ["admin_notification"],
            future_read_only_field: true,
          },
          "future-read-only-stage": { shields: ["block"] },
        },
      }),
    ).toEqual({
      stage: {
        "pre-user-registration": { shields: ["block"] },
        "pre-change-password": { shields: ["admin_notification"] },
      },
    });
  });

  it("does not copy unrelated attack-protection response fields", () => {
    const call = callFor(cases.find((item) => item.path === "mode")!);

    expect(
      buildWritablePatchBody(call, {
        enabled: true,
        mode: "count_per_identifier_and_ip",
        max_attempts: 10,
        future_read_only_field: true,
      }),
    ).toEqual({ mode: "count_per_identifier" });
  });

  it("preserves complete database options as required by Auth0", () => {
    const call = callFor(
      cases.find((item) => item.path === "options.password_history.enable")!,
    );

    expect(
      buildWritablePatchBody(call, {
        strategy: "auth0",
        display_name: "Customer login database",
        options: {
          password_history: { enable: false, size: 5 },
          requires_username: false,
          customScripts: { login: "function login() {}" },
        },
      }),
    ).toEqual({
      display_name: "Customer login database",
      options: {
        password_history: { enable: true, size: 5 },
        requires_username: false,
        customScripts: { login: "function login() {}" },
      },
    });
  });

  it("rejects a non-database connection", () => {
    const call = callFor(
      cases.find((item) => item.path === "options.password_history.enable")!,
    );

    expect(() =>
      buildWritablePatchBody(call, {
        strategy: "google-oauth2",
        options: { password_history: { enable: false } },
      }),
    ).toThrow("not an Auth0 database connection");
  });
});

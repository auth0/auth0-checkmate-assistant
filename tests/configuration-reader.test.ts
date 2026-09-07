import { describe, expect, it, vi } from "vitest";
import { loadActionableConfiguration } from "../src/auth0/configuration-reader.js";
import type { Fetcher } from "../src/auth0/fetcher.js";
import type { CheckmateConfig } from "../src/config/env.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

const config: CheckmateConfig = {
  profile: "dev",
  domain: "tenant.auth0.com",
  clientId: "client-id",
  clientSecret: "client-secret",
  outputDirectory: "/tmp",
  disablePdfReporting: true,
  timeoutMs: 30_000,
};

const passwordPolicyFinding: NormalizedCheckmateFinding = {
  id: "password-policy",
  validatorId: "checkPasswordPolicy",
  title: "Databases - Password Policy",
  status: "failed",
  affectedResource: { name: "Username-Password-Authentication" },
  raw: {},
};

describe("Auth0 actionable configuration reader", () => {
  it("automatically retries a rate-limited breached-password read", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "breached-password",
      validatorId: "checkBreachedPassword",
      title: "Breached Password Detection",
      status: "failed",
      raw: {},
    };
    const sleep = vi.fn(() => Promise.resolve());
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ message: "Too many requests" }), {
          status: 429,
          headers: { "retry-after": "2" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            enabled: false,
            shields: [],
            stage: {
              "pre-user-registration": { shields: [] },
              "pre-change-password": { shields: [] },
            },
          }),
        ),
      );

    const result = await loadActionableConfiguration(
      [finding],
      config,
      fetcher,
      { retry: { sleep } },
    );

    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledOnce();
    expect(sleep).toHaveBeenCalledWith(2_000);
    expect(result.get("breached-password")).toHaveLength(4);
  });

  it("reads the live password policy and creates an exact change", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              id: "con_database",
              name: "Username-Password-Authentication",
              strategy: "auth0",
              options: { passwordPolicy: "fair" },
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      [passwordPolicyFinding],
      config,
      fetcher,
    );

    expect(result.get("password-policy")).toEqual([
      {
        resourceType: "connection",
        resourceId: "con_database",
        resourceName: "Username-Password-Authentication",
        configPath: "options.passwordPolicy",
        currentValue: "fair",
        targetValue: "good",
      },
    ]);
    const requestBody = fetcher.mock.calls[0]?.[1]?.body;
    expect(typeof requestBody).toBe("string");
    if (typeof requestBody !== "string") {
      throw new Error("Expected a JSON token request body.");
    }
    const tokenBody = JSON.parse(requestBody) as { scope: string };
    expect(tokenBody.scope).toContain("read:connections_options");
  });

  it("does not turn system Management API settings into automatic changes", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "management-api-user-access",
      validatorId: "checkManagementAPIUserAccess",
      title: "Management API user access",
      status: "failed",
      affectedResource: { name: "Auth0 Management API" },
      raw: {},
    };
    const fetcher = vi.fn<Fetcher>();

    const result = await loadActionableConfiguration(
      [finding],
      config,
      fetcher,
    );

    expect(result.size).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("does not propose legacy fields for a flexible password policy", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              id: "con_database",
              name: "Username-Password-Authentication",
              strategy: "auth0",
              options: { password_options: { policy_version: 2 } },
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      [passwordPolicyFinding],
      config,
      fetcher,
    );
    expect(result.size).toBe(0);
  });

  it("does not treat a brute-force mode difference as an easy toggle", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "brute-force",
      validatorId: "checkBruteForce",
      title: "Brute Force Protection",
      status: "failed",
      raw: {},
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            enabled: true,
            shields: ["block", "user_notification"],
            mode: "count_per_identifier_and_ip",
            allowlist: [],
          }),
        ),
      );

    const result = await loadActionableConfiguration(
      [finding],
      config,
      fetcher,
    );
    expect(result.size).toBe(0);
  });

  it("maps the account-lockout finding to the documented identifier-only mode", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "account-lockout",
      validatorId: "checkBruteForce",
      title: "Brute Force Protection",
      status: "failed",
      evidence: {
        field: "enableAccountLockout",
        value: "count_per_identifier_and_ip",
      },
      raw: {},
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            enabled: true,
            shields: ["block", "user_notification"],
            mode: "count_per_identifier_and_ip",
            max_attempts: 10,
            allowlist: [],
          }),
        ),
      );

    const result = await loadActionableConfiguration(
      [finding],
      config,
      fetcher,
    );

    expect(result.get("account-lockout")).toEqual([
      {
        resourceType: "attack_protection",
        resourceId: "checkBruteForce",
        resourceName: "Brute Force Protection",
        configPath: "mode",
        currentValue: "count_per_identifier_and_ip",
        targetValue: "count_per_identifier",
      },
    ]);
  });

  it("creates exact application hardening changes from live client settings", async () => {
    const applicationName =
      "Test App (client_12345678) (First-Party Application)";
    const applicationFindings: NormalizedCheckmateFinding[] = [
      {
        id: "jwt-algorithm",
        validatorId: "checkJWTSignAlg",
        title: "Application JWT signing algorithm",
        status: "failed",
        affectedResource: { name: applicationName },
        raw: {},
      },
      {
        id: "cross-origin",
        validatorId: "checkCrossOriginAuthentication",
        title: "Application cross-origin authentication",
        status: "failed",
        affectedResource: { name: applicationName },
        raw: {},
      },
      {
        id: "implicit-grant",
        validatorId: "checkGrantTypes",
        title: "Application grant types",
        status: "failed",
        affectedResource: { name: applicationName },
        raw: {},
      },
      {
        id: "insecure-callback-3000",
        validatorId: "checkAllowedCallbacks",
        title: "Application Allowed Callbacks",
        status: "failed",
        affectedResource: { name: applicationName },
        evidence: {
          field: "insecure_callbacks",
          value: "http://localhost:3000/auth/callback",
        },
        raw: {},
      },
      {
        id: "insecure-callback-4000",
        validatorId: "checkAllowedCallbacks",
        title: "Application Allowed Callbacks",
        status: "failed",
        affectedResource: { name: applicationName },
        evidence: {
          field: "insecure_callbacks",
          value: "http://localhost:4000/auth/callback",
        },
        raw: {},
      },
    ];
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              client_id: "client_12345678",
              name: "Test App",
              app_type: "spa",
              jwt_configuration: {
                alg: "HS256",
                lifetime_in_seconds: 36000,
              },
              cross_origin_auth: false,
              cross_origin_authentication: true,
              grant_types: ["authorization_code", "implicit", "refresh_token"],
              callbacks: [
                "https://test.example.com/auth/callback",
                "http://localhost:3000/auth/callback",
                "http://localhost:4000/auth/callback",
              ],
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      applicationFindings,
      config,
      fetcher,
    );

    expect(result.get("jwt-algorithm")).toEqual([
      {
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        configPath: "jwt_configuration.alg",
        currentValue: "HS256",
        targetValue: "RS256",
      },
    ]);
    expect(result.get("cross-origin")).toEqual([
      {
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        configPath: "cross_origin_authentication",
        currentValue: true,
        targetValue: false,
      },
    ]);
    expect(result.get("implicit-grant")).toEqual([
      {
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        configPath: "grant_types",
        currentValue: ["authorization_code", "implicit", "refresh_token"],
        targetValue: ["authorization_code", "refresh_token"],
      },
    ]);
    expect(result.get("insecure-callback-3000")).toEqual([
      {
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        configPath: "callbacks",
        currentValue: [
          "https://test.example.com/auth/callback",
          "http://localhost:3000/auth/callback",
          "http://localhost:4000/auth/callback",
        ],
        targetValue: [
          "https://test.example.com/auth/callback",
          "http://localhost:4000/auth/callback",
        ],
      },
    ]);
    expect(result.get("insecure-callback-4000")).toEqual([
      {
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        configPath: "callbacks",
        currentValue: [
          "https://test.example.com/auth/callback",
          "http://localhost:3000/auth/callback",
          "http://localhost:4000/auth/callback",
        ],
        targetValue: [
          "https://test.example.com/auth/callback",
          "http://localhost:3000/auth/callback",
        ],
      },
    ]);
    const tokenBody = JSON.parse(
      fetcher.mock.calls[0]?.[1]?.body as string,
    ) as {
      scope: string;
    };
    expect(tokenBody.scope).toContain("read:clients");
  });

  it("maps an application to another tenant by one unambiguous name", async () => {
    const finding: NormalizedCheckmateFinding = {
      id: "implicit-grant",
      validatorId: "checkGrantTypes",
      title: "Application grant types",
      status: "failed",
      affectedResource: {
        name: "Shared App (dev_client_12345678) (First-Party Application)",
      },
      raw: {},
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "management-token" })),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            {
              client_id: "prod_client_87654321",
              name: "Shared App",
              grant_types: ["authorization_code", "implicit"],
            },
          ]),
        ),
      );

    const result = await loadActionableConfiguration(
      [finding],
      { ...config, profile: "prod" },
      fetcher,
      { includeCompliant: true },
    );

    expect(result.get("implicit-grant")?.[0]).toMatchObject({
      resourceId: "prod_client_87654321",
      resourceName: "Shared App",
      targetValue: ["authorization_code"],
    });
  });
});

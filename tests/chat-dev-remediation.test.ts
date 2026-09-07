import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Fetcher } from "../src/auth0/fetcher.js";
import { loadCheckmateReport } from "../src/checkmate/report-loader.js";
import {
  executeChatDevPlan,
  prepareChatDevPlan,
  redactChatDevRequestBody,
} from "../src/chat/dev-remediation-service.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("chat dev remediation service", () => {
  it("shows password authentication settings while redacting real secrets", () => {
    expect(
      redactChatDevRequestBody({
        options: {
          authentication_methods: {
            password: {
              enabled: true,
              api_behavior: "optional",
              signup_behavior: "allow",
            },
          },
          configuration: {
            password: "database-password",
            client_secret: "database-client-secret",
          },
        },
      }),
    ).toEqual({
      options: {
        authentication_methods: {
          password: {
            enabled: true,
            api_behavior: "optional",
            signup_behavior: "allow",
          },
        },
        configuration: {
          password: "[REDACTED]",
          client_secret: "[REDACTED]",
        },
      },
    });
  });

  it("maps a recommended report finding to an exact validated dev PATCH preview", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "chat-dev-plan-"));
    const reportId = "latest-report.json";
    const reportPath = path.join(directory, reportId);
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          severity: "High",
          name: "GrantMate (prod_client_12345678) (Regular Web App)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "Unexpected implicit grant type enabled.",
        },
      ]),
    );
    const report = await loadCheckmateReport(reportPath);
    const findingId = report.findings[0]!.id;
    const liveClient = {
      client_id: "dev_client_87654321",
      name: "GrantMate",
      app_type: "regular_web",
      grant_types: ["authorization_code", "implicit", "refresh_token"],
      jwt_configuration: { alg: "RS256", lifetime_in_seconds: 36000 },
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "read-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify([liveClient])))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "validation-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(liveClient)));
    vi.stubGlobal("fetch", fetcher);

    const prepared = await prepareChatDevPlan({
      reportsDirectory: directory,
      reportId,
      findingIds: [findingId],
      env: {
        AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-m2m-client",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-m2m-secret",
        AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
      },
      now: () => new Date("2026-07-14T14:00:00.000Z"),
    });

    expect(prepared.preview).toMatchObject({
      profile: "dev",
      tenantDomain: "dev-tenant.auth0.com",
      sourceReport: reportId,
      calls: [
        {
          method: "PATCH",
          url: "https://dev-tenant.auth0.com/api/v2/clients/dev_client_87654321",
          resourceName: "GrantMate",
          status: "ready",
          body: {
            grant_types: ["authorization_code", "refresh_token"],
          },
          changes: [
            expect.objectContaining({
              findingId,
              description: "Remove the Implicit grant type from GrantMate.",
            }),
          ],
        },
      ],
    });
    expect(prepared.preview.planSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(prepared.approvedRequestDigests["api-call-1"]).toMatch(
      /^[a-f0-9]{64}$/,
    );
    expect(prepared.plan.profile).toBe("dev");
    expect(
      fetcher.mock.calls.some(([, request]) => request?.method === "PATCH"),
    ).toBe(false);
    await expect(
      executeChatDevPlan({
        plan: prepared.plan,
        approvedRequestDigests: prepared.approvedRequestDigests,
        expectedTenantDomain: prepared.preview.tenantDomain,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-m2m-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-m2m-secret",
          AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
        },
      }),
    ).rejects.toThrow("CHECKMATE_CHAT_DEV_WRITE_DOMAIN");
  });

  it("combines insecure callback findings into one exact client PATCH preview", async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), "chat-callback-plan-"),
    );
    const reportId = "callback-report.json";
    const reportPath = path.join(directory, reportId);
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          severity: "High",
          name: "Assistant0 (report_client_12345678) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:3000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          severity: "High",
          name: "Assistant0 (report_client_12345678) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:4000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
      ]),
    );
    const report = await loadCheckmateReport(reportPath);
    const findingIds = report.findings.map((finding) => finding.id);
    const liveClient = {
      client_id: "dev_client_87654321",
      name: "Assistant0",
      callbacks: [
        "https://assistant.example.com/auth/callback",
        "http://localhost:3000/auth/callback",
        "http://localhost:4000/auth/callback",
      ],
    };
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "read-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify([liveClient])))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "validation-token" })),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(liveClient)));
    vi.stubGlobal("fetch", fetcher);

    const prepared = await prepareChatDevPlan({
      reportsDirectory: directory,
      reportId,
      findingIds,
      env: {
        AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-m2m-client",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-m2m-secret",
      },
      now: () => new Date("2026-07-15T02:00:00.000Z"),
    });

    expect(prepared.preview.calls).toHaveLength(1);
    expect(prepared.preview.calls[0]).toMatchObject({
      method: "PATCH",
      url: "https://dev-tenant.auth0.com/api/v2/clients/dev_client_87654321",
      resourceName: "Assistant0",
      status: "ready",
      body: {
        callbacks: ["https://assistant.example.com/auth/callback"],
      },
    });
    expect(prepared.preview.calls[0]?.changes).toHaveLength(2);
    expect(
      prepared.preview.calls[0]?.changes.every(
        (item) =>
          item.description ===
          "Remove the insecure callback URL from Assistant0.",
      ),
    ).toBe(true);
    expect(
      fetcher.mock.calls.some(([, request]) => request?.method === "PATCH"),
    ).toBe(false);
  });
});

import { describe, expect, it, vi } from "vitest";
import { assessProductionCredentialAccess } from "../src/auth0/production-credential-access.js";
import type { Fetcher } from "../src/auth0/fetcher.js";
import type { CheckmateConfig } from "../src/config/env.js";

const config: CheckmateConfig = {
  profile: "prod",
  domain: "production.auth0.com",
  clientId: "prod-reader",
  clientSecret: "prod-secret",
  outputDirectory: "/tmp/reports",
  disablePdfReporting: true,
  timeoutMs: 30_000,
};

describe("production credential access assessment", () => {
  it("reports read-only Management API scopes", async () => {
    const fetcher = vi.fn<Fetcher>().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "opaque-token",
          scope: "read:clients read:connections read:attack_protection",
        }),
      ),
    );

    const result = await assessProductionCredentialAccess(config, { fetcher });

    expect(result).toMatchObject({ status: "read_only", writeScopes: [] });
    const request = JSON.parse(fetcher.mock.calls[0]?.[1]?.body as string) as {
      scope?: string;
      client_id: string;
      client_secret: string;
    };
    expect(request).toMatchObject({
      client_id: "prod-reader",
      client_secret: "prod-secret",
    });
    expect(request.scope).toBeUndefined();
  });

  it("returns a non-blocking alert when write scopes are granted", async () => {
    const fetcher = vi.fn<Fetcher>().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "opaque-token",
          scope: "read:clients update:clients delete:clients",
        }),
      ),
    );

    const result = await assessProductionCredentialAccess(config, { fetcher });

    expect(result).toMatchObject({
      status: "write_access_detected",
      writeScopes: ["delete:clients", "update:clients"],
    });
    expect(result.message).not.toContain("update:clients");
    expect(result.message).not.toContain("delete:clients");
    expect(result.message).toContain("Package creation continued");
  });

  it("reports an unverified result without blocking when scopes are unavailable", async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValue(new Response("unauthorized", { status: 401 }));

    await expect(
      assessProductionCredentialAccess(config, { fetcher }),
    ).resolves.toMatchObject({ status: "unverified", writeScopes: [] });
  });

  it("retries a rate-limited credential token request", async () => {
    const sleep = vi.fn(() => Promise.resolve());
    const fetcher = vi
      .fn<Fetcher>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ message: "Too many requests" }), {
          status: 429,
          headers: { "retry-after": "2" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "opaque-token",
            scope: "read:clients",
          }),
        ),
      );

    const result = await assessProductionCredentialAccess(config, {
      fetcher,
      retry: { sleep },
    });

    expect(result.status).toBe("read_only");
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(2_000);
  });
});

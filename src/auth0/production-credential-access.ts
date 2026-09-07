import { z } from "zod";
import type { CheckmateConfig } from "../config/env.js";
import { isValidTenantDomain } from "../utils/tenant-domain.js";
import type { Fetcher } from "./fetcher.js";
import {
  fetchWithRateLimitRetry,
  type RateLimitRetryOptions,
} from "./rate-limit-retry.js";

const tokenSchema = z.object({
  access_token: z.string().min(1),
  scope: z.string().optional(),
});

export interface ProductionCredentialAccessResult {
  status: "read_only" | "write_access_detected" | "unverified";
  checkedAt: string;
  writeScopes: string[];
  message: string;
}

interface ProductionCredentialAccessOptions {
  fetcher?: Fetcher;
  now?: () => Date;
  retry?: RateLimitRetryOptions;
}

function tokenScopes(accessToken: string): string[] {
  const parts = accessToken.split(".");
  if (parts.length !== 3 || !parts[1]) return [];
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const scope = typeof payload.scope === "string" ? payload.scope : "";
    const permissions = Array.isArray(payload.permissions)
      ? payload.permissions.filter(
          (permission): permission is string => typeof permission === "string",
        )
      : [];
    return [...scope.split(/\s+/), ...permissions].filter(Boolean);
  } catch {
    return [];
  }
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

export async function assessProductionCredentialAccess(
  config: CheckmateConfig,
  options: ProductionCredentialAccessOptions = {},
): Promise<ProductionCredentialAccessResult> {
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  if (config.profile !== "prod") {
    return {
      status: "unverified",
      checkedAt,
      writeScopes: [],
      message:
        "Production credential access can only be checked for the prod profile.",
    };
  }
  const domain = config.domain.trim().toLowerCase();
  if (!isValidTenantDomain(domain)) {
    return {
      status: "unverified",
      checkedAt,
      writeScopes: [],
      message:
        "The production tenant domain is not a valid Auth0 tenant domain.",
    };
  }

  try {
    const fetcher = options.fetcher ?? fetch;
    const response = await fetchWithRateLimitRetry(
      () =>
        fetcher(`https://${domain}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            grant_type: "client_credentials",
            client_id: config.clientId,
            client_secret: config.clientSecret,
            audience: `https://${domain}/api/v2/`,
          }),
          signal: AbortSignal.timeout(30_000),
        }),
      options.retry,
    );
    if (!response.ok) {
      return {
        status: "unverified",
        checkedAt,
        writeScopes: [],
        message: `Production credential access could not be verified (token request returned ${response.status}).`,
      };
    }
    const parsed = tokenSchema.safeParse((await response.json()) as unknown);
    if (!parsed.success) {
      return {
        status: "unverified",
        checkedAt,
        writeScopes: [],
        message:
          "Production credential access could not be verified because Auth0 returned an invalid token response.",
      };
    }
    const grantedScopes = unique([
      ...(parsed.data.scope?.split(/\s+/).filter(Boolean) ?? []),
      ...tokenScopes(parsed.data.access_token),
    ]);
    if (grantedScopes.length === 0) {
      return {
        status: "unverified",
        checkedAt,
        writeScopes: [],
        message:
          "Production credentials worked, but Auth0 did not expose their granted scopes. Confirm that the client grant is read-only in the Auth0 Dashboard.",
      };
    }
    const writeScopes = grantedScopes.filter((scope) =>
      /^(create|update|delete):/.test(scope),
    );
    if (writeScopes.length > 0) {
      return {
        status: "write_access_detected",
        checkedAt,
        writeScopes,
        message:
          "Production credentials have Management API write access. Package creation continued, but these credentials should be replaced with a read-only client grant.",
      };
    }
    return {
      status: "read_only",
      checkedAt,
      writeScopes: [],
      message: "Production credentials expose read-only Management API scopes.",
    };
  } catch {
    return {
      status: "unverified",
      checkedAt,
      writeScopes: [],
      message:
        "Production credential access could not be verified. Confirm the client grant scopes in the Auth0 Dashboard.",
    };
  }
}

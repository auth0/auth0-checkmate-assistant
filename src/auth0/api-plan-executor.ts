import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { CheckmateConfig } from "../config/env.js";
import type { ProfileName } from "../config/profiles.js";
import {
  apiPlanSchema,
  type ApiPlan,
  type ApiPlanCall,
} from "../remediation/api-plan.js";
import { AppError, toErrorMessage } from "../utils/errors.js";
import { isValidTenantDomain } from "../utils/tenant-domain.js";
import type { Fetcher } from "./fetcher.js";
import {
  fetchWithRateLimitRetry,
  rateLimitRetryLimit,
  type RateLimitRetryOptions,
  waitForRateLimitRetry,
} from "./rate-limit-retry.js";
import { buildWritablePatchBody } from "./writable-patch.js";

const tokenSchema = z.object({
  access_token: z.string().min(1),
  scope: z.string().optional(),
});
const recordSchema = z.record(z.unknown());

export interface ApiCallExecution {
  id: string;
  endpoint: string;
  status:
    | "applied"
    | "already_applied"
    | "resumed_verified"
    | "verification_failed"
    | "failed"
    | "rolled_back"
    | "rollback_already_applied"
    | "rollback_failed";
  correlationId: string;
  error?: string;
}

export interface ApiExecutionResult {
  operation: "apply" | "rollback";
  status: "succeeded" | "failed";
  startedAt: string;
  completedAt: string;
  profile: "dev";
  calls: ApiCallExecution[];
  error?: string;
}

export interface ApiPlanExecutorOptions {
  fetcher?: Fetcher;
  now?: () => Date;
  includeRequestBodies?: boolean;
  approvedRequestDigests?: Readonly<Record<string, string>>;
  authorizationMode?: "read_only" | "read_write";
  previousExecution?: ApiExecutionResult;
  retry?: RateLimitRetryOptions;
}

export interface ApiPlanValidationResult {
  valid: boolean;
  profile: ProfileName;
  validatedAt: string;
  calls: Array<{
    id: string;
    endpoint: string;
    method: "PATCH";
    resourceName: string;
    status: "ready" | "already_applied" | "invalid";
    requestBody?: Record<string, unknown>;
    requestSha256?: string;
    error?: string;
  }>;
  error?: string;
}

function tenantBaseUrl(domain: string): string {
  if (!isValidTenantDomain(domain)) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "The selected profile domain is not a valid Auth0 tenant domain.",
    );
  }
  return `https://${domain}`;
}

function assertPlanTenant(
  plan: ApiPlan,
  config: CheckmateConfig,
  requireBinding: boolean,
): void {
  if (!plan.tenantDomain) {
    if (requireBinding) {
      throw new AppError(
        "AUTH0_WRITE_FAILED",
        `The ${plan.profile} API plan is not bound to an Auth0 tenant. Create a new change package.`,
      );
    }
    return;
  }
  if (plan.tenantDomain !== config.domain) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The ${plan.profile} API plan is bound to ${plan.tenantDomain} and cannot be used with ${config.domain}.`,
    );
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  const parsed = recordSchema.safeParse(value);
  if (!parsed.success) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 returned invalid ${label} configuration.`,
    );
  }
  return parsed.data;
}

async function responseJson(
  response: Response,
  label: string,
): Promise<unknown> {
  if (!response.ok) {
    let detail = "";
    try {
      const text = await response.text();
      if (text) {
        try {
          const parsed = JSON.parse(text) as unknown;
          if (parsed !== null && typeof parsed === "object") {
            const body = parsed as Record<string, unknown>;
            const messages = [
              body.message,
              body.error_description,
              body.error,
            ].filter(
              (value): value is string =>
                typeof value === "string" && value.trim().length > 0,
            );
            detail = [...new Set(messages)].join(" — ");
          }
        } catch {
          detail = text;
        }
      }
    } catch {
      // Retain the status-only error when Auth0 does not return a readable body.
    }
    const safeDetail = detail.replace(/\s+/g, " ").trim().slice(0, 500);
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `${label} failed with status ${response.status}${safeDetail ? `: ${safeDetail}` : ""}.`,
    );
  }
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `${label} returned invalid JSON.`,
      { cause: error },
    );
  }
}

function safeSegments(dottedPath: string): string[] {
  const segments = dottedPath.split(".");
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        !/^[a-zA-Z0-9_-]+$/.test(segment) ||
        ["__proto__", "prototype", "constructor"].includes(segment),
    )
  ) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The API plan contains an unsupported configuration path: ${dottedPath}`,
    );
  }
  return segments;
}

function valueAt(source: unknown, dottedPath: string): unknown {
  let current = source;
  for (const segment of safeSegments(dottedPath)) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function sameValue(left: unknown, right: unknown): boolean {
  if (
    (left === null || left === undefined) &&
    (right === null || right === undefined)
  ) {
    return true;
  }
  return JSON.stringify(left) === JSON.stringify(right);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function apiRequestSha256(
  method: "PATCH",
  endpoint: string,
  body: Record<string, unknown>,
): string {
  return createHash("sha256")
    .update(`${method}\n${endpoint}\n${canonicalJson(body)}`, "utf8")
    .digest("hex");
}

function targetValue(call: ApiPlanCall, path: string): unknown {
  const target = valueAt(call.body, path);
  if (target === undefined) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The API plan is missing a target value for ${path}.`,
    );
  }
  return target;
}

function classifyLiveState(
  call: ApiPlanCall,
  live: Record<string, unknown>,
): "target" | "safe_to_apply" {
  let allTargets = true;
  for (const precondition of call.preconditions) {
    const current = valueAt(live, precondition.path);
    const target = targetValue(call, precondition.path);
    if (sameValue(current, target)) continue;
    allTargets = false;
    if (!sameValue(current, precondition.expectedValue)) {
      throw new AppError(
        "AUTH0_WRITE_FAILED",
        `Execution stopped because ${call.resourceName} changed after the plan was created (${precondition.path}). Review the tenant and create a new plan.`,
      );
    }
  }
  return allTargets ? "target" : "safe_to_apply";
}

function scopesFor(
  plan: ApiPlan,
  mode: "read_only" | "read_write" = "read_write",
): string[] {
  const client = plan.calls.some((call) => call.resourceType === "client");
  const connection = plan.calls.some(
    (call) => call.resourceType === "connection",
  );
  const attack = plan.calls.some(
    (call) => call.resourceType === "attack_protection",
  );
  return [
    ...(client
      ? ["read:clients", ...(mode === "read_write" ? ["update:clients"] : [])]
      : []),
    ...(connection
      ? [
          "read:connections",
          "read:connections_options",
          ...(mode === "read_write"
            ? ["update:connections", "update:connections_options"]
            : []),
        ]
      : []),
    ...(attack
      ? [
          "read:attack_protection",
          ...(mode === "read_write" ? ["update:attack_protection"] : []),
        ]
      : []),
  ];
}

function changedPaths(call: ApiPlanCall): string[] {
  return call.preconditions.map((precondition) => precondition.path);
}

function preservationDifference(
  before: unknown,
  after: unknown,
  selectedPaths: readonly string[],
  currentPath = "",
): string | undefined {
  if (
    (before === null || before === undefined) &&
    (after === null || after === undefined)
  ) {
    return undefined;
  }
  if (currentPath && selectedPaths.includes(currentPath)) return undefined;
  if (before !== null && typeof before === "object" && !Array.isArray(before)) {
    if (after === null || typeof after !== "object" || Array.isArray(after)) {
      return currentPath || "resource";
    }
    for (const [key, value] of Object.entries(before)) {
      safeSegments(key);
      const path = currentPath ? `${currentPath}.${key}` : key;
      if (selectedPaths.includes(path)) continue;
      const nestedSelection = selectedPaths.some((item) =>
        item.startsWith(`${path}.`),
      );
      const afterValue = (after as Record<string, unknown>)[key];
      if (nestedSelection) {
        const difference = preservationDifference(
          value,
          afterValue,
          selectedPaths,
          path,
        );
        if (difference) return difference;
      } else if (
        !(
          (value === null || value === undefined) &&
          (afterValue === null || afterValue === undefined)
        ) &&
        !sameValue(value, afterValue)
      ) {
        return path;
      }
    }
    return undefined;
  }
  return sameValue(before, after) ? undefined : currentPath || "resource";
}

function verifyAppliedState(
  call: ApiPlanCall,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): void {
  if (classifyLiveState(call, after) !== "target") {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 did not retain the planned settings for ${call.resourceName}.`,
    );
  }
  const difference = preservationDifference(before, after, changedPaths(call));
  if (difference) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 changed an unselected setting for ${call.resourceName} (${difference}). Execution stopped for review.`,
    );
  }
}

function setValueAt(
  target: Record<string, unknown>,
  dottedPath: string,
  value: unknown,
): void {
  const segments = safeSegments(dottedPath);
  let current = target;
  for (const segment of segments.slice(0, -1)) {
    const existing = current[segment];
    if (
      existing !== null &&
      typeof existing === "object" &&
      !Array.isArray(existing)
    ) {
      current = existing as Record<string, unknown>;
    } else {
      const nested: Record<string, unknown> = {};
      current[segment] = nested;
      current = nested;
    }
  }
  current[segments.at(-1)!] = structuredClone(value);
}

function inverseCall(call: ApiPlanCall): ApiPlanCall {
  const body: Record<string, unknown> = {};
  const preconditions = call.preconditions.map((precondition) => {
    setValueAt(body, precondition.path, precondition.expectedValue);
    return {
      path: precondition.path,
      expectedValue: targetValue(call, precondition.path),
    };
  });
  return {
    ...call,
    body,
    preconditions,
    validatedRequestSha256: undefined,
    curl: undefined,
  };
}

async function managementAuthorization(
  fetcher: Fetcher,
  baseUrl: string,
  config: CheckmateConfig,
  scopes: string[],
  purpose: "validation" | "execution",
  retry?: RateLimitRetryOptions,
): Promise<string> {
  const response = await fetchWithRateLimitRetry(
    () =>
      fetcher(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          grant_type: "client_credentials",
          client_id: config.clientId,
          client_secret: config.clientSecret,
          audience: `${baseUrl}/api/v2/`,
          scope: scopes.join(" "),
        }),
        signal: AbortSignal.timeout(30_000),
      }),
    retry,
  );
  if (!response.ok) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 could not grant the required ${purpose} scopes (${scopes.join(", ")}) for ${config.profile}.`,
    );
  }
  const token = tokenSchema.safeParse(
    await responseJson(response, `Auth0 ${purpose} token request`),
  );
  if (!token.success) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Auth0 returned an invalid ${purpose} access token.`,
    );
  }
  if (token.data.scope !== undefined) {
    const granted = new Set(token.data.scope.split(/\s+/).filter(Boolean));
    const missing = scopes.filter((scope) => !granted.has(scope));
    if (missing.length > 0) {
      throw new AppError(
        "AUTH0_WRITE_FAILED",
        `Auth0 ${purpose} is missing required scopes (${missing.join(", ")}) for ${config.profile}.`,
      );
    }
  }
  return `Bearer ${token.data.access_token}`;
}

async function readLiveResource(
  fetcher: Fetcher,
  baseUrl: string,
  call: ApiPlanCall,
  authorization: string,
  retry?: RateLimitRetryOptions,
): Promise<Record<string, unknown>> {
  const url = new URL(call.endpoint, baseUrl);
  if (call.resourceType === "connection") {
    url.searchParams.set("fields", "id,name,display_name,strategy,options");
    url.searchParams.set("include_fields", "true");
  }
  const response = await fetchWithRateLimitRetry(
    () =>
      fetcher(url, {
        headers: { authorization },
        signal: AbortSignal.timeout(30_000),
      }),
    retry,
  );
  return record(
    await responseJson(response, `Auth0 read for ${call.resourceName}`),
    call.resourceName,
  );
}

export async function validateApiPlan(
  untrustedPlan: ApiPlan,
  config: CheckmateConfig,
  options: ApiPlanExecutorOptions = {},
): Promise<ApiPlanValidationResult> {
  const plan = apiPlanSchema.parse(untrustedPlan);
  if (plan.profile !== config.profile) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `The ${plan.profile} API plan cannot be validated against the ${config.profile} profile.`,
    );
  }
  assertPlanTenant(plan, config, false);
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? (() => new Date());
  const validatedAt = now().toISOString();
  const baseUrl = tenantBaseUrl(config.domain);
  const scopes = scopesFor(plan, options.authorizationMode ?? "read_write");
  if (scopes.length === 0) {
    return {
      valid: true,
      profile: config.profile,
      validatedAt,
      calls: [],
    };
  }
  const authorization = await managementAuthorization(
    fetcher,
    baseUrl,
    config,
    scopes,
    "validation",
    options.retry,
  );
  const calls: ApiPlanValidationResult["calls"] = [];
  for (const call of plan.calls) {
    try {
      const live = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
        options.retry,
      );
      const status = classifyLiveState(call, live);
      const body = buildWritablePatchBody(call, live);
      const requestSha256 = apiRequestSha256(call.method, call.endpoint, body);
      if (
        requestSha256 &&
        call.validatedRequestSha256 &&
        call.validatedRequestSha256 !== requestSha256
      ) {
        throw new AppError(
          "AUTH0_WRITE_FAILED",
          `The validated API request for ${call.resourceName} changed after package creation. Create a new change package.`,
        );
      }
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        method: call.method,
        resourceName: call.resourceName,
        status: status === "target" ? "already_applied" : "ready",
        ...(options.includeRequestBodies ? { requestBody: body } : {}),
        requestSha256,
      });
    } catch (error) {
      const message = toErrorMessage(error);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        method: call.method,
        resourceName: call.resourceName,
        status: "invalid",
        error: message,
      });
      return {
        valid: false,
        profile: config.profile,
        validatedAt,
        calls,
        error: message,
      };
    }
  }
  return {
    valid: true,
    profile: config.profile,
    validatedAt,
    calls,
  };
}

export async function executeApiPlan(
  untrustedPlan: ApiPlan,
  config: CheckmateConfig,
  options: ApiPlanExecutorOptions = {},
): Promise<ApiExecutionResult> {
  const plan = apiPlanSchema.parse(untrustedPlan);
  if (config.profile !== "dev" || plan.profile !== "dev") {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "API plan execution is restricted to the dev profile.",
    );
  }
  assertPlanTenant(plan, config, true);
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const baseUrl = tenantBaseUrl(config.domain);
  const scopes = scopesFor(plan, "read_write");
  if (scopes.length === 0) {
    return {
      operation: "apply",
      status: "succeeded",
      startedAt,
      completedAt: now().toISOString(),
      profile: "dev",
      calls: [],
    };
  }

  const authorization = await managementAuthorization(
    fetcher,
    baseUrl,
    config,
    scopes,
    "execution",
    options.retry,
  );
  const calls: ApiCallExecution[] = [];
  const previousCalls = new Map(
    options.previousExecution?.operation === "apply"
      ? options.previousExecution.calls.map((call) => [call.id, call])
      : [],
  );

  for (const call of plan.calls) {
    const correlationId = `checkmate-${randomUUID()}`.slice(0, 64);
    let patchAccepted = false;
    try {
      const live = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
        options.retry,
      );
      const previous = previousCalls.get(call.id);
      if (
        previous?.status === "applied" ||
        previous?.status === "resumed_verified"
      ) {
        if (classifyLiveState(call, live) !== "target") {
          throw new AppError(
            "AUTH0_WRITE_FAILED",
            `Execution cannot resume because the previously applied change for ${call.resourceName} is no longer present. Review the tenant before continuing.`,
          );
        }
        calls.push({
          id: call.id,
          endpoint: call.endpoint,
          status: "resumed_verified",
          correlationId,
        });
        continue;
      }
      if (previous?.status === "already_applied") {
        if (classifyLiveState(call, live) !== "target") {
          throw new AppError(
            "AUTH0_WRITE_FAILED",
            `Execution cannot resume because ${call.resourceName} no longer matches the previously verified target.`,
          );
        }
        calls.push({
          id: call.id,
          endpoint: call.endpoint,
          status: "already_applied",
          correlationId,
        });
        continue;
      }
      if (classifyLiveState(call, live) === "target") {
        calls.push({
          id: call.id,
          endpoint: call.endpoint,
          status: "already_applied",
          correlationId,
        });
        continue;
      }
      let beforePatch = live;
      let verifiedAfterRateLimit: Record<string, unknown> | undefined;
      const retryLimit = rateLimitRetryLimit(options.retry);
      for (let retryIndex = 0; ; retryIndex += 1) {
        const body = buildWritablePatchBody(call, beforePatch);
        const actual = apiRequestSha256(call.method, call.endpoint, body);
        if (
          call.validatedRequestSha256 &&
          call.validatedRequestSha256 !== actual
        ) {
          throw new AppError(
            "AUTH0_WRITE_FAILED",
            `Execution stopped because the validated API request for ${call.resourceName} changed after package creation. Create and confirm a new dev package.`,
          );
        }
        const approvedDigests = options.approvedRequestDigests;
        if (approvedDigests) {
          const approved = approvedDigests[call.id];
          if (!approved || approved !== actual) {
            throw new AppError(
              "AUTH0_WRITE_FAILED",
              `Execution stopped because the exact API request for ${call.resourceName} no longer matches the confirmed preview. Create and confirm a new dev plan.`,
            );
          }
        }
        const response = await fetcher(new URL(call.endpoint, baseUrl), {
          method: "PATCH",
          headers: {
            authorization,
            "content-type": "application/json",
            "x-correlation-id": correlationId,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        });
        if (response.status !== 429) {
          patchAccepted = response.ok;
          await responseJson(response, `Auth0 update for ${call.resourceName}`);
          break;
        }
        if (retryIndex >= retryLimit) {
          await responseJson(response, `Auth0 update for ${call.resourceName}`);
          throw new AppError(
            "AUTH0_WRITE_FAILED",
            `Auth0 update for ${call.resourceName} remained rate limited after recovery attempts.`,
          );
        }
        await waitForRateLimitRetry(response, retryIndex, options.retry);
        const observed = await readLiveResource(
          fetcher,
          baseUrl,
          call,
          authorization,
          options.retry,
        );
        if (classifyLiveState(call, observed) === "target") {
          verifyAppliedState(call, live, observed);
          patchAccepted = true;
          verifiedAfterRateLimit = observed;
          break;
        }
        beforePatch = observed;
      }
      if (!verifiedAfterRateLimit) {
        const verified = await readLiveResource(
          fetcher,
          baseUrl,
          call,
          authorization,
          options.retry,
        );
        verifyAppliedState(call, live, verified);
      }
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: "applied",
        correlationId,
      });
    } catch (error) {
      const message = toErrorMessage(error);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: patchAccepted ? "verification_failed" : "failed",
        correlationId,
        error: message,
      });
      return {
        operation: "apply",
        status: "failed",
        startedAt,
        completedAt: now().toISOString(),
        profile: "dev",
        calls,
        error: message,
      };
    }
  }

  return {
    operation: "apply",
    status: "succeeded",
    startedAt,
    completedAt: now().toISOString(),
    profile: "dev",
    calls,
  };
}

export async function rollbackApiPlan(
  untrustedPlan: ApiPlan,
  config: CheckmateConfig,
  appliedExecution: ApiExecutionResult,
  options: ApiPlanExecutorOptions = {},
): Promise<ApiExecutionResult> {
  const plan = apiPlanSchema.parse(untrustedPlan);
  assertPlanTenant(plan, config, true);
  if (config.profile !== "dev" || plan.profile !== "dev") {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "API plan rollback is restricted to the dev profile.",
    );
  }
  if (appliedExecution.operation !== "apply") {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "Rollback requires a previous apply execution record.",
    );
  }
  const eligible = new Set(
    appliedExecution.calls
      .filter(
        (call) =>
          call.status === "applied" ||
          call.status === "resumed_verified" ||
          call.status === "verification_failed",
      )
      .map((call) => call.id),
  );
  if (eligible.size === 0) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "No applied changes are available to roll back.",
    );
  }

  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const baseUrl = tenantBaseUrl(config.domain);
  const authorization = await managementAuthorization(
    fetcher,
    baseUrl,
    config,
    scopesFor(plan, "read_write"),
    "execution",
    options.retry,
  );
  const calls: ApiCallExecution[] = [];

  for (const original of [...plan.calls].reverse()) {
    if (!eligible.has(original.id)) continue;
    const call = inverseCall(original);
    const correlationId = `checkmate-rollback-${randomUUID()}`.slice(0, 64);
    try {
      const live = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
        options.retry,
      );
      if (classifyLiveState(call, live) === "target") {
        calls.push({
          id: call.id,
          endpoint: call.endpoint,
          status: "rollback_already_applied",
          correlationId,
        });
        continue;
      }
      const body = buildWritablePatchBody(call, live);
      const response = await fetcher(new URL(call.endpoint, baseUrl), {
        method: "PATCH",
        headers: {
          authorization,
          "content-type": "application/json",
          "x-correlation-id": correlationId,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
      });
      await responseJson(response, `Auth0 rollback for ${call.resourceName}`);
      const verified = await readLiveResource(
        fetcher,
        baseUrl,
        call,
        authorization,
        options.retry,
      );
      verifyAppliedState(call, live, verified);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: "rolled_back",
        correlationId,
      });
    } catch (error) {
      const message = toErrorMessage(error);
      calls.push({
        id: call.id,
        endpoint: call.endpoint,
        status: "rollback_failed",
        correlationId,
        error: message,
      });
      return {
        operation: "rollback",
        status: "failed",
        startedAt,
        completedAt: now().toISOString(),
        profile: "dev",
        calls,
        error: message,
      };
    }
  }

  return {
    operation: "rollback",
    status: "succeeded",
    startedAt,
    completedAt: now().toISOString(),
    profile: "dev",
    calls,
  };
}

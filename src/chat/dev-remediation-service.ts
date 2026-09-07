import { createHash } from "node:crypto";
import path from "node:path";
import {
  executeApiPlan,
  validateApiPlan,
  type ApiExecutionResult,
  type ApiPlanValidationResult,
} from "../auth0/api-plan-executor.js";
import { loadActionableConfiguration } from "../auth0/configuration-reader.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import { loadCheckmateConfig } from "../config/env.js";
import { buildActionCandidates } from "../remediation/action-candidates.js";
import type { ActionableChange } from "../remediation/actionable-change.js";
import {
  apiPlanSchema,
  buildApiPlanFromActions,
  type ApiPlan,
} from "../remediation/api-plan.js";

const MAX_RECOMMENDED_FINDINGS = 12;
const REDACTED = "[REDACTED]";
const SENSITIVE_KEYS = new Set([
  "access_token",
  "api_key",
  "authorization",
  "client_secret",
  "cookie",
  "credential",
  "id_token",
  "password",
  "private_key",
  "refresh_token",
  "secret",
  "signing_key",
]);

export interface ChatDevPlanChange {
  actionId: string;
  findingId: string;
  resourceName: string;
  configPath: string;
  currentValue: unknown;
  targetValue: unknown;
  description: string;
}

export interface ChatDevApiCallPreview {
  id: string;
  method: "PATCH";
  url: string;
  endpoint: string;
  resourceName: string;
  status: "ready" | "already_applied";
  changes: ChatDevPlanChange[];
  body?: Record<string, unknown>;
  sensitiveValuesRedacted: boolean;
}

export interface ChatDevPlanPreview {
  profile: "dev";
  tenantDomain: string;
  sourceReport: string;
  generatedAt: string;
  planSha256: string;
  calls: ChatDevApiCallPreview[];
}

export interface PreparedChatDevPlan {
  preview: ChatDevPlanPreview;
  plan: ApiPlan;
  approvedRequestDigests: Record<string, string>;
}

export interface PrepareChatDevPlanInput {
  reportsDirectory: string;
  reportId: string;
  findingIds: string[];
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

export interface ExecuteChatDevPlanInput {
  plan: unknown;
  approvedRequestDigests: Record<string, string>;
  expectedTenantDomain: string;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

export interface ExecutedChatDevPlan {
  validation: ApiPlanValidationResult;
  execution: ApiExecutionResult;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stableJson(value), "utf8").digest("hex");
}

function safeReportPath(reportsDirectory: string, reportId: string): string {
  if (
    path.basename(reportId) !== reportId ||
    !reportId.toLowerCase().endsWith(".json")
  ) {
    throw new Error("The recommended CheckMate report ID is invalid.");
  }
  const directory = path.resolve(reportsDirectory);
  const candidate = path.resolve(directory, reportId);
  if (!candidate.startsWith(`${directory}${path.sep}`)) {
    throw new Error(
      "The recommended CheckMate report is outside the report directory.",
    );
  }
  return candidate;
}

function assertDevWriteBoundary(
  env: NodeJS.ProcessEnv,
  devDomain: string,
): void {
  const allowlistedDomain = env.CHECKMATE_CHAT_DEV_WRITE_DOMAIN?.trim();
  if (!allowlistedDomain || allowlistedDomain !== devDomain) {
    throw new Error(
      "CHECKMATE_CHAT_DEV_WRITE_DOMAIN must exactly match the configured dev tenant before a chatbot API plan can be created.",
    );
  }
}

function normalizedKey(value: string): string {
  return value.toLowerCase().replace(/[-\s]/g, "_");
}

function isAuthenticationMethodPassword(
  path: readonly string[],
  nested: unknown,
): boolean {
  return (
    path.map(normalizedKey).join(".") ===
      "options.authentication_methods.password" &&
    nested !== null &&
    typeof nested === "object" &&
    !Array.isArray(nested)
  );
}

export function redactChatDevRequestBody(
  value: unknown,
  path: readonly string[] = [],
): unknown {
  if (Array.isArray(value))
    return value.map((item, index) =>
      redactChatDevRequestBody(item, [...path, String(index)]),
    );
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        SENSITIVE_KEYS.has(normalizedKey(key)) &&
        !isAuthenticationMethodPassword([...path, key], nested)
          ? REDACTED
          : redactChatDevRequestBody(nested, [...path, key]),
      ]),
    );
  }
  return value;
}

function changeDescription(change: ActionableChange): string {
  switch (change.configPath) {
    case "jwt_configuration.alg":
      return `Set JWT signing to ${String(change.targetValue)} on ${change.resourceName}.`;
    case "cross_origin_authentication":
      return `Disable cross-origin authentication on ${change.resourceName}.`;
    case "grant_types":
      return `Remove the Implicit grant type from ${change.resourceName}.`;
    case "callbacks":
      return `Remove the insecure callback URL from ${change.resourceName}.`;
    case "enabled":
      return `Enable ${change.resourceName}.`;
    case "shields":
      return `Set shields to Block on ${change.resourceName}.`;
    case "mode":
      return `Enable Account Lockout on ${change.resourceName}.`;
    case "stage.pre-user-registration.shields":
      return `Block breached passwords during user registration on ${change.resourceName}.`;
    case "stage.pre-change-password.shields":
      return `Block breached passwords during password changes on ${change.resourceName}.`;
    case "options.passwordPolicy":
      return `Set the password policy to ${String(change.targetValue)} on ${change.resourceName}.`;
    case "options.password_complexity_options.min_length":
      return `Set the minimum password length to ${String(change.targetValue)} on ${change.resourceName}.`;
    default:
      return `Set ${change.configPath} on ${change.resourceName}.`;
  }
}

export async function prepareChatDevPlan(
  input: PrepareChatDevPlanInput,
): Promise<PreparedChatDevPlan> {
  const uniqueFindingIds = [...new Set(input.findingIds)].slice(
    0,
    MAX_RECOMMENDED_FINDINGS,
  );
  if (uniqueFindingIds.length === 0) {
    throw new Error(
      "The answer did not identify a supported finding to change.",
    );
  }
  const reportPath = safeReportPath(input.reportsDirectory, input.reportId);
  const report = await loadCheckmateReport(reportPath);
  const selected = report.findings.filter((finding) =>
    uniqueFindingIds.includes(finding.id),
  );
  if (selected.length === 0) {
    throw new Error(
      "The recommended findings were not found in the selected report.",
    );
  }

  const env = input.env ?? process.env;
  const now = input.now ?? (() => new Date());
  const devConfig = loadCheckmateConfig("dev", env);
  const configuration = await loadActionableConfiguration(selected, devConfig);
  const candidates = buildActionCandidates(configuration);
  if (candidates.length === 0) {
    throw new Error(
      "This recommendation does not map to a supported automatic dev change. Continue with the reviewed manual process.",
    );
  }
  const generatedAt = now().toISOString();
  const plan = apiPlanSchema.parse({
    ...buildApiPlanFromActions(
      input.reportId,
      "dev",
      generatedAt,
      candidates.map((candidate) => ({
        actionId: candidate.actionId,
        change: candidate.change,
      })),
    ),
    tenantDomain: devConfig.domain,
  });
  const validation = await validateApiPlan(plan, devConfig, {
    includeRequestBodies: true,
    now,
  });
  if (!validation.valid) {
    throw new Error(
      validation.error ?? "The generated dev API plan did not pass preflight.",
    );
  }

  const candidateByAction = new Map(
    candidates.map((candidate) => [candidate.actionId, candidate]),
  );
  const validationByCall = new Map(
    validation.calls.map((call) => [call.id, call]),
  );
  const approvedRequestDigests: Record<string, string> = {};
  const calls: ChatDevApiCallPreview[] = plan.calls.map((call) => {
    const checked = validationByCall.get(call.id);
    if (!checked || checked.status === "invalid") {
      throw new Error(
        `The API preflight result for ${call.resourceName} is missing.`,
      );
    }
    if (checked.status === "ready") {
      if (!checked.requestSha256 || !checked.requestBody) {
        throw new Error(
          `The exact API request for ${call.resourceName} could not be previewed.`,
        );
      }
      approvedRequestDigests[call.id] = checked.requestSha256;
    }
    const redactedBody = checked.requestBody
      ? redactChatDevRequestBody(checked.requestBody)
      : undefined;
    const preview: ChatDevApiCallPreview = {
      id: call.id,
      method: call.method,
      url: `https://${devConfig.domain}${call.endpoint}`,
      endpoint: call.endpoint,
      resourceName: call.resourceName,
      status: checked.status,
      changes: call.actionIds.map((actionId) => {
        const candidate = candidateByAction.get(actionId);
        if (!candidate) {
          throw new Error(
            `Unknown action ${actionId} in the generated API plan.`,
          );
        }
        return {
          actionId,
          findingId: candidate.findingId,
          resourceName: candidate.change.resourceName,
          configPath: candidate.change.configPath,
          currentValue: candidate.change.currentValue,
          targetValue: candidate.change.targetValue,
          description: changeDescription(candidate.change),
        };
      }),
      sensitiveValuesRedacted:
        redactedBody !== undefined &&
        JSON.stringify(redactedBody).includes(REDACTED),
    };
    if (redactedBody && typeof redactedBody === "object") {
      preview.body = redactedBody as Record<string, unknown>;
    }
    return preview;
  });
  if (calls.every((call) => call.status === "already_applied")) {
    throw new Error("The recommended dev settings are already applied.");
  }

  return {
    plan,
    approvedRequestDigests,
    preview: {
      profile: "dev",
      tenantDomain: devConfig.domain,
      sourceReport: input.reportId,
      generatedAt,
      planSha256: sha256(plan),
      calls,
    },
  };
}

export async function executeChatDevPlan(
  input: ExecuteChatDevPlanInput,
): Promise<ExecutedChatDevPlan> {
  const plan = apiPlanSchema.parse(input.plan);
  if (plan.profile !== "dev") {
    throw new Error("Chatbot execution is restricted to a dev API plan.");
  }
  const env = input.env ?? process.env;
  const now = input.now ?? (() => new Date());
  const devConfig = loadCheckmateConfig("dev", env);
  assertDevWriteBoundary(env, devConfig.domain);
  if (devConfig.domain !== input.expectedTenantDomain) {
    throw new Error(
      "The configured dev tenant changed after confirmation. Create a new plan.",
    );
  }

  const validation = await validateApiPlan(plan, devConfig, {
    includeRequestBodies: true,
    now,
  });
  if (!validation.valid) {
    throw new Error(
      validation.error ?? "The dev API plan failed its final preflight.",
    );
  }
  for (const call of validation.calls) {
    if (call.status !== "ready") continue;
    if (
      !call.requestSha256 ||
      input.approvedRequestDigests[call.id] !== call.requestSha256
    ) {
      throw new Error(
        `The exact API request for ${call.resourceName} changed after confirmation. Create and confirm a new dev plan.`,
      );
    }
  }
  const execution = await executeApiPlan(plan, devConfig, {
    approvedRequestDigests: input.approvedRequestDigests,
    now,
  });
  return { validation, execution };
}

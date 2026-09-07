import { z } from "zod";
import path from "node:path";
import type { ActionableChange } from "./actionable-change.js";
import type { ReviewSession } from "./review-schema.js";
import { TENANT_DOMAIN_PATTERN } from "../utils/tenant-domain.js";

const apiCallSchema = z.object({
  id: z.string().min(1),
  method: z.literal("PATCH"),
  endpoint: z.string().startsWith("/api/v2/"),
  resourceType: z.enum(["connection", "attack_protection", "client"]),
  resourceId: z.string().min(1),
  resourceName: z.string().min(1),
  bodyStrategy: z.enum([
    "merge_live_connection_options",
    "merge_live_nested_objects",
  ]),
  actionIds: z.array(z.string().min(1)).min(1),
  preconditions: z.array(
    z.object({ path: z.string().min(1), expectedValue: z.unknown() }),
  ),
  body: z.record(z.unknown()),
  validatedRequestSha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  curl: z
    .object({
      shell: z.literal("bash"),
      requiredEnvironmentVariables: z.array(z.string().min(1)).min(3),
      script: z.string().min(1),
    })
    .optional(),
});

export const apiPlanSchema = z.object({
  schemaVersion: z.literal(1),
  generatedAt: z.string().datetime(),
  sourceReport: z.string().min(1),
  profile: z.enum(["dev", "prod"]),
  tenantDomain: z.string().regex(TENANT_DOMAIN_PATTERN).optional(),
  validatedAt: z.string().datetime().optional(),
  calls: z.array(apiCallSchema),
  unchangedActionIds: z.array(z.string().min(1)),
  alreadyCompliantActionIds: z.array(z.string().min(1)),
});

export type ApiPlan = z.infer<typeof apiPlanSchema>;
export type ApiPlanCall = z.infer<typeof apiCallSchema>;

function endpointFor(change: ActionableChange): string {
  if (change.resourceType === "client") {
    return `/api/v2/clients/${encodeURIComponent(change.resourceId)}`;
  }
  if (change.resourceType === "connection") {
    return `/api/v2/connections/${encodeURIComponent(change.resourceId)}`;
  }
  if (change.resourceName === "Breached Password Detection") {
    return "/api/v2/attack-protection/breached-password-detection";
  }
  if (change.resourceName === "Brute Force Protection") {
    return "/api/v2/attack-protection/brute-force-protection";
  }
  throw new Error(`No API endpoint mapping exists for: ${change.resourceName}`);
}

function setNested(
  target: Record<string, unknown>,
  dottedPath: string,
  value: unknown,
): void {
  const segments = dottedPath.split(".");
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        !/^[a-zA-Z0-9_-]+$/.test(segment) ||
        ["__proto__", "prototype", "constructor"].includes(segment),
    )
  ) {
    throw new Error(`Unsupported configuration path: ${dottedPath}`);
  }
  let current = target;
  for (const segment of segments.slice(0, -1)) {
    const existing = current[segment];
    if (existing === undefined) {
      const next: Record<string, unknown> = {};
      current[segment] = next;
      current = next;
    } else if (
      existing !== null &&
      typeof existing === "object" &&
      !Array.isArray(existing)
    ) {
      current = existing as Record<string, unknown>;
    } else {
      throw new Error(`Conflicting configuration path: ${dottedPath}`);
    }
  }
  const finalSegment = segments.at(-1);
  if (!finalSegment)
    throw new Error(`Unsupported configuration path: ${dottedPath}`);
  current[finalSegment] = value;
}

function setPlannedTarget(
  body: Record<string, unknown>,
  change: ActionableChange,
): void {
  if (
    change.configPath === "callbacks" &&
    Array.isArray(body.callbacks) &&
    Array.isArray(change.targetValue)
  ) {
    const nextCallbacks = new Set(change.targetValue);
    body.callbacks = body.callbacks.filter(
      (callback): callback is string =>
        typeof callback === "string" && nextCallbacks.has(callback),
    );
    return;
  }
  setNested(body, change.configPath, change.targetValue);
}

interface MutableCall {
  method: "PATCH";
  endpoint: string;
  resourceType: ActionableChange["resourceType"];
  resourceId: string;
  resourceName: string;
  bodyStrategy: ApiPlanCall["bodyStrategy"];
  actionIds: string[];
  preconditions: Array<{ path: string; expectedValue: unknown }>;
  body: Record<string, unknown>;
}

export interface ApprovedActionChange {
  actionId: string;
  change: ActionableChange;
}

function callsForActions(
  actions: readonly ApprovedActionChange[],
): ApiPlanCall[] {
  const grouped = new Map<string, MutableCall>();
  for (const action of actions) {
    const { change } = action;
    const endpoint = endpointFor(change);
    const key = `${change.resourceType}:${endpoint}`;
    let call = grouped.get(key);
    if (!call) {
      call = {
        method: "PATCH",
        endpoint,
        resourceType: change.resourceType,
        resourceId: change.resourceId,
        resourceName: change.resourceName,
        bodyStrategy:
          change.resourceType === "connection"
            ? "merge_live_connection_options"
            : "merge_live_nested_objects",
        actionIds: [],
        preconditions: [],
        body: {},
      };
      grouped.set(key, call);
    }
    if (!call.actionIds.includes(action.actionId)) {
      call.actionIds.push(action.actionId);
    }
    call.preconditions.push({
      path: change.configPath,
      expectedValue: change.currentValue,
    });
    setPlannedTarget(call.body, change);
  }
  return [...grouped.values()].map((call, index) => ({
    id: `api-call-${index + 1}`,
    ...call,
  }));
}

export function buildApiPlanFromActions(
  sourceReport: string,
  profile: "dev" | "prod",
  generatedAt: string,
  actions: readonly ApprovedActionChange[],
): ApiPlan {
  return apiPlanSchema.parse({
    schemaVersion: 1,
    generatedAt,
    sourceReport: path.basename(sourceReport),
    profile,
    calls: callsForActions(actions),
    unchangedActionIds: [],
    alreadyCompliantActionIds: [],
  });
}

export function buildApiPlan(
  session: ReviewSession,
  profile: "dev" | "prod",
  generatedAt: string,
): ApiPlan {
  const unchangedActionIds: string[] = [];
  const approvedActions: ApprovedActionChange[] = [];
  for (const entry of session.decisions) {
    if (!entry.actionableChangeId) continue;
    if (entry.decision.status !== "approved") {
      unchangedActionIds.push(entry.actionableChangeId);
      continue;
    }
    for (const change of entry.actionableChanges ?? []) {
      approvedActions.push({
        actionId: entry.actionableChangeId,
        change,
      });
    }
  }
  return apiPlanSchema.parse({
    schemaVersion: 1,
    generatedAt,
    sourceReport: path.basename(session.report.sourceReport),
    profile,
    calls: callsForActions(approvedActions),
    unchangedActionIds,
    alreadyCompliantActionIds: [],
  });
}

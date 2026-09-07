import type { ActionableConfigurationMap } from "../auth0/configuration-reader.js";
import type { ProfileName } from "../config/profiles.js";
import type {
  ActionableChange,
  ConfigurationValue,
} from "./actionable-change.js";
import { apiPlanSchema, buildApiPlan, type ApiPlan } from "./api-plan.js";
import type { ReviewSession } from "./review-schema.js";

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

const PASSWORD_POLICY_RANK: Record<string, number> = {
  none: 0,
  low: 1,
  fair: 2,
  good: 3,
  excellent: 4,
};

export function targetIsSatisfied(
  configPath: string,
  current: ConfigurationValue,
  target: ConfigurationValue,
): boolean {
  if (configPath === "options.passwordPolicy") {
    return (
      typeof current === "string" &&
      typeof target === "string" &&
      (PASSWORD_POLICY_RANK[current] ?? -1) >=
        (PASSWORD_POLICY_RANK[target] ?? Number.POSITIVE_INFINITY)
    );
  }
  if (configPath.endsWith(".min_length")) {
    return (
      typeof current === "number" &&
      typeof target === "number" &&
      current >= target
    );
  }
  if (configPath === "grant_types") {
    return sameValue(current, target);
  }
  if (Array.isArray(current) && Array.isArray(target)) {
    return target.every((value) => current.includes(value));
  }
  return sameValue(current, target);
}

function matchingChange(
  original: ActionableChange,
  available: readonly ActionableChange[],
): ActionableChange | undefined {
  return available.find(
    (candidate) =>
      candidate.resourceType === original.resourceType &&
      candidate.resourceName === original.resourceName &&
      candidate.configPath === original.configPath &&
      (original.configPath === "grant_types"
        ? Array.isArray(original.targetValue) &&
          !original.targetValue.includes("implicit") &&
          Array.isArray(candidate.targetValue) &&
          !candidate.targetValue.includes("implicit")
        : sameValue(candidate.targetValue, original.targetValue)),
  );
}

export function buildProfileApiPlan(
  session: ReviewSession,
  configuration: ActionableConfigurationMap,
  profile: ProfileName,
  generatedAt: string,
): ApiPlan {
  const available = [...configuration.values()].flat();
  const projected = structuredClone(session);
  const alreadyCompliantActionIds: string[] = [];

  for (const entry of projected.decisions) {
    if (entry.decision.status !== "approved") continue;
    const mapped: ActionableChange[] = [];
    for (const original of entry.actionableChanges ?? []) {
      const candidate = matchingChange(original, available);
      if (!candidate) {
        throw new Error(
          `Unable to map ${original.resourceName} (${original.configPath}) to the ${profile} tenant.`,
        );
      }
      if (
        targetIsSatisfied(
          candidate.configPath,
          candidate.currentValue,
          candidate.targetValue,
        )
      ) {
        if (entry.actionableChangeId) {
          alreadyCompliantActionIds.push(entry.actionableChangeId);
        }
      } else {
        mapped.push(candidate);
      }
    }
    entry.actionableChanges = mapped;
  }

  const plan = buildApiPlan(projected, profile, generatedAt);
  return apiPlanSchema.parse({
    ...plan,
    alreadyCompliantActionIds: [...new Set(alreadyCompliantActionIds)],
  });
}

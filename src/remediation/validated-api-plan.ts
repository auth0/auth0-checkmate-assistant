import type { ApiPlanValidationResult } from "../auth0/api-plan-executor.js";
import { apiPlanSchema, type ApiPlan } from "./api-plan.js";
import { buildCurlApiScript } from "./curl-api-script.js";

export function finalizeValidatedApiPlan(
  plan: ApiPlan,
  validation: ApiPlanValidationResult,
  tenantDomain: string,
): ApiPlan {
  if (!validation.valid || validation.profile !== plan.profile) {
    throw new Error(
      validation.error ??
        `The ${plan.profile} API plan did not pass live validation.`,
    );
  }

  const results = new Map(validation.calls.map((call) => [call.id, call]));
  const alreadyCompliantActionIds = new Set(plan.alreadyCompliantActionIds);
  const calls = plan.calls.map((call) => {
    const result = results.get(call.id);
    if (!result) {
      throw new Error(
        `The ${plan.profile} API validation did not cover ${call.resourceName}.`,
      );
    }
    if (result.status === "invalid") {
      throw new Error(
        result.error ?? `${call.resourceName} did not pass API validation.`,
      );
    }
    if (result.status === "already_applied") {
      call.actionIds.forEach((actionId) =>
        alreadyCompliantActionIds.add(actionId),
      );
    }
    if (!result.requestSha256) {
      throw new Error(
        `The validated PATCH request digest is missing for ${call.resourceName}.`,
      );
    }
    return {
      ...call,
      validatedRequestSha256: result.requestSha256,
      curl: buildCurlApiScript(
        plan.profile,
        call,
        result.requestSha256,
        tenantDomain,
      ),
    };
  });

  return apiPlanSchema.parse({
    ...plan,
    tenantDomain,
    validatedAt: validation.validatedAt,
    calls,
    alreadyCompliantActionIds: [...alreadyCompliantActionIds],
  });
}

export function assertValidatedApiPlan(plan: ApiPlan): void {
  if (!plan.tenantDomain) {
    throw new Error(
      `The ${plan.profile} API plan is not bound to an Auth0 tenant.`,
    );
  }
  if (!plan.validatedAt) {
    throw new Error(
      `The ${plan.profile} API plan has not passed live validation.`,
    );
  }
  const unvalidated = plan.calls.filter(
    (call) => !call.validatedRequestSha256 || !call.curl,
  );
  if (unvalidated.length > 0) {
    throw new Error(
      `The ${plan.profile} API plan contains unvalidated calls: ${unvalidated
        .map((call) => call.resourceName)
        .join(", ")}.`,
    );
  }
}

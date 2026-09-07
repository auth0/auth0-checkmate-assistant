import type { ApiPlan } from "./api-plan.js";
import { buildConsolidatedApiPlanShell } from "./consolidated-api-plan-shell.js";

export function buildApiPlanShellScript(plan: ApiPlan): string {
  if (!plan.tenantDomain) {
    throw new Error(
      `The ${plan.profile} API plan is not bound to an Auth0 tenant.`,
    );
  }
  const missing = plan.calls.filter((call) => !call.curl?.script);
  if (missing.length > 0) {
    throw new Error(
      `The ${plan.profile} API plan contains calls without validated curl scripts: ${missing
        .map((call) => call.resourceName)
        .join(", ")}.`,
    );
  }
  return buildConsolidatedApiPlanShell(plan);
}

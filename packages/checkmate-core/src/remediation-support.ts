import type { NormalizedCheckmateFinding } from "./types.js";

// Single source of truth for the CheckMate validators the deterministic
// remediation mapping can turn into an executable change. The Auth0
// configuration reader derives its per-resource sets from these groups.
export const AUTO_REMEDIABLE_VALIDATOR_GROUPS = {
  connection: [
    "checkPasswordPolicy",
    "checkPasswordComplexity",
    "checkPasswordNoPersonalInfo",
    "checkPasswordHistory",
    "checkAuthenticationMethods",
    "checkEmailAttributeVerification",
  ],
  attackProtection: ["checkBruteForce", "checkBreachedPassword"],
  client: [
    "checkJWTSignAlg",
    "checkCrossOriginAuthentication",
    "checkGrantTypes",
    "checkAllowedCallbacks",
  ],
} as const;

export const AUTO_REMEDIABLE_VALIDATORS: ReadonlySet<string> = new Set(
  Object.values(AUTO_REMEDIABLE_VALIDATOR_GROUPS).flat(),
);

export function isAutoRemediableFinding(
  finding: Pick<NormalizedCheckmateFinding, "validatorId">,
): boolean {
  return AUTO_REMEDIABLE_VALIDATORS.has(finding.validatorId ?? "");
}

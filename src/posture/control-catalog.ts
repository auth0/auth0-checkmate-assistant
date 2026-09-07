import type { CheckmatePriority } from "../findings/types.js";

export const POSTURE_MODEL_VERSION = "checkmate-1.8.4";

export type ScoredCheckmatePriority = "red" | "yellow" | "green";

export const CHECKMATE_PRIORITY_POINTS: Record<
  ScoredCheckmatePriority,
  number
> = {
  red: 5,
  yellow: 3,
  green: 1,
};

export interface PostureControl {
  validatorId: string;
  title: string;
  priority: ScoredCheckmatePriority;
}

const control = (
  validatorId: string,
  title: string,
  priority: ScoredCheckmatePriority,
): PostureControl => ({ validatorId, title, priority });

/**
 * The complete set of red, yellow, and green validators registered by
 * @auth0/auth0-checkmate 1.8.4. Blue informational and violet GenAI
 * validators remain visible in the report but do not contribute points.
 */
export const POSTURE_CONTROLS: readonly PostureControl[] = [
  control("checkActionsRuntime", "Actions runtime", "red"),
  control("checkAllowedCallbacks", "Allowed callback URLs", "red"),
  control(
    "checkCrossOriginAuthentication",
    "Cross-origin authentication",
    "red",
  ),
  control("checkCustomDomain", "Custom domain", "red"),
  control("checkDependencies", "Extension dependency versions", "red"),
  control("checkErrorPageTemplate", "Error page template", "red"),
  control("checkGrantTypes", "OAuth grant types", "red"),
  control("checkJWTSignAlg", "Application JWT signing algorithm", "red"),
  control("checkManagementAPIUserAccess", "Management API user access", "red"),
  control("checkPasswordPolicy", "Password policy", "red"),
  control("checkSandboxVersion", "Extensibility runtime", "red"),
  control("checkWebOrigins", "Allowed web origins", "red"),

  control("checkAPIAuthorizationPolicy", "API authorization policy", "yellow"),
  control("checkAPISigningAlgorithm", "API signing algorithm", "yellow"),
  control("checkAuthenticationMethods", "Authentication methods", "yellow"),
  control("checkBackchannelLogout", "Back-channel logout", "yellow"),
  control("checkBlockCanonicalDomain", "Canonical domain blocking", "yellow"),
  control("checkBreachedPassword", "Breached-password protection", "yellow"),
  control("checkCanonicalDomain", "Canonical domain", "yellow"),
  control("checkDASHardCodedValues", "Secrets in database scripts", "yellow"),
  control("checkEmailAttributeVerification", "Email verification", "yellow"),
  control("checkEmailProvider", "Email provider", "yellow"),
  control("checkGuardianFactors", "Strong MFA factors", "yellow"),
  control("checkLogStream", "Security log streaming", "yellow"),
  control("checkNetworkACL", "Tenant access control list", "yellow"),
  control("checkPasswordComplexity", "Password complexity", "yellow"),
  control(
    "checkPasswordNoPersonalInfo",
    "Personal information in passwords",
    "yellow",
  ),
  control("checkPasswordResetMFA", "MFA during password reset", "yellow"),
  control("checkRefreshToken", "Refresh-token configuration", "yellow"),

  control("checkAllowedLogoutUrl", "Allowed logout URLs", "green"),
  control(
    "checkAppTokenSenderConstraining",
    "Application token sender-constraining",
    "green",
  ),
  control("checkManagementAPIACL", "Management API access control", "green"),
  control("checkPasswordHistory", "Password history", "green"),
  control("checkPKCEEnforcement", "PKCE enforcement", "green"),
  control(
    "checkPreRegistrationUserEnumeration",
    "Pre-registration user enumeration",
    "green",
  ),
  control(
    "checkTokenConstrainingResourceServer",
    "API token sender-constraining",
    "green",
  ),
];

export const POSTURE_MAXIMUM_SCORE = POSTURE_CONTROLS.reduce(
  (total, item) => total + CHECKMATE_PRIORITY_POINTS[item.priority],
  0,
);

export const POSTURE_REVIEW_GUIDANCE: Readonly<Record<string, string>> = {
  checkPasswordResetMFA:
    "Review the password reset flow and require MFA for privileged or sensitive accounts.",
  checkCrossOriginAuthentication:
    "Disable cross-origin authentication for applications that do not require a legacy cross-origin flow.",
  checkPKCEEnforcement:
    "Enforce PKCE for public applications where the application flow supports it.",
  checkRefreshToken:
    "Review refresh-token rotation and expiry settings for applications that use refresh tokens.",
  checkManagementAPIUserAccess:
    "Identify approved applications, then restrict Management API user access to that approved set.",
  checkLogStream:
    "Configure a log stream to the organisation's monitoring or SIEM destination.",
};

export interface PostureRecommendationImpact {
  label: string;
  points: number;
}

function priorityFromSeverity(
  severity: string | undefined,
): CheckmatePriority | undefined {
  switch (severity?.trim().toLowerCase()) {
    case "high":
      return "red";
    case "moderate":
    case "medium":
      return "yellow";
    case "low":
      return "green";
    case "info":
      return "blue";
    case "genai":
      return "violet";
    default:
      return undefined;
  }
}

export function postureRecommendationImpact(
  validatorId: string | undefined,
  reportPriority?: CheckmatePriority,
  severity?: string,
): PostureRecommendationImpact {
  const catalogPriority = POSTURE_CONTROLS.find(
    (item) => item.validatorId === validatorId,
  )?.priority;
  const priority =
    catalogPriority ?? reportPriority ?? priorityFromSeverity(severity);
  switch (priority) {
    case "red":
      return { label: "High priority", points: 5 };
    case "yellow":
      return { label: "Moderate priority", points: 3 };
    case "green":
      return { label: "Low priority", points: 1 };
    case "blue":
      return { label: "Information only", points: 0 };
    case "violet":
      return { label: "GenAI insight", points: 0 };
    default:
      return { label: "Unscored", points: 0 };
  }
}

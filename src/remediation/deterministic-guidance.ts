import { z } from "zod";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import { buildActionCandidates } from "./action-candidates.js";
import type {
  ActionableChange,
  ConfigurationValue,
} from "./actionable-change.js";

export const DETERMINISTIC_GUIDANCE_ENGINE =
  "checkmate-1.8.4-deterministic-guidance-v1";

const conciseBulletSchema = z.string().trim().min(1).max(220);

export const recommendationAnalysisSchema = z
  .object({
    whatItMeans: z.array(conciseBulletSchema).min(1).max(3),
    whyItMatters: z.array(conciseBulletSchema).min(1).max(3),
    remediationConsiderations: z.array(conciseBulletSchema).length(1),
  })
  .strict();

export type RecommendationAnalysis = z.infer<
  typeof recommendationAnalysisSchema
>;

export type RecommendationSelectionMode =
  "single" | "applications" | "connections" | "changes";

export interface DeterministicRecommendation {
  key: string;
  title: string;
  analysis: RecommendationAnalysis;
  selectionMode: RecommendationSelectionMode;
  defaultSelected: boolean;
  actions: Array<{
    actionId: string;
    finding: NormalizedCheckmateFinding;
    actionableChange: ActionableChange;
  }>;
}

const recommendationGroups = [
  {
    key: "applications-remove-implicit",
    resourceType: "client",
    selectionMode: "applications",
    configPath: "grant_types",
    title: "Remove the Implicit grant type from",
    whatItMeans: [
      "These applications currently allow the Implicit grant type.",
    ],
    suggestion: "Remove the Implicit grant type from selected applications.",
    reason: [
      "This prevents tokens from being returned directly through the browser flow.",
      "Other configured grant types remain unchanged.",
    ],
    defaultSelected: false,
  },
  {
    key: "applications-use-rs256",
    resourceType: "client",
    selectionMode: "applications",
    configPath: "jwt_configuration.alg",
    title: "Set JWT signing to RS256",
    whatItMeans: ["These applications are not using RS256 for JWT signing."],
    suggestion: "Set JWT signing to RS256 for selected applications.",
    reason: [
      "RS256 uses asymmetric signing and keeps verification separate from signing.",
      "Other JWT settings remain unchanged.",
    ],
    defaultSelected: false,
  },
  {
    key: "applications-disable-cross-origin",
    resourceType: "client",
    selectionMode: "applications",
    configPath: "cross_origin_authentication",
    title: "Disable cross-origin authentication for",
    whatItMeans: [
      "These applications currently allow cross-origin authentication.",
    ],
    suggestion:
      "Disable cross-origin authentication for selected applications.",
    reason: [
      "This removes an unnecessary browser-based authentication surface.",
      "Cross-origin authentication should be disabled.",
    ],
    defaultSelected: true,
  },
  {
    key: "connections-enable-password-history",
    resourceType: "connection",
    selectionMode: "connections",
    configPath: "options.password_history.enable",
    title: "Enable password history",
    whatItMeans: [
      "These database connections currently allow users to reuse previous passwords.",
    ],
    suggestion: "Enable password history for selected database connections.",
    reason: [
      "Password history prevents users from reusing recently used passwords.",
      "Other database connection settings remain unchanged.",
    ],
    defaultSelected: true,
  },
  {
    key: "connections-block-personal-information",
    resourceType: "connection",
    selectionMode: "connections",
    configPath: "options.password_no_personal_info.enable",
    title: "Block personal information",
    whatItMeans: [
      "These database connections currently allow personal information in passwords.",
    ],
    suggestion:
      "Block personal information in passwords for selected database connections.",
    reason: [
      "Personal information can make passwords easier to guess.",
      "Other database connection settings remain unchanged.",
    ],
    defaultSelected: true,
  },
  {
    key: "connections-enable-passkeys",
    resourceType: "connection",
    selectionMode: "connections",
    configPath: "options.authentication_methods.passkey.enabled",
    title: "Enable passkeys",
    whatItMeans: [
      "These database connections currently use passwords without passkeys as an authentication option.",
    ],
    suggestion: "Enable passkeys for selected database connections.",
    reason: [
      "Passkeys provide a phishing-resistant alternative to passwords.",
      "Passkey prerequisites must be validated before the change is executed.",
    ],
    defaultSelected: false,
  },
] as const satisfies ReadonlyArray<{
  key: string;
  resourceType: ActionableChange["resourceType"];
  selectionMode: Exclude<RecommendationSelectionMode, "single" | "changes">;
  configPath: string;
  title: string;
  whatItMeans: readonly string[];
  suggestion: string;
  reason: readonly string[];
  defaultSelected: boolean;
}>;

function readableValue(value: ConfigurationValue): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value === null) return "not configured";
  if (typeof value === "boolean") return value ? "enabled" : "disabled";
  return String(value);
}

function guidanceFor(change: ActionableChange):
  | {
      title: string;
      analysis: RecommendationAnalysis;
    }
  | undefined {
  const name = change.resourceName;
  switch (change.configPath) {
    case "options.passwordPolicy":
      return {
        title: `Set the password policy to Good for ${name}`,
        analysis: {
          whatItMeans: [
            `${name} currently uses the ${readableValue(change.currentValue)} password policy.`,
          ],
          whyItMatters: [
            "A stronger password policy makes weak passwords harder to create.",
            "Other database connection settings remain unchanged.",
          ],
          remediationConsiderations: [
            `Set the password policy to Good for ${name}.`,
          ],
        },
      };
    case "options.password_complexity_options.min_length":
      return {
        title: `Set the minimum password length to ${readableValue(change.targetValue)} for ${name}`,
        analysis: {
          whatItMeans: [
            `${name} currently allows a minimum password length of ${readableValue(change.currentValue)}.`,
          ],
          whyItMatters: [
            "Longer passwords are more resistant to guessing and brute-force attacks.",
            "Other password-complexity settings remain unchanged.",
          ],
          remediationConsiderations: [
            `Set the minimum password length to ${readableValue(change.targetValue)} for ${name}.`,
          ],
        },
      };
    case "options.attributes.email.verification_method":
      return {
        title: `Use OTP email verification for ${name}`,
        analysis: {
          whatItMeans: [
            `${name} is not using a one-time passcode for email verification.`,
          ],
          whyItMatters: [
            "A one-time passcode requires the user to prove access to the email address.",
            "Other connection attributes remain unchanged.",
          ],
          remediationConsiderations: [
            `Set the email verification method to OTP for ${name}.`,
          ],
        },
      };
    case "mode":
      return {
        title: "Enable account lockout for brute-force protection",
        analysis: {
          whatItMeans: [
            "Brute Force Protection is not counting failed attempts per identifier for account lockout.",
          ],
          whyItMatters: [
            "Account lockout slows repeated password attempts against the same account.",
            "This is a direct tenant-level attack-protection setting.",
          ],
          remediationConsiderations: [
            "Set Brute Force Protection to count failed attempts per identifier.",
          ],
        },
      };
    case "enabled": {
      const breached = name === "Breached Password Detection";
      return {
        title: `Enable ${name}`,
        analysis: {
          whatItMeans: [`${name} is currently disabled.`],
          whyItMatters: [
            breached
              ? "This detects credentials that are known to have been compromised."
              : "This detects repeated authentication attempts and enables configured protective responses.",
            "This is a tenant-level protection setting.",
          ],
          remediationConsiderations: [`Enable ${name}.`],
        },
      };
    }
    case "shields": {
      const breached = name === "Breached Password Detection";
      return {
        title: breached
          ? "Block logins that use breached credentials"
          : "Block brute-force attempts and notify affected users",
        analysis: {
          whatItMeans: [
            breached
              ? "Breached Password Detection is not configured to block risky authentication attempts."
              : "Brute Force Protection is not configured to block attacks and notify affected users.",
          ],
          whyItMatters: [
            breached
              ? "Blocking prevents known-compromised credentials from being used successfully."
              : "Blocking interrupts repeated attacks, while notification helps users respond.",
            "Other attack-protection settings remain unchanged.",
          ],
          remediationConsiderations: [
            breached
              ? "Set the Breached Password Detection response to Block."
              : "Set Brute Force Protection to Block and User notification.",
          ],
        },
      };
    }
    case "stage.pre-user-registration.shields":
      return {
        title: "Block breached passwords during user registration",
        analysis: {
          whatItMeans: [
            "Breached passwords are not blocked before a new user is registered.",
          ],
          whyItMatters: [
            "Blocking prevents new accounts from starting with known-compromised credentials.",
            "Other registration settings remain unchanged.",
          ],
          remediationConsiderations: [
            "Set Breached Password Detection to Block during pre-user-registration.",
          ],
        },
      };
    case "stage.pre-change-password.shields":
      return {
        title: "Block breached passwords during password changes",
        analysis: {
          whatItMeans: [
            "Breached passwords are not blocked before a password change is completed.",
          ],
          whyItMatters: [
            "Blocking prevents users from changing to known-compromised credentials.",
            "Other password-change settings remain unchanged.",
          ],
          remediationConsiderations: [
            "Set Breached Password Detection to Block during pre-change-password.",
          ],
        },
      };
    default:
      return undefined;
  }
}

export function buildDeterministicRecommendations(
  findings: readonly NormalizedCheckmateFinding[],
  configuration: ReadonlyMap<string, readonly ActionableChange[]>,
): DeterministicRecommendation[] {
  const findingById = new Map(findings.map((finding) => [finding.id, finding]));
  const candidates = buildActionCandidates(configuration);
  const candidateOrder = new Map(
    candidates.map((candidate, index) => [candidate.actionId, index]),
  );
  const usedActionIds = new Set<string>();
  const recommendations: DeterministicRecommendation[] = [];

  for (const group of recommendationGroups) {
    const actions = candidates.flatMap((candidate) => {
      const finding = findingById.get(candidate.findingId);
      if (
        !finding ||
        candidate.change.resourceType !== group.resourceType ||
        candidate.change.configPath !== group.configPath
      ) {
        return [];
      }
      usedActionIds.add(candidate.actionId);
      return [
        {
          actionId: candidate.actionId,
          finding,
          actionableChange: candidate.change,
        },
      ];
    });
    if (actions.length === 0) continue;
    recommendations.push({
      key: group.key,
      title: group.title,
      selectionMode: group.selectionMode,
      defaultSelected: group.defaultSelected,
      actions,
      analysis: recommendationAnalysisSchema.parse({
        whatItMeans: group.whatItMeans,
        whyItMatters: group.reason,
        remediationConsiderations: [group.suggestion],
      }),
    });
  }

  const callbackCandidates = candidates.filter(
    (candidate) =>
      candidate.change.resourceType === "client" &&
      candidate.change.configPath === "callbacks" &&
      findingById.has(candidate.findingId),
  );
  const callbacksByClient = new Map<string, typeof callbackCandidates>();
  for (const candidate of callbackCandidates) {
    usedActionIds.add(candidate.actionId);
    const grouped = callbacksByClient.get(candidate.change.resourceId) ?? [];
    grouped.push(candidate);
    callbacksByClient.set(candidate.change.resourceId, grouped);
  }
  for (const grouped of callbacksByClient.values()) {
    const first = grouped[0];
    if (!first) continue;
    const name = first.change.resourceName;
    recommendations.push({
      key: `callbacks-${first.actionId}`,
      title: `Remove insecure callback URLs from ${name}`,
      selectionMode: "changes",
      defaultSelected: false,
      actions: grouped.flatMap((candidate) => {
        const finding = findingById.get(candidate.findingId);
        return finding
          ? [
              {
                actionId: candidate.actionId,
                finding,
                actionableChange: candidate.change,
              },
            ]
          : [];
      }),
      analysis: recommendationAnalysisSchema.parse({
        whatItMeans: [
          `${name} allows callback URLs that CheckMate identified as insecure.`,
        ],
        whyItMatters: [
          "Removing development callback URLs reduces the chance of authentication responses being redirected to unintended local endpoints.",
          "All other configured callback URLs remain unchanged.",
        ],
        remediationConsiderations: [
          `Remove the selected insecure callback URLs from ${name}.`,
        ],
      }),
    });
  }

  for (const candidate of candidates) {
    if (usedActionIds.has(candidate.actionId)) continue;
    const finding = findingById.get(candidate.findingId);
    if (!finding) continue;
    const guidance = guidanceFor(candidate.change);
    if (!guidance) continue;
    recommendations.push({
      key: candidate.actionId,
      title: guidance.title,
      selectionMode: "single",
      defaultSelected: true,
      actions: [
        {
          actionId: candidate.actionId,
          finding,
          actionableChange: candidate.change,
        },
      ],
      analysis: recommendationAnalysisSchema.parse(guidance.analysis),
    });
  }

  const recommendationOrder = (
    recommendation: DeterministicRecommendation,
  ): number =>
    Math.min(
      ...recommendation.actions.map(
        ({ actionId }) => candidateOrder.get(actionId) ?? Infinity,
      ),
    );
  return recommendations.sort(
    (left, right) => recommendationOrder(left) - recommendationOrder(right),
  );
}

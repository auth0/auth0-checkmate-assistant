import { describe, expect, it } from "vitest";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import type { ActionableChange } from "../src/remediation/actionable-change.js";
import {
  buildDeterministicRecommendations,
  DETERMINISTIC_GUIDANCE_ENGINE,
} from "../src/remediation/deterministic-guidance.js";

function entry(
  index: number,
  configPath: string,
  resourceName: string,
  currentValue: ActionableChange["currentValue"],
  targetValue: ActionableChange["targetValue"],
): { finding: NormalizedCheckmateFinding; change: ActionableChange } {
  return {
    finding: {
      id: `finding-${index}`,
      title: `Finding ${index}`,
      status: "failed",
      raw: {},
    },
    change: {
      resourceType: configPath.startsWith("options.")
        ? "connection"
        : "attack_protection",
      resourceId: `resource-${index}`,
      resourceName,
      configPath,
      currentValue,
      targetValue,
    },
  };
}

describe("deterministic remediation guidance", () => {
  it("uses a versioned guidance engine", () => {
    expect(DETERMINISTIC_GUIDANCE_ENGINE).toBe(
      "checkmate-1.8.4-deterministic-guidance-v1",
    );
  });

  it("creates specific guidance for every ungrouped supported setting", () => {
    const entries = [
      entry(1, "options.passwordPolicy", "Primary database", "fair", "good"),
      entry(
        2,
        "options.password_complexity_options.min_length",
        "Primary database",
        8,
        12,
      ),
      entry(
        3,
        "options.attributes.email.verification_method",
        "Primary database",
        "link",
        "otp",
      ),
      entry(
        4,
        "mode",
        "Brute Force Protection",
        "count_per_identifier_and_ip",
        "count_per_identifier",
      ),
      entry(5, "enabled", "Breached Password Detection", false, true),
      entry(6, "shields", "Breached Password Detection", [], ["block"]),
      entry(
        7,
        "stage.pre-user-registration.shields",
        "Breached Password Detection",
        [],
        ["block"],
      ),
      entry(
        8,
        "stage.pre-change-password.shields",
        "Breached Password Detection",
        [],
        ["block"],
      ),
    ];
    const recommendations = buildDeterministicRecommendations(
      entries.map(({ finding }) => finding),
      new Map(
        entries.map(({ finding, change }): [string, ActionableChange[]] => [
          finding.id,
          [change],
        ]),
      ),
    );

    expect(recommendations).toHaveLength(8);
    expect(recommendations.map((item) => item.actions[0]?.finding.id)).toEqual(
      entries.map(({ finding }) => finding.id),
    );
    expect(recommendations.map((item) => item.title)).toEqual([
      "Set the password policy to Good for Primary database",
      "Set the minimum password length to 12 for Primary database",
      "Use OTP email verification for Primary database",
      "Enable account lockout for brute-force protection",
      "Enable Breached Password Detection",
      "Block logins that use breached credentials",
      "Block breached passwords during user registration",
      "Block breached passwords during password changes",
    ]);
    expect(
      recommendations.every(
        (item) => item.analysis.remediationConsiderations.length === 1,
      ),
    ).toBe(true);
  });

  it("does not turn an unknown configuration path into an executable recommendation", () => {
    const unsupported = entry(
      1,
      "options.unknown_setting",
      "Primary database",
      false,
      true,
    );

    expect(
      buildDeterministicRecommendations(
        [unsupported.finding],
        new Map([[unsupported.finding.id, [unsupported.change]]]),
      ),
    ).toEqual([]);
  });
});

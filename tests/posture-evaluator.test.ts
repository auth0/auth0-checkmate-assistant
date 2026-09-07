import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadCheckmateReport } from "../src/checkmate/report-loader.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import {
  POSTURE_CONTROLS,
  POSTURE_MAXIMUM_SCORE,
  postureRecommendationImpact,
} from "../src/posture/control-catalog.js";
import {
  classifyPostureScore,
  evaluatePosture,
} from "../src/posture/evaluator.js";

const reportFixture = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/checkmate-report.json",
);

function finding(
  validatorId: string,
  id = `${validatorId}-1`,
): NormalizedCheckmateFinding {
  return {
    id,
    validatorId,
    title: validatorId,
    status: "failed",
    raw: {},
  };
}

describe("tenant configuration posture", () => {
  it("uses all 36 scorable CheckMate 1.8.4 validators", () => {
    const assessment = evaluatePosture([]);

    expect(POSTURE_CONTROLS).toHaveLength(36);
    expect(POSTURE_MAXIMUM_SCORE).toBe(118);
    expect(assessment).toMatchObject({
      modelVersion: "checkmate-1.8.4",
      maximumScore: 118,
      catalogControlCount: 36,
      passedControlCount: 36,
      current: { score: 118, rating: "green" },
      delta: 0,
    });
    expect(assessment.projected).toEqual(assessment.current);
  });

  it("deducts and restores five points for a red validator", () => {
    const current = evaluatePosture([finding("checkPasswordPolicy")]);
    const projected = evaluatePosture([finding("checkPasswordPolicy")], {
      projectedResolvedValidatorIds: new Set(["checkPasswordPolicy"]),
    });

    expect(current.current.score).toBe(113);
    expect(projected.current.score).toBe(113);
    expect(projected.projected.score).toBe(118);
    expect(projected.delta).toBe(5);
  });

  it("deducts three points for yellow and one for green", () => {
    const assessment = evaluatePosture([
      finding("checkPasswordComplexity"),
      finding("checkPasswordHistory"),
    ]);

    expect(assessment.current.score).toBe(114);
    expect(assessment.reportedControlCount).toBe(2);
    expect(assessment.passedControlCount).toBe(34);
  });

  it("counts a validator once when several detail rows are reported", () => {
    const assessment = evaluatePosture([
      finding("checkGrantTypes", "grant-1"),
      finding("checkGrantTypes", "grant-2"),
      finding("checkGrantTypes", "grant-3"),
    ]);

    expect(assessment.current.score).toBe(113);
    expect(assessment.reportedControlCount).toBe(1);
  });

  it("assigns fixed recommendation points from CheckMate priority", () => {
    expect(postureRecommendationImpact("checkPasswordPolicy")).toMatchObject({
      label: "High priority",
      points: 5,
    });
    expect(
      postureRecommendationImpact("checkPasswordNoPersonalInfo"),
    ).toMatchObject({ label: "Moderate priority", points: 3 });
    expect(postureRecommendationImpact("checkPasswordHistory")).toMatchObject({
      label: "Low priority",
      points: 1,
    });
  });

  it("does not score blue or violet validators", () => {
    const assessment = evaluatePosture([
      finding("checkSupportUrl"),
      finding("checkEnabledDynamicClientRegistration"),
    ]);

    expect(assessment.current.score).toBe(118);
    expect(assessment.reportedControlCount).toBe(0);
    expect(assessment.unscoredValidatorIds).toEqual([
      "checkEnabledDynamicClientRegistration",
      "checkSupportUrl",
    ]);
  });

  it("calculates 44 starting points from a full CheckMate report", async () => {
    const report = await loadCheckmateReport(reportFixture);
    const assessment = evaluatePosture(report.findings);

    expect(assessment.current).toMatchObject({ score: 44, rating: "red" });
    expect(assessment.reportedControlCount).toBe(24);
    expect(assessment.passedControlCount).toBe(12);
  });

  it("uses the requested red, amber, and green thresholds", () => {
    expect(classifyPostureScore(44)).toBe("red");
    expect(classifyPostureScore(59)).toBe("red");
    expect(classifyPostureScore(60)).toBe("amber");
    expect(classifyPostureScore(79)).toBe("amber");
    expect(classifyPostureScore(80)).toBe("green");
  });
});

import type { NormalizedCheckmateFinding } from "../findings/types.js";
import {
  CHECKMATE_PRIORITY_POINTS,
  POSTURE_CONTROLS,
  POSTURE_MAXIMUM_SCORE,
  POSTURE_MODEL_VERSION,
  type PostureControl,
  type ScoredCheckmatePriority,
} from "./control-catalog.js";

export type PostureRating = "red" | "amber" | "green";

export interface PostureOpenControl {
  validatorId: string;
  title: string;
  priority: ScoredCheckmatePriority;
  points: number;
}

export interface PostureSnapshot {
  score: number;
  rating: PostureRating;
  openControls: PostureOpenControl[];
}

export interface PostureAssessment {
  modelVersion: string;
  maximumScore: number;
  current: PostureSnapshot;
  projected: PostureSnapshot;
  delta: number;
  catalogControlCount: number;
  reportedControlCount: number;
  passedControlCount: number;
  unscoredValidatorIds: string[];
}

export interface EvaluatePostureOptions {
  projectedResolvedValidatorIds?: ReadonlySet<string>;
}

export function classifyPostureScore(score: number): PostureRating {
  if (score < 60) return "red";
  if (score < 80) return "amber";
  return "green";
}

function openControl(control: PostureControl): PostureOpenControl {
  return {
    validatorId: control.validatorId,
    title: control.title,
    priority: control.priority,
    points: CHECKMATE_PRIORITY_POINTS[control.priority],
  };
}

function snapshot(openValidatorIds: ReadonlySet<string>): PostureSnapshot {
  const openControls = POSTURE_CONTROLS.filter((control) =>
    openValidatorIds.has(control.validatorId),
  ).map(openControl);
  const openPoints = openControls.reduce(
    (total, control) => total + control.points,
    0,
  );
  const score = POSTURE_MAXIMUM_SCORE - openPoints;
  return {
    score,
    rating: classifyPostureScore(score),
    openControls,
  };
}

export function evaluatePosture(
  findings: readonly NormalizedCheckmateFinding[],
  options: EvaluatePostureOptions = {},
): PostureAssessment {
  const catalogValidatorIds = new Set(
    POSTURE_CONTROLS.map((control) => control.validatorId),
  );
  const reportedValidatorIds = new Set(
    findings.flatMap((finding) =>
      finding.validatorId ? [finding.validatorId] : [],
    ),
  );
  const openValidatorIds = new Set(
    [...reportedValidatorIds].filter((validatorId) =>
      catalogValidatorIds.has(validatorId),
    ),
  );
  const resolvedValidatorIds =
    options.projectedResolvedValidatorIds ?? new Set<string>();
  const projectedOpenValidatorIds = new Set(
    [...openValidatorIds].filter(
      (validatorId) => !resolvedValidatorIds.has(validatorId),
    ),
  );
  const current = snapshot(openValidatorIds);
  const projected = snapshot(projectedOpenValidatorIds);

  return {
    modelVersion: POSTURE_MODEL_VERSION,
    maximumScore: POSTURE_MAXIMUM_SCORE,
    current,
    projected,
    delta: projected.score - current.score,
    catalogControlCount: POSTURE_CONTROLS.length,
    reportedControlCount: openValidatorIds.size,
    passedControlCount: POSTURE_CONTROLS.length - openValidatorIds.size,
    unscoredValidatorIds: [...reportedValidatorIds]
      .filter((validatorId) => !catalogValidatorIds.has(validatorId))
      .sort(),
  };
}

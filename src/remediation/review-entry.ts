import type { NormalizedCheckmateFinding } from "../findings/types.js";
import { redactText } from "../security/redaction.js";
import type { RemediationDecisionStatus } from "./plan-schema.js";
import type { ReviewEntry } from "./review-schema.js";
import type { ActionableChange } from "./actionable-change.js";
import type { RecommendationAnalysis } from "./deterministic-guidance.js";

export function boundedUserText(
  value: string,
  sensitiveValues: readonly string[],
): string {
  return redactText(value, sensitiveValues).slice(0, 4_000);
}

export function createReviewEntry(
  finding: NormalizedCheckmateFinding,
  analysis: RecommendationAnalysis,
  decision: RemediationDecisionStatus,
  rationale: string,
  decidedAt: string,
  sensitiveValues: readonly string[],
  actionableChanges: readonly ActionableChange[] = [],
): ReviewEntry {
  const entry: ReviewEntry = {
    checkmateFindingId: redactText(finding.id, sensitiveValues),
    checkmateTitle: redactText(finding.title, sensitiveValues),
    checkmateStatus: finding.status,
    analysis,
    decision: {
      status: decision,
      rationale: boundedUserText(rationale, sensitiveValues),
      decidedAt,
    },
  };
  if (actionableChanges.length > 0) {
    entry.actionableChanges = [...actionableChanges];
  }
  if (finding.validatorId) {
    entry.checkmateValidatorId = redactText(
      finding.validatorId,
      sensitiveValues,
    );
  }
  if (finding.description) {
    entry.checkmateMessage = redactText(finding.description, sensitiveValues);
  }
  if (finding.recommendation) {
    entry.checkmateRecommendation = redactText(
      finding.recommendation,
      sensitiveValues,
    );
  }
  return entry;
}

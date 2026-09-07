import { z } from "zod";
import { remediationDecisionStatusSchema } from "./plan-schema.js";
import { actionableChangeSchema } from "./actionable-change.js";
import { recommendationAnalysisSchema } from "./deterministic-guidance.js";

export const reviewEntrySchema = z.object({
  checkmateFindingId: z.string().min(1),
  actionableChangeId: z.string().min(1).optional(),
  checkmateValidatorId: z.string().min(1).optional(),
  checkmateTitle: z.string().min(1),
  checkmateStatus: z.enum(["passed", "failed", "warning", "unknown"]),
  checkmateMessage: z.string().optional(),
  checkmateRecommendation: z.string().optional(),
  analysis: recommendationAnalysisSchema,
  actionableChanges: z.array(actionableChangeSchema).optional(),
  decision: z.object({
    status: remediationDecisionStatusSchema,
    rationale: z.string().min(1).max(4_000),
    adminNote: z.string().min(1).max(4_000).optional(),
    decidedAt: z.string().datetime(),
  }),
});

const executionCallSchema = z.object({
  id: z.string().min(1),
  endpoint: z.string().startsWith("/api/v2/"),
  status: z.enum([
    "applied",
    "already_applied",
    "resumed_verified",
    "verification_failed",
    "failed",
    "rolled_back",
    "rollback_already_applied",
    "rollback_failed",
  ]),
  correlationId: z.string().min(1).max(64),
  error: z.string().min(1).optional(),
});

const executionRecordSchema = z.object({
  planFile: z.string().min(1),
  planSha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  operation: z.enum(["apply", "rollback"]).default("apply"),
  status: z.enum(["succeeded", "failed"]),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime(),
  profile: z.literal("dev"),
  calls: z.array(executionCallSchema),
  error: z.string().min(1).optional(),
});

export const reviewSessionSchema = z.object({
  schemaVersion: z.literal(1),
  report: z.object({
    sourceReport: z.string().min(1),
    tenant: z.string().min(1).optional(),
    reportTimestamp: z.string().optional(),
  }),
  review: z.object({
    guidanceEngine: z.string().min(1),
    startedAt: z.string().datetime(),
    lastUpdatedAt: z.string().datetime(),
    completedAt: z.string().datetime().optional(),
  }),
  decisions: z.array(reviewEntrySchema),
  execution: executionRecordSchema.optional(),
  executionHistory: z.array(executionRecordSchema).optional(),
});

export type ReviewEntry = z.infer<typeof reviewEntrySchema>;
export type ReviewSession = z.infer<typeof reviewSessionSchema>;

import { z } from "zod";

export const chatAnswerSchema = z.object({
  headline: z.string().min(1).max(240),
  headlineFindingIds: z.array(z.string().min(1).max(200)).max(4),
  sections: z
    .array(
      z.object({
        title: z.string().min(1).max(120),
        items: z
          .array(
            z.object({
              text: z.string().min(1).max(800),
              basis: z.enum(["checkmate_report", "auth0_live"]),
              findingIds: z.array(z.string().min(1).max(200)).max(4),
            }),
          )
          .min(1)
          .max(8),
      }),
    )
    .min(1)
    .max(6),
  evidenceGaps: z.array(z.string().min(1).max(400)).max(6),
  suggestedQuestions: z
    .array(
      z.object({
        question: z.string().min(1).max(180),
        findingIds: z.array(z.string().min(1).max(200)).max(4),
      }),
    )
    .max(4),
  actionConfirmations: z
    .array(
      z.object({
        question: z.string().min(1).max(220),
        findingIds: z.array(z.string().min(1).max(200)).min(1).max(4),
      }),
    )
    .max(1),
});

export const chatRequestSchema = z.object({
  question: z.string().trim().min(1).max(2_000),
  history: z
    .array(
      z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string().trim().min(1).max(4_000),
      }),
    )
    .max(12)
    .default([]),
});

export const checkmateScanRequestSchema = z
  .object({ profile: z.enum(["dev", "prod"]) })
  .strict();

export const devPlanRequestSchema = z
  .object({ recommendationId: z.string().min(20).max(100) })
  .strict();

export const devExecuteRequestSchema = z
  .object({
    planId: z.string().min(20).max(100),
    planSha256: z.string().regex(/^[a-f0-9]{64}$/),
    confirmed: z.literal(true),
    tenantDomain: z.string().min(1).max(255),
    confirmationText: z.literal("EXECUTE DEV"),
  })
  .strict();

import { z } from "zod";

export const remediationDecisionStatusSchema = z.enum([
  "approved",
  "accepted_risk",
]);

export type RemediationDecisionStatus = z.infer<
  typeof remediationDecisionStatusSchema
>;

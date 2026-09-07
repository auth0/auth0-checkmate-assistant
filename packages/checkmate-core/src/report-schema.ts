import { z } from "zod";

export const rawFindingObjectSchema = z.object({}).catchall(z.unknown());

export const rawReportSchema = z.union([
  z.array(z.unknown()),
  z.object({}).catchall(z.unknown()),
]);

export type RawFindingObject = z.infer<typeof rawFindingObjectSchema>;

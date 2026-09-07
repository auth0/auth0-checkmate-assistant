import { z } from "zod";

export const configurationValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(z.string()),
]);

export type ConfigurationValue = z.infer<typeof configurationValueSchema>;

export const actionableChangeSchema = z.object({
  resourceType: z.enum(["connection", "attack_protection", "client"]),
  resourceId: z.string().min(1),
  resourceName: z.string().min(1),
  configPath: z.string().min(1),
  currentValue: configurationValueSchema,
  targetValue: configurationValueSchema,
});

export type ActionableChange = z.infer<typeof actionableChangeSchema>;

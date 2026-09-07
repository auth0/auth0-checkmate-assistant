import { z } from "zod";
import { AppError } from "../utils/errors.js";

export const profileNameSchema = z.enum(["prod", "dev"]);
export type ProfileName = z.infer<typeof profileNameSchema>;

export interface ProfileDefinition {
  domainEnv: string;
  clientIdEnv: string;
  clientSecretEnv: string;
}

export const profiles: Record<ProfileName, ProfileDefinition> = {
  prod: {
    domainEnv: "AUTH0CHECKMATE_PROD_DOMAIN",
    clientIdEnv: "AUTH0CHECKMATE_PROD_CLIENT_ID",
    clientSecretEnv: "AUTH0CHECKMATE_PROD_CLIENT_SECRET",
  },
  dev: {
    domainEnv: "AUTH0CHECKMATE_DEV_DOMAIN",
    clientIdEnv: "AUTH0CHECKMATE_DEV_CLIENT_ID",
    clientSecretEnv: "AUTH0CHECKMATE_DEV_CLIENT_SECRET",
  },
};

export function selectProfile(name: string): {
  name: ProfileName;
  definition: ProfileDefinition;
} {
  const parsed = profileNameSchema.safeParse(name);
  if (!parsed.success) {
    throw new AppError(
      "INVALID_PROFILE",
      `Invalid profile: ${name}. Allowed profiles: prod, dev.`,
    );
  }
  return { name: parsed.data, definition: profiles[parsed.data] };
}

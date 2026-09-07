import path from "node:path";
import { config as loadDotenv } from "dotenv";
import { z } from "zod";
import { selectProfile, type ProfileName } from "./profiles.js";
import { AppError } from "../utils/errors.js";

const timeoutSchema = z.coerce.number().int().positive().max(3_600_000);

export interface CheckmateConfig {
  profile: ProfileName;
  domain: string;
  clientId: string;
  clientSecret: string;
  outputDirectory: string;
  disablePdfReporting: boolean;
  timeoutMs: number;
}

export function initialiseEnvironment(): void {
  loadDotenv({ quiet: true });
}

function required(env: NodeJS.ProcessEnv, variableName: string): string {
  const value = env[variableName]?.trim();
  if (!value) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      `Missing required environment variable:\n${variableName}`,
    );
  }
  return value;
}

export function loadCheckmateConfig(
  profileName: string,
  env: NodeJS.ProcessEnv = process.env,
): CheckmateConfig {
  const profile = selectProfile(profileName);
  const timeoutValue = env.AUTH0CHECKMATE_TIMEOUT_MS ?? "300000";
  const parsedTimeout = timeoutSchema.safeParse(timeoutValue);
  if (!parsedTimeout.success) {
    throw new AppError(
      "MISSING_CONFIGURATION",
      "AUTH0CHECKMATE_TIMEOUT_MS must be a positive integer no greater than 3600000.",
    );
  }

  return {
    profile: profile.name,
    domain: required(env, profile.definition.domainEnv),
    clientId: required(env, profile.definition.clientIdEnv),
    clientSecret: required(env, profile.definition.clientSecretEnv),
    outputDirectory: path.resolve(env.AUTH0CHECKMATE_FILE_PATH ?? "./reports"),
    disablePdfReporting:
      (env.AUTH0CHECKMATE_DISABLE_PDF_REPORTING ?? "true").toLowerCase() !==
      "false",
    timeoutMs: parsedTimeout.data,
  };
}

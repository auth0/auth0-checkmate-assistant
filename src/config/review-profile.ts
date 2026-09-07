import path from "node:path";
import { loadCheckmateConfig, type CheckmateConfig } from "./env.js";
import { profiles, type ProfileName } from "./profiles.js";

function configuredProfile(
  profile: ProfileName,
  env: NodeJS.ProcessEnv,
): CheckmateConfig | undefined {
  const definition = profiles[profile];
  if (
    !env[definition.domainEnv]?.trim() ||
    !env[definition.clientIdEnv]?.trim() ||
    !env[definition.clientSecretEnv]?.trim()
  ) {
    return undefined;
  }
  return loadCheckmateConfig(profile, env);
}

export function resolveReviewProfile(
  requestedProfile: string | undefined,
  reportPath: string,
  env: NodeJS.ProcessEnv,
): CheckmateConfig | undefined {
  if (requestedProfile) return loadCheckmateConfig(requestedProfile, env);

  const configured = (["dev", "prod"] as const)
    .map((profile) => configuredProfile(profile, env))
    .filter((config): config is CheckmateConfig => Boolean(config));
  const filename = path.basename(reportPath).toLowerCase();
  const matching = configured.filter((config) =>
    filename.includes(config.domain.toLowerCase()),
  );
  if (matching.length === 1) return matching[0];
  return configured.length === 1 ? configured[0] : undefined;
}

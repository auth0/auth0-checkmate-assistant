import { isSensitiveKey } from "./sensitive-fields.js";

export function collectSensitiveEnvironmentValues(
  env: NodeJS.ProcessEnv,
): string[] {
  return Object.entries(env)
    .filter(([key, value]) => isSensitiveKey(key) && Boolean(value))
    .map(([, value]) => value as string);
}

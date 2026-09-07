import { isSensitiveKey } from "./sensitive-fields.js";

export const REDACTED = "[REDACTED]";

export function redactText(
  text: string,
  sensitiveValues: readonly string[] = [],
): string {
  const knownValuesRedacted = sensitiveValues
    .filter((value) => value.length > 0)
    .sort((left, right) => right.length - left.length)
    .reduce((result, value) => result.split(value).join(REDACTED), text);

  return knownValuesRedacted
    .replace(/(authorization\s*[:=]\s*)(?:bearer\s+)?\S+/gi, `$1${REDACTED}`)
    .replace(
      /((?:secret|token|password|api[_-]?key)\s*[:=]\s*)\S+/gi,
      `$1${REDACTED}`,
    )
    .replace(/(bearer\s+)\S+/gi, `$1${REDACTED}`)
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      REDACTED,
    );
}

export function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        isSensitiveKey(key) ? REDACTED : redactSensitive(item),
      ]),
    );
  }

  return value;
}

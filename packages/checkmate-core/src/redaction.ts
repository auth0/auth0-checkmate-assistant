const REDACTED = "[REDACTED]";

const SENSITIVE_KEY =
  /(?:^|_)(?:authorization|client_secret|secret|token|password|api_key|private_key)(?:$|_)/i;

export function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        SENSITIVE_KEY.test(key) ? REDACTED : redactSensitive(item),
      ]),
    );
  }

  if (typeof value === "string") {
    return value
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

  return value;
}

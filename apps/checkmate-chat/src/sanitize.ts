const REDACTED = "[REDACTED]";
const MAX_DEPTH = 8;
const MAX_ARRAY_ITEMS = 50;
const MAX_STRING_LENGTH = 6_000;
const MAX_SERIALIZED_LENGTH = 60_000;

const SENSITIVE_KEYS = new Set([
  "apikey",
  "api_key",
  "authorization",
  "clientsecret",
  "client_secret",
  "cookie",
  "credential",
  "idtoken",
  "id_token",
  "password",
  "privatekey",
  "private_key",
  "refreshtoken",
  "refresh_token",
  "secret",
  "signingkey",
  "signing_key",
  "accesstoken",
  "access_token",
]);

function maskPersonalData(value: string): string {
  return value
    .replace(/\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, "[EMAIL]@$1")
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, "$1.$2.$3.x");
}

function sanitizeValue(
  value: unknown,
  options: { maskPersonalData: boolean },
  depth: number,
  seen: WeakSet<object>,
): unknown {
  if (depth > MAX_DEPTH) return "[TRUNCATED]";
  if (typeof value === "string") {
    const masked = options.maskPersonalData ? maskPersonalData(value) : value;
    return masked.length > MAX_STRING_LENGTH
      ? `${masked.slice(0, MAX_STRING_LENGTH)}…[TRUNCATED]`
      : masked;
  }
  if (
    value === null ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, options, depth + 1, seen));
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "undefined") return "[UNDEFINED]";
  if (typeof value === "symbol") return value.description ?? "[SYMBOL]";
  if (typeof value === "function") return "[FUNCTION]";
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[-\s]/g, "_");
    output[key] = SENSITIVE_KEYS.has(normalizedKey)
      ? REDACTED
      : sanitizeValue(item, options, depth + 1, seen);
  }
  return output;
}

export function sanitizeToolResult(
  value: unknown,
  options: { maskPersonalData?: boolean } = {},
): unknown {
  const sanitized = sanitizeValue(
    value,
    { maskPersonalData: options.maskPersonalData ?? false },
    0,
    new WeakSet(),
  );
  const serialized = JSON.stringify(sanitized);
  if (serialized.length <= MAX_SERIALIZED_LENGTH) return sanitized;
  return {
    truncated: true,
    content: `${serialized.slice(0, MAX_SERIALIZED_LENGTH)}…[TRUNCATED]`,
  };
}

export function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : "Unknown error.";
  return maskPersonalData(message).slice(0, 500);
}

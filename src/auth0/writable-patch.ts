import type { ApiPlanCall } from "../remediation/api-plan.js";
import { AppError } from "../utils/errors.js";

export const CLIENT_JWT_WRITABLE_FIELDS = [
  "alg",
  "lifetime_in_seconds",
  "scopes",
] as const;

export const BREACHED_PASSWORD_STAGE_WRITABLE_FIELDS = {
  "pre-user-registration": ["shields"],
  "pre-change-password": ["shields"],
} as const;

const CLIENT_PATHS = new Set([
  "callbacks",
  "grant_types",
  "cross_origin_authentication",
  "jwt_configuration.alg",
]);

const CONNECTION_PATHS = new Set([
  "options.passwordPolicy",
  "options.password_complexity_options.min_length",
  "options.password_history.enable",
  "options.password_no_personal_info.enable",
  "options.authentication_methods.passkey.enabled",
  "options.attributes.email.verification_method",
]);

const BRUTE_FORCE_PATHS = new Set(["enabled", "shields", "mode"]);

const BREACHED_PASSWORD_PATHS = new Set([
  "enabled",
  "shields",
  "stage.pre-user-registration.shields",
  "stage.pre-change-password.shields",
]);

type CallKind = "client" | "connection" | "brute_force" | "breached_password";

function fail(message: string): never {
  throw new AppError("AUTH0_WRITE_FAILED", message);
}

function safeKey(key: string): void {
  if (
    !/^[a-zA-Z0-9_-]+$/.test(key) ||
    ["__proto__", "prototype", "constructor"].includes(key)
  ) {
    fail(`The API plan contains an unsafe configuration field: ${key}`);
  }
}

function callKind(call: ApiPlanCall): CallKind {
  if (call.resourceType === "client") {
    const expected = `/api/v2/clients/${encodeURIComponent(call.resourceId)}`;
    if (
      call.endpoint !== expected ||
      call.bodyStrategy !== "merge_live_nested_objects"
    ) {
      fail(
        `The API plan contains an invalid client endpoint: ${call.endpoint}`,
      );
    }
    return "client";
  }
  if (call.resourceType === "connection") {
    const expected = `/api/v2/connections/${encodeURIComponent(call.resourceId)}`;
    if (
      call.endpoint !== expected ||
      call.bodyStrategy !== "merge_live_connection_options"
    ) {
      fail(
        `The API plan contains an invalid connection endpoint: ${call.endpoint}`,
      );
    }
    return "connection";
  }
  if (call.bodyStrategy !== "merge_live_nested_objects") {
    fail(
      `The API plan contains an invalid attack-protection body strategy for ${call.endpoint}.`,
    );
  }
  if (
    call.endpoint === "/api/v2/attack-protection/breached-password-detection"
  ) {
    return "breached_password";
  }
  if (call.endpoint === "/api/v2/attack-protection/brute-force-protection") {
    return "brute_force";
  }
  return fail(
    `The API plan contains an unsupported attack-protection endpoint: ${call.endpoint}`,
  );
}

function allowedPaths(kind: CallKind): ReadonlySet<string> {
  if (kind === "client") return CLIENT_PATHS;
  if (kind === "connection") return CONNECTION_PATHS;
  if (kind === "brute_force") return BRUTE_FORCE_PATHS;
  return BREACHED_PASSWORD_PATHS;
}

function valueAt(source: unknown, dottedPath: string): unknown {
  let current = source;
  for (const segment of dottedPath.split(".")) {
    safeKey(segment);
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function leafPaths(value: unknown, prefix = ""): string[] {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return prefix ? [prefix] : [];
    return entries.flatMap(([key, nested]) => {
      safeKey(key);
      return leafPaths(nested, prefix ? `${prefix}.${key}` : key);
    });
  }
  return prefix ? [prefix] : [];
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function assertAllowedValue(
  kind: CallKind,
  path: string,
  value: unknown,
): void {
  if (value === null) return;
  if (path === "callbacks" || path === "grant_types") {
    if (!isStringArray(value))
      fail(`The API plan has an invalid value for ${path}.`);
    return;
  }
  if (path === "jwt_configuration.alg") {
    if (
      typeof value !== "string" ||
      !["HS256", "RS256", "PS256"].includes(value)
    ) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path === "options.passwordPolicy") {
    if (
      typeof value !== "string" ||
      !["none", "low", "fair", "good", "excellent"].includes(value)
    ) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path === "options.password_complexity_options.min_length") {
    if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > 128) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path === "options.attributes.email.verification_method") {
    if (value !== "link" && value !== "otp") {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path === "shields") {
    const allowed =
      kind === "brute_force"
        ? ["block", "user_notification"]
        : ["block", "user_notification", "admin_notification"];
    if (
      !isStringArray(value) ||
      value.some((item) => !allowed.includes(item))
    ) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path.endsWith(".shields")) {
    if (
      !isStringArray(value) ||
      value.some((item) => !["block", "admin_notification"].includes(item))
    ) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (path === "mode") {
    if (
      value !== "count_per_identifier" &&
      value !== "count_per_identifier_and_ip"
    ) {
      fail(`The API plan has an invalid value for ${path}.`);
    }
    return;
  }
  if (typeof value !== "boolean") {
    fail(`The API plan has an invalid value for ${path}.`);
  }
}

export function assertSupportedApiPlanCall(call: ApiPlanCall): void {
  const kind = callKind(call);
  const allowed = allowedPaths(kind);
  const plannedPaths = leafPaths(call.body);
  const preconditionPaths = new Set(
    call.preconditions.map((precondition) => precondition.path),
  );
  if (plannedPaths.length === 0 || preconditionPaths.size === 0) {
    fail(
      `The API plan contains no writable settings for ${call.resourceName}.`,
    );
  }
  for (const path of [...plannedPaths, ...preconditionPaths]) {
    if (!allowed.has(path)) {
      fail(`The API plan contains an unsupported writable setting: ${path}`);
    }
  }
  for (const path of plannedPaths) {
    if (!preconditionPaths.has(path)) {
      fail(`The API plan is missing a precondition for ${path}.`);
    }
    assertAllowedValue(kind, path, valueAt(call.body, path));
  }
  for (const path of preconditionPaths) {
    const target = valueAt(call.body, path);
    if (target === undefined) {
      fail(`The API plan is missing a target value for ${path}.`);
    }
    assertAllowedValue(kind, path, target);
  }
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return structuredClone(value);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`Auth0 returned invalid ${label} configuration.`);
  }
  return value as Record<string, unknown>;
}

function optionalRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  return value === undefined || value === null ? {} : record(value, label);
}

function mergeRecords(
  target: Record<string, unknown>,
  patch: Record<string, unknown>,
  deleteNulls = false,
): Record<string, unknown> {
  for (const [key, value] of Object.entries(patch)) {
    safeKey(key);
    if (deleteNulls && value === null) {
      delete target[key];
      continue;
    }
    const existing = target[key];
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const existingRecord =
        existing !== null &&
        typeof existing === "object" &&
        !Array.isArray(existing)
          ? cloneRecord(existing as Record<string, unknown>)
          : {};
      target[key] = mergeRecords(
        existingRecord,
        value as Record<string, unknown>,
        deleteNulls,
      );
    } else {
      target[key] = structuredClone(value);
    }
  }
  return target;
}

function removeNullValues(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(removeNullValues);
  if (value !== null && typeof value === "object") {
    const cleaned: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      safeKey(key);
      if (nested !== null && nested !== undefined) {
        cleaned[key] = removeNullValues(nested);
      }
    }
    return cleaned;
  }
  return value;
}

function clientJwtBody(
  live: Record<string, unknown>,
  planned: Record<string, unknown>,
): Record<string, unknown> {
  const writable = new Set<string>(CLIENT_JWT_WRITABLE_FIELDS);
  const writableLive = Object.fromEntries(
    Object.entries(live).filter(([key]) => writable.has(key)),
  );
  return mergeRecords(writableLive, planned);
}

function breachedPasswordStageBody(
  live: Record<string, unknown>,
  planned: Record<string, unknown>,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [stage, fields] of Object.entries(
    BREACHED_PASSWORD_STAGE_WRITABLE_FIELDS,
  )) {
    const current = live[stage];
    const currentRecord =
      current !== null && typeof current === "object" && !Array.isArray(current)
        ? (current as Record<string, unknown>)
        : {};
    const selected = Object.fromEntries(
      Object.entries(currentRecord).filter(([key]) =>
        (fields as readonly string[]).includes(key),
      ),
    );
    const patch = planned[stage];
    if (patch !== undefined) {
      Object.assign(
        selected,
        record(patch, `planned breached-password ${stage}`),
      );
    }
    if (Object.keys(selected).length > 0) body[stage] = selected;
  }
  return body;
}

function assertJsonPayload(value: unknown, path = "body"): void {
  if (
    value === undefined ||
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    (typeof value === "number" && !Number.isFinite(value))
  ) {
    fail(`The API plan produced an invalid PATCH value at ${path}.`);
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertJsonPayload(item, `${path}[${index}]`),
    );
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      safeKey(key);
      assertJsonPayload(nested, `${path}.${key}`);
    }
  }
}

export function buildWritablePatchBody(
  call: ApiPlanCall,
  live: Record<string, unknown>,
): Record<string, unknown> {
  assertSupportedApiPlanCall(call);
  const kind = callKind(call);
  let body: Record<string, unknown>;
  if (kind === "connection") {
    if (typeof live.strategy === "string" && live.strategy !== "auth0") {
      fail(
        `Execution stopped because ${call.resourceName} is not an Auth0 database connection.`,
      );
    }
    const liveOptions = record(
      removeNullValues(live.options),
      "connection options",
    );
    const plannedOptions = record(
      call.body.options,
      "planned connection options",
    );
    body = {
      ...(typeof live.display_name === "string"
        ? { display_name: live.display_name }
        : {}),
      // Auth0 replaces the complete connection options object on PATCH. Keep
      // all live options and overlay only the supported, approved changes.
      options: mergeRecords(cloneRecord(liveOptions), plannedOptions, true),
    };
  } else {
    body = {};
    for (const [key, planned] of Object.entries(call.body)) {
      if (kind === "client" && key === "jwt_configuration") {
        body[key] = clientJwtBody(
          optionalRecord(live[key], "client JWT"),
          record(planned, "planned client JWT"),
        );
      } else if (kind === "breached_password" && key === "stage") {
        body[key] = breachedPasswordStageBody(
          optionalRecord(live[key], "breached-password stage"),
          record(planned, "planned breached-password stage"),
        );
      } else {
        body[key] = structuredClone(planned);
      }
    }
  }
  assertJsonPayload(body);
  return body;
}

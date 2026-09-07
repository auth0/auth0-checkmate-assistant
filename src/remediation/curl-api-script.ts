import type { ApiPlanCall } from "./api-plan.js";
import {
  assertSupportedApiPlanCall,
  BREACHED_PASSWORD_STAGE_WRITABLE_FIELDS,
  CLIENT_JWT_WRITABLE_FIELDS,
} from "../auth0/writable-patch.js";
import { isValidTenantDomain } from "../utils/tenant-domain.js";

function bashQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function base64Json(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function scopes(call: ApiPlanCall): string[] {
  if (call.resourceType === "client") return ["read:clients", "update:clients"];
  if (call.resourceType === "connection") {
    return [
      "read:connections",
      "read:connections_options",
      "update:connections",
      "update:connections_options",
    ];
  }
  if (call.resourceType === "attack_protection") {
    return ["read:attack_protection", "update:attack_protection"];
  }
  throw new Error("Unsupported API plan resource type.");
}

function readEndpoint(call: ApiPlanCall): string {
  return call.resourceType === "connection"
    ? `${call.endpoint}?fields=id,name,display_name,strategy,options&include_fields=true`
    : call.endpoint;
}

const TOKEN_PAYLOAD_SCRIPT = `const fs = require("node:fs");
const values = fs.readFileSync(0).toString("utf8").split("\\0");
if (values.length < 5) throw new Error("Unable to prepare the Auth0 token request.");
const [clientId, clientSecret, audience, scope] = values;
process.stdout.write(JSON.stringify({
  grant_type: "client_credentials",
  client_id: clientId,
  client_secret: clientSecret,
  audience,
  scope,
}));`;

const TOKEN_PARSER_SCRIPT = `const fs = require("node:fs");
try {
  const token = JSON.parse(fs.readFileSync(0, "utf8"));
  if (typeof token.access_token !== "string" || token.access_token.length === 0) {
    throw new Error("Auth0 returned no access token.");
  }
  if (token.access_token.length > 16384 || /[\\r\\n]/.test(token.access_token)) {
    throw new Error("Auth0 returned an unsafe access token value.");
  }
  if (typeof token.scope === "string") {
    const granted = new Set(token.scope.split(/\\s+/).filter(Boolean));
    const missing = process.env.SCOPES.split(/\\s+/).filter((scope) => !granted.has(scope));
    if (missing.length > 0) throw new Error("Auth0 token is missing scopes: " + missing.join(", "));
  }
  process.stdout.write(token.access_token);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Invalid Auth0 token response.");
  process.exit(1);
}`;

const REQUEST_BUILDER_SCRIPT = `const crypto = require("node:crypto");
const fs = require("node:fs");
const clientJwtWritableFields = new Set(${JSON.stringify(CLIENT_JWT_WRITABLE_FIELDS)});
const breachedPasswordStageWritableFields = ${JSON.stringify(BREACHED_PASSWORD_STAGE_WRITABLE_FIELDS)};

function pathValue(source, dottedPath) {
  return dottedPath.split(".").reduce((current, segment) =>
    current !== null && typeof current === "object" && !Array.isArray(current)
      ? current[segment]
      : undefined, source);
}

function same(left, right) {
  if ((left === null || left === undefined) && (right === null || right === undefined)) return true;
  return JSON.stringify(left) === JSON.stringify(right);
}

function merge(current, planned, deleteNulls = false) {
  if (current !== null && typeof current === "object" && !Array.isArray(current) &&
      planned !== null && typeof planned === "object" && !Array.isArray(planned)) {
    const result = structuredClone(current);
    for (const [key, value] of Object.entries(planned)) {
      if (deleteNulls && value === null) delete result[key];
      else result[key] = merge(result[key], value, deleteNulls);
    }
    return result;
  }
  return structuredClone(planned);
}

function clientJwtBody(current, planned) {
  for (const plannedKey of Object.keys(planned ?? {})) {
    if (!clientJwtWritableFields.has(plannedKey)) {
      throw new Error("Execution stopped: API plan contains a non-writable client JWT setting.");
    }
  }
  const writableCurrent = Object.fromEntries(Object.entries(current ?? {})
    .filter(([key]) => clientJwtWritableFields.has(key)));
  return merge(writableCurrent, planned);
}

function breachedPasswordStageBody(current, planned) {
  const result = {};
  for (const [stage, fields] of Object.entries(breachedPasswordStageWritableFields)) {
    const writable = new Set(fields);
    const currentStage = current?.[stage] ?? {};
    const plannedStage = planned?.[stage];
    if (plannedStage !== undefined) {
      for (const plannedKey of Object.keys(plannedStage)) {
        if (!writable.has(plannedKey)) {
          throw new Error("Execution stopped: API plan contains a non-writable breached-password stage setting.");
        }
      }
    }
    const selected = Object.fromEntries(Object.entries(currentStage)
      .filter(([key]) => writable.has(key)));
    const merged = merge(selected, plannedStage ?? {});
    if (Object.keys(merged).length > 0) result[stage] = merged;
  }
  return result;
}

function mergeLiveNestedObject(resourceType, endpoint, key, current, planned) {
  if (resourceType === "client" && key === "jwt_configuration") {
    return clientJwtBody(current, planned);
  }
  if (endpoint === "/api/v2/attack-protection/breached-password-detection" && key === "stage") {
    return breachedPasswordStageBody(current, planned);
  }
  return structuredClone(planned);
}

function stripNulls(value) {
  if (Array.isArray(value)) return value.map(stripNulls);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([, nested]) => nested !== null && nested !== undefined)
      .map(([key, nested]) => [key, stripNulls(nested)]));
  }
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    return "{" + Object.entries(value)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, nested]) => JSON.stringify(key) + ":" + canonical(nested))
      .join(",") + "}";
  }
  return JSON.stringify(value) ?? "null";
}

try {
  const live = JSON.parse(fs.readFileSync(0, "utf8"));
  const planned = JSON.parse(Buffer.from(process.env.CHECKMATE_PLANNED_B64, "base64").toString("utf8"));
  const preconditions = JSON.parse(Buffer.from(process.env.CHECKMATE_PRECONDITIONS_B64, "base64").toString("utf8"));
  const allTargets = preconditions.every((item) => same(pathValue(live, item.path), pathValue(planned, item.path)));
  if (allTargets) {
    process.stdout.write(JSON.stringify({ state: "already_applied" }));
    process.exit(0);
  }
  const safe = preconditions.every((item) => {
    const current = pathValue(live, item.path);
    return same(current, item.expectedValue) || same(current, pathValue(planned, item.path));
  });
  if (!safe) throw new Error("Execution stopped: live configuration drifted from the validated plan.");

  let body;
  if (process.env.CHECKMATE_BODY_STRATEGY === "merge_live_nested_objects") {
    body = Object.fromEntries(Object.entries(planned).map(([key, value]) =>
      [key, mergeLiveNestedObject(process.env.CHECKMATE_RESOURCE_TYPE, process.env.CHECKMATE_ENDPOINT, key, live[key], value)]));
  } else if (process.env.CHECKMATE_BODY_STRATEGY === "merge_live_connection_options") {
    if (typeof live.strategy === "string" && live.strategy !== "auth0") {
      throw new Error("Execution stopped: target is not an Auth0 database connection.");
    }
    body = {
      ...(typeof live.display_name === "string" ? { display_name: live.display_name } : {}),
      options: merge(stripNulls(live.options ?? {}), planned.options, true),
    };
  } else {
    throw new Error("Execution stopped: unsupported body strategy.");
  }

  const digest = crypto.createHash("sha256")
    .update("PATCH\\n" + process.env.CHECKMATE_ENDPOINT + "\\n" + canonical(body), "utf8")
    .digest("hex");
  if (digest !== process.env.CHECKMATE_EXPECTED_REQUEST_SHA256) {
    throw new Error("Execution stopped: the exact PATCH request changed after package validation.");
  }
  process.stdout.write(JSON.stringify({ state: "safe_to_apply", body }));
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to prepare the PATCH request.");
  process.exit(1);
}`;

const RESPONSE_FIELD_SCRIPT = `const fs = require("node:fs");
const value = JSON.parse(fs.readFileSync(0, "utf8"));
const field = process.argv[1];
if (field === "body") process.stdout.write(JSON.stringify(value.body));
else process.stdout.write(String(value[field] ?? ""));`;

const RATE_LIMIT_DELAY_SCRIPT = `const fs = require("node:fs");
const headers = fs.readFileSync(process.argv[1], "utf8");
const attempt = Number.parseInt(process.argv[2] ?? "0", 10);
const values = (name) => [...headers.matchAll(new RegExp("^" + name + ":\\\\s*([^\\\\r\\\\n]+)", "gim"))]
  .map((match) => match[1].trim());
const retryAfter = values("retry-after").at(-1);
const resetAt = values("x-ratelimit-reset").at(-1);
let delay;
if (retryAfter && /^\\d+(?:\\.\\d+)?$/.test(retryAfter)) delay = Number(retryAfter);
else if (retryAfter && Number.isFinite(Date.parse(retryAfter))) delay = (Date.parse(retryAfter) - Date.now()) / 1000;
else if (resetAt && Number.isFinite(Number(resetAt))) delay = Number(resetAt) - Date.now() / 1000;
else delay = Math.min(2 ** Math.max(Number.isFinite(attempt) ? attempt : 0, 0), 30);
process.stdout.write(String(Math.min(Math.max(delay ?? 0, 0), 30)));`;

const PATCH_ERROR_SCRIPT = `const fs = require("node:fs");
try {
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const message = [value.message, value.error_description, value.error]
    .find((item) => typeof item === "string" && item.length > 0);
  if (message) process.stdout.write(message.replace(/[\\r\\n]+/g, " ").slice(0, 500));
} catch {}`;

const VERIFY_SCRIPT = `const fs = require("node:fs");
function pathValue(source, dottedPath) {
  return dottedPath.split(".").reduce((current, segment) =>
    current !== null && typeof current === "object" && !Array.isArray(current)
      ? current[segment]
      : undefined, source);
}
function same(left, right) {
  if ((left === null || left === undefined) && (right === null || right === undefined)) return true;
  return JSON.stringify(left) === JSON.stringify(right);
}
function preservationDifference(before, after, selectedPaths, currentPath = "") {
  if ((before === null || before === undefined) && (after === null || after === undefined)) return undefined;
  if (currentPath && selectedPaths.includes(currentPath)) return undefined;
  if (before !== null && typeof before === "object" && !Array.isArray(before)) {
    if (after === null || typeof after !== "object" || Array.isArray(after)) return currentPath || "resource";
    for (const [key, value] of Object.entries(before)) {
      const path = currentPath ? currentPath + "." + key : key;
      if (selectedPaths.includes(path)) continue;
      const nestedSelection = selectedPaths.some((item) => item.startsWith(path + "."));
      const afterValue = after[key];
      if (nestedSelection) {
        const difference = preservationDifference(value, afterValue, selectedPaths, path);
        if (difference) return difference;
      } else if (!((value === null || value === undefined) && (afterValue === null || afterValue === undefined)) && !same(value, afterValue)) return path;
    }
  } else if (!same(before, after)) return currentPath || "resource";
  return undefined;
}
try {
  const live = JSON.parse(fs.readFileSync(0, "utf8"));
  const before = JSON.parse(fs.readFileSync(process.env.CHECKMATE_BEFORE_FILE, "utf8"));
  const planned = JSON.parse(Buffer.from(process.env.CHECKMATE_PLANNED_B64, "base64").toString("utf8"));
  const preconditions = JSON.parse(Buffer.from(process.env.CHECKMATE_PRECONDITIONS_B64, "base64").toString("utf8"));
  const verified = preconditions.every((item) =>
    JSON.stringify(pathValue(live, item.path)) === JSON.stringify(pathValue(planned, item.path)));
  if (!verified) throw new Error("Auth0 did not retain every planned setting.");
  const difference = preservationDifference(before, live, preconditions.map((item) => item.path));
  if (difference) throw new Error("Auth0 changed an unselected setting: " + difference);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Unable to verify the PATCH result.");
  process.exit(1);
}`;

export const CURL_API_SHELL_RUNTIME = {
  tokenPayloadScript: TOKEN_PAYLOAD_SCRIPT,
  tokenParserScript: TOKEN_PARSER_SCRIPT,
  requestBuilderScript: REQUEST_BUILDER_SCRIPT,
  responseFieldScript: RESPONSE_FIELD_SCRIPT,
  rateLimitDelayScript: RATE_LIMIT_DELAY_SCRIPT,
  patchErrorScript: PATCH_ERROR_SCRIPT,
  verifyScript: VERIFY_SCRIPT,
} as const;

export function curlApiRequiredScopes(call: ApiPlanCall): readonly string[] {
  return scopes(call);
}

export function curlApiReadEndpoint(call: ApiPlanCall): string {
  return readEndpoint(call);
}

export interface CurlApiScript {
  shell: "bash";
  requiredEnvironmentVariables: string[];
  script: string;
}

export function buildCurlApiScript(
  profile: "dev" | "prod",
  call: ApiPlanCall,
  requestSha256: string,
  expectedDomain: string,
): CurlApiScript {
  assertSupportedApiPlanCall(call);
  if (!isValidTenantDomain(expectedDomain)) {
    throw new Error(
      "The curl API script requires a valid Auth0 tenant domain.",
    );
  }
  const prefix = `AUTH0CHECKMATE_${profile.toUpperCase()}`;
  const domainVariable = `${prefix}_DOMAIN`;
  const clientIdVariable = `${prefix}_CLIENT_ID`;
  const clientSecretVariable = `${prefix}_CLIENT_SECRET`;

  return {
    shell: "bash",
    requiredEnvironmentVariables: [
      domainVariable,
      clientIdVariable,
      clientSecretVariable,
    ],
    script: `#!/usr/bin/env bash
set -euo pipefail

# Generated from a live-preflighted CheckMate API plan.
# Requires only bash, curl, and Node.js. Credentials are read from the environment.
umask 077
for command in curl node; do
  command -v "\${command}" >/dev/null 2>&1 || {
    echo "Missing required command: \${command}" >&2
    exit 1
  }
done

EXPECTED_DOMAIN=${bashQuote(expectedDomain)}
DOMAIN="\${${domainVariable}:?Set ${domainVariable}}"
CLIENT_ID="\${${clientIdVariable}:?Set ${clientIdVariable}}"
CLIENT_SECRET="\${${clientSecretVariable}:?Set ${clientSecretVariable}}"
export -n CLIENT_ID CLIENT_SECRET 2>/dev/null || true
unset ${clientIdVariable} ${clientSecretVariable}
if [[ "\${DOMAIN}" != "\${EXPECTED_DOMAIN}" ]]; then
  echo "Execution stopped: ${domainVariable} must exactly match the validated tenant \${EXPECTED_DOMAIN}." >&2
  exit 1
fi

export BASE_URL="https://\${DOMAIN}"
export SCOPES=${bashQuote(scopes(call).join(" "))}
export CHECKMATE_ENDPOINT=${bashQuote(call.endpoint)}
export CHECKMATE_READ_ENDPOINT=${bashQuote(readEndpoint(call))}
export CHECKMATE_RESOURCE_NAME=${bashQuote(call.resourceName)}
export CHECKMATE_RESOURCE_TYPE=${bashQuote(call.resourceType)}
export CHECKMATE_BODY_STRATEGY=${bashQuote(call.bodyStrategy)}
export CHECKMATE_EXPECTED_REQUEST_SHA256=${bashQuote(requestSha256)}
export CHECKMATE_PLANNED_B64=${bashQuote(base64Json(call.body))}
export CHECKMATE_PRECONDITIONS_B64=${bashQuote(base64Json(call.preconditions))}

WORK_DIRECTORY="$(mktemp -d "\${TMPDIR:-/tmp}/checkmate-curl.XXXXXX")"
TOKEN_PAYLOAD_FILE="\${WORK_DIRECTORY}/token-request.json"
AUTH_HEADER_FILE="\${WORK_DIRECTORY}/authorization-header"
BEFORE_FILE="\${WORK_DIRECTORY}/before.json"
PATCH_RESPONSE_FILE="\${WORK_DIRECTORY}/patch-response.json"
PATCH_HEADERS_FILE="\${WORK_DIRECTORY}/patch-headers.txt"
cleanup() {
  rm -f "\${TOKEN_PAYLOAD_FILE}" "\${AUTH_HEADER_FILE}" "\${BEFORE_FILE}" \
    "\${PATCH_RESPONSE_FILE}" "\${PATCH_HEADERS_FILE}"
  rmdir "\${WORK_DIRECTORY}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export CHECKMATE_BEFORE_FILE="\${BEFORE_FILE}"

printf '%s\\0%s\\0%s\\0%s\\0' \
  "\${CLIENT_ID}" "\${CLIENT_SECRET}" "\${BASE_URL}/api/v2/" "\${SCOPES}" |
  node -e ${bashQuote(TOKEN_PAYLOAD_SCRIPT)} > "\${TOKEN_PAYLOAD_FILE}"
unset CLIENT_SECRET

TOKEN_RESPONSE="$(
  curl --fail-with-body --silent --show-error \\
    --retry 5 --retry-delay 1 --retry-max-time 150 \\
    --request POST "\${BASE_URL}/oauth/token" \\
    --header 'content-type: application/json' \\
    --data-binary "@\${TOKEN_PAYLOAD_FILE}"
)"
export -n TOKEN_RESPONSE 2>/dev/null || true
ACCESS_TOKEN="$(printf '%s' "\${TOKEN_RESPONSE}" | node -e ${bashQuote(TOKEN_PARSER_SCRIPT)})"
export -n ACCESS_TOKEN 2>/dev/null || true
printf 'Authorization: Bearer %s\\n' "\${ACCESS_TOKEN}" > "\${AUTH_HEADER_FILE}"
unset ACCESS_TOKEN TOKEN_RESPONSE CLIENT_ID

read_resource() {
  curl --fail-with-body --silent --show-error \\
    --retry 5 --retry-delay 1 --retry-max-time 150 \\
    "\${BASE_URL}\${CHECKMATE_READ_ENDPOINT}" \\
    --header "@\${AUTH_HEADER_FILE}"
}

LIVE="$(read_resource)"
printf '%s' "\${LIVE}" > "\${BEFORE_FILE}"
REQUEST="$(printf '%s' "\${LIVE}" | node -e ${bashQuote(REQUEST_BUILDER_SCRIPT)})"
STATE="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} state)"
if [[ "\${STATE}" == "already_applied" ]]; then
  echo "No change needed: \${CHECKMATE_RESOURCE_NAME} already has the planned settings."
  exit 0
fi
PATCH_BODY="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} body)"
PATCH_ATTEMPT=0
PATCH_MAX_RETRIES=5
PATCH_CORRELATION_ID="checkmate-curl-$(date +%s)"
while true; do
  : > "\${PATCH_RESPONSE_FILE}"
  : > "\${PATCH_HEADERS_FILE}"
  if ! PATCH_STATUS="$(
    printf '%s' "\${PATCH_BODY}" |
      curl --silent --show-error \\
        --output "\${PATCH_RESPONSE_FILE}" \\
        --dump-header "\${PATCH_HEADERS_FILE}" \\
        --write-out '%{http_code}' \\
        --request PATCH "\${BASE_URL}\${CHECKMATE_ENDPOINT}" \\
        --header "@\${AUTH_HEADER_FILE}" \\
        --header 'content-type: application/json' \\
        --header "x-correlation-id: \${PATCH_CORRELATION_ID}" \\
        --data-binary @-
  )"; then
    echo "Auth0 PATCH request failed before a response was received." >&2
    exit 1
  fi

  case "\${PATCH_STATUS}" in
    2??)
      break
      ;;
    429)
      if (( PATCH_ATTEMPT >= PATCH_MAX_RETRIES )); then
        PATCH_ERROR="$(node -e ${bashQuote(PATCH_ERROR_SCRIPT)} "\${PATCH_RESPONSE_FILE}")"
        echo "Auth0 PATCH remained rate limited after \${PATCH_MAX_RETRIES} controlled retries\${PATCH_ERROR:+: \${PATCH_ERROR}}." >&2
        exit 1
      fi
      PATCH_DELAY="$(node -e ${bashQuote(RATE_LIMIT_DELAY_SCRIPT)} "\${PATCH_HEADERS_FILE}" "\${PATCH_ATTEMPT}")"
      echo "Auth0 rate limit reached for \${CHECKMATE_RESOURCE_NAME}; waiting \${PATCH_DELAY}s before a safe re-check (retry $((PATCH_ATTEMPT + 1))/\${PATCH_MAX_RETRIES})." >&2
      sleep "\${PATCH_DELAY}"

      LIVE="$(read_resource)"
      REQUEST="$(printf '%s' "\${LIVE}" | node -e ${bashQuote(REQUEST_BUILDER_SCRIPT)})"
      STATE="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} state)"
      if [[ "\${STATE}" == "already_applied" ]]; then
        printf '%s' "\${LIVE}" | node -e ${bashQuote(VERIFY_SCRIPT)}
        echo "Applied and verified: \${CHECKMATE_RESOURCE_NAME}"
        exit 0
      fi
      PATCH_BODY="$(printf '%s' "\${REQUEST}" | node -e ${bashQuote(RESPONSE_FIELD_SCRIPT)} body)"
      PATCH_ATTEMPT=$((PATCH_ATTEMPT + 1))
      ;;
    *)
      PATCH_ERROR="$(node -e ${bashQuote(PATCH_ERROR_SCRIPT)} "\${PATCH_RESPONSE_FILE}")"
      echo "Auth0 PATCH failed with status \${PATCH_STATUS}\${PATCH_ERROR:+: \${PATCH_ERROR}}." >&2
      exit 1
      ;;
  esac
done

VERIFIED="$(read_resource)"
printf '%s' "\${VERIFIED}" | node -e ${bashQuote(VERIFY_SCRIPT)}
echo "Applied and verified: \${CHECKMATE_RESOURCE_NAME}"
`,
  };
}

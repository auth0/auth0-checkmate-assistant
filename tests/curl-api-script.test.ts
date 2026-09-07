import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { apiRequestSha256 } from "../src/auth0/api-plan-executor.js";
import type { ApiPlanCall } from "../src/remediation/api-plan.js";
import { buildCurlApiScript } from "../src/remediation/curl-api-script.js";
import { buildApiPlanShellScript } from "../src/remediation/api-plan-shell.js";

function connectionCall(): ApiPlanCall {
  return {
    id: "api-call-1",
    method: "PATCH",
    endpoint: "/api/v2/connections/con_database",
    resourceType: "connection",
    resourceId: "con_database",
    resourceName: "Username-Password-Authentication",
    bodyStrategy: "merge_live_connection_options",
    actionIds: ["action-history"],
    preconditions: [
      { path: "options.password_history.enable", expectedValue: false },
    ],
    body: { options: { password_history: { enable: true } } },
  };
}

describe("generated curl API scripts", () => {
  it("uses profile-specific environment variables and contains valid Bash", () => {
    const call = connectionCall();
    const generated = buildCurlApiScript(
      "prod",
      call,
      "a".repeat(64),
      "prod-tenant.auth0.com",
    );

    expect(generated.requiredEnvironmentVariables).toEqual([
      "AUTH0CHECKMATE_PROD_DOMAIN",
      "AUTH0CHECKMATE_PROD_CLIENT_ID",
      "AUTH0CHECKMATE_PROD_CLIENT_SECRET",
    ]);
    expect(generated.script).toContain(
      'CLIENT_ID="${AUTH0CHECKMATE_PROD_CLIENT_ID:?Set AUTH0CHECKMATE_PROD_CLIENT_ID}"',
    );
    expect(generated.script).toContain(
      "EXPECTED_DOMAIN='prod-tenant.auth0.com'",
    );
    expect(generated.script).toContain("--request PATCH");
    expect(generated.script).toContain("--data-binary @-");
    expect(generated.script).toContain("PATCH_MAX_RETRIES=5");
    expect(generated.script).toContain("--write-out '%{http_code}'");
    expect(generated.script).toContain(
      "waiting ${PATCH_DELAY}s before a safe re-check",
    );
    expect(generated.script).toContain("umask 077");
    expect(generated.script).toContain('AUTH_HEADER_FILE="${WORK_DIRECTORY}');
    expect(generated.script).toContain('--header "@${AUTH_HEADER_FILE}"');
    expect(generated.script).not.toContain(
      '--header "authorization: Bearer ${ACCESS_TOKEN}"',
    );
    expect(generated.script).not.toContain("jq");
    expect(
      spawnSync("bash", ["-n"], {
        input: generated.script,
        encoding: "utf8",
      }),
    ).toMatchObject({ status: 0, stderr: "" });
  });

  it("obtains a token, preserves live connection options, patches, and verifies", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const tokenBodyFile = path.join(directory, "token-body.json");
    const curlArgsFile = path.join(directory, "curl-args.txt");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      id: "con_database",
      name: "Username-Password-Authentication",
      display_name: "Customer login database",
      options: {
        password_history: { enable: false, size: 5 },
        requires_username: false,
      },
    };
    const expectedBody = {
      display_name: "Customer login database",
      options: {
        password_history: { enable: true, size: 5 },
        requires_username: false,
        passwordPolicy: "good",
      },
    };
    const after = { ...before, options: expectedBody.options };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "\${AUTH0CHECKMATE_DEV_CLIENT_SECRET:-}" || -n "\${CLIENT_SECRET:-}" ]]; then
  echo "credential leaked into curl environment" >&2
  exit 91
fi
printf '%s\n' "$*" >> "\${CURL_ARGS_FILE}"
if [[ "$*" == *"/oauth/token"* ]]; then
  for argument in "$@"; do
    if [[ "\${argument}" == @* ]]; then
      cat "\${argument#@}" > "\${TOKEN_BODY_FILE}"
    fi
  done
  printf '%s' '{"access_token":"test-token","scope":"read:connections read:connections_options update:connections update:connections_options"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
  output_file=""
  headers_file=""
  while (( $# > 0 )); do
    case "$1" in
      --output)
        shift
        output_file="$1"
        ;;
      --dump-header)
        shift
        headers_file="$1"
        ;;
    esac
    shift
  done
  [[ -z "\${output_file}" ]] || printf '%s' '{}' > "\${output_file}"
  [[ -z "\${headers_file}" ]] || printf 'HTTP/2 200\\r\\n\\r\\n' > "\${headers_file}"
  printf '200'
else
  if [[ -s "\${PATCH_BODY_FILE}" ]]; then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const call = connectionCall();
    call.preconditions.push({
      path: "options.passwordPolicy",
      expectedValue: null,
    });
    call.body.options = {
      ...(call.body.options as Record<string, unknown>),
      passwordPolicy: "good",
    };
    const digest = apiRequestSha256(call.method, call.endpoint, expectedBody);
    const generated = buildCurlApiScript(
      "dev",
      call,
      digest,
      "tenant.auth0.com",
    );
    await writeFile(scriptFile, generated.script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        TOKEN_BODY_FILE: tokenBodyFile,
        CURL_ARGS_FILE: curlArgsFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(result.stdout).toContain(
      "Applied and verified: Username-Password-Authentication",
    );
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
    expect(JSON.parse(await readFile(tokenBodyFile, "utf8"))).toMatchObject({
      client_id: "client-from-env",
      client_secret: "secret-from-env",
    });
    expect(generated.script).not.toContain("client-from-env");
    expect(generated.script).not.toContain("secret-from-env");
    const curlArguments = await readFile(curlArgsFile, "utf8");
    expect(curlArguments).not.toContain("secret-from-env");
    expect(curlArguments).not.toContain("test-token");
  });

  it("removes read-only client JWT fields from the generated PATCH", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      client_id: "client_12345678",
      name: "Default App",
      jwt_configuration: {
        alg: "HS256",
        lifetime_in_seconds: 36000,
        scopes: {},
        secret_encoded: true,
      },
    };
    const expectedBody = {
      jwt_configuration: {
        alg: "RS256",
        lifetime_in_seconds: 36000,
        scopes: {},
      },
    };
    const after = {
      ...before,
      jwt_configuration: {
        ...before.jwt_configuration,
        alg: "RS256",
      },
    };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"/oauth/token"* ]]; then
  printf '%s' '{"access_token":"test-token","scope":"read:clients update:clients"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
  output_file=""
  headers_file=""
  while (( $# > 0 )); do
    case "$1" in
      --output)
        shift
        output_file="$1"
        ;;
      --dump-header)
        shift
        headers_file="$1"
        ;;
    esac
    shift
  done
  [[ -z "\${output_file}" ]] || printf '%s' '{}' > "\${output_file}"
  [[ -z "\${headers_file}" ]] || printf 'HTTP/2 200\\r\\n\\r\\n' > "\${headers_file}"
  printf '200'
else
  if [[ -s "\${PATCH_BODY_FILE}" ]]; then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const call: ApiPlanCall = {
      id: "api-call-client-jwt",
      method: "PATCH",
      endpoint: "/api/v2/clients/client_12345678",
      resourceType: "client",
      resourceId: "client_12345678",
      resourceName: "Default App",
      bodyStrategy: "merge_live_nested_objects",
      actionIds: ["action-rs256"],
      preconditions: [
        { path: "jwt_configuration.alg", expectedValue: "HS256" },
      ],
      body: { jwt_configuration: { alg: "RS256" } },
    };
    const generated = buildCurlApiScript(
      "dev",
      call,
      apiRequestSha256(call.method, call.endpoint, expectedBody),
      "tenant.auth0.com",
    );
    await writeFile(scriptFile, generated.script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
  });

  it("removes non-writable breached-password stage fields from the generated PATCH", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      enabled: true,
      stage: {
        "pre-user-registration": {
          shields: [],
          future_read_only_field: true,
        },
        "pre-change-password": {
          shields: ["admin_notification"],
          future_read_only_field: true,
        },
        "future-read-only-stage": { shields: ["block"] },
      },
    };
    const expectedBody = {
      stage: {
        "pre-user-registration": { shields: ["block"] },
        "pre-change-password": { shields: ["admin_notification"] },
      },
    };
    const after = {
      ...before,
      stage: {
        ...before.stage,
        "pre-user-registration": {
          ...before.stage["pre-user-registration"],
          shields: ["block"],
        },
      },
    };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"/oauth/token"* ]]; then
  printf '%s' '{"access_token":"test-token","scope":"read:attack_protection update:attack_protection"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
  output_file=""
  headers_file=""
  while (( $# > 0 )); do
    case "$1" in
      --output)
        shift
        output_file="$1"
        ;;
      --dump-header)
        shift
        headers_file="$1"
        ;;
    esac
    shift
  done
  [[ -z "\${output_file}" ]] || printf '%s' '{}' > "\${output_file}"
  [[ -z "\${headers_file}" ]] || printf 'HTTP/2 200\\r\\n\\r\\n' > "\${headers_file}"
  printf '200'
else
  if [[ -s "\${PATCH_BODY_FILE}" ]]; then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const call: ApiPlanCall = {
      id: "api-call-breached-password-stage",
      method: "PATCH",
      endpoint: "/api/v2/attack-protection/breached-password-detection",
      resourceType: "attack_protection",
      resourceId: "breached-password",
      resourceName: "Breached Password Detection",
      bodyStrategy: "merge_live_nested_objects",
      actionIds: ["action-registration-block"],
      preconditions: [
        {
          path: "stage.pre-user-registration.shields",
          expectedValue: [],
        },
      ],
      body: {
        stage: { "pre-user-registration": { shields: ["block"] } },
      },
    };
    const generated = buildCurlApiScript(
      "dev",
      call,
      apiRequestSha256(call.method, call.endpoint, expectedBody),
      "tenant.auth0.com",
    );
    await writeFile(scriptFile, generated.script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
  });

  it("re-reads and safely retries a PATCH after Auth0 returns 429", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const patchCountFile = path.join(directory, "patch-count.txt");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      id: "con_database",
      name: "Username-Password-Authentication",
      options: {
        password_history: { enable: false, size: 5 },
        requires_username: false,
      },
    };
    const expectedBody = {
      options: {
        password_history: { enable: true, size: 5 },
        requires_username: false,
      },
    };
    const after = { ...before, options: expectedBody.options };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"/oauth/token"* ]]; then
  printf '%s' '{"access_token":"test-token","scope":"read:connections read:connections_options update:connections update:connections_options"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
  count=0
  [[ ! -f "\${PATCH_COUNT_FILE}" ]] || count="$(cat "\${PATCH_COUNT_FILE}")"
  count=$((count + 1))
  printf '%s' "\${count}" > "\${PATCH_COUNT_FILE}"
  output_file=""
  headers_file=""
  while (( $# > 0 )); do
    case "$1" in
      --output)
        shift
        output_file="$1"
        ;;
      --dump-header)
        shift
        headers_file="$1"
        ;;
    esac
    shift
  done
  if (( count == 1 )); then
    [[ -z "\${output_file}" ]] || printf '%s' '{"message":"Global limit has been reached"}' > "\${output_file}"
    [[ -z "\${headers_file}" ]] || printf 'HTTP/2 429\\r\\nRetry-After: 0\\r\\n\\r\\n' > "\${headers_file}"
    printf '429'
  else
    [[ -z "\${output_file}" ]] || printf '%s' '{}' > "\${output_file}"
    [[ -z "\${headers_file}" ]] || printf 'HTTP/2 200\\r\\n\\r\\n' > "\${headers_file}"
    printf '200'
  fi
else
  count=0
  [[ ! -f "\${PATCH_COUNT_FILE}" ]] || count="$(cat "\${PATCH_COUNT_FILE}")"
  if (( count >= 2 )); then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const call = connectionCall();
    const generated = buildCurlApiScript(
      "dev",
      call,
      apiRequestSha256(call.method, call.endpoint, expectedBody),
      "tenant.auth0.com",
    );
    await writeFile(scriptFile, generated.script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        PATCH_COUNT_FILE: patchCountFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0 });
    expect(result.stderr).toContain("waiting 0s before a safe re-check");
    expect(result.stdout).toContain(
      "Applied and verified: Username-Password-Authentication",
    );
    expect(await readFile(patchCountFile, "utf8")).toBe("2");
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
  });

  it("stops before authentication when the configured tenant does not match", () => {
    const generated = buildCurlApiScript(
      "dev",
      connectionCall(),
      "a".repeat(64),
      "expected.auth0.com",
    );
    const result = spawnSync("bash", {
      input: generated.script,
      encoding: "utf8",
      env: {
        ...process.env,
        AUTH0CHECKMATE_DEV_DOMAIN: "wrong.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "must exactly match the validated tenant expected.auth0.com",
    );
    expect(result.stderr).not.toContain("secret-from-env");
  });

  it("uses one token and shared runtime for every validated call", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-curl-"));
    const patchBodyFile = path.join(directory, "patch-body.json");
    const tokenCountFile = path.join(directory, "token-count.txt");
    const fakeCurl = path.join(directory, "curl");
    const scriptFile = path.join(directory, "change.sh");
    const before = {
      id: "con_database",
      name: "Username-Password-Authentication",
      options: {
        password_history: { enable: false, size: 5 },
        requires_username: false,
      },
    };
    const expectedBody = {
      options: {
        password_history: { enable: true, size: 5 },
        requires_username: false,
      },
    };
    const after = { ...before, options: expectedBody.options };
    await writeFile(
      fakeCurl,
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"/oauth/token"* ]]; then
  count=0
  [[ ! -f "\${TOKEN_COUNT_FILE}" ]] || count="$(cat "\${TOKEN_COUNT_FILE}")"
  printf '%s' "$((count + 1))" > "\${TOKEN_COUNT_FILE}"
  printf '%s' '{"access_token":"test-token","scope":"read:connections read:connections_options update:connections update:connections_options"}'
elif [[ "$*" == *"--request PATCH"* ]]; then
  cat > "\${PATCH_BODY_FILE}"
  output_file=""
  headers_file=""
  while (( $# > 0 )); do
    case "$1" in
      --output)
        shift
        output_file="$1"
        ;;
      --dump-header)
        shift
        headers_file="$1"
        ;;
    esac
    shift
  done
  [[ -z "\${output_file}" ]] || printf '%s' '{}' > "\${output_file}"
  [[ -z "\${headers_file}" ]] || printf 'HTTP/2 200\\r\\n\\r\\n' > "\${headers_file}"
  printf '200'
else
  if [[ -s "\${PATCH_BODY_FILE}" ]]; then
    printf '%s' '${JSON.stringify(after)}'
  else
    printf '%s' '${JSON.stringify(before)}'
  fi
fi
`,
    );
    await chmod(fakeCurl, 0o700);

    const first = connectionCall();
    const second = {
      ...connectionCall(),
      id: "api-call-2",
      resourceName: "Second database",
    };
    const digest = apiRequestSha256(first.method, first.endpoint, expectedBody);
    const script = buildApiPlanShellScript({
      schemaVersion: 1,
      generatedAt: "2026-08-03T10:00:00.000Z",
      sourceReport: "report.json",
      profile: "dev",
      tenantDomain: "tenant.auth0.com",
      validatedAt: "2026-08-03T10:01:00.000Z",
      unchangedActionIds: [],
      alreadyCompliantActionIds: [],
      calls: [
        {
          ...first,
          validatedRequestSha256: digest,
          curl: {
            shell: "bash",
            requiredEnvironmentVariables: ["A", "B", "C"],
            script: "#!/usr/bin/env bash\nexit 99\n",
          },
        },
        {
          ...second,
          validatedRequestSha256: digest,
          curl: {
            shell: "bash",
            requiredEnvironmentVariables: ["A", "B", "C"],
            script: "#!/usr/bin/env bash\nexit 99\n",
          },
        },
      ],
    });
    await writeFile(scriptFile, script, { mode: 0o700 });
    const result = spawnSync("bash", [scriptFile], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH ?? ""}`,
        PATCH_BODY_FILE: patchBodyFile,
        TOKEN_COUNT_FILE: tokenCountFile,
        AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
        AUTH0CHECKMATE_DEV_CLIENT_ID: "client-from-env",
        AUTH0CHECKMATE_DEV_CLIENT_SECRET: "secret-from-env",
      },
    });

    expect(result).toMatchObject({ status: 0, stderr: "" });
    expect(result.stdout).toContain("validated API call 1 of 2");
    expect(result.stdout).toContain("validated API call 2 of 2");
    expect(result.stdout).toContain(
      "No change needed: Second database already has the planned settings.",
    );
    expect(result.stdout).toContain(
      "Applied and verified all validated API calls.",
    );
    expect(await readFile(tokenCountFile, "utf8")).toBe("1");
    expect(JSON.parse(await readFile(patchBodyFile, "utf8"))).toEqual(
      expectedBody,
    );
    expect(script.match(/TOKEN_RESPONSE=/g)).toHaveLength(1);
    expect(script.match(/apply_validated_call \\/g)).toHaveLength(2);
  });
});

import { spawn } from "node:child_process";
import type { SpawnOptions } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type { CheckmateConfig } from "../config/env.js";
import type { ScanMetadata } from "./types.js";
import { AppError } from "../utils/errors.js";
import { redactText } from "../security/redaction.js";

const OUTPUT_LIMIT = 1_000_000;
const require = createRequire(import.meta.url);

export interface CheckmateRuntime {
  entrypoint: string;
  version?: string;
}

export function resolveCheckmateRuntime(): CheckmateRuntime {
  try {
    const packageJsonPath =
      require.resolve("@auth0/auth0-checkmate/package.json");
    const packageMetadata = JSON.parse(
      readFileSync(packageJsonPath, "utf8"),
    ) as unknown;
    const version =
      packageMetadata !== null &&
      typeof packageMetadata === "object" &&
      "version" in packageMetadata &&
      typeof packageMetadata.version === "string"
        ? packageMetadata.version
        : undefined;
    const runtime: CheckmateRuntime = {
      entrypoint: path.join(path.dirname(packageJsonPath), "bin", "index.js"),
    };
    if (version) runtime.version = version;
    return runtime;
  } catch (error) {
    throw new AppError(
      "CHECKMATE_NOT_FOUND",
      "The bundled Auth0 CheckMate dependency could not be resolved. Run npm install.",
      { cause: error },
    );
  }
}

export interface ProcessExecution {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ProcessRequest {
  executable: string;
  args: readonly string[];
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

export type ProcessRunner = (
  request: ProcessRequest,
) => Promise<ProcessExecution>;

function appendLimited(current: string, chunk: Buffer | string): string {
  const combined = current + chunk.toString();
  return combined.length > OUTPUT_LIMIT
    ? combined.slice(combined.length - OUTPUT_LIMIT)
    : combined;
}

export const spawnCheckmateProcess: ProcessRunner = async (request) =>
  new Promise((resolve, reject) => {
    const options: SpawnOptions = {
      env: request.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    };
    const child = spawn(request.executable, [...request.args], options);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, request.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = appendLimited(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = appendLimited(stderr, chunk);
    });
    child.once("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(
        new AppError(
          "CHECKMATE_FAILED",
          "Auth0 CheckMate could not be started.",
          { cause: error },
        ),
      );
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(
          new AppError(
            "CHECKMATE_TIMEOUT",
            `Auth0 CheckMate exceeded the ${request.timeoutMs} ms timeout.`,
          ),
        );
        return;
      }
      resolve({ exitCode: code ?? -1, stdout, stderr });
    });
  });

function safeBaseEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const allowed = [
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "TERM",
    "SystemRoot",
    "PATHEXT",
  ];
  return Object.fromEntries(
    allowed.flatMap((key) => (env[key] === undefined ? [] : [[key, env[key]]])),
  );
}

export function buildCheckmateEnvironment(
  config: CheckmateConfig,
  env: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return {
    ...safeBaseEnvironment(env),
    AUTH0CHECKMATE_DOMAIN: config.domain,
    AUTH0CHECKMATE_CLIENT_ID: config.clientId,
    AUTH0CHECKMATE_CLIENT_SECRET: config.clientSecret,
    AUTH0CHECKMATE_FILE_PATH: config.outputDirectory,
    AUTH0CHECKMATE_DISABLE_PDF_REPORTING: "true",
    AUTH0CHECKMATE_SHOW_VALIDATORS: "false",
  };
}

export interface RunCheckmateOptions {
  config: CheckmateConfig;
  processRunner?: ProcessRunner;
}

export async function runCheckmate(options: RunCheckmateOptions): Promise<{
  execution: ProcessExecution;
  metadata: Omit<ScanMetadata, "reportPath">;
}> {
  const startedAt = new Date();
  const runner = options.processRunner ?? spawnCheckmateProcess;
  const runtime = resolveCheckmateRuntime();
  const execution = await runner({
    executable: process.execPath,
    args: [runtime.entrypoint],
    env: buildCheckmateEnvironment(options.config),
    timeoutMs: options.config.timeoutMs,
  });
  const finishedAt = new Date();
  const safeOutput = {
    ...execution,
    stdout: redactText(execution.stdout, [options.config.clientSecret]),
    stderr: redactText(execution.stderr, [options.config.clientSecret]),
  };

  if (safeOutput.exitCode !== 0) {
    const detail = safeOutput.stderr.trim() || safeOutput.stdout.trim();
    throw new AppError(
      "CHECKMATE_FAILED",
      `Auth0 CheckMate exited with code ${safeOutput.exitCode}.${detail ? ` ${detail}` : ""}`,
    );
  }

  return {
    execution: safeOutput,
    metadata: {
      profile: options.config.profile,
      targetDomain: options.config.domain,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      ...(runtime.version ? { checkmateVersion: runtime.version } : {}),
      exitCode: safeOutput.exitCode,
    },
  };
}

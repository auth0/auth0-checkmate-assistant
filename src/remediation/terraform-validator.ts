import { spawn } from "node:child_process";
import type { SpawnOptions } from "node:child_process";
import { unlink } from "node:fs/promises";
import path from "node:path";
import type { CheckmateConfig } from "../config/env.js";
import { toErrorMessage } from "../utils/errors.js";

const OUTPUT_LIMIT = 200_000;

export interface TerraformCommandRequest {
  args: readonly string[];
  cwd: string;
  captureFullStdout?: boolean;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

export interface TerraformCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type TerraformCommandRunner = (
  request: TerraformCommandRequest,
) => Promise<TerraformCommandResult>;

export interface TerraformValidationResult {
  valid: boolean;
  validatedAt: string;
  terraformFile: string;
  steps: Array<{
    command: "fmt" | "init" | "validate" | "plan" | "show";
    valid: boolean;
    message: string;
  }>;
  error?: string;
}

interface TerraformPlannedChange {
  address?: unknown;
  mode?: unknown;
  type?: unknown;
  change?: {
    actions?: unknown;
    importing?: unknown;
  };
}

function validatePlanJson(content: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch (error) {
    throw new Error("Terraform returned an unreadable JSON plan.", {
      cause: error,
    });
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new Error("Terraform returned an invalid JSON plan.");
  }
  const resourceChanges = (parsed as { resource_changes?: unknown })
    .resource_changes;
  if (resourceChanges !== undefined && !Array.isArray(resourceChanges)) {
    throw new Error("Terraform returned invalid resource changes.");
  }
  for (const item of (resourceChanges ?? []) as TerraformPlannedChange[]) {
    if (item === null || typeof item !== "object") {
      throw new Error("Terraform returned an invalid planned resource.");
    }
    const actions = item.change?.actions;
    if (
      !Array.isArray(actions) ||
      actions.some((action) => typeof action !== "string")
    ) {
      throw new Error("Terraform returned invalid planned actions.");
    }
    const address =
      typeof item.address === "string" ? item.address : "resource";
    if (actions.includes("delete")) {
      throw new Error(
        `Terraform validation rejected a destructive change for ${address}.`,
      );
    }
    if (
      item.mode !== "data" &&
      actions.includes("create") &&
      item.change?.importing === undefined
    ) {
      throw new Error(
        `Terraform validation rejected an unimported resource creation for ${address}.`,
      );
    }
    if (
      item.mode !== "data" &&
      typeof item.type === "string" &&
      !["auth0_client", "auth0_connection", "auth0_attack_protection"].includes(
        item.type,
      )
    ) {
      throw new Error(
        `Terraform validation rejected an unexpected managed resource type: ${item.type}.`,
      );
    }
  }
  return "Terraform plan is executable and contains no destroy, replacement, or unimported create actions.";
}

function appendLimited(current: string, chunk: Buffer | string): string {
  const combined = current + chunk.toString();
  return combined.length > OUTPUT_LIMIT
    ? combined.slice(combined.length - OUTPUT_LIMIT)
    : combined;
}

export const spawnTerraformCommand: TerraformCommandRunner = async (request) =>
  new Promise((resolve, reject) => {
    const options: SpawnOptions = {
      cwd: request.cwd,
      env: request.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    };
    const child = spawn("terraform", [...request.args], options);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, request.timeoutMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = request.captureFullStdout
        ? stdout + chunk.toString()
        : appendLimited(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = appendLimited(stderr, chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error("Terraform validation timed out."));
        return;
      }
      resolve({ exitCode: code ?? -1, stdout, stderr });
    });
  });

function safeTerraformEnvironment(
  env: NodeJS.ProcessEnv,
  providerConfig?: Pick<
    CheckmateConfig,
    "domain" | "clientId" | "clientSecret"
  >,
): NodeJS.ProcessEnv {
  const allowed = [
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
  ];
  const safeEnvironment: NodeJS.ProcessEnv = {
    ...Object.fromEntries(
      allowed.flatMap((key) =>
        env[key] === undefined ? [] : [[key, env[key]]],
      ),
    ),
    TF_IN_AUTOMATION: "1",
    CHECKPOINT_DISABLE: "1",
  };
  if (providerConfig) {
    safeEnvironment.AUTH0_DOMAIN = providerConfig.domain;
    safeEnvironment.AUTH0_CLIENT_ID = providerConfig.clientId;
    safeEnvironment.AUTH0_CLIENT_SECRET = providerConfig.clientSecret;
  }
  return safeEnvironment;
}

export async function validateTerraformConfiguration(
  terraformFile: string,
  options: {
    runner?: TerraformCommandRunner;
    env?: NodeJS.ProcessEnv;
    providerConfig?: Pick<
      CheckmateConfig,
      "domain" | "clientId" | "clientSecret"
    >;
    now?: () => Date;
  } = {},
): Promise<TerraformValidationResult> {
  const runner = options.runner ?? spawnTerraformCommand;
  const cwd = path.dirname(terraformFile);
  const env = safeTerraformEnvironment(
    options.env ?? process.env,
    options.providerConfig,
  );
  const now = options.now ?? (() => new Date());
  const steps: TerraformValidationResult["steps"] = [];
  const commands = [
    {
      command: "fmt" as const,
      args: ["fmt", "-no-color", path.basename(terraformFile)],
    },
    {
      command: "init" as const,
      args: ["init", "-upgrade", "-backend=false", "-input=false", "-no-color"],
    },
    {
      command: "validate" as const,
      args: ["validate", "-no-color"],
    },
    {
      command: "plan" as const,
      args: [
        "plan",
        "-input=false",
        "-lock=false",
        "-no-color",
        "-detailed-exitcode",
        "-out=.checkmate-validation.tfplan",
      ],
    },
    {
      command: "show" as const,
      args: ["show", "-json", ".checkmate-validation.tfplan"],
    },
  ];
  try {
    for (const command of commands) {
      const result = await runner({
        args: command.args,
        cwd,
        env,
        timeoutMs: 120_000,
        captureFullStdout: command.command === "show",
      });
      let message =
        [result.stdout.trim(), result.stderr.trim()]
          .filter(Boolean)
          .join("\n") || "Validation passed.";
      const validExitCode =
        result.exitCode === 0 ||
        (command.command === "plan" && result.exitCode === 2);
      steps.push({
        command: command.command,
        valid: validExitCode,
        message,
      });
      if (!validExitCode) {
        return {
          valid: false,
          validatedAt: now().toISOString(),
          terraformFile,
          steps,
          error: message,
        };
      }
      if (command.command === "show") {
        try {
          message = validatePlanJson(result.stdout);
        } catch (error) {
          const unsafeMessage = toErrorMessage(error);
          steps[steps.length - 1] = {
            command: command.command,
            valid: false,
            message: unsafeMessage,
          };
          return {
            valid: false,
            validatedAt: now().toISOString(),
            terraformFile,
            steps,
            error: unsafeMessage,
          };
        }
        steps[steps.length - 1] = {
          command: command.command,
          valid: true,
          message,
        };
      }
    }
    return {
      valid: true,
      validatedAt: now().toISOString(),
      terraformFile,
      steps,
    };
  } catch (error) {
    const message = toErrorMessage(error);
    return {
      valid: false,
      validatedAt: now().toISOString(),
      terraformFile,
      steps,
      error: message,
    };
  } finally {
    await unlink(path.join(cwd, ".checkmate-validation.tfplan")).catch(
      () => undefined,
    );
  }
}

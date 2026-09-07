import { randomBytes } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { ChatConfig } from "./config.js";
import type { DevPlanPreview } from "./types.js";

export interface PreparedDevPlanState {
  preview: Omit<DevPlanPreview, "planId" | "expiresAt" | "executionEnabled">;
  plan: unknown;
  approvedRequestDigests: Record<string, string>;
}

export interface DevExecutionResult {
  validation: {
    valid: boolean;
    validatedAt: string;
    calls: Array<{
      id: string;
      endpoint: string;
      status: "ready" | "already_applied" | "invalid";
      error?: string;
    }>;
    error?: string;
  };
  execution: {
    status: "succeeded" | "failed";
    startedAt: string;
    completedAt: string;
    profile: "dev";
    calls: Array<{
      id: string;
      endpoint: string;
      status: "applied" | "already_applied" | "failed";
      correlationId: string;
      error?: string;
    }>;
    error?: string;
  };
}

interface RootRemediationModule {
  prepareChatDevPlan(input: {
    reportsDirectory: string;
    reportId: string;
    findingIds: string[];
  }): Promise<PreparedDevPlanState>;
  executeChatDevPlan(input: {
    plan: unknown;
    approvedRequestDigests: Record<string, string>;
    expectedTenantDomain: string;
  }): Promise<DevExecutionResult>;
}

export interface DevRemediationLike {
  prepare(
    reportId: string,
    findingIds: string[],
  ): Promise<PreparedDevPlanState>;
  execute(prepared: PreparedDevPlanState): Promise<DevExecutionResult>;
  writeAudit(planId: string, record: Record<string, unknown>): Promise<string>;
}

function isRootModule(value: unknown): value is RootRemediationModule {
  return Boolean(
    value &&
    typeof value === "object" &&
    "prepareChatDevPlan" in value &&
    typeof (value as { prepareChatDevPlan?: unknown }).prepareChatDevPlan ===
      "function" &&
    "executeChatDevPlan" in value &&
    typeof (value as { executeChatDevPlan?: unknown }).executeChatDevPlan ===
      "function",
  );
}

export class DevRemediationCoordinator implements DevRemediationLike {
  private modulePromise?: Promise<RootRemediationModule>;

  constructor(private readonly config: ChatConfig) {}

  private loadModule(): Promise<RootRemediationModule> {
    if (!this.modulePromise) {
      const url = pathToFileURL(
        path.resolve(
          this.config.projectRoot,
          "dist/src/chat/dev-remediation-service.js",
        ),
      ).href;
      this.modulePromise = import(url).then((module: unknown) => {
        if (!isRootModule(module)) {
          throw new Error(
            "The compiled dev remediation service is unavailable.",
          );
        }
        return module;
      });
    }
    return this.modulePromise;
  }

  async prepare(
    reportId: string,
    findingIds: string[],
  ): Promise<PreparedDevPlanState> {
    if (!this.config.devPlanningEnabled) {
      throw new Error(
        "Configure the dev tenant domain, client ID, and client secret before preparing API calls.",
      );
    }
    const module = await this.loadModule();
    return module.prepareChatDevPlan({
      reportsDirectory: this.config.reportsDirectory,
      reportId,
      findingIds,
    });
  }

  async execute(prepared: PreparedDevPlanState): Promise<DevExecutionResult> {
    const module = await this.loadModule();
    return module.executeChatDevPlan({
      plan: prepared.plan,
      approvedRequestDigests: prepared.approvedRequestDigests,
      expectedTenantDomain: prepared.preview.tenantDomain,
    });
  }

  async writeAudit(
    planId: string,
    record: Record<string, unknown>,
  ): Promise<string> {
    if (!/^[a-zA-Z0-9_-]{20,100}$/.test(planId)) {
      throw new Error("The dev plan audit ID is invalid.");
    }
    const directory = path.resolve(
      this.config.projectRoot,
      "remediation-plans/chat-executions",
    );
    await mkdir(directory, { recursive: true });
    const outputPath = path.join(directory, `${planId}.json`);
    const temporaryPath = `${outputPath}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, outputPath);
    return outputPath;
  }
}

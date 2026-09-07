import path from "node:path";
import { pathToFileURL } from "node:url";
import type { ChatConfig } from "./config.js";

export type ChatScanProfile = "dev" | "prod";

export interface ChatScanResult {
  profile: ChatScanProfile;
  tenantDomain: string;
  reportId: string;
  startedAt: string;
  finishedAt: string;
  checkmateVersion?: string;
}

interface RootScanModule {
  runChatCheckmateScan(input: {
    profile: ChatScanProfile;
    reportsDirectory: string;
  }): Promise<ChatScanResult>;
}

export interface CheckmateScanLike {
  run(profile: ChatScanProfile): Promise<ChatScanResult>;
}

function isRootModule(value: unknown): value is RootScanModule {
  return Boolean(
    value &&
    typeof value === "object" &&
    "runChatCheckmateScan" in value &&
    typeof (value as { runChatCheckmateScan?: unknown })
      .runChatCheckmateScan === "function",
  );
}

export class CheckmateScanCoordinator implements CheckmateScanLike {
  private modulePromise?: Promise<RootScanModule>;

  constructor(private readonly config: ChatConfig) {}

  private loadModule(): Promise<RootScanModule> {
    if (!this.modulePromise) {
      const url = pathToFileURL(
        path.resolve(
          this.config.projectRoot,
          "dist/src/chat/checkmate-scan-service.js",
        ),
      ).href;
      this.modulePromise = import(url).then((module: unknown) => {
        if (!isRootModule(module)) {
          throw new Error(
            "The compiled CheckMate scan service is unavailable.",
          );
        }
        return module;
      });
    }
    return this.modulePromise;
  }

  async run(profile: ChatScanProfile): Promise<ChatScanResult> {
    const target = this.config.scanTargets[profile];
    if (!target.configured) {
      throw new Error(
        `The ${profile} CheckMate profile is not fully configured in .env.`,
      );
    }
    const module = await this.loadModule();
    return module.runChatCheckmateScan({
      profile,
      reportsDirectory: this.config.reportsDirectory,
    });
  }
}

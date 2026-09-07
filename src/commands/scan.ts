import type { Command } from "commander";
import { loadCheckmateConfig } from "../config/env.js";
import {
  ensureDirectory,
  findGeneratedJsonReport,
  listJsonFiles,
} from "../utils/filesystem.js";
import { createLogger } from "../utils/logger.js";
import { runCheckmate, type ProcessRunner } from "../checkmate/runner.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import {
  createReportSummary,
  formatReportSummary,
} from "../checkmate/summary.js";
import { AppError } from "../utils/errors.js";
import type { ScanMetadata } from "../checkmate/types.js";

interface ScanOptions {
  profile: string;
  verbose?: boolean;
}

export interface ScanDependencies {
  processRunner?: ProcessRunner;
  env?: NodeJS.ProcessEnv;
}

export async function executeScan(
  options: ScanOptions,
  dependencies: ScanDependencies = {},
): Promise<ScanMetadata> {
  const config = loadCheckmateConfig(options.profile, dependencies.env);
  const logger = createLogger({
    verbose: options.verbose ?? false,
    sensitiveValues: [config.clientSecret],
  });
  await ensureDirectory(config.outputDirectory);
  const before = await listJsonFiles(config.outputDirectory);
  const startedMs = Date.now();

  logger.info(`Running CheckMate against profile: ${config.profile}`);
  logger.info(`Target domain: ${config.domain}`);
  const result = await runCheckmate({
    config,
    ...(dependencies.processRunner
      ? { processRunner: dependencies.processRunner }
      : {}),
  });
  logger.verbose("CheckMate standard output:", result.execution.stdout.trim());
  logger.verbose("CheckMate standard error:", result.execution.stderr.trim());

  const after = await listJsonFiles(config.outputDirectory);
  const reportPath = findGeneratedJsonReport(before, after, startedMs);
  if (!reportPath) {
    throw new AppError(
      "REPORT_NOT_FOUND",
      `Auth0 CheckMate completed but produced no JSON report in: ${config.outputDirectory}`,
    );
  }

  const report = await loadCheckmateReport(reportPath);
  const summary = createReportSummary(report, config.domain);
  logger.info("CheckMate completed successfully");
  logger.info(formatReportSummary(summary));
  return { ...result.metadata, reportPath };
}

export function registerScanCommand(program: Command): void {
  program
    .command("scan")
    .description("Run Auth0 CheckMate and load the generated JSON report")
    .requiredOption("--profile <profile>", "environment profile: prod or dev")
    .option("--verbose", "show redacted CheckMate output")
    .action(async (options: ScanOptions) => {
      await executeScan(options);
    });
}

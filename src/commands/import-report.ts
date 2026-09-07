import path from "node:path";
import type { Command } from "commander";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import {
  createReportSummary,
  formatReportSummary,
} from "../checkmate/summary.js";
import { copyIntoWorkspace } from "../utils/filesystem.js";

export async function executeImportReport(sourcePath: string): Promise<string> {
  // Validate before copying so malformed inputs never enter the report workspace.
  await loadCheckmateReport(sourcePath);
  const storedPath = await copyIntoWorkspace(
    sourcePath,
    path.resolve("reports"),
  );
  const report = await loadCheckmateReport(storedPath);
  console.log(formatReportSummary(createReportSummary(report)));
  return storedPath;
}

export function registerImportReportCommand(program: Command): void {
  program
    .command("import-report")
    .description("Validate and import an existing CheckMate JSON report")
    .argument("<report>", "path to a CheckMate JSON report")
    .action(async (report: string) => {
      await executeImportReport(report);
    });
}

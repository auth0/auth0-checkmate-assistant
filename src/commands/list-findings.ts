import { Option, type Command } from "commander";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import {
  filterFindings,
  type FindingStatusFilter,
} from "../findings/filter.js";
import { formatFindings } from "../findings/formatter.js";

interface ListOptions {
  report: string;
  status: FindingStatusFilter;
}

export async function executeListFindings(options: ListOptions): Promise<void> {
  const report = await loadCheckmateReport(options.report);
  console.log(formatFindings(filterFindings(report.findings, options.status)));
}

export function registerListFindingsCommand(program: Command): void {
  program
    .command("list-findings")
    .description("List findings from a CheckMate JSON report")
    .requiredOption("--report <report>", "path to a CheckMate JSON report")
    .addOption(
      new Option("--status <status>", "filter by finding status")
        .choices(["failed", "warning", "passed", "unknown", "all"])
        .default("failed"),
    )
    .action(async (options: ListOptions) => executeListFindings(options));
}

import type {
  LoadedCheckmateReport,
  ReportPriorityCounts,
  ReportSummary,
} from "./types.js";
import { displayPath } from "../utils/filesystem.js";

export function createReportSummary(
  report: LoadedCheckmateReport,
  tenantOverride?: string,
): ReportSummary {
  const priorities: ReportPriorityCounts = {
    red: 0,
    yellow: 0,
    green: 0,
    blue: 0,
    violet: 0,
    unknown: 0,
  };
  const validators = new Map<string, keyof ReportPriorityCounts>();
  for (const finding of report.findings) {
    const validatorId = finding.validatorId ?? finding.id;
    validators.set(validatorId, finding.priority ?? "unknown");
  }
  for (const priority of validators.values()) priorities[priority] += 1;
  const summary: ReportSummary = {
    reportPath: report.sourcePath,
    reportedValidatorCount: validators.size,
    detailItemCount: report.findings.length,
    priorities,
  };
  const tenant = report.tenant ?? tenantOverride;
  if (tenant) summary.tenant = tenant;
  if (report.generatedAt) summary.generatedAt = report.generatedAt;
  return summary;
}

export function formatReportSummary(summary: ReportSummary): string {
  const lines = [
    `Tenant/domain: ${summary.tenant ?? "not included in report"}`,
    `Report timestamp: ${summary.generatedAt ?? "not included in report"}`,
    `Reported validators: ${summary.reportedValidatorCount}`,
    `High priority (red): ${summary.priorities.red}`,
    `Moderate priority (yellow): ${summary.priorities.yellow}`,
    `Low priority (green): ${summary.priorities.green}`,
    `Information only (blue): ${summary.priorities.blue}`,
    `GenAI insights (violet): ${summary.priorities.violet}`,
    `Detail items: ${summary.detailItemCount}`,
  ];
  if (summary.priorities.unknown > 0)
    lines.push(`Unknown priority: ${summary.priorities.unknown}`);
  lines.push(`JSON report: ${displayPath(summary.reportPath)}`);
  return lines.join("\n");
}

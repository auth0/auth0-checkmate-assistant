import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { LoadedCheckmateReport } from "./types.js";
import { loadCheckmateReport } from "./report-loader.js";

const DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024;
const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

export interface ReportRepositoryOptions {
  reportsDirectory: string;
  maxReportAgeDays?: number;
  maxReportBytes?: number;
  now?: () => Date;
}

export interface ReportCounts {
  passed: number;
  failed: number;
  warning: number;
  unknown: number;
}

export interface ReportMetadata {
  reportId: string;
  tenant?: string;
  generatedAt?: string;
  modifiedAt: string;
  sizeBytes: number;
  totalFindings: number;
  counts: ReportCounts;
  findingsOnly: boolean;
  passedChecksIncluded: boolean;
  ageDays?: number;
  stale: boolean;
  freshnessWarning?: string;
}

export type ReportListEntry =
  | ({ valid: true } & ReportMetadata)
  | {
      reportId: string;
      modifiedAt: string;
      sizeBytes: number;
      valid: false;
      error: string;
    };

export interface ReportContext {
  metadata: ReportMetadata;
  report: LoadedCheckmateReport;
}

interface ReportFile {
  reportId: string;
  path: string;
  modifiedAt: string;
  modifiedAtMs: number;
  sizeBytes: number;
}

function countFindings(report: LoadedCheckmateReport): ReportCounts {
  return report.findings.reduce<ReportCounts>(
    (counts, finding) => {
      counts[finding.status] += 1;
      return counts;
    },
    { passed: 0, failed: 0, warning: 0, unknown: 0 },
  );
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown report error.";
}

export class ReportRepository {
  readonly reportsDirectory: string;
  readonly maxReportAgeDays: number;
  readonly maxReportBytes: number;
  private readonly now: () => Date;

  constructor(options: ReportRepositoryOptions) {
    this.reportsDirectory = path.resolve(options.reportsDirectory);
    this.maxReportAgeDays = options.maxReportAgeDays ?? 7;
    this.maxReportBytes = options.maxReportBytes ?? DEFAULT_MAX_REPORT_BYTES;
    this.now = options.now ?? (() => new Date());

    if (!Number.isFinite(this.maxReportAgeDays) || this.maxReportAgeDays < 0) {
      throw new Error("maxReportAgeDays must be a non-negative number.");
    }
    if (!Number.isSafeInteger(this.maxReportBytes) || this.maxReportBytes < 1) {
      throw new Error("maxReportBytes must be a positive integer.");
    }
  }

  async listReports(): Promise<ReportListEntry[]> {
    const files = await this.listFiles();
    return Promise.all(
      files.map(async (file): Promise<ReportListEntry> => {
        try {
          const context = await this.loadFile(file);
          return { valid: true, ...context.metadata };
        } catch (error) {
          return {
            reportId: file.reportId,
            modifiedAt: file.modifiedAt,
            sizeBytes: file.sizeBytes,
            valid: false,
            error: this.safeErrorMessage(error),
          };
        }
      }),
    );
  }

  async getReport(reportId?: string): Promise<ReportContext> {
    const files = await this.listFiles();
    if (files.length === 0) {
      throw new Error(
        "No CheckMate JSON reports were found in the configured reports directory.",
      );
    }

    if (reportId) {
      const file = files.find((candidate) => candidate.reportId === reportId);
      if (!file) {
        throw new Error(
          `Unknown reportId "${reportId}". Call checkmate_list_reports to select a valid report.`,
        );
      }
      try {
        return await this.loadFile(file);
      } catch (error) {
        throw new Error(
          `Unable to load report ${file.reportId}: ${this.safeErrorMessage(error)}`,
        );
      }
    }

    const errors: string[] = [];
    for (const file of files) {
      try {
        return await this.loadFile(file);
      } catch (error) {
        errors.push(`${file.reportId}: ${this.safeErrorMessage(error)}`);
      }
    }
    throw new Error(
      `No valid CheckMate reports were found. ${errors.join(" ")}`,
    );
  }

  private async listFiles(): Promise<ReportFile[]> {
    let entries;
    try {
      entries = await readdir(this.reportsDirectory, { withFileTypes: true });
    } catch (error) {
      throw new Error(
        `Unable to read the configured CheckMate reports directory: ${message(error)}`,
      );
    }

    const candidates = entries.filter(
      (entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".json"),
    );
    const files = await Promise.all(
      candidates.map(async (entry): Promise<ReportFile> => {
        const filePath = path.join(this.reportsDirectory, entry.name);
        const metadata = await stat(filePath);
        return {
          reportId: entry.name,
          path: filePath,
          modifiedAt: metadata.mtime.toISOString(),
          modifiedAtMs: metadata.mtimeMs,
          sizeBytes: metadata.size,
        };
      }),
    );
    return files.sort((left, right) => right.modifiedAtMs - left.modifiedAtMs);
  }

  private async loadFile(file: ReportFile): Promise<ReportContext> {
    if (file.sizeBytes > this.maxReportBytes) {
      throw new Error(
        `Report exceeds the configured ${this.maxReportBytes}-byte size limit.`,
      );
    }
    const report = await loadCheckmateReport(file.path);
    return {
      report,
      metadata: this.createMetadata(file, report),
    };
  }

  private createMetadata(
    file: ReportFile,
    report: LoadedCheckmateReport,
  ): ReportMetadata {
    const timestamp = report.generatedAt
      ? Date.parse(report.generatedAt)
      : Number.NaN;
    const ageDays = Number.isFinite(timestamp)
      ? Math.max(0, (this.now().getTime() - timestamp) / MILLISECONDS_PER_DAY)
      : undefined;
    const stale = ageDays !== undefined && ageDays > this.maxReportAgeDays;
    const metadata: ReportMetadata = {
      reportId: file.reportId,
      modifiedAt: file.modifiedAt,
      sizeBytes: file.sizeBytes,
      totalFindings: report.findings.length,
      counts: countFindings(report),
      findingsOnly: report.findingsOnly,
      passedChecksIncluded:
        !report.findingsOnly ||
        report.findings.some((finding) => finding.status === "passed"),
      stale,
    };
    if (report.tenant) metadata.tenant = report.tenant;
    if (report.generatedAt) metadata.generatedAt = report.generatedAt;
    if (ageDays !== undefined) metadata.ageDays = Number(ageDays.toFixed(2));
    if (stale) {
      metadata.freshnessWarning = `This report is older than ${this.maxReportAgeDays} days. Run a new CheckMate scan before making current-state claims.`;
    }
    return metadata;
  }

  private safeErrorMessage(error: unknown): string {
    return message(error)
      .split(this.reportsDirectory)
      .join("[reports-directory]");
  }
}

import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ReportRepository } from "@checkmate-assistant/core";

async function writeReport(
  directory: string,
  filename: string,
  report: unknown,
): Promise<void> {
  await writeFile(path.join(directory, filename), JSON.stringify(report));
}

describe("report repository", () => {
  it("loads a selected report and records findings-only coverage", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-mcp-"));
    await writeReport(directory, "report.json", [
      {
        finding_name: "checkMfa",
        finding_title: "MFA",
        severity: "High",
        message: "MFA is not enforced.",
      },
    ]);
    const repository = new ReportRepository({
      reportsDirectory: directory,
      now: () => new Date("2026-07-14T00:00:00.000Z"),
    });

    const context = await repository.getReport("report.json");
    expect(context.metadata).toMatchObject({
      reportId: "report.json",
      totalFindings: 1,
      findingsOnly: true,
      passedChecksIncluded: false,
      counts: { failed: 1, passed: 0, warning: 0, unknown: 0 },
    });
  });

  it("shows invalid files but selects the newest valid report", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-mcp-"));
    await writeReport(directory, "valid.json", [
      { title: "Valid finding", status: "failed" },
    ]);
    await writeFile(path.join(directory, "invalid.json"), "{invalid");
    const repository = new ReportRepository({ reportsDirectory: directory });

    const reports = await repository.listReports();
    expect(reports).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ reportId: "valid.json", valid: true }),
        expect.objectContaining({ reportId: "invalid.json", valid: false }),
      ]),
    );
    const invalid = reports.find((report) => !report.valid);
    expect(invalid && invalid.error).not.toContain(directory);
    await expect(repository.getReport()).resolves.toMatchObject({
      metadata: { reportId: "valid.json" },
    });
  });

  it("does not accept paths outside the configured report directory", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-mcp-"));
    await writeReport(directory, "valid.json", []);
    const repository = new ReportRepository({ reportsDirectory: directory });

    await expect(repository.getReport("../outside.json")).rejects.toThrow(
      "Unknown reportId",
    );
  });

  it("flags reports older than the configured freshness threshold", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-mcp-"));
    await writeReport(directory, "old.json", {
      generatedAt: "2026-07-01T00:00:00.000Z",
      findings: [],
    });
    const repository = new ReportRepository({
      reportsDirectory: directory,
      maxReportAgeDays: 7,
      now: () => new Date("2026-07-14T00:00:00.000Z"),
    });

    const context = await repository.getReport();
    expect(context.metadata.ageDays).toBe(13);
    expect(context.metadata.stale).toBe(true);
    expect(context.metadata.freshnessWarning).toContain("older than 7 days");
  });
});

import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadCheckmateReport } from "../src/checkmate/report-loader.js";

describe("report loading", () => {
  it("parses valid JSON", async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), "checkmate-loader-"),
    );
    const reportPath = path.join(directory, "report.json");
    await writeFile(
      reportPath,
      JSON.stringify([{ title: "Finding", status: "red" }]),
    );
    const report = await loadCheckmateReport(reportPath);
    expect(report.findings[0]?.status).toBe("failed");
    expect(report.generatedAt).toBeTruthy();
  });

  it("returns a clear malformed JSON error", async () => {
    const directory = await mkdtemp(
      path.join(os.tmpdir(), "checkmate-loader-"),
    );
    const reportPath = path.join(directory, "bad.json");
    await writeFile(reportPath, "{not-json");
    await expect(loadCheckmateReport(reportPath)).rejects.toThrow(
      "Report is not valid JSON",
    );
  });
});

import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { CheckmateReportError } from "./errors.js";
import { normalizeCheckmateReport } from "./report-normalizer.js";
import type { LoadedCheckmateReport } from "./types.js";

export async function loadCheckmateReport(
  filePath: string,
): Promise<LoadedCheckmateReport> {
  const absolutePath = path.resolve(filePath);
  let contents: string;
  let modifiedAt: string;
  try {
    const [data, metadata] = await Promise.all([
      readFile(absolutePath, "utf8"),
      stat(absolutePath),
    ]);
    contents = data;
    modifiedAt = metadata.mtime.toISOString();
  } catch (error) {
    throw new CheckmateReportError(
      "REPORT_READ_ERROR",
      `Unable to read report: ${filePath}`,
      { cause: error },
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(contents) as unknown;
  } catch (error) {
    throw new CheckmateReportError(
      "INVALID_JSON",
      `Report is not valid JSON: ${filePath}`,
      { cause: error },
    );
  }

  const normalized = normalizeCheckmateReport(raw);
  return {
    ...normalized,
    generatedAt: normalized.generatedAt ?? modifiedAt,
    sourcePath: absolutePath,
  };
}

import { rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { reviewSessionSchema, type ReviewSession } from "./review-schema.js";
import { ensureDirectory } from "../utils/filesystem.js";
import { AppError } from "../utils/errors.js";

function safeFilename(value: string): string {
  return value
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 100);
}

export function createReviewOutputPath(
  reportPath: string,
  startedAt: Date,
  outputDirectory = path.resolve("remediation-plans"),
): string {
  const reportName =
    safeFilename(path.parse(reportPath).name) || "checkmate-report";
  const timestamp = startedAt.toISOString().replace(/[:.]/g, "-");
  return path.join(outputDirectory, `${reportName}-review-${timestamp}.json`);
}

export async function writeReviewSession(
  outputPath: string,
  session: ReviewSession,
): Promise<void> {
  const validated = reviewSessionSchema.safeParse(session);
  if (!validated.success) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      "The review session is invalid and was not written.",
      { cause: validated.error },
    );
  }

  await ensureDirectory(path.dirname(outputPath));
  const temporaryPath = path.join(
    path.dirname(outputPath),
    `.${path.basename(outputPath)}.${process.pid}.tmp`,
  );
  try {
    await writeFile(
      temporaryPath,
      `${JSON.stringify(validated.data, null, 2)}\n`,
      {
        encoding: "utf8",
        mode: 0o600,
      },
    );
    await rename(temporaryPath, outputPath);
  } catch (error) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      `Unable to write review decisions under: ${path.dirname(outputPath)}`,
      { cause: error },
    );
  }
}

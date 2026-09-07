import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse, stringify } from "yaml";
import { apiPlanSchema, type ApiPlan } from "./api-plan.js";
import { ensureDirectory } from "../utils/filesystem.js";
import { AppError } from "../utils/errors.js";

function apiPlanSha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function parseApiPlan(content: string): ApiPlan {
  try {
    return apiPlanSchema.parse(parse(content) as unknown);
  } catch (error) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      "The saved API plan is invalid and cannot be executed.",
      { cause: error },
    );
  }
}

export async function readApiPlan(
  inputPath: string,
): Promise<{ plan: ApiPlan; sha256: string }> {
  let content: string;
  try {
    content = await readFile(inputPath, "utf8");
  } catch (error) {
    throw new AppError(
      "AUTH0_WRITE_FAILED",
      `Unable to read the saved API plan: ${inputPath}`,
      { cause: error },
    );
  }
  return {
    plan: parseApiPlan(content),
    sha256: apiPlanSha256(content),
  };
}

export async function writeApiPlan(
  outputPath: string,
  plan: ApiPlan,
): Promise<void> {
  const validated = apiPlanSchema.safeParse(plan);
  if (!validated.success) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      "The API plan is invalid and was not written.",
      { cause: validated.error },
    );
  }
  await ensureDirectory(path.dirname(outputPath));
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryPath, stringify(validated.data), {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, outputPath);
  } catch (error) {
    throw new AppError(
      "REVIEW_WRITE_ERROR",
      `Unable to write API plan: ${outputPath}`,
      { cause: error },
    );
  }
}

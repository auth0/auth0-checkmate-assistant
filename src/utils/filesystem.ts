import { copyFile, mkdir, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { AppError } from "./errors.js";

export async function ensureDirectory(directory: string): Promise<void> {
  try {
    await mkdir(directory, { recursive: true });
  } catch (error) {
    throw new AppError(
      "OUTPUT_DIRECTORY_ERROR",
      `Unable to create output directory: ${directory}`,
      { cause: error },
    );
  }
}

export interface JsonFileSnapshot {
  path: string;
  modifiedMs: number;
  size: number;
}

export async function listJsonFiles(
  directory: string,
): Promise<JsonFileSnapshot[]> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    throw new AppError(
      "OUTPUT_DIRECTORY_ERROR",
      `Unable to read output directory: ${directory}`,
      {
        cause: error,
      },
    );
  }

  const files = entries
    .filter(
      (entry) =>
        entry.isFile() && path.extname(entry.name).toLowerCase() === ".json",
    )
    .map(async (entry) => {
      const filePath = path.join(directory, entry.name);
      const metadata = await stat(filePath);
      return {
        path: filePath,
        modifiedMs: metadata.mtimeMs,
        size: metadata.size,
      };
    });

  return Promise.all(files);
}

export function findGeneratedJsonReport(
  before: readonly JsonFileSnapshot[],
  after: readonly JsonFileSnapshot[],
  startedMs: number,
): string | undefined {
  const prior = new Map(
    before.map((file) => [file.path, `${file.modifiedMs}:${file.size}`]),
  );
  return after
    .filter(
      (file) =>
        file.modifiedMs >= startedMs - 1_000 ||
        prior.get(file.path) !== `${file.modifiedMs}:${file.size}`,
    )
    .sort((left, right) => right.modifiedMs - left.modifiedMs)[0]?.path;
}

export async function copyIntoWorkspace(
  source: string,
  workspace: string,
): Promise<string> {
  await ensureDirectory(workspace);
  const absoluteSource = path.resolve(source);
  if (path.dirname(absoluteSource) === path.resolve(workspace))
    return absoluteSource;

  const parsed = path.parse(absoluteSource);
  let destination = path.join(workspace, parsed.base);
  try {
    await stat(destination);
    destination = path.join(
      workspace,
      `${parsed.name}-imported-${Date.now()}${parsed.ext}`,
    );
  } catch {
    // A missing destination is the expected path for a first import.
  }

  try {
    await copyFile(absoluteSource, destination);
    return destination;
  } catch (error) {
    throw new AppError(
      "FILE_COPY_ERROR",
      `Unable to copy report into: ${workspace}`,
      {
        cause: error,
      },
    );
  }
}

export function displayPath(filePath: string): string {
  const relative = path.relative(process.cwd(), filePath);
  return relative.length > 0 && !relative.startsWith("..")
    ? relative
    : filePath;
}

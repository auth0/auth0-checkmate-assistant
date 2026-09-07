import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { executeScan } from "../src/commands/scan.js";
import type { ProcessRunner } from "../src/checkmate/runner.js";

describe("scan command", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("loads a report produced by a mocked CheckMate process", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-scan-"));
    vi.stubEnv("AUTH0CHECKMATE_PROD_DOMAIN", "tenant.example.auth0.com");
    vi.stubEnv("AUTH0CHECKMATE_PROD_CLIENT_ID", "client-id");
    vi.stubEnv("AUTH0CHECKMATE_PROD_CLIENT_SECRET", "client-secret");
    vi.stubEnv("AUTH0CHECKMATE_FILE_PATH", directory);

    const processRunner: ProcessRunner = async (request) => {
      await writeFile(
        path.join(
          request.env.AUTH0CHECKMATE_FILE_PATH!,
          "generated-report.json",
        ),
        JSON.stringify([
          {
            finding_name: "validator",
            finding_title: "Finding",
            message: "Issue",
          },
        ]),
      );
      return { exitCode: 0, stdout: "complete", stderr: "" };
    };

    const metadata = await executeScan({ profile: "prod" }, { processRunner });
    expect(metadata.targetDomain).toBe("tenant.example.auth0.com");
    expect(metadata.reportPath).toBe(
      path.join(directory, "generated-report.json"),
    );
    expect(metadata.exitCode).toBe(0);
  });
});

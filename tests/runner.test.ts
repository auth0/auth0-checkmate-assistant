import { describe, expect, it, vi } from "vitest";
import {
  buildCheckmateEnvironment,
  resolveCheckmateRuntime,
  runCheckmate,
} from "../src/checkmate/runner.js";
import type { CheckmateConfig } from "../src/config/env.js";

const config: CheckmateConfig = {
  profile: "prod",
  domain: "tenant.example.auth0.com",
  clientId: "client-id",
  clientSecret: "secret-value",
  outputDirectory: "/tmp/reports",
  disablePdfReporting: true,
  timeoutMs: 10_000,
};

describe("CheckMate runner", () => {
  it("uses the current Node runtime and the bundled fixed CheckMate entrypoint", async () => {
    const processRunner = vi
      .fn()
      .mockResolvedValue({ exitCode: 0, stdout: "ok", stderr: "" });
    const result = await runCheckmate({ config, processRunner });
    const runtime = resolveCheckmateRuntime();
    expect(processRunner).toHaveBeenCalledWith(
      expect.objectContaining({
        executable: process.execPath,
        args: [runtime.entrypoint],
      }),
    );
    const request = processRunner.mock.calls[0]?.[0] as {
      env: NodeJS.ProcessEnv;
    };
    expect(request.env.AUTH0CHECKMATE_CLIENT_SECRET).toBe("secret-value");
    expect(runtime.entrypoint).toMatch(
      /node_modules\/@auth0\/auth0-checkmate\/bin\/index\.js$/,
    );
    expect(result.metadata.checkmateVersion).toBe("1.8.4");
  });

  it("does not forward unrelated credentials from the parent environment", () => {
    const childEnvironment = buildCheckmateEnvironment(config, {
      PATH: "/usr/bin",
      UNRELATED_API_KEY: "unrelated-secret",
      GITHUB_TOKEN: "github-secret",
    });
    expect(childEnvironment.PATH).toBe("/usr/bin");
    expect(childEnvironment.UNRELATED_API_KEY).toBeUndefined();
    expect(childEnvironment.GITHUB_TOKEN).toBeUndefined();
  });

  it("turns a non-zero child exit into a redacted application error", async () => {
    const processRunner = vi.fn().mockResolvedValue({
      exitCode: 7,
      stdout: "",
      stderr: "authentication failed for secret-value",
    });
    await expect(runCheckmate({ config, processRunner })).rejects.toThrow(
      "Auth0 CheckMate exited with code 7. authentication failed for [REDACTED]",
    );
  });
});

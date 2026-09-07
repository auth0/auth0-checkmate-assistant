import { describe, expect, it } from "vitest";
import { loadCheckmateConfig } from "../src/config/env.js";
import { selectProfile } from "../src/config/profiles.js";

describe("profile configuration", () => {
  it("selects only allowlisted profiles", () => {
    expect(selectProfile("prod").definition.clientSecretEnv).toBe(
      "AUTH0CHECKMATE_PROD_CLIENT_SECRET",
    );
    expect(() => selectProfile("staging")).toThrow(
      "Allowed profiles: prod, dev",
    );
  });

  it("reports a missing variable by name without exposing another value", () => {
    const env = {
      AUTH0CHECKMATE_PROD_DOMAIN: "tenant.example.auth0.com",
      AUTH0CHECKMATE_PROD_CLIENT_SECRET: "never-print-this",
    };
    expect(() => loadCheckmateConfig("prod", env)).toThrow(
      "AUTH0CHECKMATE_PROD_CLIENT_ID",
    );
    try {
      loadCheckmateConfig("prod", env);
    } catch (error) {
      expect((error as Error).message).not.toContain("never-print-this");
    }
  });
});

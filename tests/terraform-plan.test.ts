import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ApiPlan } from "../src/remediation/api-plan.js";
import {
  buildTerraformDeploymentConfiguration,
  terraformCoverage,
} from "../src/remediation/terraform-plan.js";
import {
  validateTerraformConfiguration,
  type TerraformCommandRunner,
} from "../src/remediation/terraform-validator.js";

function plan(): ApiPlan {
  return {
    schemaVersion: 1,
    generatedAt: "2026-07-14T02:00:00.000Z",
    sourceReport: "/private/reports/tenant.json",
    profile: "dev",
    unchangedActionIds: ["action-unchanged"],
    alreadyCompliantActionIds: [],
    calls: [
      {
        id: "api-call-1",
        method: "PATCH",
        endpoint: "/api/v2/connections/con_dev",
        resourceType: "connection",
        resourceId: "con_dev",
        resourceName: "Username-Password-Authentication",
        bodyStrategy: "merge_live_connection_options",
        actionIds: ["action-history"],
        preconditions: [
          {
            path: "options.password_history.enable",
            expectedValue: false,
          },
        ],
        body: { options: { password_history: { enable: true } } },
      },
      {
        id: "api-call-2",
        method: "PATCH",
        endpoint: "/api/v2/clients/client_12345678",
        resourceType: "client",
        resourceId: "client_12345678",
        resourceName: "Test App",
        bodyStrategy: "merge_live_nested_objects",
        actionIds: ["action-implicit"],
        preconditions: [
          {
            path: "grant_types",
            expectedValue: ["authorization_code", "implicit"],
          },
        ],
        body: { grant_types: ["authorization_code"] },
      },
    ],
  };
}

function validatedRequestBodies(): Record<string, Record<string, unknown>> {
  return {
    "api-call-1": {
      options: {
        mfa: { active: true, return_enroll_settings: true },
        import_mode: false,
        configuration: { private_key: "must-not-be-embedded" },
        passwordPolicy: "good",
        passkey_options: {
          challenge_ui: "both",
          local_enrollment_enabled: true,
          progressive_enrollment_enabled: true,
        },
        authentication_methods: {
          password: { enabled: true },
          passkey: { enabled: true },
        },
        password_history: { enable: true, size: 5 },
        requires_username: false,
      },
    },
  };
}

describe("Terraform deployment output", () => {
  it("imports and manages supported resources through the official Auth0 provider", () => {
    const terraform = buildTerraformDeploymentConfiguration(
      plan(),
      validatedRequestBodies(),
    );

    expect(terraform).toContain('source  = "auth0/auth0"');
    expect(terraform).toContain('version = "~> 1.52.0"');
    expect(terraform).toContain('data "auth0_connection"');
    expect(terraform).toContain('data "auth0_client"');
    expect(terraform).toContain('resource "auth0_connection"');
    expect(terraform).toContain('resource "auth0_client"');
    expect(terraform).toContain("import {");
    expect(terraform).toContain("prevent_destroy = true");
    expect(terraform).toContain('client_id = "client_12345678"');
    expect(terraform).toContain('connection_id        = "con_dev"');
    expect(terraform).toContain('grant_types       = ["authorization_code"]');
    expect(terraform).toContain("password_history {");
    expect(terraform).toContain("size = 5");
    expect(terraform).toContain("mfa {");
    expect(terraform).toContain("return_enroll_settings = true");
    expect(terraform).toContain('password_policy = "good"');
    expect(terraform).toContain("passkey_options {");
    expect(terraform).toContain(
      "configuration = data.auth0_connection.username_password_authentication_043ac6d9.options[0].configuration",
    );
    expect(terraform).not.toContain("must-not-be-embedded");
    expect(terraform).not.toContain("options[0].password_history");
    expect(terraform).toContain("api_only_call_ids          = []");
    expect(terraform).not.toContain("/private/reports");
  });

  it("fails closed when complete live connection options are unavailable", () => {
    expect(() => buildTerraformDeploymentConfiguration(plan())).toThrow(
      "complete validated request body",
    );
  });

  it("fails closed when the provider schema cannot represent a live option", () => {
    const bodies = validatedRequestBodies();
    (bodies["api-call-1"]!.options as Record<string, unknown>)[
      "future_read_only_field"
    ] = true;

    expect(() => buildTerraformDeploymentConfiguration(plan(), bodies)).toThrow(
      "has no schema for connection option",
    );
    // The error identifies the offending connection for the operator.
    expect(() => buildTerraformDeploymentConfiguration(plan(), bodies)).toThrow(
      'Connection "Username-Password-Authentication" (con_dev):',
    );
  });

  it("reports official-provider coverage for every supported call", () => {
    expect(terraformCoverage(plan())).toEqual({
      managedCallIds: ["api-call-1", "api-call-2"],
      apiOnlyCalls: [],
    });
  });

  it("runs fmt, init, and validate as fixed Terraform commands", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-tf-"));
    const terraformFile = path.join(directory, "main.tf");
    await writeFile(
      terraformFile,
      buildTerraformDeploymentConfiguration(plan(), validatedRequestBodies()),
    );
    const runner = vi
      .fn<TerraformCommandRunner>()
      .mockImplementation((request) =>
        Promise.resolve({
          exitCode: request.args[0] === "plan" ? 2 : 0,
          stdout:
            request.args[0] === "show"
              ? JSON.stringify({
                  resource_changes: [
                    {
                      address: "auth0_connection.database",
                      mode: "managed",
                      type: "auth0_connection",
                      change: {
                        actions: ["update"],
                        importing: { id: "con_dev" },
                      },
                    },
                  ],
                })
              : "Success!",
          stderr: "",
        }),
      );

    const result = await validateTerraformConfiguration(terraformFile, {
      runner,
      env: { PATH: process.env.PATH },
      now: () => new Date("2026-07-14T03:00:00.000Z"),
    });

    expect(result.valid).toBe(true);
    expect(result.steps.map((step) => step.command)).toEqual([
      "fmt",
      "init",
      "validate",
      "plan",
      "show",
    ]);
    expect(runner.mock.calls.map(([request]) => request.args[0])).toEqual([
      "fmt",
      "init",
      "validate",
      "plan",
      "show",
    ]);
    expect(runner.mock.calls[0]?.[0].env).not.toHaveProperty(
      "AUTH0_CLIENT_SECRET",
    );
  });

  it("rejects destructive changes found in the machine-readable plan", async () => {
    const runner = vi
      .fn<TerraformCommandRunner>()
      .mockImplementation((request) =>
        Promise.resolve({
          exitCode: request.args[0] === "plan" ? 2 : 0,
          stdout:
            request.args[0] === "show"
              ? JSON.stringify({
                  resource_changes: [
                    {
                      address: "auth0_client.example",
                      mode: "managed",
                      type: "auth0_client",
                      change: { actions: ["delete", "create"] },
                    },
                  ],
                })
              : "Success!",
          stderr: "",
        }),
      );

    const result = await validateTerraformConfiguration("/tmp/main.tf", {
      runner,
    });

    expect(result).toMatchObject({
      valid: false,
      error:
        "Terraform validation rejected a destructive change for auth0_client.example.",
    });
  });

  it("stops validation after the first failed command", async () => {
    const runner = vi.fn<TerraformCommandRunner>().mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "File is not formatted.",
    });

    const result = await validateTerraformConfiguration("/tmp/main.tf", {
      runner,
    });

    expect(result).toMatchObject({
      valid: false,
      error: "File is not formatted.",
    });
    expect(runner).toHaveBeenCalledOnce();
  });
});

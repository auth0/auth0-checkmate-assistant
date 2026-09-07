import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type {
  ApiExecutionResult,
  ApiPlanValidationResult,
} from "../src/auth0/api-plan-executor.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";
import type { ScanMetadata } from "../src/checkmate/types.js";
import type { ActionableChange } from "../src/remediation/actionable-change.js";
import { apiPlanSchema, type ApiPlan } from "../src/remediation/api-plan.js";
import { createChangePackagePaths } from "../src/remediation/change-package-writer.js";
import { reviewSessionSchema } from "../src/remediation/review-schema.js";
import type { TerraformValidationResult } from "../src/remediation/terraform-validator.js";
import { startUiServer } from "../src/ui/server.js";
import { parse } from "yaml";

describe("local review UI", () => {
  it("shows only supported findings and saves a validated decision", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "report.json");
    const outputDirectory = path.join(directory, "plans");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkManagementAPIUserAccess",
          finding_title: "Management API user access",
          status: "red",
          severity: "High",
          name: "Auth0 Management API",
          message: "Management API user access is open to every application.",
          recommendation: "Restrict access to approved applications.",
          evidence: { private_field: "must-not-reach-browser" },
        },
        {
          finding_name: "checkPasswordPolicy",
          finding_title: "Databases - Password Policy",
          status: "red",
          severity: "Moderate",
          name: "Username-Password-Authentication",
          message: "The password policy is below the required level.",
          recommendation: "Use a good password policy.",
        },
        {
          finding_name: "checkPasswordPolicy",
          finding_title: "Databases - Password Policy",
          status: "red",
          severity: "Moderate",
          field: "secondary_setting",
          message: "A second row describes the same password validator.",
          recommendation: "Use a good password policy.",
        },
      ]),
    );
    const configurationLoader = vi.fn(
      (
        findings: readonly NormalizedCheckmateFinding[],
        config: { profile: "dev" | "prod" },
      ) => {
        const action: ActionableChange = {
          resourceType: "connection",
          resourceId: `con_${config.profile}`,
          resourceName: "Username-Password-Authentication",
          configPath: "options.passwordPolicy",
          currentValue: "fair",
          targetValue: "good",
        };
        const historyAction: ActionableChange = {
          resourceType: "connection",
          resourceId: `con_${config.profile}`,
          resourceName: "Username-Password-Authentication",
          configPath: "options.password_history.enable",
          currentValue: false,
          targetValue: true,
        };
        return Promise.resolve(
          new Map(
            findings
              .filter(
                (finding) => finding.validatorId === "checkPasswordPolicy",
              )
              .map((finding): [string, ActionableChange[]] => [
                finding.id,
                [action, historyAction],
              ]),
          ),
        );
      },
    );
    const planExecutor = vi.fn((): Promise<ApiExecutionResult> =>
      Promise.resolve({
        operation: "apply",
        status: "succeeded",
        startedAt: "2026-07-10T10:01:00.000Z",
        completedAt: "2026-07-10T10:01:01.000Z",
        profile: "dev",
        calls: [
          {
            id: "api-call-1",
            endpoint: "/api/v2/connections/con_database",
            status: "applied",
            correlationId: "checkmate-test",
          },
        ],
      }),
    );
    const planRollbackExecutor = vi.fn((): Promise<ApiExecutionResult> =>
      Promise.resolve({
        operation: "rollback",
        status: "succeeded",
        startedAt: "2026-07-10T10:02:00.000Z",
        completedAt: "2026-07-10T10:02:01.000Z",
        profile: "dev",
        calls: [
          {
            id: "api-call-1",
            endpoint: "/api/v2/connections/con_database",
            status: "rolled_back",
            correlationId: "checkmate-rollback-test",
          },
        ],
      }),
    );
    const apiPlanValidator = vi.fn(
      (plan: ApiPlan): Promise<ApiPlanValidationResult> =>
        Promise.resolve({
          valid: true,
          profile: plan.profile,
          validatedAt: "2026-07-10T10:00:00.000Z",
          calls: plan.calls.map((call) => ({
            id: call.id,
            endpoint: call.endpoint,
            method: call.method,
            resourceName: call.resourceName,
            status: "ready",
            requestBody: structuredClone(call.body),
            requestSha256: "a".repeat(64),
          })),
        }),
    );
    const terraformValidator = vi.fn(
      (terraformFile: string): Promise<TerraformValidationResult> =>
        Promise.resolve({
          valid: true,
          validatedAt: "2026-07-10T10:00:00.000Z",
          terraformFile,
          steps: [
            { command: "fmt", valid: true, message: "formatted" },
            { command: "init", valid: true, message: "initialised" },
            { command: "validate", valid: true, message: "validated" },
          ],
        }),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory,
      },
      {
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "inventory-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "never-return-this-secret",
          AUTH0CHECKMATE_PROD_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_PROD_CLIENT_ID: "prod-client",
          AUTH0CHECKMATE_PROD_CLIENT_SECRET: "prod-secret",
        },
        now: () => new Date("2026-07-10T10:00:00.000Z"),
        configurationLoader,
        planExecutor,
        planRollbackExecutor,
        apiPlanValidator,
        productionCredentialAccessInspector: vi.fn(() =>
          Promise.resolve({
            status: "write_access_detected" as const,
            checkedAt: "2026-07-10T10:00:00.000Z",
            writeScopes: ["update:clients"],
            message:
              "Production credentials have Management API write access (update:clients). Package creation continued.",
          }),
        ),
        terraformValidator,
      },
    );

    try {
      const root = await fetch(running.url);
      expect(root.status).toBe(200);
      expect(root.headers.get("content-security-policy")).toContain(
        "default-src 'self'",
      );
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      expect(cookie).toMatch(/^checkmate_session=/);
      const stateResponse = await fetch(`${running.url}/api/state`, {
        headers: { cookie: cookie! },
      });
      const initialText = await stateResponse.text();
      expect(initialText).not.toContain("checkManagementAPIUserAccess");
      expect(initialText).not.toContain("must-not-reach-browser");
      expect(initialText).not.toContain("never-return-this-secret");
      const initial = JSON.parse(initialText) as {
        triaged: boolean;
        reportValidatorCount: number;
        reportFindingCount: number;
        posture: {
          current: { score: number; rating: string };
          projected: { score: number; rating: string };
        };
        findings: unknown[];
      };
      expect(initial).toMatchObject({
        triaged: false,
        reportValidatorCount: 2,
        reportFindingCount: 3,
        findings: [],
      });
      expect(initial.posture.current).toEqual(initial.posture.projected);
      expect(initial.posture.current.score).toBe(108);

      const triageResponse = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(triageResponse.status).toBe(200);
      const triaged = (await triageResponse.json()) as {
        triaged: boolean;
        posture: {
          projected: {
            openControls: Array<{
              title: string;
              importance: string;
              guidance: string;
              recommendationAvailable: boolean;
            }>;
          };
        };
        findings: Array<{
          key: string;
          title: string;
          impact: string;
          points: number;
          analysis: { remediationConsiderations: string[] };
          actionableChanges: Array<{
            actionId: string;
            configPath: string;
            currentValue: string;
            targetValue: string;
          }>;
        }>;
      };
      expect(triaged.triaged).toBe(true);
      expect(triaged.findings).toHaveLength(2);
      const passwordPolicy = triaged.findings.find(
        ({ title }) =>
          title ===
          "Set the password policy to Good for Username-Password-Authentication",
      );
      const passwordHistory = triaged.findings.find(
        ({ title }) => title === "Enable password history",
      );
      expect(passwordPolicy).toMatchObject({
        title:
          "Set the password policy to Good for Username-Password-Authentication",
        impact: "High priority",
        points: 5,
        analysis: {
          remediationConsiderations: [
            "Set the password policy to Good for Username-Password-Authentication.",
          ],
        },
        actionableChanges: [
          {
            configPath: "options.passwordPolicy",
            currentValue: "fair",
            targetValue: "good",
          },
        ],
      });
      expect(JSON.stringify(triaged.findings)).not.toContain(
        "Management API user access",
      );
      expect(triaged.posture.projected.openControls).toContainEqual(
        expect.objectContaining({
          title: "Management API user access",
          importance: "High priority",
          recommendationAvailable: false,
        }),
      );
      const findingKey = passwordPolicy!.key;

      const saveResponse = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey,
          status: "accepted_risk",
          rationale: "The current access is temporarily accepted.",
        }),
      });
      expect(saveResponse.status).toBe(200);
      const savedState = (await saveResponse.json()) as {
        state: {
          posture: {
            current: { score: number };
            projected: { score: number };
          };
          findings: Array<{ key: string; adminNote?: string }>;
        };
      };
      expect(
        savedState.state.findings.find((finding) => finding.key === findingKey)
          ?.adminNote,
      ).toBe("The current access is temporarily accepted.");
      expect(savedState.state.posture.projected.score).toBe(
        savedState.state.posture.current.score,
      );
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions[0]?.decision.status).toBe("accepted_risk");
      expect(stored.decisions[0]?.decision.rationale).toBe(
        "The current access is temporarily accepted.",
      );
      expect(stored.decisions[0]?.decision.adminNote).toBe(
        "The current access is temporarily accepted.",
      );
      expect(stored.decisions[0]?.actionableChangeId).toBe(findingKey);
      expect(stored.decisions[0]?.actionableChanges?.[0]).toMatchObject({
        configPath: "options.passwordPolicy",
        currentValue: "fair",
        targetValue: "good",
      });
      expect(stored.review.completedAt).toBeUndefined();
      expect(stored.review.guidanceEngine).toBe(
        "checkmate-1.8.4-deterministic-guidance-v1",
      );

      const earlySubmitResponse = await fetch(`${running.url}/api/submit`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(earlySubmitResponse.status).toBe(400);

      const secondSaveResponse = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: passwordHistory!.key,
          status: "approved",
          rationale: "Accept the second independent action.",
        }),
      });
      expect(secondSaveResponse.status).toBe(200);
      const partiallyApproved = (await secondSaveResponse.json()) as {
        state: {
          posture: {
            current: { score: number };
            projected: { score: number };
            delta: number;
          };
        };
      };
      expect(partiallyApproved.state.posture.projected.score).toBe(
        partiallyApproved.state.posture.current.score,
      );
      expect(partiallyApproved.state.posture.delta).toBe(0);
      const completed = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(completed.decisions).toHaveLength(2);
      expect(completed.decisions[1]?.actionableChangeId).toBe(
        passwordHistory!.actionableChanges[0]!.actionId,
      );
      expect(completed.review.completedAt).toBeTruthy();

      const submitResponse = await fetch(`${running.url}/api/submit`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(submitResponse.status).toBe(200);
      const submitted = (await submitResponse.json()) as {
        created: boolean;
        state: {
          submissionReady: boolean;
          submitted: boolean;
          changePackage: {
            directory: string;
            dev: {
              apiFile: string;
              shellFile: string;
              terraformFile: string;
              apiPlanSha256: string;
              apiValidation: ApiPlanValidationResult;
            };
            prod: {
              apiFile: string;
              shellFile: string;
              terraformFile: string;
              apiPlanSha256: string;
              credentialAccess: { status: string; message: string };
            };
          };
        };
      };
      expect(submitted).toMatchObject({
        created: true,
        state: {
          submissionReady: true,
          submitted: true,
        },
      });
      expect(submitted.state.changePackage).toMatchObject({
        dev: {
          apiFile: "dev/api-plan.yml",
          shellFile: "dev/apply-api-plan.sh",
          terraformFile: "dev/main.tf",
        },
        prod: {
          apiFile: "prod/api-plan.yml",
          shellFile: "prod/apply-api-plan.sh",
          terraformFile: "prod/main.tf",
          credentialAccess: {
            status: "write_access_detected",
            message:
              "Production credentials have Management API write access. Package creation continued, but these credentials should be replaced with a read-only client grant.",
          },
        },
      });
      expect(submitted.state.changePackage.dev.apiPlanSha256).toMatch(
        /^[a-f0-9]{64}$/,
      );
      expect(
        submitted.state.changePackage.dev.apiValidation.calls[0],
      ).not.toHaveProperty("requestBody");
      const packagePaths = createChangePackagePaths(running.outputPath);
      const apiPlan = apiPlanSchema.parse(
        parse(await readFile(packagePaths.dev.apiPlan, "utf8")),
      );
      expect(apiPlan.calls).toHaveLength(1);
      expect(apiPlan.calls[0]).toMatchObject({
        method: "PATCH",
        endpoint: "/api/v2/connections/con_dev",
        actionIds: [passwordHistory!.actionableChanges[0]!.actionId],
        body: {
          options: { password_history: { enable: true } },
        },
      });
      expect(apiPlan.unchangedActionIds).toEqual([findingKey]);
      const productionPlan = apiPlanSchema.parse(
        parse(await readFile(packagePaths.prod.apiPlan, "utf8")),
      );
      expect(productionPlan).toMatchObject({
        profile: "prod",
        calls: [{ endpoint: "/api/v2/connections/con_prod" }],
      });
      expect(await readFile(packagePaths.dev.terraform, "utf8")).toContain(
        'data "auth0_connection"',
      );
      expect(await readFile(packagePaths.prod.terraform, "utf8")).toContain(
        'profile                    = "prod"',
      );
      const devShell = await readFile(packagePaths.dev.shell, "utf8");
      expect(devShell).toContain("#!/usr/bin/env bash");
      expect(devShell).toContain("# Tenant: tenant.auth0.com");
      expect(devShell).toContain(
        "AUTH0CHECKMATE_DEV_DOMAIN must exactly match the validated tenant ${EXPECTED_DOMAIN}",
      );
      expect((await stat(packagePaths.dev.shell)).mode & 0o777).toBe(0o700);

      const apiPreview = await fetch(
        `${running.url}/api/artifact?profile=dev&artifact=api`,
        { headers: { cookie: cookie! } },
      );
      expect(apiPreview.status).toBe(200);
      expect(apiPreview.headers.get("content-type")).toContain(
        "application/yaml",
      );
      expect(await apiPreview.text()).toContain("profile: dev");

      const terraformDownload = await fetch(
        `${running.url}/api/artifact?profile=prod&artifact=terraform&download=1`,
        { headers: { cookie: cookie! } },
      );
      expect(terraformDownload.status).toBe(200);
      expect(terraformDownload.headers.get("content-disposition")).toBe(
        'attachment; filename="prod-main.tf"',
      );
      expect(await terraformDownload.text()).toContain(
        'profile                    = "prod"',
      );

      const shellDownload = await fetch(
        `${running.url}/api/artifact?profile=dev&artifact=shell&download=1`,
        { headers: { cookie: cookie! } },
      );
      expect(shellDownload.status).toBe(200);
      expect(shellDownload.headers.get("content-type")).toContain(
        "text/x-shellscript",
      );
      expect(shellDownload.headers.get("content-disposition")).toBe(
        'attachment; filename="dev-apply-api-plan.sh"',
      );
      expect(await shellDownload.text()).toContain(
        "Applied and verified all validated API calls.",
      );

      const unsupportedArtifact = await fetch(
        `${running.url}/api/artifact?profile=dev&artifact=../report`,
        { headers: { cookie: cookie! } },
      );
      expect(unsupportedArtifact.status).toBe(400);

      const reviewedPlanContent = await readFile(
        packagePaths.dev.apiPlan,
        "utf8",
      );
      await writeFile(
        packagePaths.dev.apiPlan,
        `${reviewedPlanContent}\n# changed after review\n`,
      );
      const changedPlanResponse = await fetch(`${running.url}/api/execute`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ confirmed: true }),
      });
      expect(changedPlanResponse.status).toBe(400);
      expect(await changedPlanResponse.text()).toContain(
        "changed after review",
      );
      expect(planExecutor).not.toHaveBeenCalled();
      await writeFile(packagePaths.dev.apiPlan, reviewedPlanContent);

      const executeResponse = await fetch(`${running.url}/api/execute`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ confirmed: true }),
      });
      expect(executeResponse.status).toBe(200);
      const executed = (await executeResponse.json()) as {
        executed: boolean;
        state: {
          canExecute: boolean;
          canRollback: boolean;
          execution: ApiExecutionResult;
        };
      };
      expect(executed).toMatchObject({
        executed: true,
        state: {
          canExecute: false,
          canRollback: true,
          execution: { status: "succeeded" },
        },
      });
      expect(planExecutor).toHaveBeenCalledOnce();
      expect(apiPlanValidator).toHaveBeenCalledTimes(2);
      expect(terraformValidator).toHaveBeenCalledTimes(2);
      const executionRecord = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(executionRecord.execution).toMatchObject({
        status: "succeeded",
        profile: "dev",
        calls: [{ status: "applied" }],
      });
      expect(executionRecord.execution?.planFile).toBe("dev/api-plan.yml");
      expect(executionRecord.execution?.planSha256).toBe(
        submitted.state.changePackage.dev.apiPlanSha256,
      );

      const rollbackResponse = await fetch(`${running.url}/api/rollback`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ confirmed: true }),
      });
      expect(rollbackResponse.status).toBe(200);
      const rolledBack = (await rollbackResponse.json()) as {
        rolledBack: boolean;
        state: {
          canRollback: boolean;
          execution: ApiExecutionResult;
        };
      };
      expect(rolledBack).toMatchObject({
        rolledBack: true,
        state: {
          canRollback: false,
          execution: { operation: "rollback", status: "succeeded" },
        },
      });
      expect(planRollbackExecutor).toHaveBeenCalledOnce();
      const rollbackRecord = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(rollbackRecord.execution).toMatchObject({
        operation: "rollback",
        status: "succeeded",
        calls: [{ status: "rolled_back" }],
      });
      expect(rollbackRecord.executionHistory).toHaveLength(2);
    } finally {
      await running.close();
    }
  });

  it("groups deterministic application changes with selectable applications", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "applications.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          status: "red",
          severity: "High",
          name: "App One (client_one12345) (First-Party Application)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "The Implicit grant type is enabled.",
        },
        {
          finding_name: "checkGrantTypes",
          finding_title: "Application Grant Types",
          status: "red",
          severity: "High",
          name: "App Two (client_two12345) (First-Party Application)",
          field: "unexpected_grant_type_for_app_type",
          value: "implicit",
          message: "The Implicit grant type is enabled.",
        },
        {
          finding_name: "checkCrossOriginAuthentication",
          finding_title: "Cross Origin Authentication",
          status: "red",
          severity: "High",
          name: "Default App (client_default12345) (First-Party Application)",
          field: "cross_origin_authentication_enabled",
          message: "Cross-origin authentication is enabled.",
        },
      ]),
    );
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map(
            findings.map((finding, index): [string, ActionableChange[]] => {
              if (finding.validatorId === "checkCrossOriginAuthentication") {
                return [
                  finding.id,
                  [
                    {
                      resourceType: "client",
                      resourceId: "client_default12345",
                      resourceName: "Default App",
                      configPath: "cross_origin_authentication",
                      currentValue: true,
                      targetValue: false,
                    },
                  ],
                ];
              }
              const suffix = index === 0 ? "one" : "two";
              return [
                finding.id,
                [
                  {
                    resourceType: "client",
                    resourceId: `client_${suffix}12345`,
                    resourceName: index === 0 ? "App One" : "App Two",
                    configPath: "grant_types",
                    currentValue: [
                      "authorization_code",
                      "implicit",
                      "refresh_token",
                    ],
                    targetValue: ["authorization_code", "refresh_token"],
                  },
                ],
              ];
            }),
          ),
        ),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-07-14T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const response = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(response.status).toBe(200);
      const state = (await response.json()) as {
        findings: Array<{
          key: string;
          title: string;
          selectionMode: string;
          defaultSelected: boolean;
          actionableChanges: Array<{ actionId: string; resourceName: string }>;
        }>;
      };
      expect(state.findings).toHaveLength(2);
      const implicitRecommendation = state.findings.find(
        (finding) => finding.key === "applications-remove-implicit",
      );
      const crossOriginRecommendation = state.findings.find(
        (finding) => finding.key === "applications-disable-cross-origin",
      );
      expect(implicitRecommendation).toMatchObject({
        key: "applications-remove-implicit",
        title: "Remove the Implicit grant type from",
        selectionMode: "applications",
        defaultSelected: false,
        actionableChanges: [
          { resourceName: "App One" },
          { resourceName: "App Two" },
        ],
      });
      expect(crossOriginRecommendation).toMatchObject({
        key: "applications-disable-cross-origin",
        title: "Disable cross-origin authentication for",
        selectionMode: "applications",
        defaultSelected: true,
        actionableChanges: [{ resourceName: "Default App" }],
      });
      const selectedActionId =
        implicitRecommendation!.actionableChanges[0]!.actionId;
      const save = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: implicitRecommendation!.key,
          status: "approved",
          rationale: "",
          selectedActionIds: [selectedActionId],
        }),
      });
      expect(save.status).toBe(200);
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions).toHaveLength(2);
      expect(
        stored.decisions.map((decision) => decision.decision.status),
      ).toEqual(["approved", "accepted_risk"]);
      expect(
        stored.decisions.map((decision) => decision.decision.rationale),
      ).toEqual(["Accepted suggestion.", "Remained unchanged."]);
      expect(
        stored.decisions.every(
          (decision) => decision.decision.adminNote === undefined,
        ),
      ).toBe(true);
    } finally {
      await running.close();
    }
  });

  it("keeps system Management API settings out of dual-format recommendations", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "management-api-access.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          name: "checkManagementAPIUserAccess",
          title: "Management API user access",
          status: "red",
          severity: "High",
          details: [
            {
              name: "Auth0 Management API",
              field: "management_api_user_access_allowed",
              status: "red",
              message: "Management API user access is allowed for all apps.",
            },
          ],
          detailsLength: 1,
        },
      ]),
    );
    const configurationLoader = vi.fn(() => Promise.resolve(new Map()));
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-08-03T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const triage = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(triage.status).toBe(200);
      const state = (await triage.json()) as {
        findings: Array<{
          key: string;
        }>;
        submissionReady: boolean;
        posture: {
          projected: {
            openControls: Array<{
              title: string;
              recommendationAvailable: boolean;
            }>;
          };
        };
      };
      expect(state.findings).toEqual([]);
      expect(state.submissionReady).toBe(false);
      expect(state.posture.projected.openControls).toEqual([
        expect.objectContaining({
          title: "Management API user access",
          recommendationAvailable: false,
        }),
      ]);
    } finally {
      await running.close();
    }
  });

  it("groups deterministic password changes with selectable connections", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "password-history.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          name: "checkPasswordHistory",
          title: "Databases - Password History",
          status: "green",
          severity: "Low",
          details: [
            {
              name: "my-own-db",
              field: "password_history_disabled",
              status: "red",
              message: "Password history is disabled.",
            },
            {
              name: "Username-Password-Authentication",
              field: "password_history_disabled",
              status: "red",
              message: "Password history is disabled.",
            },
          ],
          detailsLength: 2,
        },
        {
          name: "checkPasswordNoPersonalInfo",
          title: "Databases - Personal Information in Passwords",
          status: "yellow",
          severity: "Moderate",
          details: [
            {
              name: "my-own-db",
              field: "password_no_personal_info_disabled",
              status: "red",
              message: "Personal information in passwords is allowed.",
            },
            {
              name: "Username-Password-Authentication",
              field: "password_no_personal_info_disabled",
              status: "red",
              message: "Personal information in passwords is allowed.",
            },
          ],
          detailsLength: 2,
        },
        {
          name: "checkAuthenticationMethods",
          title: "Databases - Authentication Methods",
          status: "yellow",
          severity: "Moderate",
          details: [
            {
              name: "my-own-db",
              field: "only_password_method",
              status: "red",
              message: "Passkeys are not enabled.",
            },
            {
              name: "Username-Password-Authentication",
              field: "only_password_method",
              status: "red",
              message: "Passkeys are not enabled.",
            },
          ],
          detailsLength: 2,
        },
      ]),
    );
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map(
            findings.map((finding): [string, ActionableChange[]] => [
              finding.id,
              [
                {
                  resourceType: "connection",
                  resourceId: `con_${finding.validatorId}_${finding.affectedResource?.name === "my-own-db" ? "custom" : "default"}`,
                  resourceName: finding.affectedResource?.name ?? "Unknown",
                  configPath:
                    finding.validatorId === "checkPasswordHistory"
                      ? "options.password_history.enable"
                      : finding.validatorId === "checkPasswordNoPersonalInfo"
                        ? "options.password_no_personal_info.enable"
                        : "options.authentication_methods.passkey.enabled",
                  currentValue: false,
                  targetValue: true,
                },
              ],
            ]),
          ),
        ),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-08-03T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const response = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(response.status).toBe(200);
      const state = (await response.json()) as {
        findings: Array<{
          key: string;
          title: string;
          selectionMode: string;
          defaultSelected: boolean;
          actionableChanges: Array<{ actionId: string; resourceName: string }>;
        }>;
      };
      expect(state.findings).toHaveLength(3);
      const passwordHistory = state.findings.find(
        (finding) => finding.key === "connections-enable-password-history",
      );
      const personalInformation = state.findings.find(
        (finding) => finding.key === "connections-block-personal-information",
      );
      const passkeys = state.findings.find(
        (finding) => finding.key === "connections-enable-passkeys",
      );
      expect(passwordHistory).toMatchObject({
        key: "connections-enable-password-history",
        title: "Enable password history",
        selectionMode: "connections",
        actionableChanges: [
          { resourceName: "my-own-db" },
          { resourceName: "Username-Password-Authentication" },
        ],
      });
      expect(personalInformation).toMatchObject({
        key: "connections-block-personal-information",
        title: "Block personal information",
        selectionMode: "connections",
        actionableChanges: [
          { resourceName: "my-own-db" },
          { resourceName: "Username-Password-Authentication" },
        ],
      });
      expect(passkeys).toMatchObject({
        key: "connections-enable-passkeys",
        title: "Enable passkeys",
        selectionMode: "connections",
        defaultSelected: false,
        actionableChanges: [
          { resourceName: "my-own-db" },
          { resourceName: "Username-Password-Authentication" },
        ],
      });
    } finally {
      await running.close();
    }
  });

  it("groups insecure callback removals by application with selectable URLs", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "callbacks.json");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          status: "red",
          severity: "High",
          name: "Assistant0 (client_assistant0) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:3000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
        {
          finding_name: "checkAllowedCallbacks",
          finding_title: "Application Allowed Callbacks",
          status: "red",
          severity: "High",
          name: "Assistant0 (client_assistant0) (First-Party Application)",
          field: "insecure_callbacks",
          value: "http://localhost:4000/auth/callback",
          message: "An insecure callback URL is allowed.",
        },
      ]),
    );
    const currentCallbacks = [
      "http://localhost:3000/auth/callback",
      "http://localhost:4000/auth/callback",
      "https://assistant.example.com/auth/callback",
    ];
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map(
            findings.map((finding, index): [string, ActionableChange[]] => [
              finding.id,
              [
                {
                  resourceType: "client",
                  resourceId: "client_assistant0",
                  resourceName: "Assistant0",
                  configPath: "callbacks",
                  currentValue: currentCallbacks,
                  targetValue: currentCallbacks.filter((callback) =>
                    index === 0
                      ? !callback.includes("localhost:3000")
                      : !callback.includes("localhost:4000"),
                  ),
                },
              ],
            ]),
          ),
        ),
    );
    const running = await startUiServer(
      {
        report: reportPath,
        profile: "dev",
        status: "failed",
        port: 0,
        outputDirectory: directory,
      },
      {
        configurationLoader,
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "client-id",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "client-secret",
        },
        now: () => new Date("2026-07-25T10:00:00.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const response = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(response.status).toBe(200);
      const state = (await response.json()) as {
        findings: Array<{
          key: string;
          title: string;
          selectionMode: string;
          defaultSelected: boolean;
          actionableChanges: Array<{
            actionId: string;
            currentValue: string[];
            targetValue: string[];
          }>;
        }>;
      };
      expect(state.findings).toHaveLength(1);
      expect(state.findings[0]).toMatchObject({
        title: "Remove insecure callback URLs from Assistant0",
        selectionMode: "changes",
        defaultSelected: false,
      });
      expect(state.findings[0]?.actionableChanges).toHaveLength(2);
      const selectedActionId =
        state.findings[0]!.actionableChanges[0]!.actionId;
      const save = await fetch(`${running.url}/api/decision`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          findingKey: state.findings[0]!.key,
          status: "approved",
          rationale: "",
          selectedActionIds: [selectedActionId],
        }),
      });
      expect(save.status).toBe(200);
      const stored = reviewSessionSchema.parse(
        JSON.parse(await readFile(running.outputPath, "utf8")) as unknown,
      );
      expect(stored.decisions).toHaveLength(2);
      expect(
        stored.decisions.map((decision) => decision.decision.status),
      ).toEqual(["approved", "accepted_risk"]);
    } finally {
      await running.close();
    }
  });

  it("starts without a report and runs CheckMate from the UI", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "generated-report.json");
    const outputDirectory = path.join(directory, "plans");
    const scanExecutor = vi.fn(async () => {
      await writeFile(
        reportPath,
        JSON.stringify([
          {
            finding_name: "checkPasswordPolicy",
            finding_title: "Databases - Password Policy",
            status: "red",
            name: "Username-Password-Authentication",
            message: "The password policy is below the required level.",
          },
        ]),
      );
      return {
        profile: "dev",
        targetDomain: "tenant.auth0.com",
        startedAt: "2026-07-10T10:00:00.000Z",
        finishedAt: "2026-07-10T10:00:01.000Z",
        exitCode: 0,
        reportPath,
      } satisfies ScanMetadata;
    });
    const configurationLoader = vi.fn(
      (findings: readonly NormalizedCheckmateFinding[]) =>
        Promise.resolve(
          new Map([
            [
              findings[0]!.id,
              [
                {
                  resourceType: "connection" as const,
                  resourceId: "con_database",
                  resourceName: "Username-Password-Authentication",
                  configPath: "options.passwordPolicy",
                  currentValue: "fair",
                  targetValue: "good",
                },
              ],
            ],
          ]),
        ),
    );
    const running = await startUiServer(
      { status: "failed", port: 0, outputDirectory },
      {
        env: {
          AUTH0CHECKMATE_DEV_DOMAIN: "tenant.auth0.com",
          AUTH0CHECKMATE_DEV_CLIENT_ID: "scan-client",
          AUTH0CHECKMATE_DEV_CLIENT_SECRET: "scan-secret",
        },
        scanExecutor,
        configurationLoader,
        now: () => new Date("2026-07-10T10:00:02.000Z"),
      },
    );

    try {
      const root = await fetch(running.url);
      const cookie = root.headers.get("set-cookie")?.split(";")[0];
      const initial = (await fetch(`${running.url}/api/state`, {
        headers: { cookie: cookie! },
      }).then((response) => response.json())) as {
        hasReport: boolean;
        availableProfiles: string[];
      };
      expect(initial).toMatchObject({
        hasReport: false,
        availableProfiles: ["dev"],
      });
      expect(running.outputPath).toBe("");

      const scanResponse = await fetch(`${running.url}/api/scan`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: JSON.stringify({ profile: "dev" }),
      });
      expect(scanResponse.status).toBe(200);
      const scanned = (await scanResponse.json()) as {
        scanned: boolean;
        state: {
          hasReport: boolean;
          selectedProfile: string;
          report: { file: string };
        };
      };
      expect(scanned).toMatchObject({
        scanned: true,
        state: {
          hasReport: true,
          selectedProfile: "dev",
          report: { file: "generated-report.json" },
        },
      });
      expect(running.outputPath).toMatch(/generated-report-review-/);
      expect(scanExecutor).toHaveBeenCalledOnce();

      const triageResponse = await fetch(`${running.url}/api/triage`, {
        method: "POST",
        headers: {
          cookie: cookie!,
          origin: running.url,
          "content-type": "application/json",
        },
        body: "{}",
      });
      expect(triageResponse.status).toBe(200);
      const triaged = (await triageResponse.json()) as {
        triaged: boolean;
        findings: unknown[];
      };
      expect(triaged.triaged).toBe(true);
      expect(triaged.findings).toHaveLength(1);
    } finally {
      await running.close();
    }
  });

  it("rejects state requests without a browser session", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-ui-"));
    const reportPath = path.join(directory, "report.json");
    await writeFile(
      reportPath,
      JSON.stringify([{ title: "Finding", status: "red" }]),
    );
    const running = await startUiServer({
      report: reportPath,
      status: "failed",
      port: 0,
    });
    try {
      const response = await fetch(`${running.url}/api/state`);
      expect(response.status).toBe(401);
    } finally {
      await running.close();
    }
  });
});

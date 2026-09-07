import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  loadActionableConfiguration,
  type ActionableConfigurationMap,
} from "../auth0/configuration-reader.js";
import {
  executeApiPlan,
  rollbackApiPlan,
  validateApiPlan,
  type ApiExecutionResult,
  type ApiPlanValidationResult,
} from "../auth0/api-plan-executor.js";
import {
  assessProductionCredentialAccess,
  type ProductionCredentialAccessResult,
} from "../auth0/production-credential-access.js";
import { loadCheckmateReport } from "../checkmate/report-loader.js";
import { executeScan } from "../commands/scan.js";
import { loadCheckmateConfig, type CheckmateConfig } from "../config/env.js";
import { profiles, type ProfileName } from "../config/profiles.js";
import { resolveReviewProfile } from "../config/review-profile.js";
import {
  filterFindings,
  type FindingStatusFilter,
} from "../findings/filter.js";
import type { NormalizedCheckmateFinding } from "../findings/types.js";
import {
  buildDeterministicRecommendations,
  DETERMINISTIC_GUIDANCE_ENGINE,
  type DeterministicRecommendation,
} from "../remediation/deterministic-guidance.js";
import type { ApiPlan } from "../remediation/api-plan.js";
import { readApiPlan, writeApiPlan } from "../remediation/api-plan-writer.js";
import {
  assertValidatedApiPlan,
  finalizeValidatedApiPlan,
} from "../remediation/validated-api-plan.js";
import {
  createChangePackagePaths,
  type ChangePackagePaths,
  writeTextArtifact,
} from "../remediation/change-package-writer.js";
import { buildProfileApiPlan } from "../remediation/profile-api-plan.js";
import { buildApiPlanShellScript } from "../remediation/api-plan-shell.js";
import {
  buildTerraformDeploymentConfiguration,
  terraformCoverage,
  type TerraformCoverage,
  type TerraformValidatedRequestBodies,
} from "../remediation/terraform-plan.js";
import {
  validateTerraformConfiguration,
  type TerraformValidationResult,
} from "../remediation/terraform-validator.js";
import { redactText } from "../security/redaction.js";
import { collectSensitiveEnvironmentValues } from "../security/sensitive-values.js";
import {
  boundedUserText,
  createReviewEntry,
} from "../remediation/review-entry.js";
import type { ReviewSession } from "../remediation/review-schema.js";
import {
  createReviewOutputPath,
  writeReviewSession,
} from "../remediation/review-writer.js";
import { toErrorMessage } from "../utils/errors.js";
import { evaluatePosture } from "../posture/evaluator.js";
import {
  postureRecommendationImpact,
  POSTURE_REVIEW_GUIDANCE,
} from "../posture/control-catalog.js";

const HOST = "127.0.0.1";
const MAX_BODY_BYTES = 1_000_000;
const publicDirectory = fileURLToPath(new URL("./public/", import.meta.url));

const decisionRequestSchema = z
  .object({
    findingKey: z.string().min(1).max(500),
    status: z.enum(["approved", "accepted_risk"]),
    rationale: z.string().trim().max(4_000),
    selectedActionIds: z
      .array(z.string().min(1).max(200))
      .max(1_000)
      .optional(),
  })
  .strict();
const submitRequestSchema = z.object({}).strict();
const executeRequestSchema = z.object({ confirmed: z.literal(true) }).strict();
const rollbackRequestSchema = z.object({ confirmed: z.literal(true) }).strict();
const scanRequestSchema = z
  .object({ profile: z.enum(["dev", "prod"]) })
  .strict();
const artifactRequestSchema = z.object({
  profile: z.enum(["dev", "prod"]),
  artifact: z.enum(["api", "shell", "terraform"]),
  download: z.enum(["0", "1"]).optional(),
});

export interface UiServerOptions {
  report?: string;
  status: FindingStatusFilter;
  port: number;
  profile?: string;
  outputDirectory?: string;
}

export interface UiServerDependencies {
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  configurationLoader?: typeof loadActionableConfiguration;
  planExecutor?: typeof executeApiPlan;
  planRollbackExecutor?: typeof rollbackApiPlan;
  apiPlanValidator?: typeof validateApiPlan;
  productionCredentialAccessInspector?: typeof assessProductionCredentialAccess;
  terraformValidator?: typeof validateTerraformConfiguration;
  scanExecutor?: typeof executeScan;
}

export interface RunningUiServer {
  url: string;
  outputPath: string;
  close(): Promise<void>;
}

interface EnvironmentChangePackage {
  tenantDomain: string;
  plan: ApiPlan;
  apiPlanSha256: string;
  apiValidation: ApiPlanValidationResult;
  terraformValidation: TerraformValidationResult;
  terraformCoverage: TerraformCoverage;
}

interface SubmittedChangePackage {
  paths: ChangePackagePaths;
  dev: EnvironmentChangePackage;
  prod: EnvironmentChangePackage;
  prodCredentialAccess: ProductionCredentialAccessResult;
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
): void {
  securityHeaders(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(JSON.stringify(value));
}

function sendError(
  response: ServerResponse,
  status: number,
  error: unknown,
): void {
  sendJson(response, status, { error: toErrorMessage(error) });
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const data: unknown = chunk;
    if (!(typeof data === "string" || data instanceof Uint8Array)) {
      throw new Error("Request body contains unsupported data.");
    }
    const buffer = Buffer.from(data);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body is too large.");
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

function hasSession(request: IncomingMessage, token: Buffer): boolean {
  const cookie = request.headers.cookie ?? "";
  const value = cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith("checkmate_session="))
    ?.slice("checkmate_session=".length);
  if (!value) return false;
  const candidate = Buffer.from(value, "hex");
  return candidate.length === token.length && timingSafeEqual(candidate, token);
}

function validLocalRequest(request: IncomingMessage): boolean {
  return /^127\.0\.0\.1(?::\d+)?$/.test(request.headers.host ?? "");
}

function validOrigin(request: IncomingMessage): boolean {
  return request.headers.origin === `http://${request.headers.host}`;
}

export async function startUiServer(
  options: UiServerOptions,
  dependencies: UiServerDependencies = {},
): Promise<RunningUiServer> {
  const env = dependencies.env ?? process.env;
  const sensitiveValues = collectSensitiveEnvironmentValues(env);
  const now = dependencies.now ?? (() => new Date());
  const token = randomBytes(32);
  let report: Awaited<ReturnType<typeof loadCheckmateReport>> | undefined;
  let findings: NormalizedCheckmateFinding[] = [];
  let reportValidatorCount = 0;
  let profile: CheckmateConfig | undefined;
  let outputPath: string | undefined;
  let session: ReviewSession | undefined;
  let triaged = false;
  let recommendations: DeterministicRecommendation[] = [];
  const recommendationMap = new Map<string, DeterministicRecommendation>();
  let triagePromise: Promise<void> | undefined;
  let submittedPackage: SubmittedChangePackage | undefined;
  let execution: ApiExecutionResult | undefined;
  let executionHistory: ApiExecutionResult[] = [];
  let executing = false;
  let scanning = false;

  const availableProfiles = (["dev", "prod"] as const).filter((name) => {
    const definition = profiles[name];
    return Boolean(
      env[definition.domainEnv]?.trim() &&
      env[definition.clientIdEnv]?.trim() &&
      env[definition.clientSecretEnv]?.trim(),
    );
  });

  const initialiseReport = async (
    reportPath: string,
    requestedProfile?: ProfileName,
  ): Promise<void> => {
    const loaded = await loadCheckmateReport(reportPath);
    const selectedFindings = filterFindings(loaded.findings, options.status);
    if (selectedFindings.length === 0) {
      throw new Error("No findings matched the selected status.");
    }
    const startedAt = now();
    const nextOutputPath = createReviewOutputPath(
      loaded.sourcePath,
      startedAt,
      options.outputDirectory ?? path.resolve("remediation-plans"),
    );
    const nextSession: ReviewSession = {
      schemaVersion: 1,
      report: { sourceReport: loaded.sourcePath },
      review: {
        guidanceEngine: DETERMINISTIC_GUIDANCE_ENGINE,
        startedAt: startedAt.toISOString(),
        lastUpdatedAt: startedAt.toISOString(),
      },
      decisions: [],
    };
    if (loaded.tenant) nextSession.report.tenant = loaded.tenant;
    if (loaded.generatedAt) {
      nextSession.report.reportTimestamp = loaded.generatedAt;
    }
    report = loaded;
    findings = selectedFindings;
    reportValidatorCount = new Set(
      loaded.findings.map((finding) => finding.validatorId ?? finding.id),
    ).size;
    profile = resolveReviewProfile(
      requestedProfile ?? options.profile,
      loaded.sourcePath,
      env,
    );
    outputPath = nextOutputPath;
    session = nextSession;
    triaged = false;
    recommendations = [];
    recommendationMap.clear();
    triagePromise = undefined;
    submittedPackage = undefined;
    execution = undefined;
    executionHistory = [];
    executing = false;
  };

  if (options.report) {
    await initialiseReport(
      options.report,
      options.profile as ProfileName | undefined,
    );
  } else if (options.profile) {
    profile = resolveReviewProfile(options.profile, "", env);
  }

  const allDecisionsSaved = (): boolean =>
    Boolean(session) &&
    triaged &&
    recommendations.length > 0 &&
    recommendations.every((recommendation) =>
      recommendation.actions.every((action) =>
        session!.decisions.some(
          (decision) => decision.actionableChangeId === action.actionId,
        ),
      ),
    );

  const lastApplyExecution = (): ApiExecutionResult | undefined =>
    [...executionHistory]
      .reverse()
      .find((attempt) => attempt.operation === "apply");

  const rollbackAvailable = (): boolean => {
    let applyIndex = -1;
    for (let index = executionHistory.length - 1; index >= 0; index -= 1) {
      if (executionHistory[index]?.operation === "apply") {
        applyIndex = index;
        break;
      }
    }
    if (applyIndex < 0) return false;
    const applied = executionHistory[applyIndex];
    if (
      !applied?.calls.some(
        (call) =>
          call.status === "applied" ||
          call.status === "resumed_verified" ||
          call.status === "verification_failed",
      )
    ) {
      return false;
    }
    return !executionHistory
      .slice(applyIndex + 1)
      .some(
        (attempt) =>
          attempt.operation === "rollback" && attempt.status === "succeeded",
      );
  };

  const runApiValidation = async (
    plan: ApiPlan,
    config: CheckmateConfig,
    authorizationMode: "read_only" | "read_write" = "read_write",
  ): Promise<ApiPlanValidationResult> => {
    try {
      return await (dependencies.apiPlanValidator ?? validateApiPlan)(
        plan,
        config,
        { now, authorizationMode, includeRequestBodies: true },
      );
    } catch (error) {
      return {
        valid: false,
        profile: config.profile,
        validatedAt: now().toISOString(),
        calls: [],
        error: redactText(toErrorMessage(error), sensitiveValues),
      };
    }
  };

  const terraformRequestBodies = (
    validation: ApiPlanValidationResult,
  ): TerraformValidatedRequestBodies =>
    Object.fromEntries(
      validation.calls.flatMap((call) =>
        call.requestBody ? [[call.id, call.requestBody]] : [],
      ),
    );

  const withoutRequestBodies = (
    validation: ApiPlanValidationResult,
  ): ApiPlanValidationResult => ({
    ...validation,
    calls: validation.calls.map((call) => ({
      id: call.id,
      endpoint: call.endpoint,
      method: call.method,
      resourceName: call.resourceName,
      status: call.status,
      ...(call.requestSha256 ? { requestSha256: call.requestSha256 } : {}),
      ...(call.error ? { error: call.error } : {}),
    })),
  });

  const runTerraformValidation = (
    terraformFile: string,
    config: CheckmateConfig,
  ): Promise<TerraformValidationResult> =>
    (dependencies.terraformValidator ?? validateTerraformConfiguration)(
      terraformFile,
      { env, now, providerConfig: config },
    );

  const inspectProductionCredential = async (
    config: CheckmateConfig,
  ): Promise<ProductionCredentialAccessResult> => {
    try {
      return await (
        dependencies.productionCredentialAccessInspector ??
        assessProductionCredentialAccess
      )(config, { now });
    } catch {
      return {
        status: "unverified",
        checkedAt: now().toISOString(),
        writeScopes: [],
        message:
          "Production credential access could not be verified. Package creation continued; confirm that the client grant is read-only in the Auth0 Dashboard.",
      };
    }
  };

  const runTriage = async (): Promise<void> => {
    if (triaged) return;
    if (!report || !session) {
      throw new Error("Run a CheckMate scan or load a report first.");
    }
    if (!profile) {
      throw new Error(
        "A configured Auth0 profile is required to verify live settings. Start the UI with --profile dev or --profile prod.",
      );
    }
    triagePromise ??= (async () => {
      const configuration = await (
        dependencies.configurationLoader ?? loadActionableConfiguration
      )(findings, profile);
      recommendations = buildDeterministicRecommendations(
        findings,
        configuration,
      );
      recommendationMap.clear();
      for (const recommendation of recommendations) {
        recommendationMap.set(recommendation.key, recommendation);
      }
      triaged = true;
    })();
    try {
      await triagePromise;
    } catch (error) {
      triagePromise = undefined;
      throw error;
    }
  };

  const state = () => {
    const actionIdsByValidator = new Map<string, Set<string>>();
    const resolutionRequirementsByValidator = new Map<string, boolean[]>();
    for (const recommendation of recommendations) {
      const recommendationActionIds = new Map<string, string[]>();
      for (const action of recommendation.actions) {
        const validatorId = action.finding.validatorId;
        if (!validatorId) continue;
        const actionIds = actionIdsByValidator.get(validatorId) ?? new Set();
        actionIds.add(action.actionId);
        actionIdsByValidator.set(validatorId, actionIds);
        const grouped = recommendationActionIds.get(validatorId) ?? [];
        grouped.push(action.actionId);
        recommendationActionIds.set(validatorId, grouped);
      }
      for (const [validatorId, actionIds] of recommendationActionIds) {
        const approved = actionIds.filter((actionId) =>
          session?.decisions.some(
            (decision) =>
              decision.actionableChangeId === actionId &&
              decision.decision.status === "approved",
          ),
        ).length;
        const satisfied = approved === actionIds.length;
        const requirements =
          resolutionRequirementsByValidator.get(validatorId) ?? [];
        requirements.push(satisfied);
        resolutionRequirementsByValidator.set(validatorId, requirements);
      }
    }
    const projectedResolvedValidatorIds = new Set<string>();
    for (const [
      validatorId,
      requirements,
    ] of resolutionRequirementsByValidator) {
      if (requirements.length > 0 && requirements.every(Boolean)) {
        projectedResolvedValidatorIds.add(validatorId);
      }
    }
    const posture = report
      ? evaluatePosture(report.findings, {
          projectedResolvedValidatorIds,
        })
      : undefined;
    const projectedOpenControls = posture
      ? posture.projected.openControls.map(
          ({ validatorId, title, priority, points }) => ({
            title,
            importance:
              priority === "red"
                ? "High priority"
                : priority === "yellow"
                  ? "Moderate priority"
                  : "Low priority",
            points,
            guidance:
              POSTURE_REVIEW_GUIDANCE[validatorId] ??
              "Review this control against the tenant's technical and business requirements.",
            recommendationAvailable: actionIdsByValidator.has(validatorId),
          }),
        )
      : [];
    const publicPosture = posture
      ? {
          modelVersion: posture.modelVersion,
          current: {
            score: posture.current.score,
            rating: posture.current.rating,
            openControlCount: posture.current.openControls.length,
          },
          projected: {
            score: posture.projected.score,
            rating: posture.projected.rating,
            openControlCount: posture.projected.openControls.length,
            ...(triaged ? { openControls: projectedOpenControls } : {}),
          },
          delta: posture.delta,
          catalogControlCount: posture.catalogControlCount,
          passedControlCount: posture.passedControlCount,
          unscoredValidatorCount: posture.unscoredValidatorIds.length,
        }
      : undefined;
    return {
      hasReport: Boolean(report),
      scanning,
      availableProfiles,
      ...(profile ? { selectedProfile: profile.profile } : {}),
      ...(report
        ? {
            report: {
              file: path.basename(report.sourcePath),
              ...(report.tenant
                ? { tenant: redactText(report.tenant, sensitiveValues) }
                : {}),
              ...(report.generatedAt
                ? { generatedAt: report.generatedAt }
                : {}),
            },
          }
        : {}),
      submissionReady: allDecisionsSaved(),
      submitted: Boolean(submittedPackage),
      canExecute:
        Boolean(submittedPackage?.dev.plan.calls.length) &&
        submittedPackage?.dev.apiValidation.valid === true &&
        submittedPackage?.dev.terraformValidation.valid === true &&
        !(
          execution?.operation === "apply" && execution.status === "succeeded"
        ) &&
        execution?.operation !== "rollback",
      canRollback: rollbackAvailable(),
      executing,
      ...(submittedPackage
        ? {
            changePackage: {
              directory: path.basename(submittedPackage.paths.directory),
              dev: {
                tenantDomain: redactText(
                  submittedPackage.dev.tenantDomain,
                  sensitiveValues,
                ),
                apiFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.dev.apiPlan,
                ),
                shellFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.dev.shell,
                ),
                terraformFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.dev.terraform,
                ),
                plan: submittedPackage.dev.plan,
                apiPlanSha256: submittedPackage.dev.apiPlanSha256,
                apiValidation: submittedPackage.dev.apiValidation,
                terraformValidation: submittedPackage.dev.terraformValidation,
                terraformCoverage: submittedPackage.dev.terraformCoverage,
              },
              prod: {
                tenantDomain: redactText(
                  submittedPackage.prod.tenantDomain,
                  sensitiveValues,
                ),
                apiFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.prod.apiPlan,
                ),
                shellFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.prod.shell,
                ),
                terraformFile: path.relative(
                  submittedPackage.paths.directory,
                  submittedPackage.paths.prod.terraform,
                ),
                plan: submittedPackage.prod.plan,
                apiPlanSha256: submittedPackage.prod.apiPlanSha256,
                apiValidation: submittedPackage.prod.apiValidation,
                terraformValidation: submittedPackage.prod.terraformValidation,
                terraformCoverage: submittedPackage.prod.terraformCoverage,
                credentialAccess: {
                  status: submittedPackage.prodCredentialAccess.status,
                  message:
                    submittedPackage.prodCredentialAccess.status ===
                    "write_access_detected"
                      ? "Production credentials have Management API write access. Package creation continued, but these credentials should be replaced with a read-only client grant."
                      : submittedPackage.prodCredentialAccess.message,
                },
              },
            },
          }
        : {}),
      ...(execution ? { execution } : {}),
      triaged,
      reportValidatorCount,
      reportFindingCount: report?.findings.length ?? 0,
      ...(publicPosture ? { posture: publicPosture } : {}),
      progress: {
        completed: recommendations.filter((recommendation) =>
          recommendation.actions.every((action) =>
            session?.decisions.some(
              (decision) => decision.actionableChangeId === action.actionId,
            ),
          ),
        ).length,
        total: recommendations.length,
      },
      findings: recommendations.map((recommendation) => {
        const { analysis } = recommendation;
        const finding = recommendation.actions[0]!.finding;
        const impact = postureRecommendationImpact(
          finding.validatorId,
          finding.priority,
          finding.severity,
        );
        const saved = recommendation.actions.flatMap((action) => {
          const entry = session?.decisions.find(
            (decision) => decision.actionableChangeId === action.actionId,
          );
          return entry ? [entry] : [];
        });
        const reviewed = saved.length === recommendation.actions.length;
        const selectedActionIds = saved
          .filter((entry) => entry.decision.status === "approved")
          .flatMap((entry) =>
            entry.actionableChangeId ? [entry.actionableChangeId] : [],
          );
        const decision = reviewed
          ? selectedActionIds.length === 0
            ? "accepted_risk"
            : selectedActionIds.length === recommendation.actions.length
              ? "approved"
              : "mixed"
          : undefined;
        const adminNote =
          saved.find((entry) => entry.decision.status === "approved")?.decision
            .adminNote ?? saved[0]?.decision.adminNote;
        return {
          key: recommendation.key,
          title: redactText(recommendation.title, sensitiveValues),
          validatorTitle: redactText(finding.title, sensitiveValues),
          impact: impact.label,
          points: impact.points,
          ...(finding.severity
            ? { severity: redactText(finding.severity, sensitiveValues) }
            : {}),
          analysis,
          selectionMode: recommendation.selectionMode,
          defaultSelected: recommendation.defaultSelected,
          actionableChanges: recommendation.actions.map((action) => ({
            actionId: action.actionId,
            ...action.actionableChange,
          })),
          reviewed,
          selectedActionIds,
          ...(adminNote
            ? { adminNote: redactText(adminNote, sensitiveValues) }
            : {}),
          ...(decision ? { decision } : {}),
        };
      }),
    };
  };

  const server = http.createServer((request, response) => {
    void (async () => {
      if (!validLocalRequest(request)) {
        sendError(response, 403, "Only local requests are allowed.");
        return;
      }
      const url = new URL(request.url ?? "/", `http://${request.headers.host}`);

      if (request.method === "GET" && url.pathname === "/") {
        const content = await readFile(
          path.join(publicDirectory, "index.html"),
        );
        securityHeaders(response);
        response.setHeader(
          "Set-Cookie",
          `checkmate_session=${token.toString("hex")}; HttpOnly; SameSite=Strict; Path=/`,
        );
        response.setHeader("Content-Type", "text/html; charset=utf-8");
        response.end(content);
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/styles.css" || url.pathname === "/app.js")
      ) {
        const filename = url.pathname.slice(1);
        const content = await readFile(path.join(publicDirectory, filename));
        securityHeaders(response);
        response.setHeader(
          "Content-Type",
          filename.endsWith(".css")
            ? "text/css; charset=utf-8"
            : "text/javascript; charset=utf-8",
        );
        response.end(content);
        return;
      }
      if (!hasSession(request, token)) {
        sendError(
          response,
          401,
          "Open the interface from its local URL first.",
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/health") {
        sendJson(response, 200, { ok: true });
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        sendJson(response, 200, state());
        return;
      }
      if (request.method === "GET" && url.pathname === "/api/artifact") {
        if (!submittedPackage) {
          throw new Error(
            "Submit the change package before opening its files.",
          );
        }
        const parsed = artifactRequestSchema.parse({
          profile: url.searchParams.get("profile"),
          artifact: url.searchParams.get("artifact"),
          ...(url.searchParams.has("download")
            ? { download: url.searchParams.get("download") }
            : {}),
        });
        const environment = submittedPackage.paths[parsed.profile];
        const artifactPath =
          parsed.artifact === "api"
            ? environment.apiPlan
            : parsed.artifact === "shell"
              ? environment.shell
              : environment.terraform;
        const filename = `${parsed.profile}-${path.basename(artifactPath)}`;
        const content = await readFile(artifactPath);
        securityHeaders(response);
        response.setHeader(
          "Content-Type",
          parsed.artifact === "api"
            ? "application/yaml; charset=utf-8"
            : parsed.artifact === "shell"
              ? "text/x-shellscript; charset=utf-8"
              : "text/plain; charset=utf-8",
        );
        if (parsed.download === "1") {
          response.setHeader(
            "Content-Disposition",
            `attachment; filename="${filename}"`,
          );
        }
        response.end(content);
        return;
      }
      if (request.method === "POST" && !validOrigin(request)) {
        sendError(response, 403, "The request origin is not allowed.");
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/scan") {
        const parsed = scanRequestSchema.parse(await readBody(request));
        if (!availableProfiles.includes(parsed.profile)) {
          throw new Error(
            `The ${parsed.profile} Auth0 profile is not fully configured in .env.`,
          );
        }
        if (scanning) throw new Error("A CheckMate scan is already running.");
        if (executing) {
          throw new Error("Wait for API plan execution to finish first.");
        }
        scanning = true;
        try {
          const metadata = await (dependencies.scanExecutor ?? executeScan)(
            { profile: parsed.profile },
            { env },
          );
          await initialiseReport(metadata.reportPath, parsed.profile);
        } finally {
          scanning = false;
        }
        sendJson(response, 200, { scanned: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/triage") {
        await readBody(request);
        await runTriage();
        sendJson(response, 200, state());
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/decision") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        const parsed = decisionRequestSchema.parse(await readBody(request));
        const recommendation = recommendationMap.get(parsed.findingKey);
        if (!recommendation)
          throw new Error("This recommendation is not available.");
        const availableActionIds = new Set(
          recommendation.actions.map((action) => action.actionId),
        );
        const selectedActionIds =
          parsed.status === "approved"
            ? new Set(
                parsed.selectedActionIds ??
                  recommendation.actions.map((action) => action.actionId),
              )
            : new Set<string>();
        if (
          [...selectedActionIds].some(
            (actionId) => !availableActionIds.has(actionId),
          )
        ) {
          throw new Error(
            "The selected option is not part of this recommendation.",
          );
        }
        if (parsed.status === "approved" && selectedActionIds.size === 0) {
          throw new Error("Select at least one option, or remain unchanged.");
        }
        const decidedAt = now().toISOString();
        const adminNote = boundedUserText(
          parsed.rationale,
          sensitiveValues,
        ).trim();
        session.decisions = session.decisions.filter(
          (decision) =>
            !decision.actionableChangeId ||
            !availableActionIds.has(decision.actionableChangeId),
        );
        for (const action of recommendation.actions) {
          const selected = selectedActionIds.has(action.actionId);
          const entry = createReviewEntry(
            action.finding,
            recommendation.analysis,
            selected ? "approved" : "accepted_risk",
            adminNote ||
              (selected ? "Accepted suggestion." : "Remained unchanged."),
            decidedAt,
            sensitiveValues,
            [action.actionableChange],
          );
          if (adminNote) entry.decision.adminNote = adminNote;
          entry.actionableChangeId = action.actionId;
          session.decisions.push(entry);
        }
        session.review.lastUpdatedAt = decidedAt;
        if (allDecisionsSaved()) {
          session.review.completedAt = decidedAt;
        } else {
          delete session.review.completedAt;
        }
        submittedPackage = undefined;
        execution = undefined;
        executionHistory = [];
        delete session.execution;
        delete session.executionHistory;
        await writeReviewSession(outputPath, session);
        sendJson(response, 200, { saved: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/submit") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        submitRequestSchema.parse(await readBody(request));
        if (!allDecisionsSaved()) {
          throw new Error(
            "Save a decision for every recommendation before submitting.",
          );
        }
        const devConfig = loadCheckmateConfig("dev", env);
        const prodConfig = loadCheckmateConfig("prod", env);
        const configurationLoader =
          dependencies.configurationLoader ?? loadActionableConfiguration;
        let devConfiguration: ActionableConfigurationMap;
        let prodConfiguration: ActionableConfigurationMap;
        let prodCredentialAccess: ProductionCredentialAccessResult;
        const loadDevConfiguration = () =>
          configurationLoader(findings, devConfig, undefined, {
            includeCompliant: true,
          });
        const loadProdEnvironment = async () => {
          const configuration = await configurationLoader(
            findings,
            prodConfig,
            undefined,
            { includeCompliant: true },
          );
          const credentialAccess =
            await inspectProductionCredential(prodConfig);
          return { configuration, credentialAccess };
        };
        if (devConfig.domain === prodConfig.domain) {
          devConfiguration = await loadDevConfiguration();
          const prodEnvironment = await loadProdEnvironment();
          prodConfiguration = prodEnvironment.configuration;
          prodCredentialAccess = prodEnvironment.credentialAccess;
        } else {
          const [loadedDev, prodEnvironment] = await Promise.all([
            loadDevConfiguration(),
            loadProdEnvironment(),
          ]);
          devConfiguration = loadedDev;
          prodConfiguration = prodEnvironment.configuration;
          prodCredentialAccess = prodEnvironment.credentialAccess;
        }
        const generatedAt = now().toISOString();
        const devDraftPlan = buildProfileApiPlan(
          session,
          devConfiguration,
          "dev",
          generatedAt,
        );
        const prodDraftPlan = buildProfileApiPlan(
          session,
          prodConfiguration,
          "prod",
          generatedAt,
        );
        const devTerraformCoverage = terraformCoverage(devDraftPlan);
        const prodTerraformCoverage = terraformCoverage(prodDraftPlan);
        const unsupportedTerraformCalls = [
          ...devTerraformCoverage.apiOnlyCalls.map((call) => ({
            profile: "dev",
            ...call,
          })),
          ...prodTerraformCoverage.apiOnlyCalls.map((call) => ({
            profile: "prod",
            ...call,
          })),
        ];
        if (unsupportedTerraformCalls.length > 0) {
          const detail = unsupportedTerraformCalls
            .map(
              ({ profile: callProfile, resourceName }) =>
                `${callProfile}: ${resourceName}`,
            )
            .join(", ");
          throw new Error(
            `The dual-format change package cannot be created because these accepted changes do not have a safe official Auth0 Terraform mapping: ${detail}. Leave them unchanged and handle them through the documented manual change process.`,
          );
        }
        let devDraftValidation: ApiPlanValidationResult;
        let prodDraftValidation: ApiPlanValidationResult;
        if (devConfig.domain === prodConfig.domain) {
          devDraftValidation = await runApiValidation(devDraftPlan, devConfig);
          prodDraftValidation = await runApiValidation(
            prodDraftPlan,
            prodConfig,
            "read_only",
          );
        } else {
          [devDraftValidation, prodDraftValidation] = await Promise.all([
            runApiValidation(devDraftPlan, devConfig),
            runApiValidation(prodDraftPlan, prodConfig, "read_only"),
          ]);
        }
        if (!devDraftValidation.valid || !prodDraftValidation.valid) {
          const failures = [
            ...(devDraftValidation.valid
              ? []
              : [
                  `dev: ${devDraftValidation.error ?? "API validation failed"}`,
                ]),
            ...(prodDraftValidation.valid
              ? []
              : [
                  `prod: ${prodDraftValidation.error ?? "API validation failed"}`,
                ]),
          ];
          throw new Error(
            `The API change package was not created because live preflight validation failed (${failures.join("; ")}).`,
          );
        }
        const devPlan = finalizeValidatedApiPlan(
          devDraftPlan,
          devDraftValidation,
          devConfig.domain,
        );
        const prodPlan = finalizeValidatedApiPlan(
          prodDraftPlan,
          prodDraftValidation,
          prodConfig.domain,
        );
        assertValidatedApiPlan(devPlan);
        assertValidatedApiPlan(prodPlan);
        const paths = createChangePackagePaths(outputPath);
        await Promise.all([
          writeApiPlan(paths.dev.apiPlan, devPlan),
          writeApiPlan(paths.prod.apiPlan, prodPlan),
          writeTextArtifact(
            paths.dev.shell,
            buildApiPlanShellScript(devPlan),
            0o700,
          ),
          writeTextArtifact(
            paths.prod.shell,
            buildApiPlanShellScript(prodPlan),
            0o700,
          ),
          writeTextArtifact(
            paths.dev.terraform,
            buildTerraformDeploymentConfiguration(
              devPlan,
              terraformRequestBodies(devDraftValidation),
            ),
          ),
          writeTextArtifact(
            paths.prod.terraform,
            buildTerraformDeploymentConfiguration(
              prodPlan,
              terraformRequestBodies(prodDraftValidation),
            ),
          ),
        ]);
        const [devArtifact, prodArtifact] = await Promise.all([
          readApiPlan(paths.dev.apiPlan),
          readApiPlan(paths.prod.apiPlan),
        ]);
        assertValidatedApiPlan(devArtifact.plan);
        assertValidatedApiPlan(prodArtifact.plan);
        let devTerraformValidation: TerraformValidationResult;
        let prodTerraformValidation: TerraformValidationResult;
        if (devConfig.domain === prodConfig.domain) {
          devTerraformValidation = await runTerraformValidation(
            paths.dev.terraform,
            devConfig,
          );
          prodTerraformValidation = await runTerraformValidation(
            paths.prod.terraform,
            prodConfig,
          );
        } else {
          [devTerraformValidation, prodTerraformValidation] = await Promise.all(
            [
              runTerraformValidation(paths.dev.terraform, devConfig),
              runTerraformValidation(paths.prod.terraform, prodConfig),
            ],
          );
        }
        const devApiValidation = withoutRequestBodies(devDraftValidation);
        const prodApiValidation = withoutRequestBodies(prodDraftValidation);
        const invalidArtifacts = [
          ...(!devApiValidation.valid
            ? [`dev API: ${devApiValidation.error ?? "validation failed"}`]
            : []),
          ...(!prodApiValidation.valid
            ? [`prod API: ${prodApiValidation.error ?? "validation failed"}`]
            : []),
          ...(!devTerraformValidation.valid
            ? [
                `dev Terraform: ${devTerraformValidation.error ?? "validation failed"}`,
              ]
            : []),
          ...(!prodTerraformValidation.valid
            ? [
                `prod Terraform: ${prodTerraformValidation.error ?? "validation failed"}`,
              ]
            : []),
        ];
        if (invalidArtifacts.length > 0) {
          throw new Error(
            `The change package was not released because validation failed (${invalidArtifacts.join("; ")}).`,
          );
        }
        submittedPackage = {
          paths,
          dev: {
            tenantDomain: devConfig.domain,
            plan: devArtifact.plan,
            apiPlanSha256: devArtifact.sha256,
            apiValidation: devApiValidation,
            terraformValidation: devTerraformValidation,
            terraformCoverage: devTerraformCoverage,
          },
          prod: {
            tenantDomain: prodConfig.domain,
            plan: prodArtifact.plan,
            apiPlanSha256: prodArtifact.sha256,
            apiValidation: prodApiValidation,
            terraformValidation: prodTerraformValidation,
            terraformCoverage: prodTerraformCoverage,
          },
          prodCredentialAccess,
        };
        execution = undefined;
        executionHistory = [];
        delete session.execution;
        delete session.executionHistory;
        sendJson(response, 200, { created: true, state: state() });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/execute") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        executeRequestSchema.parse(await readBody(request));
        if (!submittedPackage) {
          throw new Error(
            "Submit and review the change package before executing it.",
          );
        }
        if (executing) {
          throw new Error("This API plan is already being executed.");
        }
        if (
          execution?.operation === "apply" &&
          execution.status === "succeeded"
        ) {
          throw new Error("This API plan has already been executed.");
        }
        if (execution?.operation === "rollback") {
          throw new Error(
            "Create a new change package after a rollback before applying changes again.",
          );
        }
        const devConfig = loadCheckmateConfig("dev", env);
        const devArtifact = await readApiPlan(
          submittedPackage.paths.dev.apiPlan,
        );
        assertValidatedApiPlan(devArtifact.plan);
        if (devArtifact.sha256 !== submittedPackage.dev.apiPlanSha256) {
          throw new Error(
            "Execution stopped because dev/api-plan.yml changed after review. Submit the decisions again to create and validate a new plan.",
          );
        }
        executing = true;
        try {
          try {
            execution = await (dependencies.planExecutor ?? executeApiPlan)(
              devArtifact.plan,
              devConfig,
              {
                now,
                ...(execution?.operation === "apply" &&
                execution.status === "failed"
                  ? { previousExecution: execution }
                  : {}),
              },
            );
          } catch (error) {
            const timestamp = now().toISOString();
            execution = {
              operation: "apply",
              status: "failed",
              startedAt: timestamp,
              completedAt: timestamp,
              profile: "dev",
              calls: [],
              error: redactText(toErrorMessage(error), sensitiveValues),
            };
          }
        } finally {
          executing = false;
        }
        const completedExecution = execution;
        if (!completedExecution) {
          throw new Error("The dev execution returned no result.");
        }
        executionHistory.push(completedExecution);
        const executionRecord = {
          planFile: path.relative(
            submittedPackage.paths.directory,
            submittedPackage.paths.dev.apiPlan,
          ),
          planSha256: devArtifact.sha256,
          ...completedExecution,
        };
        session.execution = executionRecord;
        session.executionHistory = [
          ...(session.executionHistory ?? []),
          executionRecord,
        ];
        session.review.lastUpdatedAt = completedExecution.completedAt;
        await writeReviewSession(outputPath, session);
        sendJson(response, 200, {
          executed: completedExecution.status === "succeeded",
          state: state(),
        });
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/rollback") {
        if (!session || !outputPath) {
          throw new Error("Run a CheckMate scan or load a report first.");
        }
        rollbackRequestSchema.parse(await readBody(request));
        if (!submittedPackage) {
          throw new Error(
            "Submit and review the change package before rolling it back.",
          );
        }
        if (executing) {
          throw new Error("Wait for the current dev operation to finish.");
        }
        const appliedExecution = lastApplyExecution();
        if (!appliedExecution || !rollbackAvailable()) {
          throw new Error("No applied dev changes are available to roll back.");
        }
        const devArtifact = await readApiPlan(
          submittedPackage.paths.dev.apiPlan,
        );
        assertValidatedApiPlan(devArtifact.plan);
        if (devArtifact.sha256 !== submittedPackage.dev.apiPlanSha256) {
          throw new Error(
            "Rollback stopped because dev/api-plan.yml changed after execution.",
          );
        }
        const devConfig = loadCheckmateConfig("dev", env);
        executing = true;
        try {
          try {
            execution = await (
              dependencies.planRollbackExecutor ?? rollbackApiPlan
            )(devArtifact.plan, devConfig, appliedExecution, { now });
          } catch (error) {
            const timestamp = now().toISOString();
            execution = {
              operation: "rollback",
              status: "failed",
              startedAt: timestamp,
              completedAt: timestamp,
              profile: "dev",
              calls: [],
              error: redactText(toErrorMessage(error), sensitiveValues),
            };
          }
        } finally {
          executing = false;
        }
        const completedRollback = execution;
        executionHistory.push(completedRollback);
        const rollbackRecord = {
          planFile: path.relative(
            submittedPackage.paths.directory,
            submittedPackage.paths.dev.apiPlan,
          ),
          planSha256: devArtifact.sha256,
          ...completedRollback,
        };
        session.execution = rollbackRecord;
        session.executionHistory = [
          ...(session.executionHistory ?? []),
          rollbackRecord,
        ];
        session.review.lastUpdatedAt = completedRollback.completedAt;
        await writeReviewSession(outputPath, session);
        sendJson(response, 200, {
          rolledBack: completedRollback.status === "succeeded",
          state: state(),
        });
        return;
      }
      sendError(response, 404, "Not found.");
    })().catch((error: unknown) => sendError(response, 400, error));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, HOST, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Unable to determine UI address.");
  return {
    url: `http://${HOST}:${address.port}`,
    get outputPath() {
      return outputPath ?? "";
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

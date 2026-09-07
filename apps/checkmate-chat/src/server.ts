import { randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import http, {
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import path from "node:path";
import { URL } from "node:url";
import type { CheckmateChatAgent } from "./chat-agent.js";
import { reportReferenceFromSummary } from "./chat-agent.js";
import type { CheckmateScanLike, ChatScanProfile } from "./checkmate-scan.js";
import type { ChatConfig } from "./config.js";
import type {
  DevRemediationLike,
  PreparedDevPlanState,
} from "./dev-remediation.js";
import type { ToolHubLike } from "./tool-hub.js";
import { safeError } from "./sanitize.js";
import {
  chatRequestSchema,
  checkmateScanRequestSchema,
  devExecuteRequestSchema,
  devPlanRequestSchema,
} from "./schema.js";
import type { ChatStatus, DevPlanPreview } from "./types.js";

const MAX_BODY_BYTES = 40_000;
const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1_000;
const SESSION_COOKIE = "checkmate_chat_sid";
const RECOMMENDATION_MAX_AGE_MS = 30 * 60 * 1_000;
const MAX_SESSION_RECOMMENDATIONS = 16;
const DEV_PLAN_MAX_AGE_MS = 10 * 60 * 1_000;

interface RecommendationContext {
  profile: "dev";
  reportId: string;
  findingIds: string[];
  createdAt: number;
}

interface StoredDevPlan {
  prepared: PreparedDevPlanState;
  preview: DevPlanPreview;
  status: "awaiting_confirmation" | "executing" | "completed";
  confirmedAt?: string;
  execution?: unknown;
}

interface Session {
  csrfToken: string;
  expiresAt: number;
  inFlight: boolean;
  recommendations: Map<string, RecommendationContext>;
  plans: Map<string, StoredDevPlan>;
  suggestedFindingIds: Set<string>;
  activeEnvironment?: {
    profile: ChatScanProfile;
    tenantDomain: string;
    reportId: string;
  };
}

interface ChatAgentLike {
  answer: CheckmateChatAgent["answer"];
}

export interface ChatServerOptions {
  config: ChatConfig;
  hub: ToolHubLike;
  agent: ChatAgentLike;
  scanner: CheckmateScanLike;
  remediation?: DevRemediationLike;
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  );
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  value: unknown,
): void {
  securityHeaders(response);
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(value));
}

function cookieValue(
  request: IncomingMessage,
  name: string,
): string | undefined {
  const cookie = request.headers.cookie;
  if (!cookie) return undefined;
  for (const pair of cookie.split(";")) {
    const [key, ...parts] = pair.trim().split("=");
    if (key === name) return decodeURIComponent(parts.join("="));
  }
  return undefined;
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new Error("Content-Type must be application/json.");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
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

function contentType(filePath: string): string {
  switch (path.extname(filePath)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

function reportCounts(
  value: unknown,
):
  | { passed: number; failed: number; warning: number; unknown: number }
  | undefined {
  if (!value || typeof value !== "object") return undefined;
  const report = (value as { report?: unknown }).report;
  if (!report || typeof report !== "object") return undefined;
  const counts = (report as { counts?: unknown }).counts;
  if (!counts || typeof counts !== "object") return undefined;
  const candidate = counts as Record<string, unknown>;
  if (
    ["passed", "failed", "warning", "unknown"].every(
      (key) => typeof candidate[key] === "number",
    )
  ) {
    return candidate as {
      passed: number;
      failed: number;
      warning: number;
      unknown: number;
    };
  }
  return undefined;
}

export function createChatServer(options: ChatServerOptions): Server {
  const { config, hub, agent, remediation, scanner } = options;
  const sessions = new Map<string, Session>();
  let scanInProgress = false;
  const allowedOrigins = new Set([
    `http://${config.host}:${config.port}`,
    `http://127.0.0.1:${config.port}`,
    `http://localhost:${config.port}`,
  ]);
  const allowedHosts = new Set([
    `${config.host}:${config.port}`,
    `127.0.0.1:${config.port}`,
    `localhost:${config.port}`,
  ]);

  function sessionFor(
    request: IncomingMessage,
    response: ServerResponse,
  ): Session {
    const now = Date.now();
    const existingId = cookieValue(request, SESSION_COOKIE);
    const existing = existingId ? sessions.get(existingId) : undefined;
    if (existing && existing.expiresAt > now) {
      existing.expiresAt = now + SESSION_MAX_AGE_MS;
      return existing;
    }
    const id = randomBytes(24).toString("base64url");
    const session: Session = {
      csrfToken: randomBytes(24).toString("base64url"),
      expiresAt: now + SESSION_MAX_AGE_MS,
      inFlight: false,
      recommendations: new Map(),
      plans: new Map(),
      suggestedFindingIds: new Set(),
    };
    sessions.set(id, session);
    response.setHeader(
      "Set-Cookie",
      `${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`,
    );
    if (sessions.size > 100) {
      for (const [sessionId, candidate] of sessions) {
        if (candidate.expiresAt <= now) sessions.delete(sessionId);
      }
    }
    return session;
  }

  async function statusResponse(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const session = sessionFor(request, response);
    const serverStatus = hub.getStatus();
    const status: ChatStatus = {
      aiProvider: config.aiProvider,
      model: config.model,
      remediationUrl: config.remediationUrl,
      checkmate: serverStatus.checkmate,
      auth0: serverStatus.auth0,
      devRemediation: {
        enabled: config.devRemediationEnabled && Boolean(remediation),
        planningEnabled: config.devPlanningEnabled && Boolean(remediation),
        profile: "dev",
        ...(config.devTenantDomain
          ? { tenantDomain: config.devTenantDomain }
          : {}),
        ...(config.devRemediationDisabledReason
          ? { disabledReason: config.devRemediationDisabledReason }
          : {}),
        confirmationRequired: true,
      },
      scanTargets: {
        dev: {
          ...config.scanTargets.dev,
          changesSupported: config.devRemediationEnabled,
        },
        prod: {
          ...config.scanTargets.prod,
          changesSupported: false,
        },
      },
      scanInProgress,
      ...(session.activeEnvironment
        ? {
            activeEnvironment: {
              ...session.activeEnvironment,
              changesSupported:
                session.activeEnvironment.profile === "dev" &&
                config.devRemediationEnabled,
            },
          }
        : {}),
    };
    try {
      const summary = session.activeEnvironment
        ? await hub.callTool("checkmate_get_report_summary", {
            reportId: session.activeEnvironment.reportId,
          })
        : undefined;
      if (summary && !summary.isError) {
        const report = reportReferenceFromSummary(summary.value);
        if (report) {
          const counts = reportCounts(summary.value);
          status.report = {
            ...report,
            ...(counts ? { counts } : {}),
          };
        }
      }
    } catch {
      // Scan controls remain available if the selected report cannot be loaded.
    }
    sendJson(response, 200, { ...status, csrfToken: session.csrfToken });
  }

  async function chatResponse(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const origin = request.headers.origin;
    if (!origin || !allowedOrigins.has(origin)) {
      sendJson(response, 403, { error: "The request origin is not allowed." });
      return;
    }
    const sessionId = cookieValue(request, SESSION_COOKIE);
    const session = sessionId ? sessions.get(sessionId) : undefined;
    if (
      !session ||
      session.expiresAt <= Date.now() ||
      request.headers["x-csrf-token"] !== session.csrfToken
    ) {
      sendJson(response, 403, { error: "Refresh the page and try again." });
      return;
    }
    if (session.inFlight) {
      sendJson(response, 409, {
        error: "Wait for the current answer before asking another question.",
      });
      return;
    }
    if (!session.activeEnvironment) {
      sendJson(response, 409, {
        error:
          "Run a new CheckMate scan for the development or production tenant before starting the conversation.",
      });
      return;
    }
    session.inFlight = true;
    try {
      const parsed = chatRequestSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        sendJson(response, 400, { error: "Enter a shorter valid question." });
        return;
      }
      const result = await agent.answer(
        parsed.data.question,
        parsed.data.history,
        {
          ...session.activeEnvironment,
          alreadySuggestedFindingIds: [...session.suggestedFindingIds],
        },
      );
      if (session.activeEnvironment.profile === "prod") {
        result.answer.actionConfirmations = [];
        delete result.remediation;
      }
      result.answer.actionConfirmations =
        result.answer.actionConfirmations.filter((confirmation) =>
          confirmation.findingIds.some(
            (findingId) => !session.suggestedFindingIds.has(findingId),
          ),
        );
      const reportId = result.evidence.report?.reportId;
      if (reportId !== session.activeEnvironment.reportId) {
        throw new Error(
          "The answer was not grounded in the selected CheckMate report.",
        );
      }
      if (
        session.activeEnvironment.profile === "dev" &&
        result.answer.actionConfirmations.length > 0
      ) {
        const planningAvailable = Boolean(
          remediation && config.devPlanningEnabled && reportId,
        );
        const actions = result.answer.actionConfirmations.map(
          (confirmation) => {
            for (const findingId of confirmation.findingIds) {
              session.suggestedFindingIds.add(findingId);
            }
            if (!planningAvailable || !reportId) {
              return {
                question: confirmation.question,
                available: false,
              };
            }
            const recommendationId = randomBytes(24).toString("base64url");
            session.recommendations.set(recommendationId, {
              profile: "dev",
              reportId,
              findingIds: [...confirmation.findingIds],
              createdAt: Date.now(),
            });
            return {
              recommendationId,
              question: confirmation.question,
              available: true,
            };
          },
        );
        while (session.recommendations.size > MAX_SESSION_RECOMMENDATIONS) {
          const oldest = session.recommendations.keys().next().value;
          if (!oldest) break;
          session.recommendations.delete(oldest);
        }
        result.remediation = { profile: "dev", actions };
      }
      const publicAnswer = {
        headline: result.answer.headline,
        sections: result.answer.sections.map((section) => ({
          title: section.title,
          items: section.items.map((item) => ({
            text: item.text,
            basis: item.basis,
          })),
        })),
        evidenceGaps: [],
        suggestedQuestions: result.answer.suggestedQuestions.map(
          (question) => question.question,
        ),
      };
      sendJson(response, 200, { ...result, answer: publicAnswer });
    } catch (error) {
      sendJson(response, 502, { error: safeError(error) });
    } finally {
      session.inFlight = false;
    }
  }

  function authenticatedSession(
    request: IncomingMessage,
    response: ServerResponse,
  ): Session | undefined {
    const origin = request.headers.origin;
    if (!origin || !allowedOrigins.has(origin)) {
      sendJson(response, 403, { error: "The request origin is not allowed." });
      return undefined;
    }
    const sessionId = cookieValue(request, SESSION_COOKIE);
    const session = sessionId ? sessions.get(sessionId) : undefined;
    if (
      !session ||
      session.expiresAt <= Date.now() ||
      request.headers["x-csrf-token"] !== session.csrfToken
    ) {
      sendJson(response, 403, { error: "Refresh the page and try again." });
      return undefined;
    }
    return session;
  }

  async function scanResponse(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const session = authenticatedSession(request, response);
    if (!session) return;
    if (session.inFlight || scanInProgress) {
      sendJson(response, 409, {
        error: "Wait for the current operation to finish before scanning.",
      });
      return;
    }
    const parsed = checkmateScanRequestSchema.safeParse(
      await readJsonBody(request),
    );
    if (!parsed.success) {
      sendJson(response, 400, { error: "Select dev or prod to scan." });
      return;
    }
    const target = config.scanTargets[parsed.data.profile];
    if (!target.configured) {
      sendJson(response, 400, {
        error: `The ${parsed.data.profile} CheckMate profile is not fully configured in .env.`,
      });
      return;
    }
    session.inFlight = true;
    scanInProgress = true;
    try {
      const scanned = await scanner.run(parsed.data.profile);
      if (
        scanned.profile !== parsed.data.profile ||
        (target.tenantDomain && scanned.tenantDomain !== target.tenantDomain)
      ) {
        throw new Error(
          "The completed CheckMate scan did not match the selected tenant.",
        );
      }
      const summary = await hub.callTool("checkmate_get_report_summary", {
        reportId: scanned.reportId,
      });
      if (summary.isError) {
        throw new Error("The new CheckMate report could not be read.");
      }
      const report = reportReferenceFromSummary(summary.value);
      if (!report || report.reportId !== scanned.reportId) {
        throw new Error(
          "The newly generated CheckMate report could not be selected.",
        );
      }
      session.activeEnvironment = {
        profile: scanned.profile,
        tenantDomain: scanned.tenantDomain,
        reportId: scanned.reportId,
      };
      session.recommendations.clear();
      session.plans.clear();
      session.suggestedFindingIds.clear();
      const counts = reportCounts(summary.value);
      sendJson(response, 200, {
        scanned: true,
        activeEnvironment: {
          ...session.activeEnvironment,
          changesSupported:
            scanned.profile === "dev" && config.devRemediationEnabled,
        },
        report: {
          ...report,
          ...(counts ? { counts } : {}),
        },
        scan: scanned,
      });
    } catch (error) {
      sendJson(response, 400, { error: safeError(error) });
    } finally {
      scanInProgress = false;
      session.inFlight = false;
    }
  }

  async function devPlanResponse(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const session = authenticatedSession(request, response);
    if (!session) return;
    if (!remediation || !config.devPlanningEnabled) {
      sendJson(response, 400, {
        error: "Dev remediation credentials are not configured.",
      });
      return;
    }
    if (session.activeEnvironment?.profile !== "dev") {
      sendJson(response, 400, {
        error: "Production tenant conversations do not support changes.",
      });
      return;
    }
    if (session.inFlight) {
      sendJson(response, 409, { error: "Another operation is in progress." });
      return;
    }
    session.inFlight = true;
    try {
      const parsed = devPlanRequestSchema.safeParse(
        await readJsonBody(request),
      );
      if (!parsed.success) {
        sendJson(response, 400, { error: "The recommendation is invalid." });
        return;
      }
      const recommendation = session.recommendations.get(
        parsed.data.recommendationId,
      );
      if (
        !recommendation ||
        recommendation.profile !== "dev" ||
        recommendation.reportId !== session.activeEnvironment.reportId ||
        Date.now() - recommendation.createdAt > RECOMMENDATION_MAX_AGE_MS
      ) {
        sendJson(response, 400, {
          error: "This recommendation expired. Ask the question again.",
        });
        return;
      }
      const prepared = await remediation.prepare(
        recommendation.reportId,
        recommendation.findingIds,
      );
      const planId = randomBytes(24).toString("base64url");
      const expiresAt = new Date(
        Date.now() + DEV_PLAN_MAX_AGE_MS,
      ).toISOString();
      const preview: DevPlanPreview = {
        ...prepared.preview,
        planId,
        expiresAt,
        executionEnabled: config.devRemediationEnabled,
      };
      session.plans.set(planId, {
        prepared,
        preview,
        status: "awaiting_confirmation",
      });
      session.recommendations.delete(parsed.data.recommendationId);
      while (session.plans.size > 3) {
        const oldest = session.plans.keys().next().value;
        if (!oldest) break;
        session.plans.delete(oldest);
      }
      await remediation.writeAudit(planId, {
        schemaVersion: 1,
        status: "awaiting_confirmation",
        preparedAt: new Date().toISOString(),
        preview,
      });
      sendJson(response, 200, { plan: preview });
    } catch (error) {
      sendJson(response, 400, { error: safeError(error) });
    } finally {
      session.inFlight = false;
    }
  }

  async function devExecuteResponse(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const session = authenticatedSession(request, response);
    if (!session) return;
    if (!remediation || !config.devRemediationEnabled) {
      sendJson(response, 400, {
        error: "Dev remediation credentials are not configured.",
      });
      return;
    }
    if (session.activeEnvironment?.profile !== "dev") {
      sendJson(response, 400, {
        error: "Production tenant conversations do not support changes.",
      });
      return;
    }
    if (session.inFlight) {
      sendJson(response, 409, { error: "Another operation is in progress." });
      return;
    }
    const parsed = devExecuteRequestSchema.safeParse(
      await readJsonBody(request),
    );
    if (!parsed.success) {
      sendJson(response, 400, {
        error: "Complete the dev confirmation exactly as shown.",
      });
      return;
    }
    const stored = session.plans.get(parsed.data.planId);
    if (!stored) {
      sendJson(response, 400, { error: "The dev plan was not found." });
      return;
    }
    if (stored.status !== "awaiting_confirmation") {
      sendJson(response, 409, {
        error: "This dev plan has already been used.",
      });
      return;
    }
    if (Date.parse(stored.preview.expiresAt) <= Date.now()) {
      sendJson(response, 400, {
        error: "This dev plan expired. Prepare a new API call.",
      });
      return;
    }
    if (
      parsed.data.planSha256 !== stored.preview.planSha256 ||
      parsed.data.tenantDomain !== stored.preview.tenantDomain
    ) {
      sendJson(response, 400, {
        error: "The confirmation does not match the reviewed dev plan.",
      });
      return;
    }
    session.inFlight = true;
    stored.status = "executing";
    stored.confirmedAt = new Date().toISOString();
    try {
      await remediation.writeAudit(stored.preview.planId, {
        schemaVersion: 1,
        status: "executing",
        confirmedAt: stored.confirmedAt,
        confirmation: {
          profile: "dev",
          tenantDomain: parsed.data.tenantDomain,
          planSha256: parsed.data.planSha256,
          confirmationText: parsed.data.confirmationText,
        },
        preview: stored.preview,
      });
      const result = await remediation.execute(stored.prepared);
      stored.status = "completed";
      stored.execution = result;
      await remediation.writeAudit(stored.preview.planId, {
        schemaVersion: 1,
        status: result.execution.status,
        confirmedAt: stored.confirmedAt,
        confirmation: {
          profile: "dev",
          tenantDomain: parsed.data.tenantDomain,
          planSha256: parsed.data.planSha256,
          confirmationText: parsed.data.confirmationText,
        },
        preview: stored.preview,
        validation: result.validation,
        execution: result.execution,
      });
      sendJson(response, 200, {
        executed: result.execution.status === "succeeded",
        profile: "dev",
        tenantDomain: stored.preview.tenantDomain,
        result: result.execution,
      });
    } catch (error) {
      stored.status = "completed";
      const message = safeError(error);
      stored.execution = { status: "failed", error: message };
      await remediation
        .writeAudit(stored.preview.planId, {
          schemaVersion: 1,
          status: "failed",
          confirmedAt: stored.confirmedAt,
          preview: stored.preview,
          error: message,
        })
        .catch(() => undefined);
      sendJson(response, 400, { executed: false, error: message });
    } finally {
      session.inFlight = false;
    }
  }

  async function staticResponse(
    pathname: string,
    response: ServerResponse,
  ): Promise<void> {
    const relative = pathname === "/" ? "index.html" : pathname.slice(1);
    const decoded = decodeURIComponent(relative);
    const filePath = path.resolve(config.publicDirectory, decoded);
    if (
      !filePath.startsWith(`${path.resolve(config.publicDirectory)}${path.sep}`)
    ) {
      sendJson(response, 404, { error: "Not found." });
      return;
    }
    try {
      const metadata = await stat(filePath);
      if (!metadata.isFile()) throw new Error("Not a file.");
      securityHeaders(response);
      response.statusCode = 200;
      response.setHeader("Content-Type", contentType(filePath));
      response.setHeader("Cache-Control", "no-cache");
      createReadStream(filePath).pipe(response);
    } catch {
      sendJson(response, 404, { error: "Not found." });
    }
  }

  return http.createServer((request, response) => {
    void (async () => {
      if (!request.headers.host || !allowedHosts.has(request.headers.host)) {
        sendJson(response, 403, { error: "The request host is not allowed." });
        return;
      }
      const url = new URL(request.url ?? "/", `http://${request.headers.host}`);
      if (request.method === "GET" && url.pathname === "/api/status") {
        await statusResponse(request, response);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/chat") {
        await chatResponse(request, response);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/scan") {
        await scanResponse(request, response);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/dev-plan") {
        await devPlanResponse(request, response);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/dev-execute") {
        await devExecuteResponse(request, response);
        return;
      }
      if (request.method === "GET" || request.method === "HEAD") {
        await staticResponse(url.pathname, response);
        return;
      }
      sendJson(response, 405, { error: "Method not allowed." });
    })().catch((error: unknown) => {
      if (!response.headersSent) {
        sendJson(response, 500, { error: safeError(error) });
      } else {
        response.destroy();
      }
    });
  });
}

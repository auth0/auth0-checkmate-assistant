import {
  findApplicationFindings,
  findTopicFindings,
  ReportRepository,
  searchFindings,
  SECURITY_TOPICS,
  toFindingView,
  type FindingStatus,
  type ReportMetadata,
  type SecurityTopic,
} from "@checkmate-assistant/core";
import { z } from "zod";
import type { McpToolDefinition } from "./types.js";

const findingStatusSchema = z.enum(["passed", "failed", "warning", "unknown"]);
const securityTopicSchema = z.enum([
  "credential_stuffing",
  "application_hardening",
  "mfa",
  "network_access",
  "password_security",
  "token_security",
]);

const reportIdSchema = z.string().max(255).optional();

const argumentSchemas = {
  checkmate_list_reports: z.object({}).passthrough(),
  checkmate_get_report_summary: z.object({ reportId: reportIdSchema }),
  checkmate_search_findings: z.object({
    reportId: reportIdSchema,
    query: z.string().max(500).optional(),
    statuses: z.array(findingStatusSchema).max(4).optional(),
    severities: z.array(z.string().max(40)).max(10).optional(),
    resource: z.string().max(300).optional(),
    limit: z.number().int().min(1).max(50).optional(),
  }),
  checkmate_get_finding: z.object({
    reportId: reportIdSchema,
    findingId: z.string().min(1).max(200),
  }),
  checkmate_get_application_posture: z.object({
    reportId: reportIdSchema,
    application: z.string().min(1).max(300),
  }),
  checkmate_get_security_topic_context: z.object({
    reportId: reportIdSchema,
    topic: securityTopicSchema,
  }),
} as const;

export type CheckmateToolName = keyof typeof argumentSchemas;

const REPORT_ID_PROPERTY = {
  type: "string",
  maxLength: 255,
  description: "CheckMate report file name. Omit for the newest valid report.",
} as const;

const TOOL_DEFINITIONS: McpToolDefinition[] = [
  {
    server: "checkmate",
    name: "checkmate_list_reports",
    description:
      "List available CheckMate JSON reports, newest first. Use this before selecting a historical report. Invalid files are reported but never loaded as evidence.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    server: "checkmate",
    name: "checkmate_get_report_summary",
    description:
      "Get status counts, provenance, freshness, and coverage caveats for a CheckMate report. Omit reportId to use the newest valid report.",
    inputSchema: {
      type: "object",
      properties: { reportId: REPORT_ID_PROPERTY },
    },
  },
  {
    server: "checkmate",
    name: "checkmate_search_findings",
    description:
      "Search normalized CheckMate findings by words, status, severity, or affected resource. The default status filter returns failed, warning, and unknown findings. Omit reportId to use the newest valid report.",
    inputSchema: {
      type: "object",
      properties: {
        reportId: REPORT_ID_PROPERTY,
        query: { type: "string", maxLength: 500 },
        statuses: {
          type: "array",
          maxItems: 4,
          items: {
            type: "string",
            enum: ["passed", "failed", "warning", "unknown"],
          },
        },
        severities: {
          type: "array",
          maxItems: 10,
          items: { type: "string", maxLength: 40 },
        },
        resource: { type: "string", maxLength: 300 },
        limit: { type: "integer", minimum: 1, maximum: 50 },
      },
    },
  },
  {
    server: "checkmate",
    name: "checkmate_get_finding",
    description:
      "Get one normalized CheckMate finding with redacted evidence. Use a findingId returned by another CheckMate tool.",
    inputSchema: {
      type: "object",
      properties: {
        reportId: REPORT_ID_PROPERTY,
        findingId: { type: "string", minLength: 1, maxLength: 200 },
      },
      required: ["findingId"],
    },
  },
  {
    server: "checkmate",
    name: "checkmate_get_application_posture",
    description:
      "Find all CheckMate results associated with an application name or client ID. This only reports what the selected report contains; it does not read live Auth0 configuration.",
    inputSchema: {
      type: "object",
      properties: {
        reportId: REPORT_ID_PROPERTY,
        application: { type: "string", minLength: 1, maxLength: 300 },
      },
      required: ["application"],
    },
  },
  {
    server: "checkmate",
    name: "checkmate_get_security_topic_context",
    description:
      "Collect CheckMate findings relevant to a supported security question, such as credential stuffing, MFA, application hardening, network access, password security, or token security.",
    inputSchema: {
      type: "object",
      properties: {
        reportId: REPORT_ID_PROPERTY,
        topic: {
          type: "string",
          enum: [
            "credential_stuffing",
            "application_hardening",
            "mfa",
            "network_access",
            "password_security",
            "token_security",
          ],
        },
      },
      required: ["topic"],
    },
  },
];

export interface CheckmateToolResult {
  isError: boolean;
  value: unknown;
}

function reportCaveats(metadata: ReportMetadata): string[] {
  const caveats: string[] = [];
  if (metadata.findingsOnly) {
    caveats.push(
      "This is a findings-only report. An absent finding does not prove that a control passed.",
    );
  }
  if (metadata.stale && metadata.freshnessWarning) {
    caveats.push(metadata.freshnessWarning);
  }
  caveats.push(
    `Ground conclusions in report ${metadata.reportId} and cite findingId values.`,
  );
  return caveats;
}

export function isCheckmateToolName(name: string): name is CheckmateToolName {
  return Object.hasOwn(argumentSchemas, name);
}

export class CheckmateReportTools {
  private readonly repository: ReportRepository;

  constructor(reportsDirectory: string) {
    this.repository = new ReportRepository({ reportsDirectory });
  }

  getTools(): McpToolDefinition[] {
    return TOOL_DEFINITIONS.map((tool) => ({ ...tool }));
  }

  async call(
    name: CheckmateToolName,
    args: Record<string, unknown>,
  ): Promise<CheckmateToolResult> {
    try {
      const value = await this.execute(name, args);
      return { isError: false, value };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error.";
      return { isError: true, value: { text: `Error: ${message}` } };
    }
  }

  private async execute(
    name: CheckmateToolName,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    switch (name) {
      case "checkmate_list_reports": {
        argumentSchemas[name].parse(args);
        const reports = await this.repository.listReports();
        return {
          reports,
          newestValidReportId: reports.find((report) => report.valid)?.reportId,
        };
      }
      case "checkmate_get_report_summary": {
        const { reportId } = argumentSchemas[name].parse(args);
        const context = await this.repository.getReport(reportId);
        return {
          report: context.metadata,
          caveats: reportCaveats(context.metadata),
        };
      }
      case "checkmate_search_findings": {
        const { reportId, query, statuses, severities, resource, limit } =
          argumentSchemas[name].parse(args);
        const context = await this.repository.getReport(reportId);
        const searchOptions: {
          query?: string;
          statuses?: FindingStatus[];
          severities?: string[];
          resource?: string;
          limit?: number;
        } = {};
        if (query !== undefined) searchOptions.query = query;
        if (statuses !== undefined) searchOptions.statuses = statuses;
        if (severities !== undefined) searchOptions.severities = severities;
        if (resource !== undefined) searchOptions.resource = resource;
        if (limit !== undefined) searchOptions.limit = limit;
        const findings = searchFindings(context.report.findings, searchOptions);
        return {
          report: context.metadata,
          resultCount: findings.length,
          findings,
          caveats: reportCaveats(context.metadata),
        };
      }
      case "checkmate_get_finding": {
        const { reportId, findingId } = argumentSchemas[name].parse(args);
        const context = await this.repository.getReport(reportId);
        const finding = context.report.findings.find(
          (candidate) => candidate.id === findingId,
        );
        if (!finding) {
          throw new Error(
            `Finding "${findingId}" does not exist in report ${context.metadata.reportId}.`,
          );
        }
        return {
          report: context.metadata,
          finding: toFindingView(finding, true),
          caveats: reportCaveats(context.metadata),
        };
      }
      case "checkmate_get_application_posture": {
        const { reportId, application } = argumentSchemas[name].parse(args);
        const context = await this.repository.getReport(reportId);
        const findings = findApplicationFindings(
          context.report.findings,
          application,
        );
        return {
          report: context.metadata,
          applicationQuery: application,
          resultCount: findings.length,
          findings,
          interpretation:
            findings.length === 0
              ? "No matching application findings were present. This does not prove the application is secure or that it exists in the tenant."
              : "Use failed and warning findings as report-grounded hardening opportunities. Confirm live configuration and business requirements before changing the application.",
          caveats: reportCaveats(context.metadata),
        };
      }
      case "checkmate_get_security_topic_context": {
        const { reportId, topic } = argumentSchemas[name].parse(args);
        const context = await this.repository.getReport(reportId);
        const typedTopic = topic as SecurityTopic;
        const definition = SECURITY_TOPICS[typedTopic];
        const findings = findTopicFindings(context.report.findings, typedTopic);
        return {
          report: context.metadata,
          topic: typedTopic,
          title: definition.title,
          purpose: definition.purpose,
          resultCount: findings.length,
          findings,
          additionalEvidenceNeeded: definition.additionalEvidenceNeeded,
          responseGuidance: [
            "Lead with failed and warning findings that directly support actionable suggestions.",
            "Do not recommend a control unless a returned CheckMate finding directly supports it.",
            "Do not claim the report proves an attack occurred or identifies its source.",
            "Ask for live logs or configuration when required evidence is missing.",
          ],
          caveats: reportCaveats(context.metadata),
        };
      }
    }
  }
}

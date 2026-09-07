import { CheckmateReportError } from "./errors.js";
import {
  rawFindingObjectSchema,
  rawReportSchema,
  type RawFindingObject,
} from "./report-schema.js";
import type {
  AffectedResource,
  CheckmatePriority,
  FindingStatus,
  NormalizedCheckmateFinding,
  NormalizedCheckmateReport,
} from "./types.js";

const CHECKMATE_PRIORITIES = new Set<CheckmatePriority>([
  "red",
  "yellow",
  "green",
  "blue",
  "violet",
]);

function normalizePriority(value: unknown): CheckmatePriority | undefined {
  if (typeof value !== "string") return undefined;
  const priority = value.trim().toLowerCase() as CheckmatePriority;
  return CHECKMATE_PRIORITIES.has(priority) ? priority : undefined;
}

const ARRAY_KEYS = [
  "findings",
  "results",
  "checks",
  "validators",
  "full_report",
  "summary",
] as const;

function record(value: unknown): RawFindingObject | undefined {
  const parsed = rawFindingObjectSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function stringValue(
  source: RawFindingObject,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number") return String(value);
  }
  return undefined;
}

function normalizeStatus(value: unknown): FindingStatus {
  if (typeof value !== "string") return "unknown";
  switch (value.toLowerCase()) {
    case "pass":
    case "passed":
    case "success":
    case "compliant":
    case "green":
      return "passed";
    case "fail":
    case "failed":
    case "error":
    case "non-compliant":
    case "non_compliant":
    case "red":
      return "failed";
    case "warn":
    case "warning":
    case "yellow":
    case "amber":
      return "warning";
    default:
      return "unknown";
  }
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

function affectedResource(
  source: RawFindingObject,
): AffectedResource | undefined {
  const nested = record(
    source.affectedResource ?? source.affected_resource ?? source.resource,
  );
  const type =
    (nested
      ? stringValue(nested, ["type", "resource_type", "kind"])
      : undefined) ?? stringValue(source, ["resource_type", "type"]);
  const id =
    (nested
      ? stringValue(nested, ["id", "resource_id", "client_id"])
      : undefined) ?? stringValue(source, ["resource_id", "client_id"]);
  const name =
    (nested ? stringValue(nested, ["name", "resource_name"]) : undefined) ??
    stringValue(source, ["resource_name", "name"]);
  const resource: AffectedResource = {};
  if (type) resource.type = type;
  if (id) resource.id = id;
  if (name) resource.name = name;

  return resource.type || resource.id || resource.name ? resource : undefined;
}

function evidence(source: RawFindingObject): unknown {
  if (source.evidence !== undefined) return source.evidence;
  const selected = Object.fromEntries(
    ["field", "value", "vulnFindings", "pre_requisites"]
      .filter((key) => source[key] !== undefined)
      .map((key) => [key, source[key]]),
  );
  return Object.keys(selected).length > 0 ? selected : undefined;
}

function normalizeOne(
  source: RawFindingObject,
  index: number,
  parent?: RawFindingObject,
): NormalizedCheckmateFinding {
  const validatorId =
    stringValue(source, [
      "validatorId",
      "validator_id",
      "finding_name",
      "checkId",
    ]) ??
    (parent
      ? stringValue(parent, [
          "validatorId",
          "validator_id",
          "finding_name",
          "name",
        ])
      : undefined);
  const title =
    stringValue(source, ["finding_title", "title"]) ??
    (parent ? stringValue(parent, ["finding_title", "title"]) : undefined) ??
    validatorId ??
    "Untitled CheckMate finding";
  const explicitStatus = normalizeStatus(source.status ?? parent?.status);
  const knownFlatFinding =
    source.finding_name !== undefined && source.message !== undefined;
  const status =
    explicitStatus === "unknown" && knownFlatFinding
      ? "failed"
      : explicitStatus;
  const resource = affectedResource(source);
  const field = stringValue(source, ["field"]);
  const explicitId = stringValue(source, ["id", "finding_id"]);
  const generatedId = [validatorId, field, resource?.id ?? resource?.name]
    .filter(Boolean)
    .join(":");
  const generatedPrefix = slug(generatedId).slice(0, 72).replace(/-$/g, "");
  const id = explicitId
    ? slug(explicitId) || `finding-${index + 1}`
    : `${generatedPrefix || "finding"}-${index + 1}`;
  const severity =
    stringValue(source, ["severity"]) ??
    (parent ? stringValue(parent, ["severity"]) : undefined);
  const description =
    stringValue(source, ["description", "message"]) ??
    (parent ? stringValue(parent, ["description"]) : undefined);
  const recommendation =
    stringValue(source, ["recommendation", "advisory"]) ??
    (parent ? stringValue(parent, ["recommendation", "advisory"]) : undefined);
  const finding: NormalizedCheckmateFinding = {
    id,
    title,
    status,
    raw: source,
  };

  const priority = normalizePriority(parent?.status ?? source.status);
  if (priority) finding.priority = priority;

  if (validatorId) finding.validatorId = validatorId;
  if (severity) finding.severity = severity;
  if (description) finding.description = description;
  if (recommendation) finding.recommendation = recommendation;
  if (resource) finding.affectedResource = resource;
  const findingEvidence = evidence(source);
  if (findingEvidence !== undefined) finding.evidence = findingEvidence;
  return finding;
}

function extractItems(raw: unknown): {
  items: unknown[];
  envelope?: RawFindingObject;
} {
  if (Array.isArray(raw)) return { items: raw };
  const envelope = record(raw);
  if (!envelope) {
    throw new CheckmateReportError(
      "UNSUPPORTED_REPORT",
      "Unsupported CheckMate report structure.",
    );
  }
  for (const key of ARRAY_KEYS) {
    if (Array.isArray(envelope[key])) return { items: envelope[key], envelope };
  }
  throw new CheckmateReportError(
    "UNSUPPORTED_REPORT",
    `Unsupported CheckMate report structure. Expected an array or one of: ${ARRAY_KEYS.join(", ")}.`,
  );
}

export function normalizeCheckmateReport(
  raw: unknown,
): NormalizedCheckmateReport {
  const parsed = rawReportSchema.safeParse(raw);
  if (!parsed.success) {
    throw new CheckmateReportError(
      "UNSUPPORTED_REPORT",
      "Unsupported CheckMate report structure.",
    );
  }

  const { items, envelope } = extractItems(parsed.data);
  const findings: NormalizedCheckmateFinding[] = [];
  let flattenedIndex = 0;
  for (const item of items) {
    const parent = record(item);
    if (!parent) {
      throw new CheckmateReportError(
        "UNSUPPORTED_REPORT",
        "Unsupported CheckMate report structure: each finding must be an object.",
      );
    }

    if (Array.isArray(parent.details)) {
      for (const detail of parent.details) {
        const detailRecord = record(detail);
        if (!detailRecord) {
          throw new CheckmateReportError(
            "UNSUPPORTED_REPORT",
            "Unsupported CheckMate report structure: finding details must be objects.",
          );
        }
        findings.push(normalizeOne(detailRecord, flattenedIndex++, parent));
      }
    } else {
      findings.push(normalizeOne(parent, flattenedIndex++));
    }
  }

  const tenant = envelope
    ? stringValue(envelope, ["tenant", "domain", "auth0Domain", "auth0_domain"])
    : undefined;
  const generatedAt = envelope
    ? stringValue(envelope, [
        "generatedAt",
        "generated_at",
        "timestamp",
        "date",
      ])
    : undefined;
  const report: NormalizedCheckmateReport = {
    findings,
    raw,
    findingsOnly: findings.every((finding) => finding.status !== "passed"),
  };
  if (tenant) report.tenant = tenant;
  if (generatedAt) report.generatedAt = generatedAt;
  return report;
}

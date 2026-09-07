import type {
  CheckmatePriority,
  FindingStatus,
  NormalizedCheckmateFinding,
} from "./types.js";
import { redactSensitive } from "./redaction.js";
import { isAutoRemediableFinding } from "./remediation-support.js";

export interface FindingView {
  findingId: string;
  validatorId?: string;
  title: string;
  status: FindingStatus;
  autoRemediable: boolean;
  priority?: CheckmatePriority;
  severity?: string;
  description?: string;
  recommendation?: string;
  affectedResource?: {
    type?: string;
    id?: string;
    name?: string;
  };
  evidence?: unknown;
}

export interface SearchOptions {
  query?: string;
  statuses?: FindingStatus[];
  severities?: string[];
  resource?: string;
  limit?: number;
}

export type SecurityTopic =
  | "credential_stuffing"
  | "application_hardening"
  | "mfa"
  | "network_access"
  | "password_security"
  | "token_security";

interface TopicDefinition {
  title: string;
  purpose: string;
  patterns: RegExp[];
  additionalEvidenceNeeded: string[];
}

export const SECURITY_TOPICS: Record<SecurityTopic, TopicDefinition> = {
  credential_stuffing: {
    title: "Credential-stuffing resilience",
    purpose:
      "Find CheckMate results related to preventing, detecting, and limiting automated use of compromised credentials.",
    patterns: [
      /credential.?stuff/i,
      /breached password/i,
      /brute.?force/i,
      /attack protection/i,
      /suspicious ip/i,
      /bot detection/i,
      /multi.?factor|\bmfa\b/i,
      /password policy|password complexity/i,
    ],
    additionalEvidenceNeeded: [
      "Recent Auth0 logs showing attack-protection events, affected applications, source networks, and outcomes.",
      "Current live attack-protection configuration if the report is findings-only or stale.",
      "Application traffic patterns and acceptable user-friction requirements.",
    ],
  },
  application_hardening: {
    title: "Application hardening",
    purpose:
      "Find CheckMate results related to application protocols, grants, origins, URLs, tokens, and signing configuration.",
    patterns: [
      /application|\bclient\b/i,
      /grant type|implicit grant/i,
      /cross.?origin/i,
      /callback|logout url|allowed origin/i,
      /jwt|signing|rs256|hs256/i,
      /token lifetime|token expir/i,
      /oidc|oauth/i,
    ],
    additionalEvidenceNeeded: [
      "The application's type, authentication flow, owners, and business requirements.",
      "Current live application configuration when the report does not include passed checks.",
      "Authentication test results before and after any approved change.",
    ],
  },
  mfa: {
    title: "Multi-factor authentication",
    purpose:
      "Find CheckMate results related to MFA enrollment and enforcement.",
    patterns: [/multi.?factor|\bmfa\b/i, /guardian|authenticator/i],
    additionalEvidenceNeeded: [
      "The populations and authentication flows that must be covered by MFA.",
      "Current Actions, rules, policies, and organization-level enforcement logic.",
    ],
  },
  network_access: {
    title: "Network access controls",
    purpose:
      "Find CheckMate results related to ACLs, allowlists, origins, and network restrictions.",
    patterns: [
      /network (acl|access control|allowlist)/i,
      /ip (allowlist|restriction|filter)/i,
      /cross.?origin|allowed origin|cors/i,
    ],
    additionalEvidenceNeeded: [
      "Approved source networks, operational access paths, and break-glass requirements.",
      "Current tenant and application network configuration.",
    ],
  },
  password_security: {
    title: "Password security",
    purpose:
      "Find CheckMate results related to password strength, breached passwords, and database connections.",
    patterns: [
      /password policy|password complexity|password length/i,
      /breached password/i,
      /brute.?force/i,
      /database connection|databases? -/i,
    ],
    additionalEvidenceNeeded: [
      "Current database-connection password policy and attack-protection configuration.",
      "User migration and support constraints for stronger password controls.",
    ],
  },
  token_security: {
    title: "Token security",
    purpose:
      "Find CheckMate results related to token lifetime, grants, signing, and cryptographic algorithms.",
    patterns: [
      /token (lifetime|expiration|expiry)/i,
      /jwt|signing algorithm|rs256|hs256/i,
      /implicit grant|grant type/i,
      /refresh token/i,
    ],
    additionalEvidenceNeeded: [
      "Application session requirements and current token consumers.",
      "Current live client and resource-server configuration.",
    ],
  },
};

function searchableText(finding: NormalizedCheckmateFinding): string {
  return [
    finding.id,
    finding.validatorId,
    finding.title,
    finding.status,
    finding.severity,
    finding.description,
    finding.recommendation,
    finding.affectedResource?.type,
    finding.affectedResource?.id,
    finding.affectedResource?.name,
    finding.evidence === undefined
      ? undefined
      : JSON.stringify(redactSensitive(finding.evidence)),
  ]
    .filter((value): value is string => Boolean(value))
    .join(" ")
    .toLowerCase();
}

function tokens(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 1);
}

function severityScore(severity: string | undefined): number {
  switch (severity?.toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
    case "informational":
      return 1;
    default:
      return 0;
  }
}

function statusScore(status: FindingStatus): number {
  switch (status) {
    case "failed":
      return 4;
    case "warning":
      return 3;
    case "unknown":
      return 2;
    case "passed":
      return 1;
  }
}

export function toFindingView(
  finding: NormalizedCheckmateFinding,
  includeEvidence = false,
): FindingView {
  const view: FindingView = {
    findingId: finding.id,
    title: finding.title,
    status: finding.status,
    autoRemediable: isAutoRemediableFinding(finding),
  };
  if (finding.validatorId) view.validatorId = finding.validatorId;
  if (finding.priority) view.priority = finding.priority;
  if (finding.severity) view.severity = finding.severity;
  if (finding.description) view.description = finding.description;
  if (finding.recommendation) view.recommendation = finding.recommendation;
  if (finding.affectedResource) {
    view.affectedResource = { ...finding.affectedResource };
  }
  if (includeEvidence && finding.evidence !== undefined) {
    view.evidence = redactSensitive(finding.evidence);
  }
  return view;
}

export function searchFindings(
  findings: readonly NormalizedCheckmateFinding[],
  options: SearchOptions,
): FindingView[] {
  const queryTokens = options.query ? tokens(options.query) : [];
  const resourceQuery = options.resource?.trim().toLowerCase();
  const severitySet = options.severities
    ? new Set(options.severities.map((severity) => severity.toLowerCase()))
    : undefined;
  const statusSet = options.statuses
    ? new Set(options.statuses)
    : new Set<FindingStatus>(["failed", "warning", "unknown"]);
  const limit = Math.min(Math.max(options.limit ?? 20, 1), 50);

  return findings
    .map((finding, index) => {
      const text = searchableText(finding);
      const queryScore = queryTokens.reduce(
        (score, token) => score + (text.includes(token) ? 1 : 0),
        0,
      );
      const resourceText = [
        finding.affectedResource?.name,
        finding.affectedResource?.id,
        finding.affectedResource?.type,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return { finding, index, queryScore, resourceText };
    })
    .filter(({ finding, queryScore, resourceText }) => {
      if (!statusSet.has(finding.status)) return false;
      if (
        severitySet &&
        !severitySet.has(finding.severity?.toLowerCase() ?? "unknown")
      ) {
        return false;
      }
      if (resourceQuery && !resourceText.includes(resourceQuery)) return false;
      return queryTokens.length === 0 || queryScore > 0;
    })
    .sort((left, right) => {
      const queryDifference = right.queryScore - left.queryScore;
      if (queryDifference !== 0) return queryDifference;
      const statusDifference =
        statusScore(right.finding.status) - statusScore(left.finding.status);
      if (statusDifference !== 0) return statusDifference;
      const severityDifference =
        severityScore(right.finding.severity) -
        severityScore(left.finding.severity);
      return severityDifference || left.index - right.index;
    })
    .slice(0, limit)
    .map(({ finding }) => toFindingView(finding));
}

export function findApplicationFindings(
  findings: readonly NormalizedCheckmateFinding[],
  application: string,
): FindingView[] {
  const query = application.trim().toLowerCase();
  if (!query) return [];
  return findings
    .filter((finding) => {
      const resource = [
        finding.affectedResource?.name,
        finding.affectedResource?.id,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return resource.includes(query);
    })
    .sort((left, right) => {
      const statusDifference =
        statusScore(right.status) - statusScore(left.status);
      return (
        statusDifference ||
        severityScore(right.severity) - severityScore(left.severity)
      );
    })
    .map((finding) => toFindingView(finding));
}

export function findTopicFindings(
  findings: readonly NormalizedCheckmateFinding[],
  topic: SecurityTopic,
): FindingView[] {
  const definition = SECURITY_TOPICS[topic];
  return findings
    .filter((finding) => {
      const text = searchableText(finding);
      return definition.patterns.some((pattern) => pattern.test(text));
    })
    .sort((left, right) => {
      const statusDifference =
        statusScore(right.status) - statusScore(left.status);
      return (
        statusDifference ||
        severityScore(right.severity) - severityScore(left.severity)
      );
    })
    .map((finding) => toFindingView(finding));
}

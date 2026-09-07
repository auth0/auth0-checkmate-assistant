export type FindingStatus = "passed" | "failed" | "warning" | "unknown";
export type CheckmatePriority = "red" | "yellow" | "green" | "blue" | "violet";

export interface AffectedResource {
  type?: string;
  id?: string;
  name?: string;
}

export interface NormalizedCheckmateFinding {
  id: string;
  validatorId?: string;
  title: string;
  status: FindingStatus;
  priority?: CheckmatePriority;
  severity?: string;
  description?: string;
  recommendation?: string;
  affectedResource?: AffectedResource;
  evidence?: unknown;
  raw: unknown;
}

export interface NormalizedCheckmateReport {
  tenant?: string;
  generatedAt?: string;
  findings: NormalizedCheckmateFinding[];
  raw: unknown;
  findingsOnly: boolean;
}

export interface LoadedCheckmateReport extends NormalizedCheckmateReport {
  sourcePath: string;
}

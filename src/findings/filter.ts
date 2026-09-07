import type { FindingStatus, NormalizedCheckmateFinding } from "./types.js";

export type FindingStatusFilter = FindingStatus | "all";

export function filterFindings(
  findings: readonly NormalizedCheckmateFinding[],
  status: FindingStatusFilter,
): NormalizedCheckmateFinding[] {
  return status === "all"
    ? [...findings]
    : findings.filter((finding) => finding.status === status);
}

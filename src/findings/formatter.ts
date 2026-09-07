import type { NormalizedCheckmateFinding } from "./types.js";

function compact(value: string, maximum = 140): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length > maximum
    ? `${singleLine.slice(0, maximum - 1)}…`
    : singleLine;
}

export function formatFinding(
  finding: NormalizedCheckmateFinding,
  index: number,
): string {
  const lines = [`${index + 1}. ${finding.title}`];
  if (finding.validatorId) lines.push(`   Validator: ${finding.validatorId}`);
  lines.push(`   Status: ${finding.status}`);
  if (finding.severity) lines.push(`   Severity: ${finding.severity}`);
  if (finding.affectedResource) {
    const parts = [
      finding.affectedResource.type,
      finding.affectedResource.name,
      finding.affectedResource.id,
    ].filter((part): part is string => Boolean(part));
    if (parts.length > 0) lines.push(`   Resource: ${parts.join(" / ")}`);
  }
  if (finding.recommendation) {
    lines.push(`   Recommendation: ${compact(finding.recommendation)}`);
  }
  return lines.join("\n");
}

export function formatFindings(
  findings: readonly NormalizedCheckmateFinding[],
): string {
  if (findings.length === 0) return "No findings matched the selected status.";
  return findings.map(formatFinding).join("\n\n");
}

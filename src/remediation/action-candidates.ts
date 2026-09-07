import { createHash } from "node:crypto";
import type { ActionableChange } from "./actionable-change.js";

export interface ActionCandidate {
  actionId: string;
  findingId: string;
  change: ActionableChange;
}

function signature(change: ActionableChange): string {
  return JSON.stringify([
    change.resourceType,
    change.resourceId,
    change.configPath,
    change.targetValue,
  ]);
}

export function buildActionCandidates(
  configuration: ReadonlyMap<string, readonly ActionableChange[]>,
): ActionCandidate[] {
  const seen = new Set<string>();
  const candidates: ActionCandidate[] = [];
  for (const [findingId, changes] of configuration) {
    for (const change of changes) {
      const actionSignature = signature(change);
      if (seen.has(actionSignature)) continue;
      seen.add(actionSignature);
      const digest = createHash("sha256")
        .update(`${findingId}|${actionSignature}`)
        .digest("hex")
        .slice(0, 20);
      candidates.push({
        actionId: `action-${digest}`,
        findingId,
        change,
      });
    }
  }
  return candidates;
}

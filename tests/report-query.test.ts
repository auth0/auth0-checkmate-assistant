import { describe, expect, it } from "vitest";
import type { NormalizedCheckmateFinding } from "@checkmate-assistant/core";
import {
  findApplicationFindings,
  findTopicFindings,
  isAutoRemediableFinding,
  searchFindings,
  toFindingView,
} from "@checkmate-assistant/core";

const findings: NormalizedCheckmateFinding[] = [
  {
    id: "breached-password",
    validatorId: "checkBreachedPasswordDetection",
    title: "Attack Protection - Breached Password Detection",
    status: "failed",
    severity: "High",
    description: "Breached password detection is disabled.",
    recommendation: "Enable breached password detection and blocking shields.",
    evidence: {
      enabled: false,
      client_secret: "must-not-leak",
    },
    raw: {},
  },
  {
    id: "implicit-example-spa",
    validatorId: "checkGrantTypes",
    title: "Application Grant Types",
    status: "warning",
    severity: "Medium",
    description: "Implicit grant is enabled.",
    affectedResource: {
      type: "application",
      id: "client-123",
      name: "Example SPA",
    },
    raw: {},
  },
  {
    id: "jwt-example-spa",
    validatorId: "checkJwtAlgorithm",
    title: "JWT signing algorithm",
    status: "passed",
    affectedResource: {
      type: "application",
      id: "client-123",
      name: "Example SPA",
    },
    raw: {},
  },
];

describe("report queries", () => {
  it("searches non-passing findings by default and ranks matches", () => {
    expect(searchFindings(findings, { query: "breached password" })).toEqual([
      expect.objectContaining({ findingId: "breached-password" }),
    ]);
  });

  it("returns all report results associated with an application", () => {
    expect(findApplicationFindings(findings, "client-123")).toEqual([
      expect.objectContaining({ findingId: "implicit-example-spa" }),
      expect.objectContaining({ findingId: "jwt-example-spa" }),
    ]);
  });

  it("collects credential-stuffing controls without inventing findings", () => {
    const result = findTopicFindings(findings, "credential_stuffing");
    expect(result).toEqual([
      expect.objectContaining({ findingId: "breached-password" }),
    ]);
  });

  it("redacts sensitive evidence returned for a detailed finding", () => {
    const result = toFindingView(findings[0]!, true);
    expect(result.evidence).toEqual({
      enabled: false,
      client_secret: "[REDACTED]",
    });
  });

  it("marks findings the deterministic mapping supports as autoRemediable", () => {
    const views = findApplicationFindings(findings, "Example SPA");
    expect(views.map((view) => [view.findingId, view.autoRemediable])).toEqual([
      ["implicit-example-spa", true],
      ["jwt-example-spa", false],
    ]);
    expect(isAutoRemediableFinding({ validatorId: "checkBruteForce" })).toBe(
      true,
    );
    expect(isAutoRemediableFinding({ validatorId: "checkCustomDomain" })).toBe(
      false,
    );
    expect(isAutoRemediableFinding({})).toBe(false);
  });
});

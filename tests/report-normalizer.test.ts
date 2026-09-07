import { describe, expect, it } from "vitest";
import { normalizeCheckmateReport } from "../src/checkmate/report-normalizer.js";

describe("CheckMate report normalisation", () => {
  it("flattens the official grouped summary format and preserves raw details", () => {
    const detail = {
      name: "Customer database",
      status: "red",
      field: "password_min_length_fail",
      value: 8,
      message: "Minimum length is below the recommendation.",
    };
    const report = normalizeCheckmateReport([
      {
        name: "checkPasswordComplexity",
        title: "Databases - Password Complexity",
        description: "Checks password settings.",
        status: "red",
        severity: "High",
        advisory: "Increase the minimum password length.",
        details: [detail],
      },
    ]);

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({
      validatorId: "checkPasswordComplexity",
      title: "Databases - Password Complexity",
      status: "failed",
      priority: "red",
      severity: "High",
      recommendation: "Increase the minimum password length.",
      affectedResource: { name: "Customer database" },
      raw: detail,
    });
  });

  it("preserves parent CheckMate priority when detail status differs", () => {
    const report = normalizeCheckmateReport([
      {
        name: "checkPasswordHistory",
        title: "Databases - Password History",
        status: "green",
        severity: "Low",
        details: [
          {
            name: "Customer database",
            status: "red",
            field: "password_history_disabled",
          },
        ],
      },
    ]);

    expect(report.findings[0]).toMatchObject({
      validatorId: "checkPasswordHistory",
      status: "failed",
      priority: "green",
      severity: "Low",
    });
  });

  it("normalises the documented flat finding format", () => {
    const report = normalizeCheckmateReport([
      {
        finding_name: "checkGrantTypes",
        finding_title: "Application Grant Types",
        severity: "High",
        name: "Example SPA",
        field: "unexpected_grant_type_for_app_type",
        value: "implicit",
        message: "Unexpected grant type enabled.",
      },
    ]);

    expect(report.findings[0]).toMatchObject({
      validatorId: "checkGrantTypes",
      title: "Application Grant Types",
      status: "failed",
      affectedResource: { name: "Example SPA" },
    });
  });

  it("keeps long flattened finding IDs unique", () => {
    const shared = {
      finding_name: "checkAllowedCallbacks",
      finding_title: "Application Allowed Callbacks",
      severity: "High",
      name: "Assistant0 (report_client_12345678) (First-Party Application)",
      field: "insecure_callbacks",
      message: "An insecure callback URL is allowed.",
    };
    const report = normalizeCheckmateReport([
      { ...shared, value: "http://localhost:3000/auth/callback" },
      { ...shared, value: "http://localhost:4000/auth/callback" },
    ]);

    expect(report.findings[0]?.id).not.toBe(report.findings[1]?.id);
    expect(report.findings.map((finding) => finding.id)).toEqual([
      expect.stringMatching(/-1$/),
      expect.stringMatching(/-2$/),
    ]);
  });

  it("accepts wrapped reports and unknown fields", () => {
    const report = normalizeCheckmateReport({
      tenant: "tenant.example.auth0.com",
      generated_at: "2026-07-10T00:00:00.000Z",
      findings: [
        {
          id: "one",
          title: "Known title",
          status: "warning",
          future_field: true,
        },
      ],
    });
    expect(report.tenant).toBe("tenant.example.auth0.com");
    expect(report.findings[0]?.status).toBe("warning");
  });

  it("rejects unsupported report structures", () => {
    expect(() => normalizeCheckmateReport({ unrelated: "data" })).toThrow(
      "Unsupported CheckMate report structure",
    );
    expect(() => normalizeCheckmateReport(["not-an-object"])).toThrow(
      "each finding must be an object",
    );
  });

  it("accepts an empty findings-only report without inventing passed checks", () => {
    const report = normalizeCheckmateReport([]);
    expect(report.findings).toEqual([]);
    expect(report.findingsOnly).toBe(true);
  });
});

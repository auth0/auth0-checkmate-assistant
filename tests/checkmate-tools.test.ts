import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CheckmateReportTools } from "../apps/checkmate-chat/src/checkmate-tools.js";

async function toolsWithReport(): Promise<CheckmateReportTools> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-tools-"));
  await writeFile(
    path.join(directory, "report.json"),
    JSON.stringify([
      {
        finding_name: "checkBreachedPasswordDetection",
        finding_title: "Breached Password Detection",
        severity: "High",
        name: "Tenant attack protection",
        message: "Breached password detection is disabled.",
      },
    ]),
  );
  return new CheckmateReportTools(directory);
}

describe("in-process CheckMate report tools", () => {
  it("advertises the six read-only report tools", async () => {
    const tools = await toolsWithReport();
    expect(tools.getTools().map((tool) => tool.name)).toEqual([
      "checkmate_list_reports",
      "checkmate_get_report_summary",
      "checkmate_search_findings",
      "checkmate_get_finding",
      "checkmate_get_application_posture",
      "checkmate_get_security_topic_context",
    ]);
    for (const tool of tools.getTools()) {
      expect(tool.server).toBe("checkmate");
      expect(tool.inputSchema).toMatchObject({ type: "object" });
    }
  });

  it("collects security-topic context from the report", async () => {
    const tools = await toolsWithReport();
    const result = await tools.call("checkmate_get_security_topic_context", {
      topic: "credential_stuffing",
    });
    expect(result.isError).toBe(false);
    expect(result.value).toMatchObject({
      topic: "credential_stuffing",
      resultCount: 1,
      findings: [
        expect.objectContaining({
          validatorId: "checkBreachedPasswordDetection",
          autoRemediable: false,
        }),
      ],
    });
    const value = result.value as { caveats: string[] };
    expect(value.caveats.some((caveat) => caveat.includes("report.json"))).toBe(
      true,
    );
  });

  it("binds lookups to the requested report ID", async () => {
    const tools = await toolsWithReport();
    const summary = await tools.call("checkmate_get_report_summary", {
      reportId: "report.json",
    });
    expect(summary.isError).toBe(false);
    const summaryValue = summary.value as { report: { reportId: string } };
    expect(summaryValue.report.reportId).toBe("report.json");
    const missing = await tools.call("checkmate_get_report_summary", {
      reportId: "absent.json",
    });
    expect(missing.isError).toBe(true);
    const missingValue = missing.value as { text: string };
    expect(missingValue.text).toContain("Unknown reportId");
  });

  it("returns an error result for invalid arguments", async () => {
    const tools = await toolsWithReport();
    const result = await tools.call("checkmate_get_finding", {});
    expect(result.isError).toBe(true);
  });
});

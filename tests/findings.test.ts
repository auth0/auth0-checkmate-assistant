import { describe, expect, it } from "vitest";
import { filterFindings } from "../src/findings/filter.js";
import type { NormalizedCheckmateFinding } from "../src/findings/types.js";

const findings: NormalizedCheckmateFinding[] = [
  { id: "1", title: "Failed", status: "failed", raw: {} },
  { id: "2", title: "Warning", status: "warning", raw: {} },
  { id: "3", title: "Passed", status: "passed", raw: {} },
  { id: "4", title: "Unknown", status: "unknown", raw: {} },
];

describe("findings", () => {
  it("filters by status or returns all", () => {
    expect(filterFindings(findings, "failed").map((item) => item.id)).toEqual([
      "1",
    ]);
    expect(filterFindings(findings, "all")).toHaveLength(4);
  });
});

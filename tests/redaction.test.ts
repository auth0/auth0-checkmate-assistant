import { describe, expect, it } from "vitest";
import {
  REDACTED,
  redactSensitive,
  redactText,
} from "../src/security/redaction.js";

describe("secret redaction", () => {
  it("redacts sensitive keys recursively", () => {
    expect(
      redactSensitive({
        client_secret: "secret-value",
        nested: { authorization: "Bearer token", name: "safe" },
        apiKey: "key-value",
      }),
    ).toEqual({
      client_secret: REDACTED,
      nested: { authorization: REDACTED, name: "safe" },
      apiKey: REDACTED,
    });
  });

  it("redacts known values from process output", () => {
    expect(redactText("failure for secret-value", ["secret-value"])).toBe(
      `failure for ${REDACTED}`,
    );
  });

  it("redacts credential-shaped values that a child process might emit", () => {
    expect(
      redactText(
        "authorization: Bearer abc.def.ghi token=opaque-value jwt eyJhbGci.eyJzdWI.signature",
      ),
    ).not.toMatch(/abc\.def|opaque-value|eyJhbGci/);
  });
});

import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ChatConfig } from "../apps/checkmate-chat/src/config.js";
import { AUTH0_READ_ONLY_TOOLS } from "../apps/checkmate-chat/src/config.js";
import { ToolHub } from "../apps/checkmate-chat/src/tool-hub.js";

const fixture = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/fake-auth0-mcp.mjs",
);

function config(): ChatConfig {
  return {
    projectRoot: path.resolve("."),
    publicDirectory: path.resolve("apps/checkmate-chat/public"),
    reportsDirectory: path.resolve("reports"),
    host: "127.0.0.1",
    port: 4320,
    aiProvider: "openai",
    model: "gpt-5.5",
    reasoningEffort: "high",
    aiApiKey: "test-key",
    aiTimeoutMs: 180_000,
    remediationUrl: "http://127.0.0.1:4317",
    auth0Enabled: true,
    auth0Command: process.execPath,
    auth0Arguments: [fixture],
    scanTargets: { dev: { configured: false }, prod: { configured: false } },
    devPlanningEnabled: false,
    devRemediationEnabled: false,
  };
}

describe("official Auth0 MCP integration boundary", () => {
  it("connects over stdio, exposes only the read allowlist, and calls a read tool", async () => {
    const hub = new ToolHub(config());
    try {
      await hub.initialize();

      expect(hub.getStatus().auth0).toMatchObject({
        enabled: true,
        connected: true,
        readOnly: true,
      });
      expect(
        hub
          .getTools()
          .filter((tool) => tool.server === "auth0")
          .map((tool) => tool.name)
          .sort(),
      ).toEqual([...AUTH0_READ_ONLY_TOOLS].sort());

      const result = await hub.callTool("auth0_list_applications", {});
      expect(result).toMatchObject({
        server: "auth0",
        tool: "auth0_list_applications",
        isError: false,
        value: {
          called: "auth0_list_applications",
          applications: [
            { name: "Test application", client_id: "test-client" },
          ],
        },
      });

      await expect(
        hub.callTool("auth0_update_application", {}),
      ).rejects.toThrow("not on the chatbot read-only allowlist");
    } finally {
      await hub.close();
    }
    expect(hub.getStatus().auth0).toMatchObject({
      connected: false,
      readOnly: true,
    });
  });
});

import { describe, expect, it } from "vitest";
import { loadChatConfig } from "../apps/checkmate-chat/src/config.js";

const baseEnv: NodeJS.ProcessEnv = {
  AI_PROVIDER: "openai",
  AI_REASONING_EFFORT: "high",
  AI_TIMEOUT_MS: "180000",
  OPENAI_API_KEY: "test-key",
  OPENAI_MODEL: "gpt-5.5",
  OPENAI_REASONING_EFFORT: "high",
  CHECKMATE_CHAT_MODEL: "gpt-5.4-mini",
  CHECKMATE_CHAT_REASONING_EFFORT: "low",
  AUTH0CHECKMATE_DEV_DOMAIN: "dev-tenant.auth0.com",
  AUTH0CHECKMATE_DEV_CLIENT_ID: "dev-client",
  AUTH0CHECKMATE_DEV_CLIENT_SECRET: "dev-secret",
  AUTH0CHECKMATE_PROD_DOMAIN: "prod-tenant.auth0.com",
  CHECKMATE_CHAT_DEV_WRITE_DOMAIN: "dev-tenant.auth0.com",
};

describe("chat configuration", () => {
  it("uses the requested OpenAI conversation settings and enables a distinct allowlisted dev tenant", () => {
    const config = loadChatConfig(baseEnv);

    expect(config.aiProvider).toBe("openai");
    expect(config.aiApiKey).toBe("test-key");
    expect(config.model).toBe("gpt-5.5");
    expect(config.reasoningEffort).toBe("high");
    expect(config.aiTimeoutMs).toBe(180_000);
    expect(config.devPlanningEnabled).toBe(true);
    expect(config.devRemediationEnabled).toBe(true);
    expect(config.devTenantDomain).toBe("dev-tenant.auth0.com");
    expect(config.scanTargets.dev).toEqual({
      configured: true,
      tenantDomain: "dev-tenant.auth0.com",
    });
    expect(config.scanTargets.prod).toEqual({
      configured: false,
      tenantDomain: "prod-tenant.auth0.com",
    });
    expect(config.auth0Command).toBe(process.execPath);
    expect(config.auth0Arguments).toEqual([
      expect.stringMatching(
        /node_modules[/\\]@auth0[/\\]auth0-mcp-server[/\\]dist[/\\]index\.js$/,
      ),
      "run",
      "--tools",
      "auth0_list_logs,auth0_get_log,auth0_list_applications,auth0_get_application",
      "--read-only",
    ]);
  });

  it("uses the explicit chat dev allowlist even when another workflow reuses the domain", () => {
    const config = loadChatConfig({
      ...baseEnv,
      AUTH0CHECKMATE_PROD_DOMAIN: "dev-tenant.auth0.com",
    });

    expect(config.devRemediationEnabled).toBe(true);
    expect(config.devPlanningEnabled).toBe(true);
    expect(config.devRemediationDisabledReason).toBeUndefined();
  });

  it("selects only the Anthropic credential and model for the Anthropic adapter", () => {
    const config = loadChatConfig({
      ...baseEnv,
      AI_PROVIDER: "anthropic",
      ANTHROPIC_API_KEY: "anthropic-test-key",
      ANTHROPIC_MODEL: "claude-test-model",
    });

    expect(config.aiProvider).toBe("anthropic");
    expect(config.aiApiKey).toBe("anthropic-test-key");
    expect(config.model).toBe("claude-test-model");
  });

  it("selects only the Gemini credential and model for the Google adapter", () => {
    const config = loadChatConfig({
      ...baseEnv,
      AI_PROVIDER: "google",
      GEMINI_API_KEY: "gemini-test-key",
      GEMINI_MODEL: "gemini-test-model",
    });

    expect(config.aiProvider).toBe("google");
    expect(config.aiApiKey).toBe("gemini-test-key");
    expect(config.model).toBe("gemini-test-model");
  });

  it("fails when the selected provider credential is missing", () => {
    expect(() =>
      loadChatConfig({ ...baseEnv, AI_PROVIDER: "anthropic" }),
    ).toThrow("ANTHROPIC_API_KEY is required when AI_PROVIDER=anthropic.");
  });
});

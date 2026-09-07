#!/usr/bin/env node
import path from "node:path";
import dotenv from "dotenv";
import { CheckmateChatAgent } from "./chat-agent.js";
import { CheckmateScanCoordinator } from "./checkmate-scan.js";
import { defaultProjectRoot, loadChatConfig } from "./config.js";
import { DevRemediationCoordinator } from "./dev-remediation.js";
import { ToolHub } from "./tool-hub.js";
import { createChatServer } from "./server.js";

function valueAfter(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value.`);
  }
  return value;
}

function commandEnvironment(args: string[]): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    switch (argument) {
      case "--port":
        env.CHECKMATE_CHAT_PORT = valueAfter(args, index, argument);
        index += 1;
        break;
      case "--reports-dir":
        env.CHECKMATE_REPORTS_DIR = valueAfter(args, index, argument);
        index += 1;
        break;
      case "--no-auth0":
        env.CHECKMATE_CHAT_AUTH0_ENABLED = "false";
        break;
      case "--help":
      case "-h":
        process.stdout.write(
          [
            "CheckMate one-page chatbot",
            "",
            "Usage: npm run chat -- [options]",
            "",
            "Options:",
            "  --port <number>        Local port (default: 4320)",
            "  --reports-dir <path>  CheckMate report directory (default: ./reports)",
            "  --no-auth0            Start without the optional Auth0 MCP server",
            "  -h, --help            Show this help",
          ].join("\n") + "\n",
        );
        process.exit(0);
        return env;
      default:
        throw new Error(`Unknown option: ${argument}`);
    }
  }
  return env;
}

async function main(): Promise<void> {
  const projectRoot = defaultProjectRoot();
  dotenv.config({ path: path.resolve(projectRoot, ".env"), quiet: true });
  const config = loadChatConfig(commandEnvironment(process.argv.slice(2)));
  const hub = new ToolHub(config);
  await hub.initialize();
  const agent = new CheckmateChatAgent(hub, config);
  const remediation = new DevRemediationCoordinator(config);
  const scanner = new CheckmateScanCoordinator(config);
  const server = createChatServer({ config, hub, agent, remediation, scanner });

  const close = (): void => {
    server.close(() => {
      void hub.close().finally(() => process.exit(0));
    });
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port, config.host, resolve);
    });
  } catch (error) {
    await hub.close();
    throw error;
  }
  const status = hub.getStatus();
  process.stdout.write(
    [
      `CheckMate chatbot: http://${config.host}:${config.port}`,
      `AI provider: ${config.aiProvider} (${config.model}); BYO credentials configured server-side`,
      `CheckMate reports: read in-process from ${config.reportsDirectory}`,
      `Auth0 MCP: ${status.auth0.connected ? "connected (read-only)" : status.auth0.enabled ? "unavailable; report-only answers remain available" : "disabled"}`,
      `Dev remediation: ${config.devRemediationEnabled ? `planning and execution enabled for ${config.devTenantDomain ?? "configured tenant"} with confirmation` : config.devPlanningEnabled ? `API planning enabled; execution disabled; ${config.devRemediationDisabledReason ?? "configure the dev write boundary"}` : `planning and execution disabled; ${config.devRemediationDisabledReason ?? "configure the dev tenant"}`}`,
      "Press Ctrl+C to stop.",
    ].join("\n") + "\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown error.";
  process.stderr.write(`CheckMate chatbot failed: ${message}\n`);
  process.exitCode = 1;
});

import { InvalidArgumentError, Option, type Command } from "commander";
import { startUiServer } from "../ui/server.js";
import type { FindingStatusFilter } from "../findings/filter.js";
import { displayPath } from "../utils/filesystem.js";

interface UiOptions {
  status: FindingStatusFilter;
  port: number;
  profile?: string;
}

function portNumber(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new InvalidArgumentError("Port must be an integer from 0 to 65535.");
  }
  return port;
}

export function registerUiCommand(program: Command): void {
  program
    .command("ui")
    .description("Run CheckMate and review findings in a local interface")
    .addOption(
      new Option(
        "--profile <profile>",
        "Auth0 profile used for narrow read-only configuration verification",
      ).choices(["dev", "prod"]),
    )
    .addOption(
      new Option("--status <status>", "filter findings before review")
        .choices(["failed", "warning", "passed", "unknown", "all"])
        .default("failed"),
    )
    .option(
      "--port <port>",
      "local port (use 0 to choose a free port)",
      portNumber,
      4317,
    )
    .action(async (options: UiOptions) => {
      const running = await startUiServer(options);
      console.log(`CheckMate review UI: ${running.url}`);
      if (running.outputPath) {
        console.log(
          `Decisions will be saved to: ${displayPath(running.outputPath)}`,
        );
      } else {
        console.log("Run a CheckMate scan from the local interface to begin.");
      }
      console.log("Press Ctrl+C to stop the local server.");
    });
}

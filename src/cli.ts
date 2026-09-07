#!/usr/bin/env node
import { Command } from "commander";
import { initialiseEnvironment } from "./config/env.js";
import { registerScanCommand } from "./commands/scan.js";
import { registerImportReportCommand } from "./commands/import-report.js";
import { registerListFindingsCommand } from "./commands/list-findings.js";
import { registerUiCommand } from "./commands/ui.js";
import { toErrorMessage } from "./utils/errors.js";

initialiseEnvironment();

const program = new Command()
  .name("checkmate-assistant")
  .description(
    "Read-only remediation workflow driven by Auth0 CheckMate findings",
  )
  .version("0.1.0")
  .showHelpAfterError();

registerScanCommand(program);
registerImportReportCommand(program);
registerListFindingsCommand(program);
registerUiCommand(program);

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(`Error: ${toErrorMessage(error)}`);
  process.exitCode = 1;
});

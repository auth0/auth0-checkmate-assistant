import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
  type StdioServerParameters,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ChatConfig } from "./config.js";
import { AUTH0_READ_ONLY_TOOLS } from "./config.js";
import {
  CheckmateReportTools,
  isCheckmateToolName,
} from "./checkmate-tools.js";
import { safeError, sanitizeToolResult } from "./sanitize.js";
import type {
  McpCallResult,
  McpServerStatus,
  McpToolDefinition,
} from "./types.js";

const AUTH0_TOOLS = new Set<string>(AUTH0_READ_ONLY_TOOLS);

interface ConnectedServer {
  client: Client;
  transport: StdioClientTransport;
  tools: McpToolDefinition[];
}

function textResult(result: {
  content?: Array<{ type: string; text?: string }>;
}): unknown {
  const text = result.content
    ?.filter((item) => item.type === "text" && typeof item.text === "string")
    .map((item) => item.text)
    .join("\n");
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { text };
  }
}

function extractResult(result: unknown): unknown {
  if (!result || typeof result !== "object") return result;
  const value = result as {
    structuredContent?: unknown;
    content?: Array<{ type: string; text?: string }>;
  };
  return value.structuredContent ?? textResult(value);
}

function isErrorResult(result: unknown): boolean {
  return Boolean(
    result &&
    typeof result === "object" &&
    "isError" in result &&
    (result as { isError?: unknown }).isError,
  );
}

export interface ToolHubLike {
  initialize(): Promise<void>;
  close(): Promise<void>;
  getTools(): McpToolDefinition[];
  getStatus(): {
    checkmate: McpServerStatus;
    auth0: McpServerStatus;
  };
  callTool(name: string, args: Record<string, unknown>): Promise<McpCallResult>;
}

export class ToolHub implements ToolHubLike {
  private readonly checkmate: CheckmateReportTools;
  private auth0Server: ConnectedServer | undefined;
  private readonly statuses: Record<"checkmate" | "auth0", McpServerStatus>;

  constructor(private readonly config: ChatConfig) {
    this.checkmate = new CheckmateReportTools(config.reportsDirectory);
    this.statuses = {
      checkmate: { enabled: true, connected: true, readOnly: true },
      auth0: {
        enabled: config.auth0Enabled,
        connected: false,
        readOnly: true,
      },
    };
  }

  async initialize(): Promise<void> {
    if (!this.config.auth0Enabled) return;
    try {
      await this.connectAuth0({
        command: this.config.auth0Command,
        args: this.config.auth0Arguments,
        cwd: this.config.projectRoot,
        env: {
          ...getDefaultEnvironment(),
          AUTH0_MCP_ANALYTICS: "false",
          AUTH0_MCP_READ_ONLY: "true",
          AUTH0_MCP_TOOLS: AUTH0_READ_ONLY_TOOLS.join(","),
        },
        stderr: "pipe",
      });
    } catch (error) {
      this.statuses.auth0 = {
        enabled: true,
        connected: false,
        readOnly: true,
        error: safeError(error),
      };
    }
  }

  private async connectAuth0(parameters: StdioServerParameters): Promise<void> {
    const client = new Client({
      name: "checkmate-chat-auth0-client",
      version: "0.1.0",
    });
    const transport = new StdioClientTransport(parameters);
    let recentStderr = "";
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      recentStderr = `${recentStderr}${String(chunk)}`.slice(-2_000);
    });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      const tools = listed.tools
        .filter((tool) => AUTH0_TOOLS.has(tool.name))
        .map((tool): McpToolDefinition => {
          const definition: McpToolDefinition = {
            server: "auth0",
            name: tool.name,
            inputSchema: tool.inputSchema,
          };
          if (tool.description) definition.description = tool.description;
          return definition;
        });
      this.auth0Server = { client, transport, tools };
      this.statuses.auth0 = {
        enabled: true,
        connected: true,
        readOnly: true,
      };
      transport.onclose = () => {
        this.auth0Server = undefined;
        this.statuses.auth0 = {
          enabled: true,
          connected: false,
          readOnly: true,
          error: "The Auth0 MCP server disconnected.",
        };
      };
    } catch (error) {
      await transport.close().catch(() => undefined);
      const suffix = recentStderr.trim() ? ` ${recentStderr.trim()}` : "";
      throw new Error(`${safeError(error)}${suffix}`.slice(0, 1_000));
    }
  }

  getTools(): McpToolDefinition[] {
    return [...this.checkmate.getTools(), ...(this.auth0Server?.tools ?? [])];
  }

  getStatus(): {
    checkmate: McpServerStatus;
    auth0: McpServerStatus;
  } {
    return {
      checkmate: { ...this.statuses.checkmate },
      auth0: { ...this.statuses.auth0 },
    };
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpCallResult> {
    if (isCheckmateToolName(name)) {
      const result = await this.checkmate.call(name, args);
      return {
        server: "checkmate",
        tool: name,
        isError: result.isError,
        value: sanitizeToolResult(result.value),
      };
    }
    if (!AUTH0_TOOLS.has(name)) {
      throw new Error(
        `Tool ${name} is not on the chatbot read-only allowlist.`,
      );
    }
    const server = this.auth0Server;
    if (!server || !server.tools.some((tool) => tool.name === name)) {
      throw new Error(`auth0 MCP tool ${name} is unavailable.`);
    }
    const result = await server.client.callTool({ name, arguments: args });
    return {
      server: "auth0",
      tool: name,
      isError: isErrorResult(result),
      value: sanitizeToolResult(extractResult(result), {
        maskPersonalData: true,
      }),
    };
  }

  async close(): Promise<void> {
    const server = this.auth0Server;
    this.auth0Server = undefined;
    if (server) {
      await server.client.close().catch(() => undefined);
    }
    this.statuses.auth0 = {
      enabled: this.config.auth0Enabled,
      connected: false,
      readOnly: true,
    };
  }
}

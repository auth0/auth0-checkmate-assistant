import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "fake-auth0-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

const readToolNames = [
  "auth0_list_logs",
  "auth0_get_log",
  "auth0_list_applications",
  "auth0_get_application",
];

server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: [
    ...readToolNames.map((name) => ({
      name,
      description: `Read-only test tool ${name}`,
      inputSchema: { type: "object", properties: {} },
    })),
    {
      name: "auth0_update_application",
      description: "Write tool that the chatbot must reject.",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, (request) => ({
  content: [
    {
      type: "text",
      text: JSON.stringify({
        called: request.params.name,
        applications:
          request.params.name === "auth0_list_applications"
            ? [{ name: "Test application", client_id: "test-client" }]
            : undefined,
      }),
    },
  ],
}));

await server.connect(new StdioServerTransport());

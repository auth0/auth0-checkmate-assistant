# CheckMate Assistant

This repository contains two projects:

1. **Remediation Review** — reviews CheckMate findings, records administrator decisions, and creates validated Terraform, YAML, and Bash change packages. It does not use AI.
2. **Chatbot** — answers natural-language questions using a selected CheckMate report. It uses a bring-your-own AI API key and can optionally add read-only context from the official Auth0 MCP Server.

The projects can run independently or together.

## Local use only

These tools are single-operator utilities for your own machine. Both bind to `127.0.0.1` and reject non-loopback requests, and by design have **no login or session authentication** — whoever can reach `localhost` is the operator.

Don't expose the ports to a network or bind them to `0.0.0.0`. For shared, multi-user, or hosted use, add real authentication and TLS in front as a separate deployment.

## Prerequisites

- Node.js 20.18.3 or newer; Node.js 22 LTS is recommended
- npm
- Auth0 Machine-to-Machine credentials for each configured tenant
- Terraform CLI 1.5 or newer for Remediation Review
- An OpenAI, Anthropic, or Google Gemini API key for the Chatbot

Auth0 CheckMate 1.8.4 is installed locally by `npm install`. A global CheckMate installation is not required.

## Setup

```sh
npm install
npm run build
cp .env.example .env
```

Edit `.env` with your tenant details. Do not commit this file.

At minimum, configure the development and production profiles you intend to use:

```dotenv
AUTH0CHECKMATE_DEV_DOMAIN=your-dev-tenant.auth0.com
AUTH0CHECKMATE_DEV_CLIENT_ID=
AUTH0CHECKMATE_DEV_CLIENT_SECRET=

AUTH0CHECKMATE_PROD_DOMAIN=your-prod-tenant.auth0.com
AUTH0CHECKMATE_PROD_CLIENT_ID=
AUTH0CHECKMATE_PROD_CLIENT_SECRET=
```

Use separate Auth0 applications for development and production. Production credentials should be read-only. Development credentials should receive only the write scopes required for approved changes.

For shared or public deployments, inject credentials from a secret manager instead of storing them in `.env`. See [Secret management](docs/secret-management.md).

## Project 1: Remediation Review

Remediation Review performs a fresh CheckMate scan and presents supported changes for administrator approval.

Before starting, the development tenant should mirror production's security-relevant configuration. Tenant IDs, credentials, users, logs, and customer data should remain separate.

Start the application:

```sh
npm run dev -- ui
```

Open `http://127.0.0.1:4317`.

The review workflow is:

1. Run a new CheckMate scan.
2. Review each recommendation.
3. Accept the suggestion or leave it unchanged.
4. Add optional administrator notes.
5. Submit the decisions.
6. Review and download the generated change package.
7. Explicitly confirm any development execution.

The generated package contains separate development and production artifacts:

```text
<review>.change-package/
├── dev/
│   ├── api-plan.yml
│   ├── apply-api-plan.sh
│   └── main.tf
└── prod/
    ├── api-plan.yml
    ├── apply-api-plan.sh
    └── main.tf
```

The application validates Terraform and API plans before releasing the package. Development changes require explicit confirmation and are verified after execution. Production execution is blocked; use the generated production artifacts through your normal change-management process.

Remediation Review is deterministic. Recommendation mapping, package generation, validation, and execution do not call an AI provider.

## Project 2: Chatbot

The Chatbot answers questions using bounded evidence from a newly selected CheckMate report. Examples include:

- “I recently experienced credential stuffing. What should I do first?”
- “What are the most important security weaknesses in this tenant?”
- “How should I harden this application?”

Configure one supported AI provider:

```dotenv
AI_PROVIDER=openai
OPENAI_API_KEY=
OPENAI_MODEL=gpt-5.5
AI_REASONING_EFFORT=high
```

Alternatively, use `AI_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`, or `AI_PROVIDER=google` with `GEMINI_API_KEY`. See [.env.example](.env.example) for all model and server settings.

Set the environment variable `CHECKMATE_CHAT_DEV_WRITE_DOMAIN` to be the dev domain name with write scope. Make sure you understand the changes will be made on this tenant directly. 

Start the Chatbot:

```sh
npm run chat
```

Open `http://127.0.0.1:4320`, then select either:

- **Run CheckMate for dev** — conversation plus separately confirmed development changes
- **Run CheckMate for prod** — conversation only; changes are disabled

The official Auth0 MCP Server is optional. It can enrich answers with live, read-only application and log context. The Chatbot still scans and interprets CheckMate reports without it.

To enable it, authenticate once and restart the Chatbot:

```sh
npx @auth0/auth0-mcp-server init --read-only --tools 'auth0_list_logs,auth0_get_log,auth0_list_applications,auth0_get_application'
npx @auth0/auth0-mcp-server session
```

When a supported development recommendation is accepted, deterministic application code prepares the exact API call. The AI model cannot create endpoints, request bodies, or production changes. Execution requires a separate review and confirmation.

To show the **Remediation Review** link from the Chatbot, run both projects in separate terminals.

## Security boundaries

- CheckMate findings are the Chatbot's only source of security recommendations.
- Raw reports, Auth0 credentials, API keys, tokens, and environment variables are not sent to an AI provider.
- The official Auth0 MCP connection is optional and read-only.
- Remediation Review does not use AI.
- Only explicitly confirmed development changes can be executed.
- Production execution is blocked.
- Generated plans are tenant-bound and checked for drift before execution.
- Secrets must be supplied through environment variables or a secret manager.

For additional CLI commands, run:

```sh
npm run dev -- --help
```

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more info.

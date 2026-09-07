# Secret management

CheckMate Assistant reads credentials from environment variables. It does not need a direct dependency on 1Password, Vault, or another secret manager. Inject the variables when the process starts, and keep secret values out of the repository, command-line arguments, logs, and generated packages.

The optional chatbot uses bring-your-own AI credentials. Set `AI_PROVIDER` to `openai`, `anthropic`, or `google`, then provide only the selected provider's API key. Only that key is read into the chatbot configuration and passed to its adapter. Provider usage and billing remain with the application operator. The deterministic remediation workflow does not use an AI provider.

Existing process environment variables take precedence over `.env`. This makes `.env` a convenient local-development fallback without making it the production secret store.

## Recommended approach

- Use a dedicated secret store for shared, demo, and deployed environments.
- Give each environment its own Auth0 Machine-to-Machine application and credentials.
- Keep the production client read-only. Give the development client only the write scopes required by approved remediation actions.
- Use a dedicated AI-provider project or workspace credential for this application. Apply provider limits, monitor usage, and rotate the credential when access changes.
- Start the application through the secret manager so credentials exist only in the application process environment.

## Local `.env` fallback

For individual local development, copy `.env.example` to `.env` and fill in the values:

```sh
cp .env.example .env
npm run chat
```

The repository ignores `.env` and `.env.*` files other than `.env.example`. Do not add exceptions for secret-bearing files. A Git ignore rule reduces accidental commits, but it does not protect a secret that has already been committed or otherwise exposed.

## 1Password CLI

Create a local `.env.op` file containing only 1Password secret references, not secret values:

```dotenv
AI_PROVIDER=openai
OPENAI_API_KEY=op://YOUR_VAULT/checkmate-openai/api-key

AUTH0CHECKMATE_DEV_CLIENT_ID=op://YOUR_VAULT/checkmate-dev/client-id
AUTH0CHECKMATE_DEV_CLIENT_SECRET=op://YOUR_VAULT/checkmate-dev/client-secret

AUTH0CHECKMATE_PROD_CLIENT_ID=op://YOUR_VAULT/checkmate-prod/client-id
AUTH0CHECKMATE_PROD_CLIENT_SECRET=op://YOUR_VAULT/checkmate-prod/client-secret
```

For Claude, replace `AI_PROVIDER` with `anthropic` and the OpenAI reference with `ANTHROPIC_API_KEY=op://YOUR_VAULT/checkmate-anthropic/api-key`. For Gemini, use `google` and `GEMINI_API_KEY=op://YOUR_VAULT/checkmate-gemini/api-key`. Keep only the selected provider's key in this launch file so unused credentials are not injected into the process.

Domains and other non-secret configuration can also be placed in this file or supplied separately. Start the application with:

```sh
op run --env-file="./.env.op" -- npm run chat
```

`op run` resolves the references and supplies the values only to the child process. Keep output masking enabled, and use the narrowest possible vault permissions for people, service accounts, and automation. See the official [1Password `op run` documentation](https://www.1password.dev/cli/reference/commands/run) and [secret-reference environment variable guide](https://www.1password.dev/cli/secrets-environment-variables).

## HashiCorp Vault

For a managed deployment, use Vault Agent Process Supervisor Mode. Vault Agent can authenticate using the platform identity, render secrets as environment variables, start the application, and restart it after secret rotation. The application remains unaware of Vault.

The following fragment illustrates the process-supervisor pattern. Adapt the authentication method, secret paths, policies, and command to your environment:

```hcl
env_template "OPENAI_API_KEY" {
  contents = "{{ with secret \"kv/data/checkmate/openai\" }}{{ .Data.data.api_key }}{{ end }}"
}

env_template "AUTH0CHECKMATE_DEV_CLIENT_ID" {
  contents = "{{ with secret \"kv/data/checkmate/dev\" }}{{ .Data.data.client_id }}{{ end }}"
}

env_template "AUTH0CHECKMATE_DEV_CLIENT_SECRET" {
  contents = "{{ with secret \"kv/data/checkmate/dev\" }}{{ .Data.data.client_secret }}{{ end }}"
}

exec {
  command                   = ["npm", "run", "chat"]
  restart_on_secret_changes = "always"
}
```

Use a narrowly scoped Vault policy that permits reads only from the required paths. See HashiCorp's [Vault Agent environment-variable tutorial](https://developer.hashicorp.com/vault/tutorials/vault-agent/agent-env-vars) and [template documentation](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template).

## CI/CD and hosted environments

- Store secrets in the CI/CD platform's encrypted secret store, not in workflow files or build artifacts.
- Prefer workload identity or OIDC to obtain short-lived access to Vault or a cloud secret manager when the platform supports it.
- Do not copy `.env` into a container image or deployment package.
- Restrict secret access by environment. A production deployment must not expose production write credentials to this application.

## Before publishing the repository

- Rotate any API key or client secret that has ever been shared, displayed, or committed. Deleting it from the latest revision is not sufficient.
- Scan the full Git history with a secret scanner such as Gitleaks or TruffleHog.
- Enable GitHub secret scanning and push protection. [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection) can block supported secrets before they enter the repository.
- Confirm that `.env*`, reports, remediation plans, logs, and generated artifacts remain untracked.
- Review screenshots, test fixtures, shell history, CI logs, and release artifacts for copied credentials.

OpenAI also recommends loading API keys from environment variables or a secret-management service and never committing them to a repository. See [OpenAI API key safety guidance](https://developers.openai.com/api/docs/guides/production-best-practices#api-keys).

For provider-specific authentication guidance, see the official [Anthropic API overview](https://platform.claude.com/docs/en/api/overview) and [Gemini API key guide](https://ai.google.dev/gemini-api/docs/api-key).

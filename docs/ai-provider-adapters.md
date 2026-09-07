# Adding an AI provider

CheckMate Assistant has a provider-neutral chatbot orchestration layer. Built-in adapters support:

- `openai` using `OPENAI_API_KEY` and `OPENAI_MODEL`
- `anthropic` using `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL`
- `google` using `GEMINI_API_KEY` and `GEMINI_MODEL`

Select one provider with `AI_PROVIDER`. Only the selected provider's key is read into `ChatConfig` and passed to its adapter. Provider credentials remain in the server process and are never returned by the status or chat endpoints.

## Adapter boundary

The shared contract is in `apps/checkmate-chat/src/model/contracts.ts`. A provider adapter receives:

- shared security instructions;
- bounded conversation messages;
- an allowlisted set of read-only CheckMate and Auth0 tools;
- tool results that have already been redacted; and
- an opaque continuation previously created by that same adapter.

It returns provider-neutral tool calls or a structured final answer. The shared agent—not the adapter—executes tools, binds every CheckMate lookup to the selected report, enforces lookup limits, removes ungrounded recommendations, and prevents production action confirmations.

Provider-specific translations live under `apps/checkmate-chat/src/model/`:

- `openai.ts` translates Responses API items and replays encrypted reasoning items with `store: false`.
- `anthropic.ts` translates Messages API `tool_use` and `tool_result` blocks.
- `google.ts` translates Interactions API function steps and replays full stateless history with `store: false`.

## Adding another provider

1. Add a new `AiProvider` value in `model/contracts.ts`.
2. Add its provider-specific key name, model variable, and safe default model in `config.ts`.
3. Implement `ChatModel.create()` in a new adapter. Use the provider's official SDK.
4. Register the adapter in `model/factory.ts`.
5. Add the provider to the status label, `.env.example`, README, and secret-management guide.
6. Add mocked adapter tests. No test may require a real API key or make an external request.
7. Run the shared grounding and remediation-boundary test suite against the adapter before documenting it as supported.

## Required behaviour

Every adapter must:

- support client-executed function calling;
- support a JSON-schema final response;
- preserve provider-required reasoning or thought state across tool turns;
- disable provider-side response storage when the API supports it;
- apply the configured timeout and bounded provider retry behaviour;
- return only neutral tool calls and parsed output to the shared agent;
- never expose credentials in browser status, logs, errors, continuations, or tool output; and
- fail closed when tool arguments or structured output are invalid.

Do not add a user-configurable base URL as a shortcut for “OpenAI-compatible” providers. An unrestricted endpoint can receive the operator's API key and bounded tenant evidence. A new endpoint requires an explicit adapter, a fixed trusted origin, protocol tests, and a documented data-retention review.

## Validation checklist

For each provider, test:

- first-turn tool selection;
- stateless or encrypted continuation after tool results;
- schema-valid final answers;
- rejection of invalid or ungrounded recommendations;
- selected-report binding;
- repeated-recommendation suppression;
- production action suppression;
- timeout and transient-error behaviour; and
- confirmation that no credential is included in HTTP responses or error text.

Provider APIs are not wire-compatible. Consult the official [OpenAI Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses), [Claude tool-use documentation](https://platform.claude.com/docs/en/agents-and-tools/tool-use/how-tool-use-works), and [Gemini function-calling documentation](https://ai.google.dev/gemini-api/docs/function-calling) when maintaining an adapter.

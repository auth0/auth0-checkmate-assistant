import type { ChatConfig } from "../config.js";
import { AnthropicChatModel } from "./anthropic.js";
import type { ChatModel } from "./contracts.js";
import { GoogleChatModel } from "./google.js";
import { OpenAiChatModel } from "./openai.js";

export function createChatModel(config: ChatConfig): ChatModel {
  const argumentsForProvider = [
    config.aiApiKey,
    config.model,
    config.reasoningEffort,
    config.aiTimeoutMs,
  ] as const;
  switch (config.aiProvider) {
    case "openai":
      return new OpenAiChatModel(...argumentsForProvider);
    case "anthropic":
      return new AnthropicChatModel(...argumentsForProvider);
    case "google":
      return new GoogleChatModel(...argumentsForProvider);
  }
}

import { redactSensitive, redactText } from "../security/redaction.js";

export interface Logger {
  info(message: string, data?: unknown): void;
  verbose(message: string, data?: unknown): void;
  error(message: string, data?: unknown): void;
}

export function createLogger(options: {
  verbose: boolean;
  sensitiveValues?: readonly string[];
}): Logger {
  const clean = (message: string, data?: unknown): string => {
    const safeMessage = redactText(message, options.sensitiveValues);
    if (data === undefined) return safeMessage;
    return `${safeMessage} ${JSON.stringify(redactSensitive(data))}`;
  };

  return {
    info: (message, data) => console.log(clean(message, data)),
    verbose: (message, data) => {
      if (options.verbose) console.log(clean(message, data));
    },
    error: (message, data) => console.error(clean(message, data)),
  };
}

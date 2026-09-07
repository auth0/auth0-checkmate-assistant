const DEFAULT_RATE_LIMIT_RETRIES = 5;
const MAX_RATE_LIMIT_DELAY_MS = 30_000;

export interface RateLimitRetryOptions {
  maxRetries?: number;
  sleep?: (milliseconds: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
}

export function rateLimitRetryLimit(
  options: RateLimitRetryOptions = {},
): number {
  return Math.max(
    0,
    Math.min(options.maxRetries ?? DEFAULT_RATE_LIMIT_RETRIES, 10),
  );
}

function rateLimitDelay(
  response: Response,
  retryIndex: number,
  options: RateLimitRetryOptions,
): number {
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    const delay = Number.isFinite(seconds)
      ? seconds * 1_000
      : Date.parse(retryAfter) - (options.now ?? Date.now)();
    if (Number.isFinite(delay) && delay >= 0) {
      return Math.min(delay, MAX_RATE_LIMIT_DELAY_MS);
    }
  }
  const reset = Number(response.headers.get("x-ratelimit-reset"));
  if (Number.isFinite(reset) && reset > 0) {
    const delay = reset * 1_000 - (options.now ?? Date.now)();
    if (delay >= 0) return Math.min(delay, MAX_RATE_LIMIT_DELAY_MS);
  }
  const baseDelay = Math.min(100 * 2 ** retryIndex, 1_000);
  const jitter = 0.8 + (options.random ?? Math.random)() * 0.4;
  return Math.round(baseDelay * jitter);
}

export async function fetchWithRateLimitRetry(
  request: () => Promise<Response>,
  options: RateLimitRetryOptions = {},
): Promise<Response> {
  const maxRetries = rateLimitRetryLimit(options);
  for (let retryIndex = 0; ; retryIndex += 1) {
    const response = await request();
    if (response.status !== 429 || retryIndex >= maxRetries) return response;
    await waitForRateLimitRetry(response, retryIndex, options);
  }
}

export async function waitForRateLimitRetry(
  response: Response,
  retryIndex: number,
  options: RateLimitRetryOptions = {},
): Promise<void> {
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  await response.body?.cancel();
  await sleep(rateLimitDelay(response, retryIndex, options));
}

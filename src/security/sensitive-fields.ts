export const SENSITIVE_KEY_PATTERN =
  /secret|token|password|api[_-]?key|authorization/i;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

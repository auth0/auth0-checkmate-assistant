export type AppErrorCode =
  | "INVALID_PROFILE"
  | "MISSING_CONFIGURATION"
  | "CHECKMATE_NOT_FOUND"
  | "CHECKMATE_TIMEOUT"
  | "CHECKMATE_FAILED"
  | "OUTPUT_DIRECTORY_ERROR"
  | "REPORT_NOT_FOUND"
  | "REPORT_READ_ERROR"
  | "INVALID_JSON"
  | "UNSUPPORTED_REPORT"
  | "FILE_COPY_ERROR"
  | "AI_REQUEST_FAILED"
  | "AI_RESPONSE_INVALID"
  | "AUTH0_READ_FAILED"
  | "AUTH0_WRITE_FAILED"
  | "REVIEW_INPUT_CLOSED"
  | "REVIEW_WRITE_ERROR"
  | "NOT_IMPLEMENTED";

export class AppError extends Error {
  readonly code: AppErrorCode;
  override readonly cause?: unknown;

  constructor(
    code: AppErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.cause = options?.cause;
  }
}

export function toErrorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "An unexpected error occurred.";
}

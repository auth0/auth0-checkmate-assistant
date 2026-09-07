export type CheckmateReportErrorCode =
  "REPORT_READ_ERROR" | "INVALID_JSON" | "UNSUPPORTED_REPORT";

export class CheckmateReportError extends Error {
  readonly code: CheckmateReportErrorCode;
  override readonly cause?: unknown;

  constructor(
    code: CheckmateReportErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.name = "CheckmateReportError";
    this.code = code;
    this.cause = options?.cause;
  }
}

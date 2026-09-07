import {
  CheckmateReportError,
  loadCheckmateReport as loadCoreCheckmateReport,
  type LoadedCheckmateReport,
} from "@checkmate-assistant/core";
import { AppError } from "../utils/errors.js";

export async function loadCheckmateReport(
  filePath: string,
): Promise<LoadedCheckmateReport> {
  try {
    return await loadCoreCheckmateReport(filePath);
  } catch (error) {
    if (error instanceof CheckmateReportError) {
      throw new AppError(error.code, error.message, { cause: error.cause });
    }
    throw error;
  }
}

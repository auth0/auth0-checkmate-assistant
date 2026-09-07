import type { ProfileName } from "../config/profiles.js";

export type {
  LoadedCheckmateReport,
  NormalizedCheckmateReport,
} from "@checkmate-assistant/core";

export interface ReportPriorityCounts {
  red: number;
  yellow: number;
  green: number;
  blue: number;
  violet: number;
  unknown: number;
}

export interface ReportSummary {
  tenant?: string;
  generatedAt?: string;
  reportPath: string;
  reportedValidatorCount: number;
  detailItemCount: number;
  priorities: ReportPriorityCounts;
}

export interface ScanMetadata {
  profile: ProfileName;
  targetDomain: string;
  startedAt: string;
  finishedAt: string;
  checkmateVersion?: string;
  reportPath: string;
  exitCode: number;
}

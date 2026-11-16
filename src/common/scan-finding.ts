import { Severity } from './severity.enum';

/**
 * One vulnerable package in an image, in our own format. The scanner creates it and the database
 * layer saves it.
 */
export interface ScanFinding {
  cveId: string;
  severity: Severity;
  title: string | null;
  packageName: string;
  packageType: string;
  installedVersion: string;
  fixedVersion: string | null;
}

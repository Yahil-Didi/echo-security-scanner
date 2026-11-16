import { Severity } from '../../common/severity.enum';
import { ScanStatus } from '../../database/entities';

// Simple typed classes. The Swagger plugin (nest-cli.json) builds the API docs from these types,
// and their comments become the descriptions.

export class PackageDetailResponse {
  name: string;
  /** Package ecosystem as a package URL type, e.g. deb, apk, npm. */
  type: string;
  installedVersion: string;
  fixedVersion: string | null;
}

export class CveSummaryResponse {
  cveId: string;
  severity: Severity;
  title: string | null;
}

export class SeverityCountsResponse implements Record<Severity, number> {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
}

export class ImageSummaryResponse {
  name: string;
  tag: string;
  /** `name:tag`, e.g. nginx:1.19. */
  image: string;
  scanStatus: ScanStatus;
  /** When the last scan attempt finished, successfully or not. */
  lastScannedAt: Date | null;
  lastError: string | null;
}

export class ImageWithStatsResponse extends ImageSummaryResponse {
  /** Distinct CVEs in the image. */
  totalCves: number;
  cvesBySeverity: SeverityCountsResponse;
}

export class ImageListResponse {
  total: number;
  images: ImageWithStatsResponse[];
}

export class ImageCveResponse extends CveSummaryResponse {
  packages: PackageDetailResponse[];
}

export class ImageCvesResponse extends ImageSummaryResponse {
  totalCves: number;
  cves: ImageCveResponse[];
}

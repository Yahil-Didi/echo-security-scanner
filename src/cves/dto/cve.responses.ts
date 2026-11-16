import { CveSummaryResponse, PackageDetailResponse } from '../../images/dto/image.responses';

export class CveListItemResponse extends CveSummaryResponse {
  /** How many tracked images contain this CVE. */
  affectedImages: number;
}

export class CveListResponse {
  total: number;
  cves: CveListItemResponse[];
}

export class AffectedImageResponse {
  name: string;
  tag: string;
  /** `name:tag`, e.g. nginx:1.19. */
  image: string;
  packages: PackageDetailResponse[];
}

export class CveImagesResponse extends CveSummaryResponse {
  totalImages: number;
  images: AffectedImageResponse[];
}

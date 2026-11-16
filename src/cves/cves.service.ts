import { Injectable, NotFoundException } from '@nestjs/common';
import { Severity } from '../common/severity.enum';
import { CveRepository } from '../database/repositories/cve.repository';
import { CveImagesResponse, CveListResponse } from './dto/cve.responses';

@Injectable()
export class CvesService {
  constructor(private readonly cves: CveRepository) {}

  /** All CVEs found in at least one image, optionally filtered by severity. */
  async list(severities?: Severity[]): Promise<CveListResponse> {
    const cves = await this.cves.findAllWithStats(severities);
    return { total: cves.length, cves };
  }

  /** All images that have this CVE (the ID is not case-sensitive), with their packages. */
  async getImages(rawId: string): Promise<CveImagesResponse> {
    const id = rawId.toUpperCase();
    const [cve, images] = await Promise.all([
      this.cves.findById(id),
      this.cves.findImagesByCve(id),
    ]);
    if (!cve) throw new NotFoundException(`CVE ${id} not found`);

    const { id: cveId, ...details } = cve; // severity, title
    return { cveId, ...details, totalImages: images.length, images };
  }
}

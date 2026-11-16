import { Injectable, NotFoundException } from '@nestjs/common';
import { formatImageRef, ImageRef } from '../common/image-ref';
import { ScanFinding } from '../common/scan-finding';
import { Severity } from '../common/severity.enum';
import { ImageRepository } from '../database/repositories/image.repository';
import { VulnerabilityRepository } from '../database/repositories/vulnerability.repository';
import { ImageCvesResponse, ImageListResponse } from './dto/image.responses';

@Injectable()
export class ImagesService {
  constructor(
    private readonly images: ImageRepository,
    private readonly vulnerabilities: VulnerabilityRepository,
  ) {}

  // --- Used by the scan jobs, so they never use the data layer directly. ---

  /** Adds images that are not saved yet (status PENDING); saved images keep their status. */
  track(images: ImageRef[]): Promise<void> {
    return this.images.track(images);
  }

  /** Marks the image SCANNING (tracking it if needed) and returns its id. */
  markScanning(image: ImageRef): Promise<number> {
    return this.images.markScanning(image);
  }

  /**
   * Saves this scan's findings in place of the old ones, in one transaction, and marks the image
   * SUCCESS.
   */
  replaceFindings(imageId: number, findings: ScanFinding[]): Promise<void> {
    return this.vulnerabilities.replaceFindings(imageId, findings);
  }

  /** Marks the scan FAILED with the reason; the old results stay. */
  markFailed(imageId: number, error: string): Promise<void> {
    return this.images.markFailed(imageId, error);
  }

  // --- API queries ---

  /** All images with their CVE counts, in total and per severity. */
  async list(): Promise<ImageListResponse> {
    const images = await this.images.findAllWithStats();
    return { total: images.length, images };
  }

  /** CVEs in one image (most severe first), each with the affected packages. */
  async getCves(name: string, tag: string, severities?: Severity[]): Promise<ImageCvesResponse> {
    const ref = formatImageRef({ name, tag });
    const image = await this.images.findByRef({ name, tag });
    if (!image) throw new NotFoundException(`Image ${ref} not found`);

    const { id, ...summary } = image; // name, tag, scanStatus, lastScannedAt, lastError
    const cves = await this.vulnerabilities.findCvesByImage(id, severities);
    return { ...summary, image: ref, totalCves: cves.length, cves };
  }
}

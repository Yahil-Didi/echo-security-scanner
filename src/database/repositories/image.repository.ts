import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ImageRef } from '../../common/image-ref';
import { ImageWithStatsResponse } from '../../images/dto/image.responses';
import { Cve, Image, ImageVulnerability, ScanStatus } from '../entities';
import { CVE_COUNTS_JSON, IMAGE_REF } from './sql';

/** Images and their scan status. */
@Injectable()
export class ImageRepository {
  constructor(@InjectRepository(Image) private readonly images: Repository<Image>) {}

  /** Adds images that are not saved yet (status PENDING); saved images keep their status. */
  async track(refs: ImageRef[]): Promise<void> {
    if (refs.length) await this.images.upsert(refs, ['name', 'tag']);
  }

  findByRef({ name, tag }: ImageRef): Promise<Image | null> {
    return this.images.findOneBy({ name, tag });
  }

  /**
   * All images with their CVE counts, in total and per severity, in one query. Images without
   * findings still appear, with zero counts.
   */
  findAllWithStats(): Promise<ImageWithStatsResponse[]> {
    return this.images
      .createQueryBuilder('i')
      .leftJoin(ImageVulnerability, 'iv', 'iv.imageId = i.id')
      .leftJoin(Cve, 'c', 'c.id = iv.cveId')
      .select('i.name', 'name')
      .addSelect('i.tag', 'tag')
      .addSelect(IMAGE_REF, 'image')
      .addSelect('i.scanStatus', 'scanStatus')
      .addSelect('i.lastScannedAt', 'lastScannedAt')
      .addSelect('i.lastError', 'lastError')
      .addSelect('COUNT(DISTINCT iv.cveId)::int', 'totalCves')
      .addSelect(CVE_COUNTS_JSON, 'cvesBySeverity')
      .groupBy('i.id')
      .orderBy('i.name')
      .addOrderBy('i.tag')
      .getRawMany<ImageWithStatsResponse>();
  }

  /** Marks the image as being scanned (creating it if needed) and returns its id. */
  async markScanning({ name, tag }: ImageRef): Promise<number> {
    const { identifiers } = await this.images.upsert(
      { name, tag, scanStatus: ScanStatus.SCANNING },
      ['name', 'tag'],
    );
    return (identifiers[0] as Pick<Image, 'id'>).id; // upsert returns the id (new or existing row)
  }

  /**
   * Marks a scan as failed. Only the status and the error change, so the API keeps showing the last
   * good results.
   */
  async markFailed(imageId: number, error: string): Promise<void> {
    await this.images.update(imageId, {
      scanStatus: ScanStatus.FAILED,
      lastScannedAt: new Date(),
      lastError: error,
    });
  }
}

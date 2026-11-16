import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Severity } from '../../common/severity.enum';
import { AffectedImageResponse, CveListItemResponse } from '../../cves/dto/cve.responses';
import { Cve, ImageVulnerability } from '../entities';
import { IMAGE_REF, PACKAGES_JSON } from './sql';

/** CVE lookups and lists. */
@Injectable()
export class CveRepository {
  constructor(@InjectRepository(Cve) private readonly cves: Repository<Cve>) {}

  findById(id: string): Promise<Cve | null> {
    return this.cves.findOneBy({ id });
  }

  /** CVEs found in at least one image, with how many images have each; most severe first. */
  findAllWithStats(severities?: Severity[]): Promise<CveListItemResponse[]> {
    const qb = this.cves
      .createQueryBuilder('c')
      .innerJoin(ImageVulnerability, 'iv', 'iv.cveId = c.id')
      .select('c.id', 'cveId')
      .addSelect('c.severity', 'severity')
      .addSelect('c.title', 'title')
      .addSelect('COUNT(DISTINCT iv.imageId)::int', 'affectedImages')
      .groupBy('c.id')
      .orderBy('c.severity')
      .addOrderBy('"affectedImages"', 'DESC')
      .addOrderBy('c.id');
    if (severities?.length) qb.where('c.severity IN (:...severities)', { severities });
    return qb.getRawMany<CveListItemResponse>();
  }

  /** The images that have this CVE, each with its packages, sorted by image. */
  findImagesByCve(cveId: string): Promise<AffectedImageResponse[]> {
    return this.cves.manager
      .createQueryBuilder(ImageVulnerability, 'iv')
      .innerJoin('iv.image', 'i')
      .select('i.name', 'name')
      .addSelect('i.tag', 'tag')
      .addSelect(IMAGE_REF, 'image')
      .addSelect(PACKAGES_JSON, 'packages')
      .where('iv.cveId = :cveId', { cveId })
      .groupBy('i.id')
      .orderBy('i.name')
      .addOrderBy('i.tag')
      .getRawMany<AffectedImageResponse>();
  }
}

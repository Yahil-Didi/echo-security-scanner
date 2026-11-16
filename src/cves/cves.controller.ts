import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBadRequestResponse, ApiNotFoundResponse, ApiTags } from '@nestjs/swagger';
import { SeverityQueryDto } from '../common/severity-query.dto';
import { CvesService } from './cves.service';
import { CveImagesResponse, CveListResponse } from './dto/cve.responses';

@ApiTags('cves')
@Controller('cves')
export class CvesController {
  constructor(private readonly cves: CvesService) {}

  /** All unique CVEs across all images, most severe first. */
  @Get()
  @ApiBadRequestResponse({ description: 'Invalid severity or unknown query parameter' })
  list(@Query() query: SeverityQueryDto): Promise<CveListResponse> {
    return this.cves.list(query.severity);
  }

  /** Images affected by a CVE (ID is case-insensitive), with package details. */
  @Get(':cve_id/images')
  @ApiNotFoundResponse({ description: 'No CVE with this ID has been found in any scan' })
  images(@Param('cve_id') cveId: string): Promise<CveImagesResponse> {
    return this.cves.getImages(cveId);
  }
}

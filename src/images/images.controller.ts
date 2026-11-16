import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBadRequestResponse, ApiNotFoundResponse, ApiTags } from '@nestjs/swagger';
import { SeverityQueryDto } from '../common/severity-query.dto';
import { ImageCvesResponse, ImageListResponse } from './dto/image.responses';
import { ImagesService } from './images.service';

@ApiTags('images')
@Controller('images')
export class ImagesController {
  constructor(private readonly images: ImagesService) {}

  /** Tracked images with their CVE counts per severity. */
  @Get()
  list(): Promise<ImageListResponse> {
    return this.images.list();
  }

  /** CVEs found in one image, most severe first, each with its affected packages. */
  @Get(':image_name/:tag/cves')
  @ApiBadRequestResponse({ description: 'Invalid severity or unknown query parameter' })
  @ApiNotFoundResponse({ description: 'Image not tracked' })
  cves(
    @Param('image_name') name: string,
    @Param('tag') tag: string,
    @Query() query: SeverityQueryDto,
  ): Promise<ImageCvesResponse> {
    return this.images.getCves(name, tag, query.severity);
  }
}

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ENTITIES } from '../entities';
import { CveRepository } from './cve.repository';
import { ImageRepository } from './image.repository';
import { VulnerabilityRepository } from './vulnerability.repository';

const REPOSITORIES = [ImageRepository, CveRepository, VulnerabilityRepository];

/**
 * The data layer: the only code that talks to the database. Other modules use these repositories,
 * never SQL directly.
 */
@Module({
  imports: [TypeOrmModule.forFeature(ENTITIES)],
  providers: REPOSITORIES,
  exports: REPOSITORIES,
})
export class RepositoriesModule {}

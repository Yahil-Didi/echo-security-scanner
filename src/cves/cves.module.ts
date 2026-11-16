import { Module } from '@nestjs/common';
import { RepositoriesModule } from '../database/repositories/repositories.module';
import { CvesController } from './cves.controller';
import { CvesService } from './cves.service';

@Module({
  imports: [RepositoriesModule],
  controllers: [CvesController],
  providers: [CvesService],
})
export class CvesModule {}

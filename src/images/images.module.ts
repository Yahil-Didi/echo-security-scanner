import { Module } from '@nestjs/common';
import { RepositoriesModule } from '../database/repositories/repositories.module';
import { ImagesController } from './images.controller';
import { ImagesService } from './images.service';

@Module({
  imports: [RepositoriesModule],
  controllers: [ImagesController],
  providers: [ImagesService],
  // The scan jobs save their results through ImagesService, not through the repositories.
  exports: [ImagesService],
})
export class ImagesModule {}

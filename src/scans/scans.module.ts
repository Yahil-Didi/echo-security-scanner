import { BullMQAdapter } from '@bull-board/api/bullMQAdapter';
import { BullBoardModule } from '@bull-board/nestjs';
import { Module } from '@nestjs/common';
import { ImagesModule } from '../images/images.module';
import { TrivyScanner } from '../integrations/trivy/trivy.scanner';
import { VULNERABILITY_SCANNER } from '../integrations/vulnerability-scanner';
import { ScanProcessor } from './scan.processor';
import { ScanQueueModule } from './scan-queue.module';
import { ScanSchedulerService } from './scan-scheduler.service';
import { SCAN_QUEUE } from './scans.types';

/** Schedules and runs the scan jobs. Which tool does the scanning is decided in one place below. */
@Module({
  imports: [
    ScanQueueModule,
    ImagesModule,
    // Shows this queue on the Bull Board dashboard (set up in AppModule).
    BullBoardModule.forFeature({ name: SCAN_QUEUE, adapter: BullMQAdapter }),
  ],
  providers: [
    ScanProcessor,
    ScanSchedulerService,
    // The only place that picks the scanner; scan jobs only know the interface.
    { provide: VULNERABILITY_SCANNER, useClass: TrivyScanner },
  ],
})
export class ScansModule {}

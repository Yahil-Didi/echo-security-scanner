import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Logger, Module, OnModuleInit } from '@nestjs/common';
import { Queue } from 'bullmq';
import { describeError } from '../common/describe-error';
import { SCAN_JOB_OPTIONS, SCAN_QUEUE } from './scans.types';

/** Only the scan queue, for modules that need it without the worker (e.g. the health check). */
@Module({
  imports: [BullModule.registerQueue({ name: SCAN_QUEUE, defaultJobOptions: SCAN_JOB_OPTIONS })],
  exports: [BullModule],
})
export class ScanQueueModule implements OnModuleInit {
  private readonly logger = new Logger('ScanQueue');

  constructor(@InjectQueue(SCAN_QUEUE) private readonly queue: Queue) {}

  onModuleInit(): void {
    // Without a listener, Redis connection errors print long stack traces. ioredis reconnects by
    // itself; we only log.
    this.queue.on('error', (err) => this.logger.error(`Queue error: ${describeError(err)}`));
  }
}

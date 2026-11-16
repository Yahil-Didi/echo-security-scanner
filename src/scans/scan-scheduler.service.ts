import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { ImageRef, parseImageRefs } from '../common/image-ref';
import { Env } from '../config/config.schema';
import { ImagesService } from '../images/images.service';
import { SCAN_JOB, SCAN_QUEUE, schedulerId } from './scans.types';

/** Creates and updates the scan schedules when the app starts. */
@Injectable()
export class ScanSchedulerService implements OnApplicationBootstrap {
  private readonly logger = new Logger(ScanSchedulerService.name);

  constructor(
    @InjectQueue(SCAN_QUEUE) private readonly queue: Queue<ImageRef>,
    private readonly images: ImagesService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const imageList = this.config.get('SCAN_IMAGES', { infer: true });
    const intervalMs = this.config.get('SCAN_INTERVAL_MS', { infer: true });
    const images = parseImageRefs(imageList);
    await this.images.track(images);
    await this.schedule(images, intervalMs);
  }

  /**
   * Makes one repeating scan per image, every `everyMs`, and removes schedules of images no longer
   * in the list. The ids never change, so running this on every start never creates duplicates.
   */
  async schedule(images: ImageRef[], everyMs: number): Promise<void> {
    const wanted = new Set(images.map(schedulerId));
    const existing = await this.queue.getJobSchedulers();
    const staleKeys = existing.map(({ key }) => key).filter((key) => !wanted.has(key));

    const removals = staleKeys.map((key) => this.queue.removeJobScheduler(key));
    const upserts = images.map((image) => this.upsertScheduler(image, everyMs));
    await Promise.all([...removals, ...upserts]);
    this.logger.log(`Scheduled ${images.length} images every ${everyMs}ms`);
  }

  /** Creates the image's schedule, or updates it if it already exists. */
  private upsertScheduler(image: ImageRef, everyMs: number) {
    const id = schedulerId(image);
    const job = { name: SCAN_JOB, data: image };
    return this.queue.upsertJobScheduler(id, { every: everyMs }, job);
  }
}

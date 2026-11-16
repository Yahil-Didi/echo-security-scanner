import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import { Inject, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job, UnrecoverableError } from 'bullmq';
import { Env } from '../config/config.schema';
import { describeError } from '../common/describe-error';
import { formatImageRef, ImageRef } from '../common/image-ref';
import { ImagesService } from '../images/images.service';
import {
  ScannerError,
  VULNERABILITY_SCANNER,
  VulnerabilityScanner,
} from '../integrations/vulnerability-scanner';
import { attemptLabel, SCAN_QUEUE, ScanResult, willRetry } from './scans.types';

/** Runs scan jobs: scans one image and saves the results. */
@Processor(SCAN_QUEUE)
export class ScanProcessor extends WorkerHost implements OnApplicationBootstrap {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    @Inject(VULNERABILITY_SCANNER) private readonly scanner: VulnerabilityScanner,
    private readonly images: ImagesService,
    private readonly config: ConfigService<Env, true>,
  ) {
    super();
  }

  /**
   * Sets SCAN_CONCURRENCY from config. A decorator can't read config, but BullMQ accepts a new
   * value on the running worker.
   */
  onApplicationBootstrap(): void {
    this.worker.concurrency = this.config.get('SCAN_CONCURRENCY', { infer: true });
  }

  /** Scans one image and saves the results. Logging is done in the worker events below. */
  async process(job: Job<ImageRef>): Promise<ScanResult> {
    const ref = formatImageRef(job.data);
    const imageId = await this.images.markScanning(job.data);
    try {
      const findings = await this.scanner.scan(ref);
      await this.images.replaceFindings(imageId, findings);
      return { findings: findings.length };
    } catch (err) {
      await this.markFailedSafely(imageId, err);
      // Don't retry what can't succeed (e.g. the image doesn't exist) until the next scheduled run.
      const isRetryable = !(err instanceof ScannerError) || err.isRetryable;
      throw isRetryable ? err : new UnrecoverableError(err.message);
    }
  }

  /**
   * Tries to save the failure. If that also fails (e.g. the database is down), the original error
   * still decides the retry.
   */
  private async markFailedSafely(imageId: number, err: unknown): Promise<void> {
    const message = describeError(err);
    await this.images
      .markFailed(imageId, message)
      .catch((e) => this.logger.warn(`Could not record scan failure: ${describeError(e)}`));
  }

  @OnWorkerEvent('active')
  onActive(job: Job<ImageRef>): void {
    const ref = formatImageRef(job.data);
    const attempt = attemptLabel(job, job.attemptsMade + 1);
    this.logger.log(`Scanning ${ref} (attempt ${attempt})`);
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<ImageRef, ScanResult>): void {
    const ref = formatImageRef(job.data);
    const took = (job.finishedOn ?? 0) - (job.processedOn ?? 0);
    this.logger.log(`Scanned ${ref}: ${job.returnvalue.findings} findings in ${took}ms`);
  }

  /** Only this image's job is retried; other images keep their own schedules. */
  @OnWorkerEvent('failed')
  onFailed(job: Job<ImageRef> | undefined, err: Error): void {
    if (!job) return this.logger.warn(`Scan failed: ${describeError(err)}`);
    const ref = formatImageRef(job.data);
    const attempt = attemptLabel(job, job.attemptsMade);
    const next = willRetry(job, err) ? 'will retry' : 'no retry until next schedule';
    const reason = describeError(err);
    this.logger.warn(`Scan of ${ref} failed (attempt ${attempt}, ${next}): ${reason}`);
  }

  /** Worker errors (e.g. lost Redis connection) are only logged; ioredis reconnects by itself. */
  @OnWorkerEvent('error')
  onError(err: Error): void {
    this.logger.error(`Worker error: ${describeError(err)}`);
  }
}

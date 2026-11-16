import { Job, JobsOptions, UnrecoverableError } from 'bullmq';
import { formatImageRef, ImageRef } from '../common/image-ref';

export const SCAN_QUEUE = 'image-scans';
export const SCAN_JOB = 'scan-image';

/**
 * Default options for every scan job. Failures get 3 attempts with growing delays (30s, 60s...);
 * the processor stops retries for errors that can't be fixed by retrying.
 */
export const SCAN_JOB_OPTIONS: JobsOptions = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 30_000 },
  removeOnComplete: { count: 200 },
  removeOnFail: { count: 500 },
};

export const schedulerId = (ref: ImageRef) => `scan:${formatImageRef(ref)}`;

/** What a scan job returns (visible in Bull Board). */
export type ScanResult = { findings: number };

/** e.g. "2/3": attempt `n` out of the job's allowed attempts. */
export const attemptLabel = (job: Job, n: number) => `${n}/${job.opts.attempts ?? 1}`;

/** Whether BullMQ will run this failed job again (attempts left, and not marked as final). */
export const willRetry = (job: Job, err: Error) =>
  job.attemptsMade < (job.opts.attempts ?? 1) && !(err instanceof UnrecoverableError);

import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import { HealthIndicatorService } from '@nestjs/terminus';
import { Queue } from 'bullmq';
import { describeError } from '../common/describe-error';
import { SCAN_QUEUE } from '../scans/scans.types';

/** How long /health waits for Redis to answer before it reports Redis as down. */
const PING_TIMEOUT_MS = 1500;

/** BullMQ gives a general client type; the real client is ioredis, which has ping(). */
type RedisClient = { ping(): Promise<string> };

/** Fails if the promise takes longer than `ms`, so a stuck connection can't block /health. */
const withTimeout = <T>(promise: Promise<T>, ms: number): Promise<T> => {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
};

/** Checks the Redis server that the scan queue uses. */
@Injectable()
export class RedisHealthIndicator {
  constructor(
    @InjectQueue(SCAN_QUEUE) private readonly queue: Queue,
    private readonly health: HealthIndicatorService,
  ) {}

  async pingCheck(key: string) {
    const indicator = this.health.check(key);
    try {
      const ping = async () => {
        const client = (await this.queue.client) as unknown as RedisClient;
        return client.ping();
      };
      await withTimeout(ping(), PING_TIMEOUT_MS);
      return indicator.up();
    } catch (err) {
      return indicator.down({ message: describeError(err) });
    }
  }
}

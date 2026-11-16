import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { ScanQueueModule } from '../scans/scan-queue.module';
import { HealthController } from './health.controller';
import { RedisHealthIndicator } from './redis.health';

@Module({
  imports: [TerminusModule, ScanQueueModule],
  controllers: [HealthController],
  providers: [RedisHealthIndicator],
})
export class HealthModule {}

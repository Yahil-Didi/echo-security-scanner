import { ExpressAdapter } from '@bull-board/express';
import { BullBoardModule } from '@bull-board/nestjs';
import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { QUEUES_DASHBOARD_PATH } from './app.setup';
import { configSchema, Env } from './config/config.schema';
import { CvesModule } from './cves/cves.module';
import { DatabaseModule } from './database/database.module';
import { HealthModule } from './health/health.module';
import { ImagesModule } from './images/images.module';
import { ScansModule } from './scans/scans.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validationSchema: configSchema }),
    DatabaseModule,
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => ({
        connection: {
          host: config.get('REDIS_HOST', { infer: true }),
          port: config.get('REDIS_PORT', { infer: true }),
        },
      }),
    }),
    // Job dashboard. It has no login, so use it only locally.
    BullBoardModule.forRoot({ route: QUEUES_DASHBOARD_PATH, adapter: ExpressAdapter }),
    ScansModule,
    ImagesModule,
    CvesModule,
    HealthModule,
  ],
})
export class AppModule {}

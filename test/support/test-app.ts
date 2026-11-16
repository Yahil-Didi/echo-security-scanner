import { getQueueToken } from '@nestjs/bullmq';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { configureApp } from '../../src/app.setup';
import { CvesModule } from '../../src/cves/cves.module';
import { typeOrmOptions } from '../../src/database/database.module';
import { HealthModule } from '../../src/health/health.module';
import { ImagesModule } from '../../src/images/images.module';
import { ImageRepository } from '../../src/database/repositories/image.repository';
import { VulnerabilityRepository } from '../../src/database/repositories/vulnerability.repository';
import { SCAN_QUEUE } from '../../src/scans/scans.types';

export const testDatabase = () => {
  return {
    host: process.env.TEST_DB_HOST!,
    port: Number(process.env.TEST_DB_PORT),
    username: process.env.TEST_DB_USER!,
    password: process.env.TEST_DB_PASSWORD!,
    database: process.env.TEST_DB_NAME!,
  };
};

/** Empties every table between tests. */
export const resetDatabase = (db: DataSource): Promise<void> =>
  db.query('TRUNCATE image_vulnerabilities, cves, images RESTART IDENTITY CASCADE');

export interface TestApp {
  app: INestApplication;
  /** Real repositories, used to seed data the way the scanner writes it. */
  images: ImageRepository;
  vulnerabilities: VulnerabilityRepository;
  /** Controls the Redis PING answer seen by /health. */
  redisPing: jest.Mock<Promise<string>, []>;
  reset(): Promise<void>;
}

/**
 * The real HTTP layer (same `configureApp` as production) and the real API and health modules on
 * a real Postgres with migrations applied. Only the Redis queue is faked: the API reads nothing
 * from it, and BullMQ scheduling is unit-tested separately.
 */
const compileTestModule = (redisPing: jest.Mock<Promise<string>, []>) =>
  Test.createTestingModule({
    imports: [
      TypeOrmModule.forRoot(typeOrmOptions(testDatabase())),
      ImagesModule,
      CvesModule,
      HealthModule,
    ],
  })
    .overrideProvider(getQueueToken(SCAN_QUEUE))
    .useValue({ client: Promise.resolve({ ping: redisPing }), on: jest.fn() })
    .compile();

export const createTestApp = async (): Promise<TestApp> => {
  const redisPing = jest.fn<Promise<string>, []>().mockResolvedValue('PONG');
  const moduleRef = await compileTestModule(redisPing);

  const app = configureApp(moduleRef.createNestApplication({ logger: false }));
  await app.init();

  const dataSource = moduleRef.get<DataSource>(getDataSourceToken());
  return {
    app,
    images: moduleRef.get(ImageRepository),
    vulnerabilities: moduleRef.get(VulnerabilityRepository),
    redisPing,
    reset: () => resetDatabase(dataSource),
  };
};

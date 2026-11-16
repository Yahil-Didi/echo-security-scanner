import { Queue } from 'bullmq';
import { buildConfigService } from '../../test/support/factories';
import { ImagesService } from '../images/images.service';
import { ScanSchedulerService } from './scan-scheduler.service';
import { SCAN_JOB } from './scans.types';

describe('ScanSchedulerService', () => {
  const nginx = { name: 'nginx', tag: '1.19' };
  const alpine = { name: 'alpine', tag: '3.12' };

  let queue: jest.Mocked<
    Pick<Queue, 'getJobSchedulers' | 'removeJobScheduler' | 'upsertJobScheduler'>
  >;
  let images: jest.Mocked<Pick<ImagesService, 'track'>>;
  let scheduler: ScanSchedulerService;

  beforeEach(() => {
    queue = {
      getJobSchedulers: jest.fn().mockResolvedValue([]),
      removeJobScheduler: jest.fn().mockResolvedValue(true),
      upsertJobScheduler: jest.fn().mockResolvedValue({}),
    };
    images = { track: jest.fn().mockResolvedValue(undefined) };
    scheduler = new ScanSchedulerService(
      queue as unknown as Queue,
      images as unknown as ImagesService,
      buildConfigService({ SCAN_IMAGES: 'nginx:1.19,alpine:3.12', SCAN_INTERVAL_MS: '900000' }),
    );
  });

  describe('schedule', () => {
    it('should upsert one scheduler per image under a stable id, with the given interval', async () => {
      await scheduler.schedule([nginx, alpine], 60_000);

      expect(queue.upsertJobScheduler).toHaveBeenCalledTimes(2);
      expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
        'scan:nginx:1.19',
        { every: 60_000 },
        { name: SCAN_JOB, data: nginx },
      );
      expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
        'scan:alpine:3.12',
        { every: 60_000 },
        { name: SCAN_JOB, data: alpine },
      );
    });

    it('should remove only the schedulers of images no longer in the list', async () => {
      queue.getJobSchedulers.mockResolvedValue([
        { key: 'scan:nginx:1.19' },
        { key: 'scan:mongo:4.4' },
      ] as Awaited<ReturnType<Queue['getJobSchedulers']>>);

      await scheduler.schedule([nginx], 60_000);

      expect(queue.removeJobScheduler).toHaveBeenCalledTimes(1);
      expect(queue.removeJobScheduler).toHaveBeenCalledWith('scan:mongo:4.4');
    });
  });

  describe('on bootstrap', () => {
    it('should register the configured images, then schedule them at the configured interval', async () => {
      await scheduler.onApplicationBootstrap();

      expect(images.track).toHaveBeenCalledWith([nginx, alpine]);
      expect(images.track.mock.invocationCallOrder[0]).toBeLessThan(
        queue.upsertJobScheduler.mock.invocationCallOrder[0],
      );
      expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
        'scan:nginx:1.19',
        { every: 15 * 60_000 },
        expect.anything(),
      );
    });
  });
});

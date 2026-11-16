import { Job, UnrecoverableError } from 'bullmq';
import { buildConfigService, buildFinding } from '../../test/support/factories';
import { ScanProcessor } from './scan.processor';
import { ImagesService } from '../images/images.service';
import { ImageRef } from '../common/image-ref';
import { ScannerError, VulnerabilityScanner } from '../integrations/vulnerability-scanner';

describe('ScanProcessor', () => {
  const job = {
    data: { name: 'nginx', tag: '1.19' },
    attemptsMade: 0,
    opts: { attempts: 3 },
  } as Job<ImageRef>;

  let trivy: jest.Mocked<Pick<VulnerabilityScanner, 'scan'>>;
  let images: jest.Mocked<Pick<ImagesService, 'markScanning' | 'replaceFindings' | 'markFailed'>>;
  let processor: ScanProcessor;

  beforeEach(() => {
    trivy = { scan: jest.fn() };
    images = {
      markScanning: jest.fn().mockResolvedValue(7),
      replaceFindings: jest.fn().mockResolvedValue(undefined),
      markFailed: jest.fn().mockResolvedValue(undefined),
    };
    processor = new ScanProcessor(
      trivy,
      images as unknown as ImagesService,
      buildConfigService({ SCAN_CONCURRENCY: '3' }),
    );
  });

  it('should apply the configured concurrency to the worker on bootstrap', () => {
    const worker = { concurrency: 1 };
    Object.defineProperty(processor, 'worker', { get: () => worker });

    processor.onApplicationBootstrap();

    expect(worker.concurrency).toBe(3);
  });

  it('should scan the image and store the findings', async () => {
    const findings = [buildFinding(), buildFinding({ cveId: 'CVE-2022-0001' })];
    trivy.scan.mockResolvedValue(findings);

    await expect(processor.process(job)).resolves.toEqual({ findings: 2 });

    expect(images.markScanning).toHaveBeenCalledWith({ name: 'nginx', tag: '1.19' });
    expect(trivy.scan).toHaveBeenCalledWith('nginx:1.19');
    expect(images.replaceFindings).toHaveBeenCalledWith(7, findings);
    expect(images.markFailed).not.toHaveBeenCalled();
  });

  it('should mark the image failed and rethrow transient errors so BullMQ retries', async () => {
    const error = new ScannerError('failed to download DB');
    trivy.scan.mockRejectedValue(error);

    await expect(processor.process(job)).rejects.toBe(error);

    expect(images.markFailed).toHaveBeenCalledWith(7, 'failed to download DB');
    expect(images.replaceFindings).not.toHaveBeenCalled();
  });

  it('should not retry errors that are not retryable', async () => {
    trivy.scan.mockRejectedValue(new ScannerError('nope', { isRetryable: false }));

    await expect(processor.process(job)).rejects.toBeInstanceOf(UnrecoverableError);
    expect(images.markFailed).toHaveBeenCalledWith(7, 'nope');
  });

  it('should keep the original error (and its retry decision) when recording the failure fails', async () => {
    trivy.scan.mockRejectedValue(new ScannerError('nope', { isRetryable: false }));
    images.markFailed.mockRejectedValue(new Error('database is down'));

    await expect(processor.process(job)).rejects.toBeInstanceOf(UnrecoverableError);
  });
});

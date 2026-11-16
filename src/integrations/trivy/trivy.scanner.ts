import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { execFile, ExecFileException } from 'node:child_process';
import { promisify } from 'node:util';
import { ScanFinding } from '../../common/scan-finding';
import { Env } from '../../config/config.schema';
import { ScannerError, VulnerabilityScanner } from '../vulnerability-scanner';
import { parseTrivyReport } from './trivy-report.parser';

const execFileAsync = promisify(execFile);
/** The error execFile throws: exit details plus Trivy's error output. */
type ExecFileError = ExecFileException & { stderr?: string };

/** Redis database for Trivy's layer cache, on our Redis; BullMQ uses database 0. */
const TRIVY_CACHE_REDIS_DB = 1;
/** Trivy's report for a large image is a few MB; execFile allows only 1 MB by default. */
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
/** If Trivy hangs past its own --timeout, we stop it this long after. */
const KILL_GRACE_MS = 30_000;
/** How often we ask Trivy to update its DB. Trivy downloads only when its copy is out of date. */
const DB_CHECK_INTERVAL_MS = 60 * 60 * 1000;

/** Runs the local Trivy CLI for one image and returns its findings. */
@Injectable()
export class TrivyScanner implements VulnerabilityScanner {
  private readonly binary: string;
  private readonly timeoutMs: number;
  private readonly cacheUrl: string;
  private dbUpdate?: Promise<string>;
  private dbCheckedAt = 0;

  constructor(config: ConfigService<Env, true>) {
    const host = config.get('REDIS_HOST', { infer: true });
    const port = config.get('REDIS_PORT', { infer: true });
    this.cacheUrl = `redis://${host}:${port}/${TRIVY_CACHE_REDIS_DB}`;
    this.binary = config.get('TRIVY_BINARY', { infer: true });
    this.timeoutMs = config.get('SCAN_TIMEOUT_MS', { infer: true });
  }

  async scan(imageRef: string): Promise<ScanFinding[]> {
    await this.updateDb();
    const report = await this.runTrivy(imageRef, this.trivyArgs(imageRef));
    return parseTrivyReport(report);
  }

  /**
   * Updates Trivy's vulnerability DB once for all parallel scans, at most once an hour, and scans
   * skip their own update. Parallel Trivy runs that update the same DB files break each other.
   */
  private updateDb(): Promise<string> {
    if (!this.dbUpdate || Date.now() - this.dbCheckedAt > DB_CHECK_INTERVAL_MS) {
      this.dbCheckedAt = Date.now();
      const args = ['image', '--download-db-only', '--quiet'];
      this.dbUpdate = this.runTrivy('the vulnerability DB', args);
      // On failure, the next scan tries again.
      void this.dbUpdate.catch(() => {
        this.dbUpdate = undefined;
      });
    }
    return this.dbUpdate;
  }

  /** Runs Trivy and returns its output; any failure becomes a ScannerError. */
  private async runTrivy(target: string, args: string[]): Promise<string> {
    try {
      // No shell is used, so an image name can't inject commands. Trivy gets our environment, so
      // its TRIVY_* settings (registry login, cache folder) work.
      const { stdout } = await execFileAsync(this.binary, args, {
        maxBuffer: MAX_OUTPUT_BYTES,
        timeout: this.timeoutMs + KILL_GRACE_MS,
        windowsHide: true,
      });
      return stdout;
    } catch (err) {
      throw this.toScannerError(target, err as ExecFileError);
    }
  }

  /** Turns an execFile error into a ScannerError: missing Trivy, timeout, or a Trivy error. */
  private toScannerError(imageRef: string, err: ExecFileError): ScannerError {
    if (err.code === 'ENOENT') {
      return new ScannerError(`"${this.binary}" not found on PATH`, { isRetryable: false });
    }
    if (err.killed) return new ScannerError(`Scan of ${imageRef} timed out`);
    const output = err.stderr?.trim() || err.message;
    return classifyTrivyOutput(imageRef, output);
  }

  /** The Trivy command-line arguments for one image. */
  private trivyArgs(imageRef: string): string[] {
    return [
      'image',
      ...['--format', 'json'],
      ...['--scanners', 'vuln'], // skip secret scanning: it's on by default and slow
      ...['--image-src', 'remote'], // the registry's current image, not an old local copy
      '--skip-db-update', // done once for all scans, see updateDb()
      // Shared cache: parallel scans work (Trivy's default file cache allows one process at a
      // time), and unchanged layers are not downloaded again.
      ...['--cache-backend', this.cacheUrl],
      ...['--timeout', `${Math.floor(this.timeoutMs / 1000)}s`],
      '--quiet',
      imageRef,
    ];
  }
}

/**
 * Rules for Trivy errors; the first match wins. We match the registry's error codes, because Trivy
 * wraps every image error, even rate limits, in the same "unable to find the specified image" text.
 */
const TRIVY_ERROR_RULES: { pattern: RegExp; label: string; isRetryable: boolean }[] = [
  { pattern: /TOOMANYREQUESTS|429 Too Many Requests/i, label: 'rate limited', isRetryable: true },
  { pattern: /context deadline exceeded/i, label: 'timed out', isRetryable: true },
  // Docker Hub returns UNAUTHORIZED for images that don't exist (or are private).
  {
    pattern: /MANIFEST_UNKNOWN|NAME_UNKNOWN|manifest unknown|UNAUTHORIZED|pull access denied/i,
    label: 'not found or access denied',
    isRetryable: false,
  },
];

/** The last three non-empty lines of Trivy's output, joined into one line. */
const lastLines = (output: string) =>
  output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(-3)
    .join(' | ');

/** Builds a ScannerError from Trivy's error output, using the rules above. */
export const classifyTrivyOutput = (imageRef: string, output: string): ScannerError => {
  const detail = lastLines(output);
  const rule = TRIVY_ERROR_RULES.find(({ pattern }) => pattern.test(output));
  if (!rule) return new ScannerError(`Trivy failed for ${imageRef}: ${detail}`);
  const message = `Image ${imageRef} ${rule.label}: ${detail}`;
  return new ScannerError(message, { isRetryable: rule.isRetryable });
};

import { execFile, ExecFileException } from 'node:child_process';
import { buildConfigService } from '../../../test/support/factories';
import { classifyTrivyOutput, TrivyScanner } from './trivy.scanner';
import { ScannerError } from '../vulnerability-scanner';

jest.mock('node:child_process', () => ({ execFile: jest.fn() }));

type Callback = (err: Error | null, result?: { stdout: string; stderr: string }) => void;
const execFileMock = execFile as unknown as jest.Mock;

/**
 * Lets the DB update pass, then makes the scan finish with the given outcome, shaped like
 * promisify(execFile): it resolves with { stdout, stderr } and rejects with an error that carries
 * them.
 */
const finishWith = ({
  stdout = '',
  stderr = '',
  error = null,
}: {
  stdout?: string;
  stderr?: string;
  error?: Partial<ExecFileException> | null;
}) =>
  execFileMock
    .mockImplementationOnce((_cmd, _args, _opts, callback: Callback) =>
      callback(null, { stdout: '', stderr: '' }),
    )
    .mockImplementation((_cmd: string, _args: string[], _opts: unknown, callback: Callback) =>
      error
        ? callback(
            Object.assign(new Error(error.message ?? 'Command failed'), error, { stdout, stderr }),
          )
        : callback(null, { stdout, stderr }),
    );

const REPORT = JSON.stringify({
  Results: [
    {
      Target: 'nginx:1.19 (debian 10.10)',
      Type: 'debian',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2021-3711',
          PkgName: 'openssl',
          InstalledVersion: '1.1.1d',
          FixedVersion: '1.1.1k',
          Severity: 'CRITICAL',
        },
      ],
    },
  ],
});

describe('TrivyScanner', () => {
  beforeEach(() => execFileMock.mockReset());

  const service = (env: Record<string, string> = {}) =>
    new TrivyScanner(buildConfigService({ SCAN_TIMEOUT_MS: '60000', ...env }));

  const scanWith = (outcome: Parameters<typeof finishWith>[0]) => {
    finishWith(outcome);
    return service().scan('nginx:1.19');
  };

  it('should run Trivy for JSON vulnerabilities only, straight from the registry', async () => {
    await scanWith({ stdout: REPORT });

    expect(execFileMock.mock.calls[1][1]).toEqual([
      'image',
      '--format',
      'json',
      '--scanners',
      'vuln',
      '--image-src',
      'remote',
      '--skip-db-update',
      '--cache-backend',
      'redis://localhost:6379/1',
      '--timeout',
      '60s',
      '--quiet',
      'nginx:1.19',
    ]);
  });

  it('should update the vulnerability DB once for parallel scans', async () => {
    finishWith({ stdout: REPORT });
    const scanner = service();

    await Promise.all([scanner.scan('nginx:1.19'), scanner.scan('redis:6.0')]);

    const dbUpdates = execFileMock.mock.calls.filter(([, args]) =>
      (args as string[]).includes('--download-db-only'),
    );
    expect(dbUpdates).toHaveLength(1);
    expect(execFileMock).toHaveBeenCalledTimes(3);
  });

  it('should try the DB update again after it fails', async () => {
    execFileMock.mockImplementationOnce((_cmd, _args, _opts, callback: Callback) =>
      callback(Object.assign(new Error('Command failed'), { code: 1, stderr: 'DB error' })),
    );
    const scanner = service();
    await expect(scanner.scan('nginx:1.19')).rejects.toBeInstanceOf(ScannerError);

    finishWith({ stdout: REPORT });
    await expect(scanner.scan('nginx:1.19')).resolves.toHaveLength(1);
  });

  it('should return the parsed findings on success', async () => {
    const findings = await scanWith({ stdout: REPORT });

    expect(execFileMock).toHaveBeenCalledWith(
      'trivy',
      expect.arrayContaining(['nginx:1.19']),
      expect.objectContaining({ maxBuffer: 64 * 1024 * 1024 }),
      expect.any(Function),
    );
    expect(findings).toEqual([
      expect.objectContaining({
        cveId: 'CVE-2021-3711',
        packageName: 'openssl',
        fixedVersion: '1.1.1k',
      }),
    ]);
  });

  it('should turn a non-zero exit into a classified ScannerError', async () => {
    // Classification rules themselves are covered in the classifyTrivyOutput tests below.
    const error = await scanWith({
      stderr: 'remote error: GET .../manifests/0.0.0-nope: MANIFEST_UNKNOWN: manifest unknown',
      error: { code: 1 },
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ScannerError);
    expect(error).toMatchObject({ isRetryable: false });
  });

  it('should report a missing executable as not retryable', async () => {
    await expect(
      scanWith({ error: { code: 'ENOENT', message: 'spawn trivy ENOENT' } }),
    ).rejects.toMatchObject({ message: '"trivy" not found on PATH', isRetryable: false });
  });

  it('should report a process killed by the hard timeout as a transient timeout', async () => {
    await expect(scanWith({ error: { killed: true, signal: 'SIGTERM' } })).rejects.toMatchObject({
      message: 'Scan of nginx:1.19 timed out',
      isRetryable: true,
    });
    expect(execFileMock.mock.calls[1][2]).toMatchObject({ timeout: 60_000 + 30_000 });
  });
});

/** stderr captured from real `trivy image --image-src remote` runs (Trivy 0.57.1; 0.76.2 reports the same registry codes). */
const STDERR = {
  missingTag: `FATAL	Fatal error	image scan error: scan error: unable to initialize a scanner: unable to initialize an image scanner: unable to find the specified image "nginx:0.0.0-nope" in ["remote"]: 1 error occurred:
	* remote error: GET https://index.docker.io/v2/library/nginx/manifests/0.0.0-nope: MANIFEST_UNKNOWN: manifest unknown; unknown tag=0.0.0-nope

`,
  missingRepo: `FATAL	Fatal error	image scan error: scan error: unable to initialize a scanner: unable to initialize an image scanner: unable to find the specified image "doesnotexist-xyz/nope:1" in ["remote"]: 1 error occurred:
	* remote error: GET https://index.docker.io/v2/doesnotexist-xyz/nope/manifests/1: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:doesnotexist-xyz/nope Type:repository]]
`,
  rateLimited: `FATAL	Fatal error	image scan error: scan error: unable to initialize a scanner: unable to initialize an image scanner: unable to find the specified image "nginx:1.19" in ["remote"]: 1 error occurred:
	* remote error: GET https://index.docker.io/v2/library/nginx/manifests/1.19: TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.
`,
  networkDown: `FATAL	Fatal error	image scan error: scan error: unable to initialize a scanner: unable to initialize an image scanner: unable to find the specified image "nginx:1.19" in ["remote"]: 1 error occurred:
	* remote error: Get "https://index.docker.io/v2/": dial tcp: lookup index.docker.io: no such host
`,
  deadline: 'FATAL	Fatal error	image scan error: scan error: context deadline exceeded',
  dbDownload:
    'FATAL	Fatal error	init error: DB error: failed to download vulnerability DB: tls: failed to verify certificate: x509: certificate signed by unknown authority',
};

describe('classifyTrivyOutput', () => {
  it.each([
    ['a missing tag', STDERR.missingTag, 'not found or access denied', false],
    ['a missing or private repository', STDERR.missingRepo, 'not found or access denied', false],
    ['a registry rate limit', STDERR.rateLimited, 'rate limited', true],
    ['a network failure', STDERR.networkDown, 'Trivy failed', true],
    ['a timeout', STDERR.deadline, 'timed out', true],
    ['a vulnerability DB download failure', STDERR.dbDownload, 'Trivy failed', true],
  ] as const)('should classify %s', (_case, stderr, label, isRetryable) => {
    const error = classifyTrivyOutput('nginx:1.19', stderr);

    expect(error.message).toContain(label);
    expect(error.isRetryable).toBe(isRetryable);
  });

  it('should keep the last meaningful stderr lines in the message', () => {
    const { message } = classifyTrivyOutput('nginx:0.0.0-nope', STDERR.missingTag);

    expect(message).toMatch(/^Image nginx:0\.0\.0-nope not found or access denied: /);
    expect(message).toContain('MANIFEST_UNKNOWN: manifest unknown; unknown tag=0.0.0-nope');
    expect(message).not.toMatch(/\n/);
  });
});

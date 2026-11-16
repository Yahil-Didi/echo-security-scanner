import request from 'supertest';
import { App } from 'supertest/types';
import { Severity } from '../src/common/severity.enum';
import { buildFinding } from './support/factories';
import { createTestApp, TestApp } from './support/test-app';

/**
 * Fixture:
 *   nginx:1.19   CVE-2021-3711 CRITICAL (openssl + libssl1.1), CVE-2022-1111 HIGH (lodash),
 *                CVE-2020-0002 LOW (zlib1g)
 *   alpine:3.12  CVE-2021-3711 CRITICAL (openssl, alpine), CVE-2022-1111 HIGH (lodash)
 *   redis:6.0    scan failed, no data
 *   mongo:4.4    never scanned
 */
const LODASH = buildFinding({
  cveId: 'CVE-2022-1111',
  severity: Severity.HIGH,
  title: 'lodash: prototype pollution',
  packageName: 'lodash',
  packageType: 'npm',
  installedVersion: '4.17.0',
  fixedVersion: '4.17.21',
});

const NGINX_FINDINGS = [
  buildFinding({ packageName: 'openssl' }),
  buildFinding({ packageName: 'libssl1.1' }),
  LODASH,
  buildFinding({
    cveId: 'CVE-2020-0002',
    severity: Severity.LOW,
    packageName: 'zlib1g',
    fixedVersion: null,
  }),
];

const ALPINE_FINDINGS = [
  buildFinding({ packageType: 'apk', installedVersion: '1.1.1g-r0', fixedVersion: '1.1.1l-r0' }),
  LODASH,
];

const seed = async ({ images, vulnerabilities }: TestApp) => {
  await images.track([
    { name: 'nginx', tag: '1.19' },
    { name: 'alpine', tag: '3.12' },
    { name: 'redis', tag: '6.0' },
    { name: 'mongo', tag: '4.4' },
  ]);
  const nginx = await images.markScanning({ name: 'nginx', tag: '1.19' });
  await vulnerabilities.replaceFindings(nginx, NGINX_FINDINGS);
  const alpine = await images.markScanning({ name: 'alpine', tag: '3.12' });
  await vulnerabilities.replaceFindings(alpine, ALPINE_FINDINGS);
  const redis = await images.markScanning({ name: 'redis', tag: '6.0' });
  await images.markFailed(redis, 'Image redis:6.0 not found: MANIFEST_UNKNOWN');
};

describe('REST API (system)', () => {
  let t: TestApp;
  let http: App;

  beforeAll(async () => {
    t = await createTestApp();
    http = t.app.getHttpServer();
  });
  beforeEach(async () => {
    await t.reset();
    await seed(t);
  });
  afterAll(() => t.app.close());

  describe('GET /api/images', () => {
    it('should list every tracked image with distinct CVE counts per severity', async () => {
      const { body } = await request(http).get('/api/images').expect(200);

      expect(body.total).toBe(4);
      expect(body.images.map((i: { image: string }) => i.image)).toEqual([
        'alpine:3.12',
        'mongo:4.4',
        'nginx:1.19',
        'redis:6.0',
      ]);

      const nginx = body.images.find((i: { name: string }) => i.name === 'nginx');
      expect(nginx).toMatchObject({
        scanStatus: 'SUCCESS',
        lastError: null,
        totalCves: 3, // CVE-2021-3711 counted once despite two affected packages
        cvesBySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 1, UNKNOWN: 0 },
      });
      expect(Date.parse(nginx.lastScannedAt)).not.toBeNaN();
    });

    it('should report failed and never-scanned images with zero counts', async () => {
      const { body } = await request(http).get('/api/images').expect(200);
      const byName = Object.fromEntries(body.images.map((i: { name: string }) => [i.name, i]));

      expect(byName.redis).toMatchObject({
        scanStatus: 'FAILED',
        lastError: expect.stringContaining('MANIFEST_UNKNOWN'),
        totalCves: 0,
      });
      expect(byName.mongo).toMatchObject({
        scanStatus: 'PENDING',
        lastScannedAt: null,
        totalCves: 0,
      });
    });
  });

  describe('GET /api/images/:image_name/:tag/cves', () => {
    it('should return CVEs most severe first, each with its affected packages', async () => {
      const { body } = await request(http).get('/api/images/nginx/1.19/cves').expect(200);

      expect(body).toMatchObject({ image: 'nginx:1.19', totalCves: 3 });
      expect(body.cves.map((c: { severity: string }) => c.severity)).toEqual([
        'CRITICAL',
        'HIGH',
        'LOW',
      ]);
      expect(body.cves[0]).toEqual({
        cveId: 'CVE-2021-3711',
        severity: 'CRITICAL',
        title: 'openssl: SM2 Decryption Buffer Overflow',
        packages: [
          {
            name: 'libssl1.1',
            type: 'deb',
            installedVersion: '1.1.1d-0+deb10u6',
            fixedVersion: '1.1.1d-0+deb10u7',
          },
          {
            name: 'openssl',
            type: 'deb',
            installedVersion: '1.1.1d-0+deb10u6',
            fixedVersion: '1.1.1d-0+deb10u7',
          },
        ],
      });
      expect(body.cves[2].packages[0].fixedVersion).toBeNull();
    });

    it.each([
      ['CRITICAL', ['CVE-2021-3711']],
      ['high', ['CVE-2022-1111']],
      ['CRITICAL,LOW', ['CVE-2021-3711', 'CVE-2020-0002']],
      ['MEDIUM', []],
    ])('should filter by ?severity=%s', async (severity, expected) => {
      const { body } = await request(http)
        .get('/api/images/nginx/1.19/cves')
        .query({ severity })
        .expect(200);

      expect(body.cves.map((c: { cveId: string }) => c.cveId)).toEqual(expected);
      expect(body.totalCves).toBe(expected.length);
    });

    it('should reject an unknown severity with 400', async () => {
      const { body } = await request(http)
        .get('/api/images/nginx/1.19/cves?severity=SEVERE')
        .expect(400);

      expect(body.message).toEqual([expect.stringContaining('severity must be one or more of')]);
    });

    it('should reject unknown query parameters with 400', async () => {
      await request(http).get('/api/images/nginx/1.19/cves?foo=bar').expect(400);
    });

    it('should return 404 for an untracked image', async () => {
      const { body } = await request(http).get('/api/images/nginx/9.99/cves').expect(404);
      expect(body.message).toBe('Image nginx:9.99 not found');
    });
  });

  describe('GET /api/cves', () => {
    it('should list all unique CVEs, most severe and then most widespread first', async () => {
      const { body } = await request(http).get('/api/cves').expect(200);

      expect(body.total).toBe(3);
      expect(body.cves).toEqual([
        expect.objectContaining({
          cveId: 'CVE-2021-3711',
          severity: 'CRITICAL',
          affectedImages: 2,
        }),
        expect.objectContaining({ cveId: 'CVE-2022-1111', severity: 'HIGH', affectedImages: 2 }),
        expect.objectContaining({ cveId: 'CVE-2020-0002', severity: 'LOW', affectedImages: 1 }),
      ]);
    });

    it('should filter by severity', async () => {
      const { body } = await request(http).get('/api/cves?severity=CRITICAL,HIGH').expect(200);

      expect(body.total).toBe(2);
      expect(body.cves.map((c: { cveId: string }) => c.cveId)).toEqual([
        'CVE-2021-3711',
        'CVE-2022-1111',
      ]);
    });

    it('should omit CVEs no longer present in any image', async () => {
      const nginx = (await t.images.findByRef({ name: 'nginx', tag: '1.19' }))!;
      await t.vulnerabilities.replaceFindings(nginx.id, []); // rescan: everything fixed

      const { body } = await request(http).get('/api/cves').expect(200);
      expect(body.cves.map((c: { cveId: string }) => c.cveId)).toEqual([
        'CVE-2021-3711',
        'CVE-2022-1111',
      ]);
    });
  });

  describe('GET /api/cves/:cve_id/images', () => {
    it('should return every affected image with its package details', async () => {
      const { body } = await request(http).get('/api/cves/CVE-2021-3711/images').expect(200);

      expect(body).toMatchObject({
        cveId: 'CVE-2021-3711',
        severity: 'CRITICAL',
        totalImages: 2,
      });
      expect(body.images).toEqual([
        expect.objectContaining({
          image: 'alpine:3.12',
          packages: [
            {
              name: 'openssl',
              type: 'apk',
              installedVersion: '1.1.1g-r0',
              fixedVersion: '1.1.1l-r0',
            },
          ],
        }),
        expect.objectContaining({
          image: 'nginx:1.19',
          packages: [
            expect.objectContaining({ name: 'libssl1.1' }),
            expect.objectContaining({ name: 'openssl' }),
          ],
        }),
      ]);
    });

    it('should treat the CVE id case-insensitively', async () => {
      const { body } = await request(http).get('/api/cves/cve-2021-3711/images').expect(200);
      expect(body.cveId).toBe('CVE-2021-3711');
    });

    it('should return 404 for an unknown CVE', async () => {
      const { body } = await request(http).get('/api/cves/CVE-1999-0001/images').expect(404);
      expect(body.message).toBe('CVE CVE-1999-0001 not found');
    });
  });

  describe('GET /health', () => {
    it('should return 200 when Postgres and Redis are reachable', async () => {
      const { body } = await request(http).get('/health').expect(200);

      expect(body).toMatchObject({
        status: 'ok',
        details: { database: { status: 'up' }, redis: { status: 'up' } },
      });
    });

    it('should return 503 naming the failing dependency when Redis is down', async () => {
      t.redisPing.mockRejectedValueOnce(new Error('connect ECONNREFUSED 127.0.0.1:6379'));

      const { body } = await request(http).get('/health').expect(503);

      expect(body).toMatchObject({
        status: 'error',
        info: { database: { status: 'up' } },
        error: { redis: { status: 'down', message: 'connect ECONNREFUSED 127.0.0.1:6379' } },
      });
    });
  });

  describe('API docs', () => {
    it('should serve the OpenAPI spec with every endpoint', async () => {
      const { body } = await request(http).get('/docs-json').expect(200);

      expect(Object.keys(body.paths)).toEqual(
        expect.arrayContaining([
          '/api/images',
          '/api/images/{image_name}/{tag}/cves',
          '/api/cves',
          '/api/cves/{cve_id}/images',
          '/health',
        ]),
      );
    });
  });
});

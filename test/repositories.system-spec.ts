import { DataSource } from 'typeorm';
import { Severity } from '../src/common/severity.enum';
import { Cve, Image, ImageVulnerability, ScanStatus } from '../src/database/entities';
import { typeOrmOptions } from '../src/database/database.module';
import { ImageRepository } from '../src/database/repositories/image.repository';
import { VulnerabilityRepository } from '../src/database/repositories/vulnerability.repository';
import { buildFinding } from './support/factories';
import { testDatabase, resetDatabase } from './support/test-app';

describe('Data access layer + schema (system, real Postgres)', () => {
  let db: DataSource;
  let images: ImageRepository;
  let vulnerabilities: VulnerabilityRepository;

  const nginx = { name: 'nginx', tag: '1.19' };
  const vulnerabilitiesOf = (imageId: number) =>
    db.getRepository(ImageVulnerability).find({
      where: { imageId },
      order: { cveId: 'ASC', packageName: 'ASC' },
    });

  beforeAll(async () => {
    db = await new DataSource(typeOrmOptions(testDatabase())).initialize();
    images = new ImageRepository(db.getRepository(Image));
    vulnerabilities = new VulnerabilityRepository(db.getRepository(ImageVulnerability));
  });
  beforeEach(() => resetDatabase(db));
  afterAll(() => db.destroy());

  describe('schema', () => {
    it('should match the entities exactly (migration and entities have not drifted)', async () => {
      const pending = await db.driver.createSchemaBuilder().log();
      expect(pending.upQueries.map((q) => q.query)).toEqual([]);
    });
  });

  describe('ImageRepository', () => {
    it('should register images idempotently as PENDING', async () => {
      await images.track([nginx]);
      await images.track([nginx, { name: 'alpine', tag: '3.12' }]);

      const all = await images.findAllWithStats();
      expect(all.map((i) => [i.name, i.tag, i.scanStatus])).toEqual([
        ['alpine', '3.12', ScanStatus.PENDING],
        ['nginx', '1.19', ScanStatus.PENDING],
      ]);
    });

    it('should record a failure with its error and timestamp', async () => {
      const id = await images.markScanning(nginx);
      await images.markFailed(id, 'Trivy failed');

      const image = await db.getRepository(Image).findOneByOrFail({ id });
      expect(image.scanStatus).toBe(ScanStatus.FAILED);
      expect(image.lastError).toBe('Trivy failed');
      expect(image.lastScannedAt).toBeInstanceOf(Date);
    });
  });

  describe('VulnerabilityRepository.replaceFindings', () => {
    it('should store each CVE once and one finding per affected package, and mark the image SUCCESS', async () => {
      const id = await images.markScanning(nginx);
      await vulnerabilities.replaceFindings(id, [
        buildFinding({ packageName: 'openssl' }),
        buildFinding({ packageName: 'libssl1.1' }),
        buildFinding({ cveId: 'CVE-2022-0001', severity: Severity.HIGH, packageName: 'openssl' }),
      ]);

      expect(await db.getRepository(Cve).count()).toBe(2);
      expect(
        (await vulnerabilitiesOf(id)).map((v) => [v.cveId, v.packageName, v.installedVersion]),
      ).toEqual([
        ['CVE-2021-3711', 'libssl1.1', '1.1.1d-0+deb10u6'],
        ['CVE-2021-3711', 'openssl', '1.1.1d-0+deb10u6'],
        ['CVE-2022-0001', 'openssl', '1.1.1d-0+deb10u6'],
      ]);

      const image = await db.getRepository(Image).findOneByOrFail({ id });
      expect(image).toMatchObject({ scanStatus: ScanStatus.SUCCESS, lastError: null });
      expect(image.lastScannedAt).toBeInstanceOf(Date);
    });

    it('should replace the previous results on rescan, so fixed CVEs disappear', async () => {
      const id = await images.markScanning(nginx);
      await vulnerabilities.replaceFindings(id, [
        buildFinding(),
        buildFinding({ cveId: 'CVE-2022-0001' }),
      ]);
      await vulnerabilities.replaceFindings(id, [buildFinding({ cveId: 'CVE-2022-0001' })]);

      expect((await vulnerabilitiesOf(id)).map((v) => v.cveId)).toEqual(['CVE-2022-0001']);
    });

    it('should keep the last good results when a later scan fails', async () => {
      const id = await images.markScanning(nginx);
      await vulnerabilities.replaceFindings(id, [buildFinding()]);
      await images.markFailed(id, 'Trivy failed');

      expect(await vulnerabilitiesOf(id)).toHaveLength(1);
      const image = await db.getRepository(Image).findOneByOrFail({ id });
      expect(image).toMatchObject({ scanStatus: ScanStatus.FAILED, lastError: 'Trivy failed' });
    });

    it('should keep the same package name in different ecosystems apart', async () => {
      const id = await images.markScanning(nginx);
      await vulnerabilities.replaceFindings(id, [
        buildFinding({ packageType: 'deb' }),
        buildFinding({ packageType: 'apk' }),
      ]);

      expect((await vulnerabilitiesOf(id)).map((v) => v.packageType).sort()).toEqual([
        'apk',
        'deb',
      ]);
    });

    it('should store a large scan in one save', async () => {
      const id = await images.markScanning(nginx);
      const findings = Array.from({ length: 1_234 }, (_, i) =>
        buildFinding({
          cveId: `CVE-2023-${String(i).padStart(5, '0')}`,
          packageName: `pkg-${i % 300}`,
        }),
      );
      await vulnerabilities.replaceFindings(id, findings);

      expect(await db.getRepository(ImageVulnerability).countBy({ imageId: id })).toBe(1_234);
    });

    it('should save overlapping scans of the same image (e.g. a retry meeting the next run)', async () => {
      const id = await images.markScanning(nginx);
      const findings = Array.from({ length: 50 }, (_, i) =>
        buildFinding({ cveId: `CVE-2024-${String(i).padStart(4, '0')}` }),
      );

      await Promise.all([1, 2, 3].map(() => vulnerabilities.replaceFindings(id, findings)));

      expect(await vulnerabilitiesOf(id)).toHaveLength(50);
    });

    it('should save concurrent scans of images that share CVEs', async () => {
      const scanned = await Promise.all(
        ['nginx:1.19', 'alpine:3.12', 'httpd:2.4', 'redis:6.0'].map((ref) => {
          const [name, tag] = ref.split(':');
          return images.markScanning({ name, tag });
        }),
      );
      const shared = Array.from({ length: 200 }, (_, i) =>
        buildFinding({
          cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
          packageName: `lib-${i % 50}`,
        }),
      );

      await Promise.all(scanned.map((id) => vulnerabilities.replaceFindings(id, shared)));

      expect(await db.getRepository(Cve).count()).toBe(200);
      expect(await db.getRepository(ImageVulnerability).count()).toBe(800);
    });

    it('should roll back everything if any part of the save fails', async () => {
      const id = await images.markScanning(nginx);
      await vulnerabilities.replaceFindings(id, [buildFinding()]);

      const tooLong = buildFinding({ cveId: 'CVE-2022-0001', installedVersion: 'v'.repeat(300) });
      await expect(vulnerabilities.replaceFindings(id, [tooLong])).rejects.toThrow();

      expect((await vulnerabilitiesOf(id)).map((v) => v.cveId)).toEqual(['CVE-2021-3711']);
      expect(await db.getRepository(Cve).findOneBy({ id: 'CVE-2022-0001' })).toBeNull();
    });
  });
});

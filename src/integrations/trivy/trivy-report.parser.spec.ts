import { Severity } from '../../common/severity.enum';
import { parseTrivyReport } from './trivy-report.parser';
import { ScannerError } from '../vulnerability-scanner';

const report = {
  SchemaVersion: 2,
  ArtifactName: 'nginx:1.19',
  Results: [
    {
      Target: 'nginx:1.19 (debian 10.10)',
      Class: 'os-pkgs',
      Type: 'debian',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2021-3711',
          PkgName: 'libssl1.1',
          PkgIdentifier: { PURL: 'pkg:deb/debian/libssl1.1@1.1.1d-0+deb10u6?arch=amd64' },
          InstalledVersion: '1.1.1d-0+deb10u6',
          FixedVersion: '1.1.1d-0+deb10u7',
          Severity: 'CRITICAL',
          Title: 'openssl: SM2 Decryption Buffer Overflow',
          PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2021-3711',
          PublishedDate: '2021-08-24T15:15:00Z',
        },
        // Same CVE, different package — kept.
        {
          VulnerabilityID: 'CVE-2021-3711',
          PkgName: 'openssl',
          InstalledVersion: '1.1.1d-0+deb10u6',
          FixedVersion: '1.1.1d-0+deb10u7',
          Severity: 'CRITICAL',
        },
        // Exact duplicate — dropped.
        {
          VulnerabilityID: 'CVE-2021-3711',
          PkgName: 'openssl',
          InstalledVersion: '1.1.1d-0+deb10u6',
          Severity: 'CRITICAL',
        },
        {
          VulnerabilityID: 'CVE-2019-0001',
          PkgName: 'zlib1g',
          InstalledVersion: '1:1.2.11', // no FixedVersion: Trivy omits it when there's no fix
          Severity: 'weird-value',
        },
      ],
    },
    { Target: 'Node.js', Class: 'lang-pkgs', Type: 'node-pkg', Vulnerabilities: null },
  ],
};

describe('parseTrivyReport', () => {
  it('should normalize and de-duplicate findings', () => {
    const findings = parseTrivyReport(JSON.stringify(report));

    expect(findings).toHaveLength(3);
    expect(findings[0]).toEqual({
      cveId: 'CVE-2021-3711',
      severity: Severity.CRITICAL,
      title: 'openssl: SM2 Decryption Buffer Overflow',
      packageName: 'libssl1.1',
      packageType: 'deb',
      installedVersion: '1.1.1d-0+deb10u6',
      fixedVersion: '1.1.1d-0+deb10u7',
    });
  });

  it('should map unknown severities to UNKNOWN and a missing fixed version to null', () => {
    const zlib = parseTrivyReport(JSON.stringify(report)).find((f) => f.packageName === 'zlib1g')!;
    expect(zlib.severity).toBe(Severity.UNKNOWN);
    expect(zlib.fixedVersion).toBeNull();
  });

  describe('package ecosystem (stored as a package URL type, not a Trivy name)', () => {
    const typeOf = (result: object) =>
      parseTrivyReport(JSON.stringify({ Results: [result] }))[0]?.packageType;
    const vuln = (purl?: string) => ({
      VulnerabilityID: 'CVE-1',
      PkgName: 'pkg',
      InstalledVersion: '1.0',
      ...(purl ? { PkgIdentifier: { PURL: purl } } : {}),
    });

    it.each([
      ['pkg:npm/ajv@6.12.6', 'npm'],
      ['pkg:apk/alpine/busybox@1.32.1-r6', 'apk'],
      ['pkg:deb/ubuntu/libc6@2.31', 'deb'],
      ['pkg:golang/golang.org/x/net@0.1.0', 'golang'],
      ['pkg:pypi/pip@20.0.2', 'pypi'],
    ])('should read the type %s → %s from the PURL', (purl, expected) => {
      expect(typeOf({ Type: 'whatever', Vulnerabilities: [vuln(purl)] })).toBe(expected);
    });

    it("should fall back to Trivy's own type when a finding has no PURL", () => {
      expect(typeOf({ Type: 'conan', Vulnerabilities: [vuln()] })).toBe('conan');
    });
  });

  it('should return no findings for a clean image', () => {
    expect(parseTrivyReport(JSON.stringify({ SchemaVersion: 2 }))).toEqual([]);
    expect(parseTrivyReport('null')).toEqual([]);
  });

  it('should throw a transient ScannerError on invalid JSON', () => {
    expect(() => parseTrivyReport('not json')).toThrow(ScannerError);
    expect(() => parseTrivyReport('not json')).toThrow(/Invalid Trivy JSON output/);
  });
});

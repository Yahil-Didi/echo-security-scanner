import { ScanFinding } from '../../common/scan-finding';
import { normalizeSeverity } from '../../common/severity.enum';
import { ScannerError } from '../vulnerability-scanner';
import { TrivyReport, TrivyResult, TrivyVulnerability } from './trivy.types';

/** Turns Trivy's JSON report into our findings, without duplicates. */
export const parseTrivyReport = (raw: string): ScanFinding[] => {
  const report = parseJson(raw);
  const results = report?.Results ?? [];
  const findings = results.flatMap((result) =>
    (result.Vulnerabilities ?? []).map((v) => toFinding(result, v)),
  );
  // Trivy can report the same package twice (e.g. from two layers); the table keeps only one.
  const unique = new Map(findings.map((f) => [findingKey(f), f]));
  return [...unique.values()];
};

/** Reads Trivy's output as JSON; invalid output becomes a ScannerError. */
const parseJson = (raw: string): TrivyReport | null => {
  try {
    return JSON.parse(raw) as TrivyReport | null;
  } catch (err) {
    throw new ScannerError(`Invalid Trivy JSON output: ${(err as Error).message}`);
  }
};

/** Turns one Trivy vulnerability into our finding format. */
const toFinding = (result: TrivyResult, v: TrivyVulnerability): ScanFinding => ({
  cveId: v.VulnerabilityID,
  severity: normalizeSeverity(v.Severity),
  title: v.Title ?? null,
  packageName: v.PkgName,
  packageType: packageType(result, v),
  installedVersion: v.InstalledVersion ?? '',
  fixedVersion: v.FixedVersion ?? null, // Trivy omits it when there's no fix
});

/**
 * The package ecosystem as a package URL type (`deb`, `apk`, `npm`...), which all scanners use,
 * instead of a Trivy name.
 */
const packageType = (result: TrivyResult, v: TrivyVulnerability): string =>
  v.PkgIdentifier?.PURL?.match(/^pkg:([a-z0-9.+-]+)\//i)?.[1].toLowerCase() ??
  result.Type ??
  'unknown';

/** What makes a finding unique: the same columns as the table's primary key. */
const findingKey = (f: ScanFinding) =>
  [f.cveId, f.packageName, f.packageType, f.installedVersion].join('|');

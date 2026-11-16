/** The parts of Trivy's JSON report (`trivy image --format json`) that we use. */
export interface TrivyReport {
  Results?: TrivyResult[];
}

export interface TrivyResult {
  /** e.g. `debian`, `node-pkg`. Only a fallback, because every finding has a package URL. */
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[] | null;
}

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  /** Package URL, e.g. `pkg:deb/debian/libssl1.1@1.1.1d-0+deb10u6`. */
  PkgIdentifier?: { PURL?: string };
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
}

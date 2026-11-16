import { Severity } from '../../common/severity.enum';

// SQL pieces used by more than one read query. They use real column names, so each one says which
// table aliases it needs.

/**
 * The packages of each CVE (or image) as one sorted JSON list, so the query returns one row per CVE
 * instead of one per package. Needs `iv` (image_vulnerabilities).
 */
export const PACKAGES_JSON = `json_agg(
  json_build_object(
    'name', iv.package_name,
    'type', iv.package_type,
    'installedVersion', iv.installed_version,
    'fixedVersion', iv.fixed_version
  ) ORDER BY iv.package_name, iv.package_type, iv.installed_version
)`;

/** `name:tag`, in the same format as formatImageRef. Needs `i` (images). */
export const IMAGE_REF = `i.name || ':' || i.tag`;

/**
 * CVE counts per severity as one JSON object, e.g. {"CRITICAL": 3, "HIGH": 10}. Needs `iv` and `c`
 * (cves). Built from our enum, never from user input.
 */
export const CVE_COUNTS_JSON = `json_build_object(${Object.values(Severity)
  .map((s) => `'${s}', COUNT(DISTINCT iv.cve_id) FILTER (WHERE c.severity = '${s}')`)
  .join(', ')})`;

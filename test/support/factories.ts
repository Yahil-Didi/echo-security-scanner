import { ConfigService } from '@nestjs/config';
import { Severity } from '../../src/common/severity.enum';
import { configSchema, Env } from '../../src/config/config.schema';
import { ScanFinding } from '../../src/common/scan-finding';

/** A valid finding; override only what the test cares about. */
export const buildFinding = (overrides: Partial<ScanFinding> = {}): ScanFinding => {
  return {
    cveId: 'CVE-2021-3711',
    severity: Severity.CRITICAL,
    title: 'openssl: SM2 Decryption Buffer Overflow',
    packageName: 'openssl',
    packageType: 'deb',
    installedVersion: '1.1.1d-0+deb10u6',
    fixedVersion: '1.1.1d-0+deb10u7',
    ...overrides,
  };
};

/** A ConfigService validated by the real schema (defaults applied), from env-style overrides. */
export const buildConfigService = (env: Record<string, string> = {}): ConfigService<Env, true> => {
  const { value, error } = configSchema.validate(env);
  if (error) throw error;
  return new ConfigService<Env, true>(value);
};

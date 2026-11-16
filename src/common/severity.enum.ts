/**
 * Listed from most to least severe. Postgres keeps this order, so `ORDER BY severity` puts the
 * worst first.
 */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  UNKNOWN = 'UNKNOWN',
}

/** Maps any severity text to our enum; unknown values become UNKNOWN. */
export const normalizeSeverity = (value: string | undefined | null): Severity => {
  const upper = (value ?? '').toUpperCase();
  return (Object.values(Severity) as string[]).includes(upper)
    ? (upper as Severity)
    : Severity.UNKNOWN;
};

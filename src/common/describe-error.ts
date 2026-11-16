/**
 * Turns any error into one readable line. Connection errors often have an empty message, so we use
 * their code instead (e.g. ECONNREFUSED).
 */
export const describeError = (err: unknown): string => {
  if (err instanceof Error) {
    const code = (err as NodeJS.ErrnoException).code;
    return err.message || (code ? `${err.name} ${code}` : err.name);
  }
  return String(err);
};

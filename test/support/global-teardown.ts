import { EmbeddedPostgres } from './embedded-postgres';

const globalTeardown = async (): Promise<void> => {
  await (globalThis as { __PG__?: EmbeddedPostgres }).__PG__?.stop();
};

export default globalTeardown;

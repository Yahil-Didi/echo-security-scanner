import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EmbeddedPostgres, EmbeddedPostgresServer } from './embedded-postgres';

const TEST_DB = {
  host: 'localhost',
  port: 54329,
  user: 'scanner',
  password: 'scanner',
  name: 'scanner_test',
};

const startEmbeddedPostgres = async (): Promise<EmbeddedPostgres> => {
  const pg = new EmbeddedPostgresServer({
    databaseDir: mkdtempSync(join(tmpdir(), 'scanner-test-pg-')),
    user: TEST_DB.user,
    password: TEST_DB.password,
    port: TEST_DB.port,
    persistent: false,
    initdbFlags: ['--encoding=UTF8', '--locale=C'],
    onLog: () => {},
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase(TEST_DB.name);
  return pg;
};

/**
 * Starts a throwaway PostgreSQL for the system tests, so it runs anywhere `npm install` works,
 * with no Docker needed. Set TEST_DB_HOST (+ TEST_DB_PORT/USER/PASSWORD/NAME) to use an existing
 * database instead, e.g. the docker-compose one.
 */
const globalSetup = async (): Promise<void> => {
  if (process.env.TEST_DB_HOST) return;
  (globalThis as { __PG__?: EmbeddedPostgres }).__PG__ = await startEmbeddedPostgres();
  Object.assign(process.env, {
    TEST_DB_HOST: TEST_DB.host,
    TEST_DB_PORT: String(TEST_DB.port),
    TEST_DB_USER: TEST_DB.user,
    TEST_DB_PASSWORD: TEST_DB.password,
    TEST_DB_NAME: TEST_DB.name,
  });
};

export default globalSetup;

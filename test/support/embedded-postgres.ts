/**
 * `embedded-postgres` is an ES module, while Nest (and so Jest here) compiles to CommonJS, and its
 * types only resolve under node16/bundler module resolution. Node 20.19+ / 22.12+ can `require()`
 * an ES module, so load it that way and describe the small part of its API we use.
 */
export interface EmbeddedPostgres {
  initialise(): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  createDatabase(name: string): Promise<void>;
}

export interface EmbeddedPostgresOptions {
  databaseDir: string;
  user: string;
  password: string;
  port: number;
  persistent: boolean;
  initdbFlags?: string[];
  onLog?: (message: string) => void;
}

type EmbeddedPostgresConstructor = new (options: EmbeddedPostgresOptions) => EmbeddedPostgres;

export const EmbeddedPostgresServer =
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  (require('embedded-postgres') as { default: EmbeddedPostgresConstructor }).default;

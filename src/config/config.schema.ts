import * as Joi from 'joi';

const DEFAULT_IMAGES = [
  'nginx:1.19',
  'postgres:12',
  'redis:6.0',
  'node:14-alpine',
  'python:3.8-slim',
  'alpine:3.12',
  'ubuntu:20.04',
  'mysql:8.0',
  'mongo:4.4',
  'httpd:2.4',
];

/** All settings, with their types. Read one with `config.get('NAME', { infer: true })`. */
export interface Env {
  PORT: number;
  DB_HOST: string;
  DB_PORT: number;
  DB_USER: string;
  DB_PASSWORD: string;
  DB_NAME: string;
  REDIS_HOST: string;
  REDIS_PORT: number;
  /** Comma-separated `name:tag` list. */
  SCAN_IMAGES: string;
  SCAN_INTERVAL_MS: number;
  SCAN_TIMEOUT_MS: number;
  SCAN_CONCURRENCY: number;
  TRIVY_BINARY: string;
}

/** Checked when the app starts: a wrong value stops the app, and a missing one gets its default. */
export const configSchema = Joi.object<Env>({
  PORT: Joi.number().port().default(3000),

  DB_HOST: Joi.string().default('localhost'),
  DB_PORT: Joi.number().port().default(5432),
  DB_USER: Joi.string().default('scanner'),
  DB_PASSWORD: Joi.string().allow('').default('scanner'),
  DB_NAME: Joi.string().default('scanner'),

  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().port().default(6379),

  SCAN_IMAGES: Joi.string().default(DEFAULT_IMAGES.join(',')),
  SCAN_INTERVAL_MS: Joi.number().integer().min(60_000).default(900_000), // 15 min
  SCAN_TIMEOUT_MS: Joi.number().integer().min(1_000).default(600_000), // 10 min
  // How many images one app instance scans at the same time. Each Trivy run uses a lot of CPU and
  // network.
  SCAN_CONCURRENCY: Joi.number().integer().min(1).max(10).default(10),

  TRIVY_BINARY: Joi.string().default('trivy'),
});

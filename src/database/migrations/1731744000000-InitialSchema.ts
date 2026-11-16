import { MigrationInterface, QueryRunner } from 'typeorm';

/** Creates the schema, in dependency order. */
const UP = [
  `CREATE TYPE "images_scan_status_enum" AS ENUM ('PENDING', 'SCANNING', 'SUCCESS', 'FAILED')`,
  `CREATE TYPE "cves_severity_enum" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')`,
  `CREATE TABLE "images" (
    "id" SERIAL PRIMARY KEY,
    "name" varchar(255) NOT NULL,
    "tag" varchar(128) NOT NULL,
    "scan_status" "images_scan_status_enum" NOT NULL DEFAULT 'PENDING',
    "last_scanned_at" timestamptz,
    "last_error" text,
    CONSTRAINT "uq_images_name_tag" UNIQUE ("name", "tag")
  )`,
  `CREATE TABLE "cves" (
    "id" varchar(64) PRIMARY KEY,
    "severity" "cves_severity_enum" NOT NULL DEFAULT 'UNKNOWN',
    "title" text
  )`,
  // The primary key starts with image_id, so it also serves per-image reads and deletes.
  `CREATE TABLE "image_vulnerabilities" (
    "image_id" integer NOT NULL CONSTRAINT "fk_image_vuln_image" REFERENCES "images" ("id") ON DELETE CASCADE,
    "cve_id" varchar(64) NOT NULL CONSTRAINT "fk_image_vuln_cve" REFERENCES "cves" ("id") ON DELETE CASCADE,
    "package_name" varchar(255) NOT NULL,
    "package_type" varchar(64) NOT NULL,
    "installed_version" varchar(255) NOT NULL,
    "fixed_version" varchar(255),
    PRIMARY KEY ("image_id", "cve_id", "package_name", "package_type", "installed_version")
  )`,
  `CREATE INDEX "idx_image_vuln_cve" ON "image_vulnerabilities" ("cve_id")`,
];

/** Drops it again, in reverse dependency order. */
const DOWN = [
  `DROP TABLE "image_vulnerabilities"`,
  `DROP TABLE "cves"`,
  `DROP TABLE "images"`,
  `DROP TYPE "cves_severity_enum"`,
  `DROP TYPE "images_scan_status_enum"`,
];

export class InitialSchema1731744000000 implements MigrationInterface {
  name = 'InitialSchema1731744000000';

  public async up(q: QueryRunner): Promise<void> {
    for (const sql of UP) await q.query(sql);
  }

  public async down(q: QueryRunner): Promise<void> {
    for (const sql of DOWN) await q.query(sql);
  }
}

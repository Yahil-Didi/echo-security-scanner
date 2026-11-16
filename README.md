# Echo Security Scanner

Scans 10 Docker images with Trivy every 15 minutes, saves the CVEs in Postgres and serves them
over a REST API. NestJS, TypeORM, BullMQ (Redis), Trivy CLI.

[Brief](docs/ASSIGNMENT.md) · [API examples](docs/API.md) · [DB schema](docs/DATABASE.md)

## Running it

You need Node 22, Docker and Trivy 0.76.2 (`winget install AquaSecurity.Trivy --version 0.76.2` or
`brew install trivy`). On Windows, open a new terminal after installing so `trivy` is on the PATH.

```bash
trivy --version
docker compose up -d postgres redis pgadmin
npm install
npm run start:dev
```

Or run everything in Docker, with Trivy inside the app image:

```bash
docker compose up --build
```

On a clean machine all 10 images are scanned in about 2 minutes. What keeps it fast:

- Trivy's vulnerability DB is downloaded once and shared by all scans, which skip their own update.
- Image layers are cached in Redis, so a rescan takes a few seconds.
- Up to 10 scans run in parallel (`SCAN_CONCURRENCY`).
- New images are scanned right away. After a restart they keep their schedule, so to scan now,
  promote the delayed jobs in Bull Board.

| What       | URL                                |
| ---------- | ---------------------------------- |
| API        | http://localhost:3000/api          |
| Swagger    | http://localhost:3000/docs         |
| Bull Board | http://localhost:3000/admin/queues |
| Health     | http://localhost:3000/health       |
| pgAdmin    | http://localhost:5050 (no login)   |

Bull Board and pgAdmin are just there to watch the jobs and the data.

## API

| Endpoint                                          | Returns                                    |
| ------------------------------------------------- | ------------------------------------------ |
| `GET /api/images`                                 | Images with scan status and CVE counts     |
| `GET /api/images/:image_name/:tag/cves?severity=` | CVEs of an image, with affected packages   |
| `GET /api/cves?severity=`                         | All CVEs and how many images each affects  |
| `GET /api/cves/:cve_id/images`                    | Images affected by a CVE                   |
| `GET /health`                                     | 200 if Postgres and Redis are up, else 503 |

## Design

```
startup  -> one BullMQ job scheduler per image -> a scan job every 15 min
scan job -> trivy image --format json -> parse -> save in one transaction
```

- One BullMQ scheduler per image, with a fixed id, so restarts don't duplicate schedules and one
  broken image doesn't block the others.
- Rate limits, network errors and timeouts are retried 3 times with backoff. A missing image
  isn't retried until the next run. A failed scan keeps the last results.
- Trivy runs with `execFile` (no shell) and a timeout.
- Each endpoint is a single SQL query. See [DATABASE.md](docs/DATABASE.md).

The scan job only depends on a `VulnerabilityScanner` interface
([vulnerability-scanner.ts](src/integrations/vulnerability-scanner.ts)). To use Grype or Snyk
instead, implement `scan()` and change the binding in
[scans.module.ts](src/scans/scans.module.ts). The tables and the API stay the same.

## Scaling

Every instance runs the API and a worker on the same queue, and BullMQ gives each job to one
worker, so adding instances adds scan capacity. Trivy's layer cache is in Redis, so parallel
scans share it. The findings table only keeps the latest scan, so it doesn't grow over time.

Left out on purpose: auth, scan history and image digests.

## Tests

```bash
npm run test:unit
npm run test:system
```

System tests run against an embedded Postgres, so they don't need Docker.

The tests are a small sample of the important parts (Trivy runner and parser, scan worker, scheduler,
API and repositories), not full coverage.

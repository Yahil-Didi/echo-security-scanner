# API

Base URL `http://localhost:3000`. Interactive docs with every response schema:
**<http://localhost:3000/docs>** (Swagger UI; raw spec at `/docs-json`).

- Severity filters accept one value, a comma-separated list or a repeated parameter,
  case-insensitive: `?severity=high`, `?severity=CRITICAL,HIGH`, `?severity=CRITICAL&severity=HIGH`.
  Values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
- Invalid values or unknown query parameters return `400`; unknown images or CVEs return `404`.
- Lists are sorted most severe first.

The examples below are real responses (shortened to the first items).

## `GET /api/images`

All tracked images with CVE counts per severity.

```bash
curl http://localhost:3000/api/images
```

```json
{
  "total": 10,
  "images": [
    {
      "name": "nginx",
      "tag": "1.19",
      "image": "nginx:1.19",
      "scanStatus": "SUCCESS",
      "lastScannedAt": "2026-11-16T23:14:24.106Z",
      "lastError": null,
      "totalCves": 278,
      "cvesBySeverity": { "CRITICAL": 34, "HIGH": 92, "MEDIUM": 119, "LOW": 24, "UNKNOWN": 9 }
    }
  ]
}
```

A failed scan keeps the previous counts and explains itself, e.g.
`"scanStatus": "FAILED", "lastError": "Image redis:6.0 not found or access denied: … MANIFEST_UNKNOWN …"`.

## `GET /api/images/:image_name/:tag/cves`

CVEs in one image, each with its affected packages. Optional `severity`.

```bash
curl "http://localhost:3000/api/images/nginx/1.19/cves?severity=CRITICAL"
```

```json
{
  "name": "nginx",
  "tag": "1.19",
  "image": "nginx:1.19",
  "scanStatus": "SUCCESS",
  "lastScannedAt": "2026-11-16T23:14:24.106Z",
  "lastError": null,
  "totalCves": 34,
  "cves": [
    {
      "cveId": "CVE-2018-25009",
      "severity": "CRITICAL",
      "title": "libwebp: out-of-bounds read in WebPMuxCreateInternal",
      "packages": [
        { "name": "libwebp6", "type": "deb", "installedVersion": "0.6.1-2", "fixedVersion": "0.6.1-2+deb10u1" }
      ]
    }
  ]
}
```

## `GET /api/cves`

All unique CVEs across all images, with how many images each affects: most severe, then most
widespread, first. Optional `severity`.

```bash
curl "http://localhost:3000/api/cves?severity=CRITICAL"
```

```json
{
  "total": 50,
  "cves": [
    {
      "cveId": "CVE-2023-45853",
      "severity": "CRITICAL",
      "title": "zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6",
      "affectedImages": 4
    }
  ]
}
```

## `GET /api/cves/:cve_id/images`

All images affected by a CVE (the ID is case-insensitive), with the affected packages per image.

```bash
curl http://localhost:3000/api/cves/CVE-2023-45853/images
```

```json
{
  "cveId": "CVE-2023-45853",
  "severity": "CRITICAL",
  "title": "zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6",
  "totalImages": 4,
  "images": [
    {
      "name": "nginx",
      "tag": "1.19",
      "image": "nginx:1.19",
      "packages": [
        { "name": "zlib1g", "type": "deb", "installedVersion": "1:1.2.11.dfsg-1", "fixedVersion": null }
      ]
    }
  ]
}
```

## `GET /health`

Pings PostgreSQL and Redis (with a timeout). `200` when both answer, `503` naming the one that
doesn't.

```bash
curl http://localhost:3000/health
```

```json
{
  "status": "ok",
  "info": { "database": { "status": "up" }, "redis": { "status": "up" } },
  "error": {},
  "details": { "database": { "status": "up" }, "redis": { "status": "up" } }
}
```

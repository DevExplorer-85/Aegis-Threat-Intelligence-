# Chapter 14 — Monitoring, Alerts, Backup & Recovery

Chapter 14 extends the existing FastAPI and MongoDB application. It does not use dashboard fixtures for live state. If MongoDB, the backup directory, or MongoDB Database Tools are unavailable, the API returns an unavailable/configuration-required state and does not create a successful backup record.

## Architecture

- `backend/app/lab14_api.py` samples the application MongoDB deployment and persists samples and alerts in `lab14_metrics` and `lab14_alerts` in the configured application database.
- FastAPI starts a background sampler at startup. The default interval is 30 seconds. `serverStatus` supplies connections, WiredTiger cache counters, and operation counters. `replSetGetStatus` supplies secondary optime timestamps when the source is a replica set. Standalone deployments report replication lag as not applicable.
- Open warning alerts are deduplicated by metric and affected member. Acknowledgements record the authenticated moderator and timestamp.
- An optional incoming webhook uses a shared token and writes to the same alert collection.
- Backups use MongoDB Database Tools `mongodump`, write compressed archives to a private directory, record the actual file size and SHA-256 checksum, and only then persist success metadata.
- Restore verification uses a separate `mongo-verify` service. It checks the archive checksum, restores into a random `lab14_verify_*` database, reads back collection counts, and removes only that generated scratch database. It refuses to run when the verification target resolves to the source deployment.
- Backup files are not served by FastAPI. The backup directory is created with mode `0700`; files are created with mode `0600`.

## Data sources and thresholds

| Signal | MongoDB source | Warning threshold |
| --- | --- | --- |
| Cache hit ratio | `serverStatus.wiredTiger.cache` page counters | Below 80% |
| Replication lag | Primary/secondary `optimeDate` from `replSetGetStatus` | Above 10 seconds |
| Connections | `serverStatus.connections.current` | Informational |
| Operations per second | Delta of `serverStatus.opcounters` between actual samples | Informational |
| Cache usage | `serverStatus.wiredTiger.cache` bytes currently in cache | Informational |

Cache ratio is calculated from measured page counters as `(requested - read_into_cache) / requested`. Operation rates are unavailable until two samples exist. No historical points are backfilled.

## Webhook configuration

Set `LAB14_ALERT_WEBHOOK_TOKEN` in the root Compose `.env`. Send JSON to `POST /api/webhooks/lab14/alerts` with the same value in `X-Lab14-Webhook-Token`:

```json
{
  "metric": "replication_lag_seconds",
  "actual_value": 12.4,
  "threshold": 10,
  "member": "mongo1:27017",
  "severity": "WARNING"
}
```

The endpoint returns HTTP 503 until a webhook token is configured and HTTP 401 for a missing or invalid token. Do not put the token in source control or a browser URL.

## Backup storage and schedule

The Compose app writes backups under `./output/backups` on the host (mounted at `/app/output/backups` in the app container). Existing MongoDB named volumes are untouched. The sampler runs an automatic backup every hour by default, after the first interval. Set `LAB14_BACKUP_ENABLED=false` to disable scheduled backups while retaining manual operation.

Required runtime configuration:

| Variable | Compose default | Purpose |
| --- | --- | --- |
| `LAB14_BACKUP_DIR` | `/app/output/backups` | Private backup archive directory |
| `LAB14_BACKUP_ENABLED` | `true` | Enable scheduled backups |
| `LAB14_BACKUP_INTERVAL_SECONDS` | `3600` | Scheduled backup interval |
| `LAB14_SAMPLE_INTERVAL_SECONDS` | `30` | Monitoring sampling interval |
| `LAB14_RESTORE_VERIFY_URI` | isolated `mongo-verify` service | Separate restore target; do not point at production |
| `LAB14_ALERT_WEBHOOK_TOKEN` | unset | Optional incoming webhook authentication |
| `LAB14_RPO_TARGET_SECONDS` | `3600` | Maximum target age of latest successful backup |
| `LAB14_RTO_TARGET_SECONDS` | `900` | Maximum target duration of a successful restore verification |
| `LAB14_MONGODUMP_PATH` | auto-detected | Override `mongodump` executable |
| `LAB14_MONGORESTORE_PATH` | auto-detected | Override `mongorestore` executable |

The Docker image installs MongoDB Database Tools. When running outside Compose, install the official MongoDB Database Tools, set `LAB14_BACKUP_DIR`, and configure `LAB14_RESTORE_VERIFY_URI` to a separate disposable MongoDB deployment. If any required part is missing, the dashboard shows configuration required and the action fails without recording success.

## RPO and RTO

- **RPO** is reported as the age of the newest backup file that still exists and has non-zero size. The configured target is compared with this measured age. With no valid backup, the current RPO is unknown and outside target.
- **RTO** is reported from the elapsed time of the most recent successful isolated restore verification. With no successful verification, RTO is unmeasured; the dashboard does not infer it from backup duration.

## APIs

Admin endpoints require a Bearer token for an Aegis administrator:

- `GET /api/services/lab14` — latest sample, active alerts, valid backup history, backup benchmark, and RPO/RTO.
- `GET /api/ops/metrics/monitoring?minutes=30|120|720` — actual samples and alerts in the selected window.
- `POST /api/ops/lab14/backup` — run a real `mongodump`; returns configuration or tool errors when it cannot complete.
- `POST /api/ops/lab14/verify` — checksum and restore the latest valid archive to the isolated target and report actual restored collection/document counts.

Admin and threat-hunter alert moderators can use:

- `GET /api/moderation/alerts?status=open|acknowledged|all`
- `POST /api/moderation/alerts/ack` with `{"alert_id":"…"}`

Incoming alert webhooks use:

- `POST /api/webhooks/lab14/alerts` with the `X-Lab14-Webhook-Token` header.

## Workspace routes

- `/extras/lab14` — Chapter 14 workspace.
- `/admin/ops?tab=backups` — backup operations workspace; the existing deployment tab remains Chapter 13.
- `/admin/ops?tab=monitoring` — monitoring charts.
- `/moderation?tab=alerts` — alert acknowledgement queue.

The dashboard requires an authenticated admin for operations and backup actions. Threat hunters can review and acknowledge alerts. Guest analysts cannot read operational or backup metadata.

## Run and verify

From the project root, start the updated application and the isolated verification service:

```bash
docker compose up -d --build
```

Open `http://localhost:8000/extras/lab14`. Use Aegis admin sign-in for metrics and backup operations. Check the live state before performing a manual backup; a successful response includes the real archive name and size. Restore verification writes only to the disposable verification service.

Run Chapter 14 tests from `backend/`:

```bash
./.venv_mac/bin/pytest -q tests/test_lab14.py
```


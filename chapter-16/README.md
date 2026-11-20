# Chapter 16 — Cassandra and Neo4j

Chapter 16 adds a real polyglot investigation workspace to Aegis. MongoDB remains authoritative for account and transaction evidence; Cassandra stores a durable audit timeline; Neo4j stores only explicit account/device relationships. The workspace is at `/extras/lab16`, the administrator audit view at `/admin/ops?tab=audit`, and moderator fraud review at `/moderation?tab=fraud`.

## Architecture and data ownership

| Store | Responsibility | Chapter 16 data |
|---|---|---|
| MongoDB | Account/transaction source and audit outbox | By default reads `lab10_accounts` and `lab10_transfer_history`; writes pending audit events to `lab16_audit_outbox` before attempting Cassandra. |
| Cassandra | Distributed time-series audit history | `aegis_intel.audit_by_day`, `audit_by_actor_day`, `audit_by_user_day`, and `audit_by_target_day`. The first partitions by event day; the others support actor, username, and account-target timelines. |
| Neo4j | Explicit graph edges | `(:Account {account_id})-[:USES_DEVICE]->(:Device {device_id})`; unique constraints protect each ID. |

The Mongo outbox is written first. A Cassandra event is marked delivered only after its Cassandra inserts succeed. If Cassandra is unavailable, the event remains pending and can be flushed after a successful health check. Inserts use a stable event ID, so retries are idempotent by Cassandra primary key. A failure in one evidence source is returned as unavailable/skipped; it is never interpreted as a negative fraud result.

Neo4j is populated only by **Sync explicit device links** or `POST /api/ops/lab16/graph/sync`. The sync reads the configured Mongo account collection and creates edges only for string values already present in `device_ids`. It does not infer relationships from common account names, balances, or transaction history. Investigation traverses at most three hops.

## Docker Compose

The default Aegis stack remains unchanged and does not start the memory-heavy Chapter 16 databases. The optional services use the `chapter16` Compose profile:

```sh
cp .env.example .env   # if needed; preserve any existing local environment values
# Set LAB16_NEO4J_PASSWORD in .env to a private value of at least 8 characters.
docker compose build cti   # include current Chapter 16 API and database drivers
docker compose up -d mongo1 mongo-verify cti
docker compose --profile chapter16 up -d lab16-cassandra lab16-neo4j
```

Allow roughly **2 GB RAM for Cassandra and 1 GB for Neo4j**. The dashboard Start/Stop controls manage the Chapter 16 containers through the existing Docker socket. A container's running state is shown separately from connectivity: “Online” requires a successful Cassandra/Neo4j driver query. The UI also displays circuit breaker state and the real Mongo outbox pending count.

To use the API's Start button to create a missing container, `cti` needs Docker socket access, a Docker network matching `LAB16_DOCKER_NETWORK`, and the Neo4j password in the API container environment. Compose mounts the socket and connects the service containers to `mongodb-labs-net`. To stop optional services:

```sh
docker compose --profile chapter16 stop lab16-cassandra lab16-neo4j
```

The API can also start/stop services that already exist. If started by the API, their persistent named volumes are `lab16_cassandra_data` and `lab16_neo4j_data`.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `LAB16_CASSANDRA_CONTACT_POINTS` | `localhost` outside Compose; `lab16-cassandra` in `cti` | Comma-separated Cassandra hosts. |
| `LAB16_CASSANDRA_PORT` | `9042` | Native protocol port. |
| `LAB16_CASSANDRA_KEYSPACE` | `aegis_intel` | Chapter 16 keyspace, created on a successful connection. |
| `LAB16_CASSANDRA_USERNAME` / `LAB16_CASSANDRA_PASSWORD` | unset | Optional Cassandra authentication. |
| `LAB16_CASSANDRA_TIMEOUT_SECONDS` | `3` | Connection and health-query timeout. |
| `LAB16_NEO4J_URI` | `bolt://localhost:7687` outside Compose; `bolt://lab16-neo4j:7687` in `cti` | Neo4j Bolt URI. |
| `LAB16_NEO4J_USERNAME` | `neo4j` | Neo4j login. |
| `LAB16_NEO4J_PASSWORD` | unset | Required to start/use Neo4j; never returned by APIs. |
| `LAB16_NEO4J_DATABASE` | `neo4j` | Neo4j database. |
| `LAB16_ACCOUNTS_COLLECTION` | `lab10_accounts` | MongoDB account collection. Documents should use `account_id`; explicit graph links may be stored in `device_ids: [string, ...]`. Optional real risk fields: `risk_level`, `risk_score`, `risk_signals`, `fraud_flag`, `investigation_status`. |
| `LAB16_TRANSACTIONS_COLLECTION` | `lab10_transfer_history` | MongoDB transaction history; account association supports `source_id`, `destination_id`, or `account_id`. |
| `LAB16_CIRCUIT_FAILURE_THRESHOLD` | `3` | Consecutive failures before opening a service breaker. |
| `LAB16_CIRCUIT_RESET_SECONDS` | `30` | Open interval before a health/query attempt can enter half-open. |
| `LAB16_DOCKER_NETWORK` | `mongodb-labs-net` | Network used by service controls when creating containers. |

For local Python development, install core requirements (which include the Cassandra, Neo4j, and Docker SDKs):

```sh
cd backend
python -m pip install -r requirements-core.txt
```

## APIs

- `GET /api/services/lab16` — authenticated admin; real Mongo ping, Cassandra `system.local` query, Neo4j `RETURN 1`, breaker state, last success, container state, and pending audit count.
- `POST /api/services/lab16/start` and `POST /api/services/lab16/stop` — authenticated admin; JSON body may specify `{"services":["cassandra"]}`, `neo4j`, or both.
- `GET /api/ops/audit?day=2026-11-15&actor=<actor-id>&limit=200&username=<name>&role=<role>&action=<text>&outcome=ok&target=<account-id>` — admin or existing `audit_logs` permission. Day and actor can be combined; all filters are bounded and values are bound as CQL parameters.
- `GET /api/ops/audit/summary?days=7` — permitted audit summary with categories, event counts, failed/refused count, and measured Cassandra query time.
- `GET /api/moderation/fraud` and `GET /api/moderation/fraud/{account}` — admin or existing moderator permissions; account PII is returned only to roles with `view_unredacted_pii` (or `all`). Evidence includes per-source success/skipped status, query timings, and breaker state.
- `POST /api/ops/lab16/graph/sync` — admin only; reads account records and merges explicit `device_ids` edges into Neo4j.

No browser endpoint accepts arbitrary CQL/Cypher. API responses never contain database passwords or full connection URIs.

## Audit queries

Example audit searches:

```sh
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8000/api/ops/audit?day=2026-11-15&limit=200'
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8000/api/ops/audit?actor=admin_master_1&day=2026-11-15'
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8000/api/ops/audit/summary?days=7'
```

Audit outcome values are `ok`, `refused`, and `failed`; the UI labels them OK, Refused, and Failed. The UI exposes the prepared CQL shape and actual measured execution time, never interpolated query values or arbitrary statements.

## Fraud investigation

```sh
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8000/api/moderation/fraud'
curl -H "Authorization: Bearer $TOKEN" 'http://localhost:8000/api/moderation/fraud/account-001'
```

The default Mongo collection names match the Chapter 10 transaction lab. The demo account records contain balances and versions but no fraud signals or device IDs; such accounts remain **unscored** until real evidence fields are present. Add explicit `device_ids` to an authorized account record, run graph sync, then inspect shared devices and three-hop paths. Do not use generated example edges as live investigation evidence.

## Circuit breakers and partial failure

Each database has an independent in-process breaker. After the configured consecutive failures it opens; calls are marked skipped until the reset interval, then a probe is allowed. Successful driver operations close the breaker. Pending audit events remain in MongoDB while Cassandra is stopped and are retried after Cassandra is reachable. If MongoDB cannot persist the outbox event, Chapter 16 reports that persistence failure; it does not claim Cassandra durability. Breaker state is local to each API process, so run one API replica for this demonstration or move breaker state to a shared coordination store before scaling out.

## Tests

Run the mocked unit suite:

```sh
cd backend
PYTHONPATH=. python -m pytest tests/test_lab16.py -q
```

The tests mock external services and exercise roles, health checks, start/stop handlers, outbox insertion, audit filters/summaries, fraud evidence, graph traversal, explicit shared-device sync, and partial failure. For a live integration check, set the environment variables above, run the Compose profile, sign in as an admin, use **Service Management** and **Sync explicit device links**, then search the audit and fraud views. Live checks require MongoDB, Cassandra, Neo4j, and Docker socket access; Neo4j requires the configured password.

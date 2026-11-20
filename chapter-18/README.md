# Chapter 18 — Comparative Database Capstone

Chapter 18 compares MongoDB, Cassandra and Neo4j using the same imported threat records. MongoDB `fp.full_threats` is the canonical store; Cassandra query tables and Neo4j relationship evidence are populated only after MongoDB confirms each row by read-back. Peer failures remain visible in the ingestion job.

## Data and labels

- “Ingest recent records” reads configured `working_set_test` and `threat_reports` MongoDB collections. It does not create demo records.
- JSON imports require a dataset label and stable `source_id` for duplicate-safe IDs.
- `ground_truth_false_positive` must be an explicit boolean. Precision, recall, F1 and voting evaluation remain unavailable until labelled records exist.
- Candidate status is a review prompt based on source-provided benign/false-positive tags or a supplied candidate reason. A candidate is not an adjudication.
- Analyst decisions require a note and explicit confirmation; decision history is append-only. Confirmed false positives are filtered from the Chapter 18 export while historical records remain intact.

## Database requirements

MongoDB uses the configured application connection. Cassandra and Neo4j use the existing Chapter 16 adapters and credentials (`LAB16_CASSANDRA_*`, `LAB16_NEO4J_*`). Start those services with the project’s Chapter 16 Compose profile, then restart the API so it can connect. Unavailable stores are shown as unavailable; they are never reported as empty or healthy.

## Workspace and APIs

- `/extras/lab18` — full Chapter 18 workspace
- `/moderation?tab=fp` — false-positive review
- `/admin/ops?tab=sources` — comparative source report
- `GET /api/services/lab18`, `POST /api/ops/lab18/ingest`, `GET /api/ops/lab18/ingest`
- `POST /api/ops/lab18/benchmark`, `GET /api/moderation/fp`, `GET /api/moderation/fp/value`
- `POST /api/moderation/fp/decision`, `GET /api/moderation/fp/evaluation`, `GET /api/ops/sources`, `GET /api/ops/report.pdf`, `GET /api/ops/lab18/export`

All routes use the project’s existing admin or moderator authentication dependencies. Benchmark actions execute ten measured runs per query/store; unavailable queries retain errors and null medians. PDF scalability figures are explicitly labelled estimates, never measurements.

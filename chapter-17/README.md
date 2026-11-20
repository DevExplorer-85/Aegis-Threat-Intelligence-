# Chapter 17 · Vector Search and RAG

Chapter 17 adds Ask CTI: evidence-grounded questions over the MongoDB threat report library. A signed-in user asks at `/ask`; an administrator manages indexing at `/extras/lab17` or `/admin/ops?tab=ask`.

## Architecture

1. The index job reads non-empty `security_reports.content` and normalized `security_report_passages.passage` records. It prefers existing page-numbered passages; otherwise it keeps explicit page breaks or uses stable 500-word source windows. It normalizes text, then creates overlapping 900-word chunks (120-word overlap).
2. The configured embedding endpoint creates vectors in batches of 32 chunks. MongoDB stores each vector, its model and dimension, report/page metadata, and stable chunk ID in `ask_vector_chunks`. Re-indexing is idempotent. A model or dimension mismatch stops the run rather than mixing vector spaces.
3. The backend attempts to create the configured Atlas Vector Search HNSW index. When MongoDB reports it `READY`, retrieval uses `$vectorSearch`; on local MongoDB or unavailable Atlas Search, retrieval performs a measured exact cosine scan over compatible stored vectors.
4. The optional chat-completion provider receives the question and retrieved excerpts with instructions to cite each claim. When it is absent or unreachable, Ask CTI returns a plainly labelled extractive answer. The UI never presents that as an LLM answer.
5. Sources include report title, page, relevance score, report ID, and retrieved text. User history is queried and deleted by authenticated user ID.

## Providers and configuration

Set these values in the backend environment (for Compose, copy `.env.example` to `.env`). Keys are never included in frontend assets or API responses.

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMBEDDING_API_URL` | `https://api.openai.com/v1/embeddings` | OpenAI-compatible embeddings endpoint |
| `EMBEDDING_API_KEY` | empty | Required to index and ask semantic questions |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Must remain the same for all vectors in an index |
| `LLM_API_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible chat API base |
| `LLM_API_KEY` | empty | Optional; absent/unavailable providers use extractive fallback |
| `LLM_MODEL` | `gpt-4o-mini` | Chat completion model |
| `LAB17_VECTOR_INDEX` | `ask_vector_index` | Atlas Search index name |
| `LAB17_MIN_RELEVANCE` | `0.20` | Minimum cosine/vector score shown as supporting evidence |

OpenAI-compatible providers can be used by setting the appropriate endpoint, key, and model. The embedding provider must return a finite numeric vector; dimension is recorded from the first result and checked on every query.

## API

All Ask and admin APIs require a valid `Authorization: Bearer <session-token>`.

| Method and path | Access | Purpose |
| --- | --- | --- |
| `POST /api/ask` | Signed-in users | Embed question, retrieve chunks, generate cited answer or extractive fallback |
| `GET /api/ask/history` | Signed-in user | Return only that user's conversation history |
| `DELETE /api/ask/history` | Signed-in user | Forget only that user's conversation history |
| `GET /api/ops/ask-index` | Admin | Index counts, provider/index status, job progress, answer counts |
| `POST /api/ops/ask-index` | Admin | Start one protected indexing job; duplicate active jobs return 409 |
| `GET /api/services/lab17` | Admin | Current provider, vector-index, and job state |
| `POST /api/ops/ask-benchmark` | Admin | Measure exact cosine, in-memory IVF-style coarse-list, and READY Atlas HNSW if available |
| `GET /api/ops/ask-benchmark` | Admin | Recent measured benchmark records |

## Vector indexing and benchmarks

Atlas Vector Search uses HNSW when its Search index is ready. The index job attempts Vector Search index creation and reports failures. This project's Compose stack runs MongoDB 7.0, so it uses exact cosine retrieval unless you configure Atlas or a compatible self-managed MongoDB deployment. MongoDB currently documents HNSW and flat indexing methods; Chapter 17 labels MongoDB IVF unsupported rather than inventing database results. The benchmark measures actual durations and recall against exact top-5 over its sampled vectors. Its in-memory IVF-style method is an educational coarse-centroid inverted-list implementation, explicitly identified in its configuration. The benchmark caps its scan corpus at 2,000 vectors to keep the interactive workspace bounded. See [MongoDB Vector Search compatibility and index methods](https://www.mongodb.com/docs/vector-search/).

## Run

Local backend:

```bash
cd backend
python -m pip install -r requirements-core.txt
EMBEDDING_API_KEY=... LLM_API_KEY=... MONGO_URI=mongodb://localhost:27017 uvicorn app.main:app --reload --port 8000
```

Docker Compose:

```bash
cp .env.example .env
# Set EMBEDDING_API_KEY; LLM_API_KEY is optional.
docker compose up -d --build cti
```

Sign in through the Aegis app. Open `/extras/lab17`, choose **Document Index**, and start indexing. Wait for completed chunks and review any actual failures. Then open `/ask` and ask a question. Without an embedding key, indexing and semantic retrieval cannot run; without an LLM key, retrieved answers are clearly labelled extractive.

Run the Chapter 17 mocked unit tests from the project root:

```bash
PYTHONPATH=backend python -m pytest -q backend/tests/test_lab17.py
```

## Verification

Unit tests use mocked MongoDB/provider responses and do not incur API cost. To exercise real integration behavior, configure a reachable MongoDB database with report documents and provider keys, sign in as admin, index the reports, then ask a question and confirm citations refer to stored report/page values. For Atlas HNSW, use an Atlas deployment with Vector Search enabled; local MongoDB can only verify the exact-scan path. Benchmarking uses live indexed vectors; no HNSW measurements are shown unless the READY MongoDB index executes successfully.

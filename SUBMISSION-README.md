# Cyber Threat Intelligence Lab 7

## Data sources and freshness

The canonical threat-intelligence data is fetched from the exact public sources below. The synchronizer reads each MISP `manifest.json`, downloads only unknown or newer events, and upserts events by `(feed_id, event_uuid)`. Each event stores its original MISP UUID, feed ID, source slug and source feed URL. MISP attributes are stored separately in `indicators` and refer to their event by UUID.

| Collection or data | Source | Fetch method | Update cadence |
|---|---|---|---|
| `feed_events` | [CIRCL OSINT](https://www.circl.lu/doc/misp/feed-osint), [Botvrij.eu](https://www.botvrij.eu/data/feed-osint), [abuse.ch ThreatFox](https://threatfox.abuse.ch/downloads/misp) | HTTPS MISP feed: read `<feed-url>/manifest.json`, then fetch `<feed-url>/<uuid>.json` for new or changed timestamps. | Run incrementally; daily schedule instructions below. |
| `indicators` | Attributes in those MISP events | One document per source attribute, including type, value, category, tags, `to_ids`, source and `event_uuid`. | Same sync run as events. |
| `threat_actors` | MISP Galaxy `threat-actor`, `malpedia`, and `tool` clusters | Fetch the public cluster JSON from `https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{name}.json`; derive mentions from source event titles/tags. Common-word aliases are excluded, multiword free-text matches require capitalization, and the most frequent matches are printed for review. | Rebuilt when feeds sync. |
| `threat_reports`, `threat_classifications`, `sources`, `intelligence_feeds` | Derived from the source events and feed configuration | Preserve source event fields; classification comes from MISP Galaxy/semantic tags. | Rebuilt when feeds sync. |
| `security_reports`, `security_report_passages` | [`jacobdjwilson/awesome-annual-security-reports`](https://github.com/jacobdjwilson/awesome-annual-security-reports) | Import Markdown conversions from a local clone; passages are text chunks derived from each report. | Manual refresh or explicit UI sync. |
| `vt_cache` | VirusTotal API v3 | Live indicator lookup with `VIRUSTOTAL_API_KEY`; cache each result for 24 hours. No file uploads are performed. | On lookup. The API reports the free-tier rate/quota limit when VirusTotal returns HTTP 429. |
| Lab 7.2 `working_set_test` | 100,000 original MISP attributes fetched from the CIRCL, Botvrij.eu and ThreatFox event JSON endpoints | The fetcher preserves the original attribute UUID and fields and adds event/feed provenance. It does not copy records from MongoDB's `indicators` collection or synthesize data. | Fetch with `python -m scripts.fetch_working_set`. |
| `vulnerabilities` | No vulnerability source was specified for this project | Remains empty; the UI must not invent CVEs, scores or countries. | Not applicable. |

Feed dates, original UUIDs and source links are displayed in the dashboard. Severity is the MISP threat-level mapping, not an independent score. An indicator’s `to_ids` flag is shown as an IDS-use flag, not as proof that it is malicious. The optional authorized-instance synchronizer writes to `misp_instance_events`, separate from the three public feeds.

## Run a feed sync

From `backend/`:

```powershell
.\venv\Scripts\python.exe -m scripts.sync_feeds --max-events 50
.\venv\Scripts\python.exe -m scripts.sync_feeds
```

`--max-events 50` is a quick capped run (per feed), not a complete backfill. Run without the cap to fetch all events listed in the current manifests. Retries and bounded concurrent downloads are enabled. A non-zero exit code means at least one feed/event failed; the global last-success timestamp advances only after a complete run. `GET /sync-status` provides the last successful sync time and per-feed state, shown in the page header.

### Daily schedule on Windows

Run once from `backend/` in PowerShell to register a daily 6:00 AM task for the current Windows user:

```powershell
.\scripts\register_daily_sync.ps1
```

The task runs as the current user and requires that user to be logged in. Check it with `Get-ScheduledTask -TaskName "cti-feed-sync"` and its latest run with `Get-ScheduledTaskInfo -TaskName "cti-feed-sync"`.

## Annual reports

The annual-report repository is not bundled. From the project directory, clone it so the backend can find `awesome-annual-security-reports/Markdown Conversions/`:

```powershell
git clone https://github.com/jacobdjwilson/awesome-annual-security-reports.git
```

The verification library loads the newest matching passages from local MongoDB on page load and supports passage search. Each threat indicator's **Verify against reports** action checks the exact indicator, its event classification and title, and explicit MISP Galaxy cluster names. It shows direct matches separately from contextual report matches, and links to the source feed event and report Markdown/PDF. Contextual results are leads to review, not confirmation; no report match is not proof of a false indicator. The library does not generate an automated verdict. The UI imports missing Markdown reports only after explicit confirmation. For PDFs you are authorized to process, install the optional integration and convert a local PDF directory into the clone's Markdown folder:

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements-integrations.txt
.\venv\Scripts\python.exe -m scripts.convert_reports "..\awesome-annual-security-reports\Annual Security Reports" --output "..\awesome-annual-security-reports\Markdown Conversions"
```

Then use **Check for new reports** and **Sync missing reports** in the dashboard. The source repository's MIT license covers its own project files; individual security reports may have separate rights and must be authorized before conversion or import.

## Cross-Source Analysis

Open **Cross-Source Analysis** from the dashboard navigation to compare the full `working_set_test` dataset on the server. The page reports only exact normalized CVEs, supported IOC types, and explicitly tagged MISP Galaxy values that occur in at least two distinct feed IDs. It stores compact evidence in `cross_source_matches` and refresh metadata in `cross_source_analysis_state`; it does not copy full threat records or label common items as duplicate records. Feed synchronization marks a prior result stale; fetch a new 100,000-record snapshot with `python -m scripts.fetch_working_set` when you want new attributes in the lab dataset, then use **Refresh Cross-Source Analysis** to rebuild the derived matches. Results are paginated and include links to the original MISP event and expandable technical details.

## Backend setup

From `backend/`, create a local `.env` from `.env.example`, set `MONGO_URI` and `DATABASE_NAME`, then install/start:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements-core.txt
python -m uvicorn app.main:app --reload
```

Set `VIRUSTOTAL_API_KEY` as an environment variable (or in the private local `.env`, which must not be committed). Keep all API keys and passwords out of tracked files. VirusTotal search is featured at the top of `frontend/index.html`; its status check reveals only whether a key is configured, and the key is never sent to the browser. When served by FastAPI on port 8000, the frontend and the separate `frontend/cross-source.html` page use that same origin; when opened from a separate local frontend server, they use `http://127.0.0.1:8000`.

## Lab scripts

From `backend/`, run `python -m scripts.fetch_working_set` to fetch exactly 100,000 original MISP attributes from the public event feeds for Lab 7.2. Then run `python -m scripts.working_set_analysis` for collection and live WiredTiger cache statistics or `python -m scripts.random_read_monitor` for ten-second random-read measurements. The dashboard opens on the Lab 7.2 working-set collection, pages through validated source events (30 per page), and shows the 100,000-record indicator total. Each event initially renders up to 10 indicators; **Load more indicators** fetches the remaining records in batches of 20, and every indicator has its own **Verify** action. **CTI events** switches to the separate canonical event collection. Report matches are evidence to review, not an automated verdict, and no match is not proof of a false event. The working-set benchmark uses that same lab collection. WiredTiger cache counters are actual process-wide values, not a per-collection residency claim. Run `python -m scripts.bson_analysis` / `python -m scripts.embedded_redesign` for the schema exercises.

The Lab 7.2 builder replaces only its derived `working_set_test` subset from the unchanged canonical `indicators` data. The dashboard validates each indicator's source, MISP attribute UUID, and linked event title, then groups indicators by feed event so one MISP event is not repeated as separate cards. All indicators can be loaded within their event in paginated batches and verified individually; pagination is by complete event while the interface reports the underlying indicator total. Before dropping or rebuilding canonical/source collections, first take and verify a `mongodump`. Do not commit `.env`, API keys, database dumps, virtual environments, or third-party report content.

## Unified Docker labs (Chapters 7–12)

The Compose setup serves the existing CTI dashboard and the full Chapter 7–12 learning platform from one frontend at `http://localhost:8000`. The Chapter 7–9 exercises use the standalone MongoDB server and the Chapter 7 database. Chapter 10 uses a dedicated, single-node replica set (`mongo10`) for transactions. Chapter 11 uses a separate mongos router, one config-server member, and two single-node shard replica sets to demonstrate actual sharding, per-shard statistics, and routed query plans. Chapter 12 introduces least-privilege Role-Based Access Control (RBAC), TLS in-transit encryption, and field-level redaction views protecting the CIA triad (Confidentiality, Integrity, Availability). These exercises write to isolated lab databases; CTI source collections are preserved.

The image contains application code only. `.env`, API keys, backups, and experiment output are not included. MongoDB persists in the named `mongo1_data` volume (retained from the previous setup); never use `docker compose down -v` if you want to preserve that data. Test and experiment writes use `lab_ch*` collections so the original Threat Feed, IOC search, VirusTotal, and Threat Verifier data is not modified by these labs.

### Windows / PowerShell first run

1. Start Docker Desktop and open PowerShell in the project directory:

   ```powershell
   Set-Location "C:\Users\Riyansh Jain\OneDrive\Desktop\no-sql_lab-7"
   if (-not (Test-Path .env)) { Copy-Item .env.example .env }
   notepad .env
   ```

   Set the four image variables to your Docker Hub namespace when publishing. Optional integration credentials can remain blank. Never put secrets in a Dockerfile or image.

2. To load your own Chapter 7 data, create an authorized MongoDB archive at `.\backup\ch7.archive`. For example, set `MONGO_URI` privately in your current PowerShell session and run:

   ```powershell
   New-Item -ItemType Directory -Force .\backup | Out-Null
   mongodump --uri="$env:MONGO_URI" --db=cyber_threat_intelligence --archive=.\backup\ch7.archive --gzip
   ```

   The archive is mounted read-only and excluded from the image build. No other person's database is included. Without this archive, the app can start, but real-data experiments report that the Chapter 7 data is missing.

3. Build the runner images and start MongoDB. If you already have the images, you can skip the build:

   ```powershell
   $DockerHubUser = "riyansh24"
   docker build --tag "$DockerHubUser/mongodb-labs:2.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs:2.0" --build-arg "LAB_ALLOWED_CHAPTERS=all" .
   docker build --tag "$DockerHubUser/mongodb-labs-ch7:2.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs-ch7:2.0" --build-arg "LAB_ALLOWED_CHAPTERS=7" .
   docker build --tag "$DockerHubUser/mongodb-labs-ch8:2.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs-ch8:2.0" --build-arg "LAB_ALLOWED_CHAPTERS=8" .
   docker build --tag "$DockerHubUser/mongodb-labs-ch9:2.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs-ch9:2.0" --build-arg "LAB_ALLOWED_CHAPTERS=9" .
   docker build --tag "$DockerHubUser/mongodb-labs-ch10:1.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs-ch10:1.0" --build-arg "LAB_ALLOWED_CHAPTERS=10" .
   docker build --tag "$DockerHubUser/mongodb-labs-ch11:1.0" --build-arg "LAB_IMAGE=$DockerHubUser/mongodb-labs-ch11:1.0" --build-arg "LAB_ALLOWED_CHAPTERS=11" .
   docker compose down --remove-orphans
   docker compose up -d mongo1
   docker compose run --rm lab-ch7 setup
   docker compose run --rm lab-ch7 7-load
   ```

   `docker compose down --remove-orphans` stops and removes the old replica-set containers but **does not remove named volumes**. Never add `-v`. The existing `mongo1_data` volume is retained when `mongo1` restarts as a standalone server; other old member volumes are retained as fallbacks. Make a verified dump first if that is the only copy of important data. `7-load` restores the archive only when needed and does not delete a populated target database.

4. Start the full CTI and MongoDB learning platform:

   ```powershell
   docker compose up -d cti
   Start-Process "http://localhost:8000"
   ```

   The site retains the original CTI pages and features, including Threat Feed, Sources/feed sync, IOC database/search, VirusTotal, Threat Verifier, reports, metrics, and Cross-Source Analysis. The MongoDB Labs link opens the Chapter 7–11 exercise catalog; the catalog reports whether the Chapter 10 replica set and Chapter 11 two-shard cluster are ready. Starting `cti` starts and initializes both isolated clusters. VirusTotal needs `VIRUSTOTAL_API_KEY` in your local `.env`; without it the rest of the platform starts and the VirusTotal feature explains that the key is unavailable.

5. From **MongoDB Labs**, open the Chapter 10 transaction labs or Chapter 11 sharding labs. Lab 11.1 and its resharding activity are informational. Lab 11.2 compares an educational timestamp bucket simulation with live MongoDB distribution, then inserts 10,000 records into each isolated sharded collection and collects per-shard `collStats` plus `explain()` results through mongos. The saved result clearly separates simulation output from measured shard distribution and participating shards. You can also run the command-line equivalents:

   ```powershell
   docker compose run --rm lab-ch8 8.1
   docker compose run --rm lab-ch9 9.1
   docker compose run --rm lab-ch10 10-all
   docker compose run --rm lab-ch11 11-all
   ```

   `10.1` demonstrates a successful bank transfer and verifies that an insufficient-funds attempt leaves both balances unchanged. `10.2` races eight requests against five units, then measures a fixed 32-reservation workload at 1, 4, 8, and 16 workers. The benchmark gives each worker its own inventory product so same-document write conflicts do not obscure throughput; the five-unit race separately demonstrates same-product contention. Both activities retry `TransientTransactionError` with capped exponential backoff and jitter; the `-try` variants increase the retry budget. `11.1` compares hashed user/customer IDs, hashed order IDs, category IDs, and monotonic date keys using cardinality, distribution, query targeting, and monotonicity; it also includes range-key alternatives and the MongoDB resharding activity. `11.2` first compares the same increasing timestamp inputs in a deterministic bucket simulation, then compares a timestamp range key with a presplit hashed customer key across two actual shards. The simulation is educational, not MongoDB chunk placement. The hashed-field range query is expected to scatter; actual counts and explain plans come from the live deployment and may vary with MongoDB version and balancer state.

   Chapter 12 covers Database Security and the CIA Triad: `12.1` configures custom least-privilege roles (`limitedLogWriter` on `nosql_labs.logs`) and distinct users (`analyst`, `app_writer`, `log_writer`). `12.1-try` audits permission boundaries, confirming that unauthorized write, cross-database read, and delete operations are rejected with code 13. `12.2` configures local CA, server certificates with Subject Alternative Names (localhost and 127.0.0.1), and combined PEMs for in-transit encryption. `12.2-try` confirms plaintext connections fail and encrypted TLS handshakes succeed. `12.3` demonstrates field-level redaction with the `employees_safe` view (masking SSN to `***-**-XXXX` and omitting salary via `$$REMOVE`) combined with scoped RBAC (`employeeSafeViewReader` for `safe_viewer` vs direct access for `hr_user`).

   `lab-ch7`, `lab-ch8`, `lab-ch9`, `lab-ch10`, `lab-ch11`, and `lab-ch12` run the corresponding chapter commands; the generic `lab` service runs the standalone Chapter 7–9 commands. Logs and JSON command/reply records are written to `.\output`.

The Chapter 11 runner replaces only `lab11_timestamp` and `lab11_hashed_customer` inside the dedicated `lab11_sharding` database on its own sharded cluster. The lab topology uses one config-server member and one member per shard to limit local resource use; do not treat it as a production topology. Lab 11.1 summarizes MongoDB 5.0+ resharding and links to the [official documentation](https://www.mongodb.com/docs/manual/core/sharding-reshard-a-collection/).

6. Publish each separate chapter repository to Docker Hub. Log in, then tag/push the images you built:

   ```powershell
   docker login
   docker push "$DockerHubUser/mongodb-labs-ch7:2.0"
   docker push "$DockerHubUser/mongodb-labs-ch8:2.0"
   docker push "$DockerHubUser/mongodb-labs-ch9:2.0"
   docker push "$DockerHubUser/mongodb-labs-ch10:1.0"
   docker push "$DockerHubUser/mongodb-labs-ch11:1.0"
   docker push "$DockerHubUser/mongodb-labs:2.0"
   ```

   The Chapter 10 image was published as `riyansh24/mongodb-labs-ch10:1.0` at [Docker Hub](https://hub.docker.com/r/riyansh24/mongodb-labs-ch10). The submission PDF is [LAB-10-DockerHub.pdf](./LAB-10-DockerHub.pdf). Re-publishing requires an authenticated Docker Hub account with permission to publish to that namespace.

The project `.dockerignore` excludes `.env`, credentials, the backup archive, and generated output. `docker compose run --rm lab compose` prints the Compose file from the image.

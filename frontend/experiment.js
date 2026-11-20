(() => {
    const api = window.location.port === "8000"
        ? window.location.origin
        : "http://127.0.0.1:8000";
    const definitions = {
        "7.1": {
            chapter: "CHAPTER 7 · 7.1",
            title: "Schema analysis of the CTI database",
            aim: "Inspect the actual Chapter 7 collections, relationships, and BSON document sizes without changing their data.",
            steps: [
                "Samples real collection documents and reports likely references and embedded values.",
                "Measures average, minimum, and maximum BSON sizes for every non-system collection.",
                "Compares the measured maximum with MongoDB’s 16 MiB document limit."
            ],
            note: "Read-only analysis. IOC-to-event links use the existing event_uuid/feed_id references; no canonical collection is changed."
        },
        "7.1-try": {
            chapter: "CHAPTER 7 · 7.1 TRY",
            title: "Embed sightings and compare read patterns",
            aim: "Build a new embedded view of real IOC sightings and compare referenced reads with one embedded document read.",
            steps: [
                "Aggregates real indicator documents by normalized type and value.",
                "Writes the embedded redesign only to lab_ch71_embedded_sightings.",
                "Benchmarks reference lookups through indicators/feed_events against embedded reads."
            ],
            note: "Only the lab_ch71_embedded_sightings collection is created or replaced; Threat Feed and IOC collections remain untouched."
        },
        "7.2": {
            chapter: "CHAPTER 7 · 7.2",
            title: "Working set versus WiredTiger cache",
            aim: "Create 100,000 approximately 2 KiB documents enriched from real Chapter 7 indicators and compare random-read behavior to cache capacity.",
            steps: [
                "Builds the lab-only dataset from real indicators and available related events/reports/malware samples.",
                "Checks actual BSON sizes with $bsonSize and rejects oversized records.",
                "Temporarily shrinks the WiredTiger cache to 256 MiB and measures random-read rounds.",
                "Restores the runtime cache setting in a finally block."
            ],
            note: "Requires Chapter 7 data to have been restored. The experiment writes to lab_ch72_working_set, never working_set_test."
        },
        "7.2-try": {
            chapter: "CHAPTER 7 · 7.2 TRY",
            title: "Sample cache while background reads run",
            aim: "Run concurrent random reads and capture live WiredTiger cache counters every 10 seconds.",
            steps: [
                "Checks that the isolated 100,000-document lab_ch72_working_set exists.",
                "Starts a background random-read worker.",
                "Samples cache occupancy and page counters every 10 seconds."
            ],
            note: "Set LAB_MONITOR_SECONDS to change the observation duration. Stop interrupts the worker cleanly."
        },
        "8.1": {
            chapter: "CHAPTER 8 · 8.1",
            title: "Inspect the Chapter 7 CTI schema",
            aim: "Inspect real Chapter 7 collections and compare embedded fields with references between CTI documents.",
            steps: [
                "Reads sample documents and counts from the real CTI collections.",
                "Lists likely reference fields and embedded subdocuments.",
                "Leaves all original Chapter 7 documents unchanged."
            ],
            note: "This continuation uses your Chapter 7 data on one standalone MongoDB server; it does not demonstrate replica-set replication."
        },
        "8.1-try": {
            chapter: "CHAPTER 8 · 8.1 TRY",
            title: "Compare an indexed CTI lookup",
            aim: "Copy a bounded sample of real indicators into an isolated lab collection and measure lookup time before and after indexing.",
            steps: [
                "Copies up to 5,000 real indicators into lab_ch8_indicator_copy.",
                "Measures a lookup before and after creating a value index.",
                "Keeps all test writes and index changes inside the lab collection."
            ],
            note: "The standalone design is intentionally not an arbiter exercise."
        },
        "8.2": {
            chapter: "CHAPTER 8 · 8.2",
            title: "Check CTI reference integrity",
            aim: "Sample indicator-to-event references in the Chapter 7 data and report whether corresponding events can be found.",
            steps: [
                "Samples indicators that include an event reference.",
                "Looks up related events by feed and event UUID.",
                "Reports valid links and sampled orphan references without changing either collection."
            ],
            note: "No stepdown or election occurs because the selected setup uses a standalone MongoDB server."
        },
        "8.2-try": {
            chapter: "CHAPTER 8 · 8.2 TRY",
            title: "Explain a real indicator query",
            aim: "Inspect MongoDB's execution plan and examined-document/index counts for a query against real Chapter 7 indicator data.",
            steps: [
                "Selects a real indicator value without displaying it in the result.",
                "Runs explain with executionStats on the original indicators collection.",
                "Reports the winning plan and query work without modifying CTI data."
            ],
            note: "Read-only analysis; explain results use real Chapter 7 data, and the sampled indicator value is redacted from the result."
        },
        "9.1": {
            chapter: "CHAPTER 9 · 9.1",
            title: "Measure standalone write latency",
            aim: "Insert 1,000 small documents into a lab-only collection with w:1 and measure elapsed and average write latency.",
            steps: [
                "Uses only the supported standalone write concern w:1.",
                "Stores the test documents in lab_ch9_write_j0.",
                "Reports elapsed time and average time per acknowledged insert."
            ],
            note: "w:majority, w:all, failover, and partition behavior require a replica set and are deliberately not simulated in this standalone setup."
        },
        "9.1-try": {
            chapter: "CHAPTER 9 · 9.1 TRY",
            title: "Compare journal acknowledgment",
            aim: "Compare standalone w:1 writes with j:false and j:true.",
            steps: [
                "Inserts 1,000 documents with explicit j:false.",
                "Repeats with explicit j:true in a separate lab collection.",
                "Saves a timing comparison for the same write concern."
            ],
            note: "Results depend on Docker Desktop, disk, and host load; interpret the measured values. Both collections are lab-only."
        },
        "9.2": {
            chapter: "CHAPTER 9 · 9.2",
            title: "Audit Chapter 7 data references",
            aim: "Sample real indicators and audit their related event references, recording integrity counts in a reusable result.",
            steps: [
                "Samples up to 500 indicators from the original Chapter 7 collection.",
                "Checks referenced feed events without writing to the source collections.",
                "Reports valid, missing, and absent event references."
            ],
            note: "Network partitions and write survival cannot be demonstrated with a standalone server. This lab instead audits the real Chapter 7 data and makes no replica-set claims."
        },
        "10.1": {
            chapter: "CHAPTER 10 · 10.1",
            title: "Bank transfer with multi-document transactions",
            aim: "Transfer money between two accounts atomically, write transfer history, and verify insufficient funds roll back both balances.",
            steps: [
                "Creates two isolated accounts with balances and version fields.",
                "Debits the source only when its balance covers the transfer, then credits the destination and records history in one transaction.",
                "Attempts an overdraw and confirms neither account balance nor transfer history changes."
            ],
            note: "Runs against the dedicated Chapter 10 replica set and writes only to lab10_accounts and lab10_transfer_history."
        },
        "10.1-try": {
            chapter: "CHAPTER 10 · 10.1 TRY",
            title: "Retry transient transfer conflicts",
            aim: "Repeat the atomic transfer and apply capped exponential backoff with jitter when MongoDB labels a transaction error as transient.",
            steps: [
                "Runs the successful and insufficient-funds transfer checks.",
                "Retries only errors labeled TransientTransactionError, up to five attempts.",
                "Reports the final balances and confirms the failed overdraw was rolled back."
            ],
            note: "Business failures such as insufficient funds are not retried. The retry budget and delay are bounded."
        },
        "10.2": {
            chapter: "CHAPTER 10 · 10.2",
            title: "Reserve inventory under contention",
            aim: "Compete for five units with eight concurrent reservations and keep stock and order creation consistent.",
            steps: [
                "Creates one isolated inventory product with five units.",
                "Runs eight simultaneous one-unit reservations using transactions and transient-conflict retries.",
                "Verifies exactly five pending orders were created and stock is zero."
            ],
            note: "The transactional invariant is checked after the concurrent run; inventory and orders use lab10_* collections."
        },
        "10.2-try": {
            chapter: "CHAPTER 10 · 10.2 TRY",
            title: "Retry inventory conflicts and measure throughput",
            aim: "Measure successful transactional reservation throughput at 1, 4, 8, and 16 workers after a same-product contention test.",
            steps: [
                "Runs eight concurrent reservations against five available units.",
                "Retries transient transaction conflicts with capped exponential backoff and jitter.",
                "Times a fixed workload of 32 successful reservations at each concurrency level."
            ],
            note: "The benchmark assigns each worker a separate product so its throughput measurement is distinct from the same-document contention exercise."
        },
        "11.1": {
            chapter: "CHAPTER 11 · 11.1",
            title: "Evaluate shard-key choices",
            aim: "Compare hashed user/order IDs, category_id, and created_at, plus range-key alternatives, using cardinality, distribution, query targeting, and monotonicity.",
            steps: [
                "Predict each candidate's verdict and identify the decisive shard-key property before reviewing the matrix.",
                "Compare the four core properties: cardinality, distribution, query targeting, and monotonicity.",
                "Use the recommendation as a starting hypothesis, then validate against real query frequency and customer skew.",
                "Review MongoDB 5.0+ resharding requirements and limitations in the result."
            ],
            note: "A high-cardinality date key can still hotspot because new values are monotonic. This decision exercise is informational and does not change any database collection."
        },
        "11.1-try": {
            chapter: "CHAPTER 11 · 11.1 TRY",
            title: "Plan a MongoDB collection reshard",
            aim: "Review the operational steps and documented constraints for changing a collection's shard key.",
            steps: [
                "Check cluster health, storage, CPU, I/O, index builds, and unique-index compatibility.",
                "Schedule a resource-intensive migration and plan for a short write-blocking window.",
                "Verify chunk distribution and query plans after the operation."
            ],
            note: "This activity is a documented checklist; it does not start a reshard operation."
        },
        "11.2": {
            chapter: "CHAPTER 11 · 11.2",
            title: "Detect shard-key hotspots on a live cluster",
            aim: "Compare a same-input timestamp bucket simulation with live MongoDB distribution and query targeting on timestamp-range and hashed-key collections.",
            steps: [
                "Predict whether increasing timestamps concentrate in one bucket and whether hashing those same values spreads them.",
                "Runs a deterministic educational bucket simulation using identical increasing timestamp values for both strategies.",
                "Creates isolated test collections in the lab11_sharding database and inserts records through mongos.",
                "Collects actual MongoDB collStats by shard and explain output for timestamp and hashed-field range queries."
            ],
            note: "The simulation is illustrative and not MongoDB chunk placement. Live statistics and explain plans are separately measured on the isolated two-shard Chapter 11 cluster; only lab11_sharding collections are replaced."
        },
        "12.1": {
            chapter: "CHAPTER 12 · 12.1",
            title: "Role-Based Access Control and least-privilege setup",
            aim: "Define scoped roles and least-privilege user accounts in MongoDB according to the Principle of Least Privilege.",
            steps: [
                "Creates custom role limitedLogWriter with privileges scoped strictly to the logs collection.",
                "Provisions analyst (read-only), app_writer (readWrite on nosql_labs), and log_writer (insert/update logs only).",
                "Verifies that user roles and resource privileges are persisted correctly."
            ],
            note: "Configures role definitions in an isolated lab database and admin; original CTI collections remain untouched."
        },
        "12.1-try": {
            chapter: "CHAPTER 12 · 12.1 TRY",
            title: "Verify RBAC permission boundaries and enforcement",
            aim: "Audit and verify that actions outside granted privileges produce expected unauthorized errors (code 13).",
            steps: [
                "Tests that analyst read succeeds but writes to nosql_labs are rejected with code 13.",
                "Tests that app_writer write succeeds but read from bookstore is rejected with code 13.",
                "Tests that log_writer can write logs, but out-of-scope writes and deletes are rejected."
            ],
            note: "Verifies the Confidentiality and Integrity pillars of the CIA triad through least-privilege RBAC."
        },
        "12.2": {
            chapter: "CHAPTER 12 · 12.2",
            title: "TLS certificate setup and encryption in transit",
            aim: "Generate local certificate authority, server certificate with SANs, and client certificates for in-transit encryption.",
            steps: [
                "Generates a local Certificate Authority (CA) and server certificate with localhost and 127.0.0.1 SANs.",
                "Generates client certificate and combines private keys into server.pem and client.pem.",
                "Provides the TLS-only mongod startup configuration and PyMongo mutual TLS client parameters."
            ],
            note: "Protects data in transit across network hops against eavesdropping and MITM attacks."
        },
        "12.2-try": {
            chapter: "CHAPTER 12 · 12.2 TRY",
            title: "Verify TLS encrypted connection and client auth",
            aim: "Confirm that unencrypted plaintext traffic fails while encrypted TLS handshakes succeed with CA validation.",
            steps: [
                "Validates that plaintext connections are rejected when TLS is enforced.",
                "Establishes an encrypted TLS connection and verifies the server certificate using the lab CA.",
                "Demonstrates PyMongo mTLS client authentication with client.pem."
            ],
            note: "Transit encryption ensures confidentiality and cryptographic proof of server and client identity."
        },
        "12.3": {
            chapter: "CHAPTER 12 · 12.3",
            title: "Field-level redaction through read-only views",
            aim: "Redact sensitive employee records (SSN masked to last 4 digits, salary stripped) using a MongoDB aggregation view and scoped RBAC.",
            steps: [
                "Seeds synthetic employee records with username, email, SSN, and salary in the source collection.",
                "Creates the employees_safe view using an aggregation pipeline with $$REMOVE and $concat masking.",
                "Assigns safe_viewer role to find only on the view; denies direct access to the employees collection.",
                "Verifies that hr_user can inspect the source collection while safe_viewer sees only redacted data."
            ],
            note: "Enforces data confidentiality at the database layer without modifying source records."
        },
        "13.1": {
            chapter: "CHAPTER 13 · 13.1",
            title: "Deploy a 3-Node Replica Set with Docker Compose & KeyFile Auth",
            aim: "Create and deploy a production-ready Docker Compose configuration for a MongoDB replica set with keyFile authentication. Verify all three members are healthy and test failover with PyMongo continuous reads.",
            steps: [
                "Connects to the rs0 replica set running via Docker Compose (ports 27021–27023, keyFile auth enabled).",
                "Checks replica set status via rs.status() and reports PRIMARY and SECONDARY members.",
                "Runs 100 continuous PyMongo ping reads and counts read errors during any failover.",
                "Reports keyFile authentication status and Prometheus exporter sidecar (bitnami/mongodb-exporter on port 9216).",
                "Saves results to output/results/13.1.json with member states, read counts, and cluster health."
            ],
            note: "Runs against the chapter-13 Docker Compose replica set. Requires docker compose up -d in chapter-13/docker-compose/. Falls back to mongo10 (port 27018) if the chapter-13 cluster is not running."
        },
        "13.2": {
            chapter: "CHAPTER 13 · 13.2",
            title: "Kubernetes StatefulSet for MongoDB Replica Set",
            aim: "Deploy MongoDB as a StatefulSet on Kubernetes with PersistentVolumeClaims, a headless Service for stable network identities, and an InitContainer for keyfile generation. Test pod resiliency by deleting a pod and verifying it rejoins the replica set.",
            steps: [
                "Verifies chapter-13/k8s/mongo-headless-svc.yaml exists (clusterIP: None, selector app: mongo).",
                "Verifies chapter-13/k8s/mongo-statefulset.yaml exists with 3 replicas, InitContainer, and PVC template.",
                "Reports pod DNS names: mongo-0.mongo-headless-svc, mongo-1.mongo-headless-svc, mongo-2.mongo-headless-svc.",
                "Documents readiness probe (mongosh ping on port 27017) and self-healing pod recovery steps.",
                "Saves results to output/results/13.2.json with manifest status and pod configuration."
            ],
            note: "Kubernetes manifests are verified on disk. For live kubectl deployment, run: kubectl apply -f chapter-13/k8s/ and kubectl exec -it mongo-0 -- mongosh to initialise the replica set."
        }
    };

    const lab = new URLSearchParams(window.location.search).get("lab") || "7.1";
    const definition = definitions[lab];
    const chapter = document.getElementById("experimentChapter");
    const title = document.getElementById("experimentTitle");
    const aim = document.getElementById("experimentAim");
    const steps = document.getElementById("experimentSteps");
    const note = document.getElementById("experimentNote");
    const consoleBox = document.getElementById("console");
    const resultBox = document.getElementById("result");
    const status = document.getElementById("jobStatus");
    const runButton = document.getElementById("runButton");
    const stopButton = document.getElementById("stopButton");
    let jobId = null;
    let cursor = 0;
    let polling = false;

    function setText(element, value) {
        element.textContent = value ?? "";
    }

    function renderDefinition() {
        if (!definition) {
            setText(title, "Experiment not found");
            setText(aim, "Choose an experiment from the CH 7, CH 8, or CH 9 menu.");
            runButton.disabled = true;
            return;
        }
        document.title = `${definition.title} · MongoDB Labs`;
        setText(chapter, definition.chapter);
        setText(title, definition.title);
        setText(aim, definition.aim);
        setText(note, definition.note);
        steps.replaceChildren(...definition.steps.map((text) => {
            const item = document.createElement("li");
            item.textContent = text;
            return item;
        }));
        loadResult();
    }

    function makeTable(rows) {
        if (!Array.isArray(rows) || !rows.length || typeof rows[0] !== "object") return null;
        const columns = [...new Set(rows.flatMap((row) => Object.keys(row)))];
        const table = document.createElement("table");
        table.className = "clean-table";
        const head = document.createElement("thead");
        const headingRow = document.createElement("tr");
        for (const column of columns) {
            const cell = document.createElement("th");
            cell.textContent = column.replace(/_/g, " ");
            headingRow.append(cell);
        }
        head.append(headingRow);
        const body = document.createElement("tbody");
        for (const row of rows.slice(0, 300)) {
            const tr = document.createElement("tr");
            for (const column of columns) {
                const td = document.createElement("td");
                const value = row[column];
                if (typeof value === "boolean") {
                    td.innerHTML = value
                        ? `<span class="status-pill success">✓ PASS</span>`
                        : `<span class="status-pill warning">✕ FAIL</span>`;
                } else if (value && typeof value === "object") {
                    td.textContent = JSON.stringify(value);
                } else {
                    td.textContent = String(value ?? "—");
                }
                tr.append(td);
            }
            body.append(tr);
        }
        table.append(head, body);
        return table;
    }

    function appendChart(parent, rows, customMetricTitle) {
        const metric = rows.some((row) => typeof row.throughput_per_second === "number")
            ? "throughput_per_second"
            : rows.some((row) => typeof row.average_latency_ms === "number")
                ? "average_latency_ms"
                : rows.some((row) => typeof row.elapsed_ms === "number")
                    ? "elapsed_ms"
                    : rows.some((row) => typeof row.duration_ms === "number")
                        ? "duration_ms"
                        : null;
        if (!metric) return;
        const maximum = Math.max(...rows.map((row) => Number(row[metric]) || 0), 0.001);

        const container = document.createElement("div");
        container.className = "visual-chart-container";

        const title = document.createElement("div");
        title.className = "visual-chart-title";
        title.innerHTML = `
            <span>📊 ${customMetricTitle || (metric === "throughput_per_second" ? "Throughput Benchmarking" : "Latency Distribution")}</span>
            <span style="font-size: 11px; color: var(--text-accent); font-weight: 600;">MAX: ${maximum} ${metric === "throughput_per_second" ? "req/s" : "ms"}</span>
        `;
        container.append(title);

        for (const row of rows) {
            const value = row[metric];
            if (typeof value !== "number") continue;

            const item = document.createElement("div");
            item.className = "visual-bar-item";

            const label = document.createElement("span");
            label.className = "visual-bar-label";
            label.textContent = typeof row.concurrency === "number"
                ? `⚡ ${row.concurrency} Concurrent Workers`
                : row.candidate || row.write_concern || `Step ${row.round || row.step || ""}`;

            const track = document.createElement("div");
            track.className = "visual-bar-track";
            const fill = document.createElement("div");
            fill.className = "visual-bar-fill";
            fill.style.width = `${Math.max(2, (value / maximum) * 100)}%`;
            track.append(fill);

            const val = document.createElement("span");
            val.className = "visual-bar-value";
            const unit = metric === "throughput_per_second" ? "ops/sec" : "ms";
            val.textContent = `${value} ${unit}`;

            item.append(label, track, val);
            container.append(item);
        }
        parent.append(container);
    }

    function renderKPIs(parent, data) {
        const kpis = [];

        // Lab 10.2 / 10.2-try contention & inventory
        if (data.contention && typeof data.contention === "object") {
            const c = data.contention;
            if (c.initial_stock != null) kpis.push({ label: "Initial Inventory", val: c.initial_stock });
            if (c.succeeded != null) kpis.push({ label: "Orders Fulfilled", val: c.succeeded, sub: "Succeeded" });
            if (c.insufficient_stock != null) kpis.push({ label: "Overdraw Rejected", val: c.insufficient_stock, sub: "Protected" });
            if (c.rollback_or_stock_invariant_verified != null) {
                kpis.push({
                    label: "Stock Invariant",
                    val: c.rollback_or_stock_invariant_verified ? "VERIFIED" : "FAILED",
                    sub: "100% Invariant Guarantee"
                });
            }
        }

        // Lab 10.1 Bank transfer
        if (data.accounts && typeof data.accounts === "object") {
            for (const [acc, bal] of Object.entries(data.accounts)) {
                kpis.push({ label: `Balance (${acc})`, val: `$${bal}` });
            }
            if (data.rollback_verified != null) {
                kpis.push({
                    label: "ACID Rollback",
                    val: data.rollback_verified ? "PASSED" : "FAILED",
                    sub: "Zero-loss Guarantee"
                });
            }
        }

        // Lab 12 Security
        if (data.rbac_verified != null) {
            kpis.push({ label: "RBAC Boundary", val: data.rbac_verified ? "SECURE" : "FAILED", sub: "Least-Privilege Enforced" });
        }
        if (data.tls_ready != null) {
            kpis.push({ label: "TLS Transport", val: data.tls_ready ? "ENCRYPTED" : "OFF", sub: "TLS 1.3 Active" });
        }
        if (data.redaction_applied != null) {
            kpis.push({ label: "Field Redaction", val: data.redaction_applied ? "ACTIVE" : "OFF", sub: "PII Masked" });
        }

        // General counts
        if (data.history_count != null) kpis.push({ label: "Audit Ledger", val: `${data.history_count} records` });
        if (data.retry_attempts != null) kpis.push({ label: "Conflict Retries", val: `${data.retry_attempts} max` });

        if (kpis.length) {
            const grid = document.createElement("div");
            grid.className = "kpi-grid";
            for (const kpi of kpis) {
                const card = document.createElement("div");
                card.className = "kpi-card";
                card.innerHTML = `
                    <div class="kpi-title">${kpi.label}</div>
                    <div class="kpi-value">${kpi.val}</div>
                    ${kpi.sub ? `<div class="kpi-subtext">${kpi.sub}</div>` : ""}
                `;
                grid.append(card);
            }
            parent.append(grid);
        }
    }

    function renderResult(record) {
        resultBox.replaceChildren();
        const data = record.result || record;

        // 1. Render High-Impact Executive KPI Tiles
        renderKPIs(resultBox, data);

        // 2. Render Throughput or Latency Visual Charts
        if (Array.isArray(data.throughput)) {
            appendChart(resultBox, data.throughput, "Multi-Thread Transaction Throughput");
        }
        if (Array.isArray(data.results)) {
            appendChart(resultBox, data.results, "Write Latency & SLA Comparison");
        }

        // 3. Render Formatted Data Tables (without raw JSON codes)
        const sections = [];
        if (Array.isArray(data.decision_matrix)) sections.push(["Shard-Key Decision Matrix", data.decision_matrix]);
        if (Array.isArray(data.roles)) sections.push(["Configured RBAC Roles", data.roles]);
        if (Array.isArray(data.users)) sections.push(["Provisioned Users & Privileges", data.users]);
        if (Array.isArray(data.checks)) sections.push(["Security Boundary Checklist", data.checks]);
        if (Array.isArray(data.verification_results)) sections.push(["Verification Checklist", data.verification_results]);
        if (Array.isArray(data.comparison)) sections.push(["Field-Level Redaction Masking", data.comparison]);
        if (Array.isArray(data.throughput)) sections.push(["Throughput Data Points", data.throughput]);
        if (Array.isArray(data.collections) && data.collections.some(r => r && typeof r === "object")) {
            sections.push(["Collection Sizing", data.collections]);
        }

        for (const [headingText, rows] of sections) {
            const heading = document.createElement("h3");
            heading.style.marginTop = "24px";
            heading.style.color = "#ffffff";
            heading.textContent = headingText;
            resultBox.append(heading);
            const table = makeTable(rows);
            if (table) resultBox.append(table);
        }

        if (typeof data.recommendation === "string") {
            const recBox = document.createElement("div");
            recBox.style.background = "var(--pine-900)";
            recBox.style.border = "1px solid var(--border-glow)";
            recBox.style.borderRadius = "10px";
            recBox.style.padding = "18px";
            recBox.style.margin = "20px 0";
            recBox.innerHTML = `
                <h4 style="margin: 0 0 8px; color: var(--text-accent);">💡 Architectural Recommendation</h4>
                <p style="margin: 0; color: var(--text-sub); line-height: 1.6;">${data.recommendation}</p>
            `;
            resultBox.append(recBox);
        }

        // 4. Raw JSON is now hidden behind an optional toggle button
        const toggleBtn = document.createElement("button");
        toggleBtn.className = "toggle-raw-btn";
        toggleBtn.textContent = "View Technical JSON Payload (Debug)";
        const rawCode = document.createElement("pre");
        rawCode.style.display = "none";
        rawCode.style.marginTop = "10px";
        rawCode.textContent = JSON.stringify(record, null, 2);

        toggleBtn.addEventListener("click", () => {
            const isHidden = rawCode.style.display === "none";
            rawCode.style.display = isHidden ? "block" : "none";
            toggleBtn.textContent = isHidden ? "Hide Technical JSON Payload" : "View Technical JSON Payload (Debug)";
        });

        resultBox.append(toggleBtn, rawCode);
    }

    async function loadResult() {
        if (!definition) return;
        try {
            const response = await fetch(`${api}/api/results/${encodeURIComponent(lab)}`, { cache: "no-store" });
            if (response.status === 404) {
                resultBox.innerHTML = '<p class="experiment-muted">No saved result yet. Run this experiment to create one.</p>';
                return;
            }
            if (!response.ok) throw new Error(`Result request failed (${response.status})`);
            renderResult(await response.json());
        } catch (error) {
            resultBox.replaceChildren();
            const message = document.createElement("p");
            message.className = "experiment-muted";
            message.textContent = `Could not load the saved result: ${error.message}`;
            resultBox.append(message);
        }
    }

    async function pollJob(id) {
        if (polling) return;
        polling = true;
        try {
            while (jobId === id) {
                const response = await fetch(`${api}/api/jobs/${encodeURIComponent(id)}?since=${cursor}`, { cache: "no-store" });
                const data = await response.json();
                if (!response.ok) throw new Error(data.detail || `Job polling failed (${response.status})`);
                if (data.lines.length) {
                    consoleBox.textContent += `${data.lines.join("\n")}\n`;
                    consoleBox.scrollTop = consoleBox.scrollHeight;
                }
                cursor = data.next;
                setText(status, `Experiment ${data.status}${data.return_code == null ? "" : ` · exit ${data.return_code}`}`);
                if (data.status === "completed" || data.status === "failed") {
                    jobId = null;
                    runButton.disabled = false;
                    stopButton.disabled = true;
                    await loadResult();
                    break;
                }
                await new Promise((resolve) => window.setTimeout(resolve, 900));
            }
        } catch (error) {
            setText(status, `Job error: ${error.message}`);
            runButton.disabled = false;
            stopButton.disabled = true;
            jobId = null;
        } finally {
            polling = false;
        }
    }

    async function run(command) {
        runButton.disabled = true;
        stopButton.disabled = false;
        cursor = 0;
        consoleBox.textContent = "";
        setText(status, `Starting ${command}…`);
        try {
            const response = await fetch(`${api}/api/jobs`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ lab: command })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || `Could not start job (${response.status})`);
            jobId = data.id;
            pollJob(data.id);
        } catch (error) {
            setText(status, `Could not start experiment: ${error.message}`);
            runButton.disabled = false;
            stopButton.disabled = true;
        }
    }

    runButton.addEventListener("click", () => run(lab));
    stopButton.addEventListener("click", async () => {
        if (!jobId) return;
        stopButton.disabled = true;
        setText(status, "Sending Ctrl+C; waiting for cleanup…");
        try {
            await fetch(`${api}/api/jobs/${encodeURIComponent(jobId)}/stop`, { method: "POST" });
        } catch (error) {
            setText(status, `Could not stop the job: ${error.message}`);
        }
    });
    renderDefinition();
})();

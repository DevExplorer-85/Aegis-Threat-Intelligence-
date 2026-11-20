(() => {
    const api = window.location.port === "8000"
        ? window.location.origin
        : "http://127.0.0.1:8000";
    const experiments = [
        ["7.1", "Schema and BSON analysis", "Read-only measurements on the actual CTI data."],
        ["7.1-try", "Embedded IOC sightings", "Build a separate embedded view and compare reads."],
        ["7.2", "Working set and WiredTiger cache", "Create 100,000 isolated records enriched from your CTI data."],
        ["7.2-try", "Background cache monitor", "Sample live cache statistics every 10 seconds."],
        ["8.1", "CTI schema inventory", "Inspect real Chapter 7 collections and document relationships."],
        ["8.1-try", "Indexed lookup", "Compare a real indicator lookup before and after indexing."],
        ["8.2", "Reference integrity", "Check sampled indicator-to-event references."],
        ["8.2-try", "Query plan", "Explain a read-only query against real indicators."],
        ["9.1", "Write latency", "Measure 1,000 standalone w:1 inserts."],
        ["9.1-try", "Journal comparison", "Compare standalone writes with j:false and j:true."],
        ["9.2", "Data integrity audit", "Audit real Chapter 7 indicators and related events."],
        ["10.1", "Bank transfer transaction", "Verify transfer atomicity and insufficient-funds rollback."],
        ["10.1-try", "Transfer retries", "Retry transient transaction conflicts with exponential backoff."],
        ["10.2", "Inventory reservation", "Race concurrent orders against the last five units of stock."],
        ["10.2-try", "Inventory throughput", "Measure transactional reservation throughput at several concurrency levels."],
        ["11.1", "Evaluate shard keys", "Compare hashed and range candidates using cardinality, distribution, query targeting, and monotonicity."],
        ["11.1-try", "MongoDB resharding", "Review the resharding procedure and operational limitations."],
        ["11.2", "Detect shard-key hotspots", "Compare a same-timestamp bucket simulation with live shard stats and query plans."],
        ["12.1", "Least-privilege RBAC setup", "Define scoped roles and user privileges conforming to the principle of least privilege."],
        ["12.1-try", "Verify RBAC permission boundaries", "Audit and confirm unauthorized reads, writes, and deletes are rejected (code 13)."],
        ["12.2", "TLS & transit encryption", "Generate local CA, server certificate with SANs, and client certificates for transport security."],
        ["12.2-try", "Verify TLS encrypted connection", "Verify that plaintext traffic fails while encrypted TLS handshakes succeed with CA validation."],
        ["12.3", "Field-level redaction with views", "Mask SSNs and remove salary fields via a read-only view with role-scoped viewer access."]
    ];

    const cards = document.getElementById("experimentCards");
    for (const [lab, name, description] of experiments) {
        const card = document.createElement("article");
        card.className = "experiment-card";
        const title = document.createElement("h2");
        title.textContent = `Chapter ${lab.split(".")[0]} · ${lab} · ${name}`;
        const text = document.createElement("p");
        text.className = "experiment-muted";
        text.textContent = description;
        const link = document.createElement("a");
        link.href = `experiment.html?lab=${encodeURIComponent(lab)}`;
        link.textContent = "Open experiment";
        card.append(title, text, link);
        cards.append(card);
    }

    async function loadTransactionStatus() {
        const target = document.getElementById("transactionStatus");
        try {
            const response = await fetch(`${api}/api/transactions/status`, { cache: "no-store" });
            if (!response.ok) throw new Error(`Status request returned HTTP ${response.status}`);
            const status = await response.json();
            if (!status.configured) {
                target.textContent = "Chapter 10 unavailable: configure MONGO_URI_CH10 to use a replica set.";
            } else if (status.connected && status.primary) {
                target.textContent = `Chapter 10 ready · replica set ${status.replica_set} has a writable primary.`;
            } else {
                target.textContent = `Chapter 10 unavailable: ${status.error || "replica-set primary is not ready."}`;
            }
        } catch (error) {
            target.textContent = `Could not check the Chapter 10 replica set: ${error.message}`;
        }
    }

    async function loadShardingStatus() {
        const target = document.getElementById("shardingStatus");
        try {
            const response = await fetch(`${api}/api/sharding/status`, { cache: "no-store" });
            if (!response.ok) throw new Error(`Status request returned HTTP ${response.status}`);
            const status = await response.json();
            if (status.connected && status.shards.length >= 2) {
                target.textContent = `Chapter 11 ready · mongos connected to ${status.shards.length} shards.`;
            } else {
                target.textContent = `Chapter 11 unavailable: ${status.error || "at least two shards are required."}`;
            }
        } catch (error) {
            target.textContent = `Could not check the Chapter 11 sharded cluster: ${error.message}`;
        }
    }

    async function loadResults() {
        const target = document.getElementById("savedResults");
        try {
            const response = await fetch(`${api}/api/results`, { cache: "no-store" });
            if (!response.ok) throw new Error(`Results request returned HTTP ${response.status}`);
            const { results } = await response.json();
            if (!results.length) {
                target.textContent = "No saved experiment results yet.";
                return;
            }
            const table = document.createElement("table");
            table.className = "experiment-table";
            const body = document.createElement("tbody");
            for (const result of results) {
                const row = document.createElement("tr");
                const lab = document.createElement("td");
                lab.textContent = result.lab;
                const date = document.createElement("td");
                date.textContent = result.generated_at || "";
                const action = document.createElement("td");
                const link = document.createElement("a");
                link.href = `experiment.html?lab=${encodeURIComponent(result.lab)}`;
                link.textContent = "View";
                action.append(link);
                row.append(lab, date, action);
                body.append(row);
            }
            table.append(body);
            target.replaceChildren(table);
        } catch (error) {
            target.textContent = `Could not load saved results: ${error.message}`;
        }
    }

    async function loadSecurityStatus() {
        const target = document.getElementById("securityStatus");
        if (!target) return;
        try {
            const response = await fetch(`${api}/api/security/status`, { cache: "no-store" });
            if (!response.ok) throw new Error(`Security status returned HTTP ${response.status}`);
            const status = await response.json();
            if (status.tls_ready) {
                target.textContent = `Chapter 12 ready · CA (${status.ca_common_name}) and server cert (${status.server_common_name}) configured. RBAC definitions ready.`;
            } else {
                target.textContent = `Chapter 12 · TLS certificates present in ${status.tls_directory}. RBAC definitions ready.`;
            }
        } catch (error) {
            target.textContent = `Could not check Chapter 12 security status: ${error.message}`;
        }
    }

    loadResults();
    loadTransactionStatus();
    loadShardingStatus();
    loadSecurityStatus();
})();

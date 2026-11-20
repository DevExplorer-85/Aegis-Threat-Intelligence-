(() => {
  const api = location.port === "8000" ? location.origin : "http://127.0.0.1:8000";
  const token = () => localStorage.getItem("cti_auth_token");
  const $ = id => document.getElementById(id);
  const esc = value => { const el = document.createElement("span"); el.textContent = String(value ?? ""); return el.innerHTML; };
  let polling = false;
  async function call(path, options = {}) {
    const headers = { ...(options.headers || {}), ...(token() ? { Authorization: `Bearer ${token()}` } : {}) };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(`${api}${path}`, { ...options, headers }); const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`); return data;
  }
  function notice(message, error = false) { const host = $("labNotice"); host.textContent = message; host.className = `l17-notice${error ? " error" : ""}`; host.hidden = false; }
  function statePill(label, enabled, detail = "") { return `<span class="l17-state-pill ${enabled ? "ok" : "warn"}">${esc(enabled ? "Ready" : "Not configured")}</span>${esc(label)}${detail ? ` · ${esc(detail)}` : ""}`; }
  function setTab(name) { document.querySelectorAll(".l17-tabs button").forEach(button => button.classList.toggle("active", button.dataset.tab === name)); document.querySelectorAll(".l17-panel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === name)); if (name === "overview" || name === "index") loadStatus(); if (name === "history") loadHistory(); if (name === "benchmark") loadBenchmarks(); }
  function renderStatus(d) {
    const entries = [["Indexed chunks", d.indexed_chunks, `${d.reports_indexed} reports indexed`], ["Questions asked", d.questions_asked, `${d.llm_answers} LLM · ${d.extractive_answers} extractive`], ["Vector dimension", d.vector_dimension ?? "—", d.embedding_model], ["Index health", d.index?.status || "unknown", d.index?.strategy || "MongoDB"]];
    $("statsGrid").innerHTML = entries.map(([label, value, sub]) => `<article class="l17-stat"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(sub)}</small></article>`).join("");
    $("providerStatus").innerHTML = `${statePill("Embedding API", d.embedding_configured, d.embedding_model)}<br>${statePill("LLM API", d.llm_configured, d.llm_model || "extractive fallback will be used")}`;
    const idx = d.index || {}; $("vectorStatus").innerHTML = `<span class="l17-state-pill ${idx.available ? "ok" : "warn"}">${esc(idx.status || "unknown")}</span>${esc(idx.detail || "No details")}`;
    $("searchIndexDetail").textContent = idx.detail || "Index status unavailable.";
    renderJob(d.job || {});
  }
  function renderJob(job) {
    const total = Number(job.total || 0), completed = Number(job.completed || 0), pct = total ? Math.min(100, completed / total * 100) : job.status === "completed" ? 100 : 0;
    $("jobStatus").textContent = `Index job · ${job.status || "idle"}`; $("jobCount").textContent = total ? `${completed.toLocaleString()} / ${total.toLocaleString()} chunks` : `${completed.toLocaleString()} completed`;
    $("jobProgress").style.width = `${pct}%`; $("jobMessage").textContent = job.message || (job.status === "running" ? "Indexing report content and generating embeddings…" : "Progress reflects completed chunk operations, not an estimate.");
    const failures = job.failures || []; $("jobFailures").innerHTML = failures.length ? `<h4>${failures.length} failed items</h4>${failures.slice(0, 30).map(f => `<div>${esc(f.item)} · ${esc(f.error)}</div>`).join("")}` : (job.status === "completed" ? '<div class="l17-state-pill ok">No item failures recorded</div>' : "");
    $("startIndex").disabled = job.status === "running";
  }
  async function loadStatus() {
    try { renderStatus(await call("/api/services/lab17")); }
    catch (error) { $("statsGrid").innerHTML = `<div class="l17-empty">${esc(error.message)}. Sign in with an administrator account to inspect indexing controls.</div>`; $("providerStatus").textContent = error.message; }
  }
  async function startIndex() {
    const button = $("startIndex"); button.disabled = true;
    try { await call("/api/ops/ask-index", { method: "POST" }); notice("Indexing started. This workspace will show completed chunks and actual failures."); await loadStatus(); pollJob(); }
    catch (error) { notice(error.message, true); button.disabled = false; }
  }
  async function pollJob() {
    if (polling) return; polling = true;
    try { let active = true; while (active) { await new Promise(resolve => setTimeout(resolve, 1300)); const data = await call("/api/services/lab17"); renderStatus(data); active = data.job?.status === "running"; } }
    catch (error) { notice(error.message, true); }
    finally { polling = false; }
  }
  function renderBenchmark(item) {
    $("benchmarkMeta").textContent = `Measured ${item.measured_at ? new Date(item.measured_at).toLocaleString() : "—"} · ${item.dataset_size || 0} vectors · ${item.sample_queries || 0} query samples`;
    const methods = item.methods || []; const max = Math.max(1, ...methods.map(m => Number(m.latency_ms || 0)));
    $("benchmarkChart").innerHTML = methods.map(method => `<article class="l17-benchmark-card ${method.supported ? "" : "unsupported"}"><h3>${esc(method.name)}</h3><span class="l17-method-pill ${method.supported ? "ok" : "warn"}">${method.supported ? "Measured" : "Unsupported / not measured"}</span><div class="l17-bar-track"><i style="width:${method.supported && method.latency_ms != null ? Math.max(2, method.latency_ms / max * 100) : 0}%"></i></div><strong>${method.latency_ms == null ? "—" : `${Number(method.latency_ms).toFixed(3)} ms`}</strong><p>Recall@5: ${method.recall_at_5 == null ? "—" : Number(method.recall_at_5).toFixed(3)}</p><small>${esc(method.configuration)}</small></article>`).join("");
    $("benchmarkMethods").innerHTML = '<p class="l17-muted">Latency chart uses measured scan duration. Recall is only shown for measured methods; unsupported algorithms have no fabricated points.</p>';
  }
  async function loadBenchmarks() { try { const d = await call("/api/ops/ask-benchmark"); if (d.items?.length) renderBenchmark(d.items[0]); else { $("benchmarkMeta").textContent = "No benchmark runs recorded."; $("benchmarkChart").innerHTML = '<div class="l17-empty">Index report chunks, then run the benchmark.</div>'; } } catch (e) { $("benchmarkMeta").textContent = e.message; } }
  async function runBenchmark() { const button = $("runBenchmark"); button.disabled = true; button.textContent = "Measuring…"; try { renderBenchmark(await call("/api/ops/ask-benchmark", { method: "POST" })); notice("Benchmark finished using the indexed vectors and measured exact scan timings."); } catch (e) { notice(e.message, true); } finally { button.disabled = false; button.textContent = "Run benchmark"; } }
  async function loadHistory() { try { const [status, benchmark] = await Promise.all([call("/api/services/lab17"), call("/api/ops/ask-benchmark")]); renderJob(status.job || {}); $("historySummary").innerHTML = `<b>Latest indexing run:</b> ${esc(status.job?.status || "none")} · ${esc(status.job?.completed ?? 0)} completed / ${esc(status.job?.total ?? 0)} total · ${esc(status.job?.finished_at || "not finished")}<br><b>Aggregate Ask usage:</b> ${esc(status.indexed_chunks)} indexed chunks · ${esc(status.reports_indexed)} reports · ${esc(status.questions_asked)} questions`; $("benchmarkHistory").innerHTML = (benchmark.items || []).map(run => `<article class="l17-history-item">Benchmark · ${esc(new Date(run.measured_at).toLocaleString())} · ${esc(run.dataset_size)} vectors · ${esc(run.sample_queries)} queries · ${esc(run.methods?.[0]?.latency_ms)} ms exact baseline</article>`).join("") || '<div class="l17-empty">No benchmark runs recorded.</div>'; } catch (e) { $("historySummary").textContent = e.message; } }
  document.querySelectorAll(".l17-tabs button").forEach(button => button.addEventListener("click", () => setTab(button.dataset.tab)));
  $("refreshOverview").onclick = loadStatus; $("startIndex").onclick = startIndex; $("runBenchmark").onclick = runBenchmark; $("refreshHistory").onclick = loadHistory;
  const initial = new URLSearchParams(location.search).get("tab"); setTab(["overview", "index", "search", "benchmark", "history"].includes(initial) ? initial : "overview");
})();

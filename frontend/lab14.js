(() => {
  const token = () => localStorage.getItem("cti_auth_token");
  const state = { summary: null, monitoring: { samples: [], alerts: [] }, alerts: [] };
  const colors = ["#70d4c8", "#80aaf6", "#efa967", "#be9ce8", "#ee8291"];
  const $ = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "—");
  const formatTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC" }).format(date) + " UTC";
  };
  const formatChartTime = (value) => {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }).format(date);
  };
  const formatAge = (seconds) => {
    if (seconds == null) return "—";
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };
  const asNum = (value, suffix = "") => value == null || !Number.isFinite(Number(value)) ? "—" : `${Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 })}${suffix}`;

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (token()) headers.set("Authorization", `Bearer ${token()}`);
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers, cache: "no-store" });
    let data;
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) throw new Error(data.detail || `Request failed (HTTP ${response.status}).`);
    return data;
  }

  function message(id, text, kind = "") {
    const el = $(id);
    el.textContent = text;
    el.className = `lab14-message ${kind}`.trim();
    el.hidden = false;
  }

  function switchView(view, updateUrl = true) {
    document.querySelectorAll("[data-panel]").forEach((panel) => { panel.hidden = panel.dataset.panel !== view; });
    document.querySelectorAll(".lab14-tabs [data-view]").forEach((button) => {
      const active = button.dataset.view === view;
      button.classList.toggle("active", active);
      button.setAttribute("aria-current", active ? "page" : "false");
    });
    if (updateUrl) {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", view === "overview" ? "overview" : view);
      history.replaceState(null, "", url);
    }
  }

  function currentView() {
    const path = window.location.pathname;
    const tab = new URLSearchParams(window.location.search).get("tab");
    if (path.startsWith("/moderation")) return "alerts";
    if (tab === "backups") return "backups";
    if (tab === "alerts") return "alerts";
    if (["metrics", "monitoring"].includes(tab)) return "metrics";
    if (tab === "recovery") return "recovery";
    return "overview";
  }

  function chartSvg(container, datasets, options = {}) {
    container.replaceChildren();
    const usable = datasets.map((set) => ({ ...set, values: set.values.filter((point) => point.value != null && Number.isFinite(Number(point.value))) })).filter((set) => set.values.length > 0);
    if (!usable.length) {
      const empty = document.createElement("p"); empty.className = "lab14-empty"; empty.textContent = options.empty || "No real samples in the selected window."; container.append(empty); return;
    }
    const ns = "http://www.w3.org/2000/svg", width = 760, height = 220, left = 46, right = 18, top = 18, bottom = 34;
    const all = usable.flatMap((set) => set.values.map((p) => Number(p.value)));
    const warn = options.warning;
    const min = options.min ?? Math.min(0, ...all, ...(warn == null ? [] : [warn]));
    const max = options.max ?? Math.max(...all, ...(warn == null ? [] : [warn]));
    const span = Math.max(1, max - min);
    const xAt = (i, n) => left + (n < 2 ? (width - left - right) / 2 : i * (width - left - right) / (n - 1));
    const yAt = (v) => height - bottom - ((v - min) / span) * (height - top - bottom);
    const svg = document.createElementNS(ns, "svg"); svg.setAttribute("viewBox", `0 0 ${width} ${height}`); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", options.label || "Monitoring chart");
    for (let i = 0; i < 4; i++) {
      const y = top + i * (height - top - bottom) / 3;
      const line = document.createElementNS(ns, "line"); line.setAttribute("x1", left); line.setAttribute("x2", width - right); line.setAttribute("y1", y); line.setAttribute("y2", y); line.setAttribute("class", "lab14-gridline"); svg.append(line);
    }
    if (warn != null) {
      const line = document.createElementNS(ns, "line"); line.setAttribute("x1", left); line.setAttribute("x2", width - right); line.setAttribute("y1", yAt(warn)); line.setAttribute("y2", yAt(warn)); line.setAttribute("class", "lab14-threshold");
      const title = document.createElementNS(ns, "title"); title.textContent = `Warning threshold: ${warn}${options.unit || ""}`; line.append(title); svg.append(line);
    }
    usable.forEach((set, index) => {
      const points = set.values.map((point, i) => `${xAt(i, set.values.length)},${yAt(Number(point.value))}`).join(" ");
      const poly = document.createElementNS(ns, "polyline"); poly.setAttribute("points", points); poly.setAttribute("fill", "none"); poly.setAttribute("stroke", colors[index % colors.length]); poly.setAttribute("stroke-width", "2.5"); poly.setAttribute("stroke-linecap", "round"); poly.setAttribute("stroke-linejoin", "round"); svg.append(poly);
      set.values.forEach((point, i) => {
        const circle = document.createElementNS(ns, "circle"); circle.setAttribute("cx", xAt(i, set.values.length)); circle.setAttribute("cy", yAt(Number(point.value))); circle.setAttribute("r", "3"); circle.setAttribute("fill", colors[index % colors.length]);
        const title = document.createElementNS(ns, "title"); title.textContent = `${formatTime(point.time)} · ${set.name}: ${asNum(point.value, options.unit || "")}`; circle.append(title); svg.append(circle);
      });
    });
    const labels = [usable[0].values[0]?.time, usable[0].values.at(-1)?.time];
    labels.forEach((label, i) => { const text = document.createElementNS(ns, "text"); text.setAttribute("x", i ? width - right : left); text.setAttribute("y", height - 8); text.setAttribute("text-anchor", i ? "end" : "start"); text.setAttribute("class", "lab14-axis-label"); text.textContent = formatChartTime(label); svg.append(text); });
    container.append(svg);
    const legend = document.createElement("div"); legend.className = "lab14-legend";
    usable.forEach((set, index) => { const item = document.createElement("span"); const swatch = document.createElement("i"); swatch.style.setProperty("--series-color", colors[index % colors.length]); item.append(swatch, document.createTextNode(esc(set.name))); legend.append(item); });
    if (warn != null) { const item = document.createElement("span"); const swatch = document.createElement("i"); swatch.className = "threshold-key"; item.append(swatch, document.createTextNode(`Warning ${warn}${options.unit || ""}`)); legend.append(item); }
    container.append(legend);
  }

  function renderMetricsTable(sample) {
    const body = $("metricsTable"); body.replaceChildren();
    if (!sample) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = 5; cell.className = "lab14-empty"; cell.textContent = "No live MongoDB sample available."; return; }
    const rows = [
      ["Cache hit ratio", sample.cache_hit_ratio_percent, "%", "≥ 80%", sample.cache_hit_ratio_percent == null ? "Unavailable" : sample.cache_hit_ratio_percent < 80 ? "WARNING" : "Healthy"],
      ["Cache usage", sample.cache_usage_mb, " MB", "—", sample.cache_usage_mb == null ? "Unavailable" : "Measured"],
      ["Connections", sample.connections, "", "—", sample.connections == null ? "Unavailable" : "Measured"],
      ["Operations per second", sample.operations_per_second, "", "—", sample.operations_per_second == null ? "Sampling" : "Measured"],
    ];
    (sample.replication_lag_by_member || []).forEach((member) => rows.push([`Replication lag · ${member.member}`, member.lag_seconds, " sec", "≤ 10 sec", member.lag_seconds == null ? "Unavailable" : member.lag_seconds > 10 ? "WARNING" : "Healthy"]));
    if (!sample.replica_set) rows.push(["Replication lag", null, "", "≤ 10 sec", "Not a replica set"]);
    for (const values of rows) {
      const row = body.insertRow();
      [values[0], asNum(values[1], values[2]), values[3], values[4], formatTime(sample.sampled_at)].forEach((value, index) => {
        const cell = row.insertCell(); cell.textContent = value;
        if (index === 3) cell.className = values[4] === "WARNING" ? "status-warning" : values[4] === "Healthy" || values[4] === "Measured" ? "status-ok" : "status-muted";
      });
    }
  }

  function renderAlerts(alerts, count) {
    const body = $("alertsTable"); body.replaceChildren();
    $("openAlertBadge").textContent = count ?? alerts.length;
    $("alertsCountHeading").textContent = count ?? alerts.length;
    $("alertSummary").textContent = count ? `${count} alert${count === 1 ? "" : "s"} need acknowledgement.` : "No open alerts.";
    if (!alerts.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = 8; cell.className = "lab14-empty"; cell.textContent = "No open alerts. Alerts will appear here when real metrics cross a configured threshold or the webhook accepts an alert."; return; }
    alerts.forEach((alert) => {
      const row = body.insertRow();
      [alert.metric, asNum(alert.actual_value), asNum(alert.threshold), alert.member, formatTime(alert.created_at), alert.severity, alert.source].forEach((value) => { row.insertCell().textContent = value; });
      const actionCell = row.insertCell();
      const button = document.createElement("button"); button.type = "button"; button.className = "lab14-secondary lab14-ack"; button.textContent = "Acknowledge"; button.dataset.alertId = alert.alert_id; actionCell.append(button);
    });
  }

  function renderBackups(rows) {
    const body = $("backupsTable"); body.replaceChildren();
    if (!rows.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = 6; cell.className = "lab14-empty"; cell.textContent = "No backup attempts found."; return; }
    rows.forEach((backup) => {
      const row = body.insertRow();
      [backup.name, asNum(backup.size_mb), formatTime(backup.created_at), backup.status, backup.trigger, backup.error || "—"].forEach((value) => { row.insertCell().textContent = value; });
    });
  }

  function renderSummary(summary) {
    state.summary = summary;
    const m = summary.metrics;
    $("serviceState").textContent = m?.stale ? `Last sample ${formatAge(summary.sample_age_seconds)} ago` : m?.connected ? "MongoDB connected" : "Waiting for MongoDB sample";
    $("serviceState").classList.toggle("online", !!m?.connected && !m?.stale);
    $("kpiCache").textContent = asNum(m?.cache_hit_ratio_percent, "%");
    const maxLag = m?.replication_lag_by_member?.length ? Math.max(...m.replication_lag_by_member.map((x) => x.lag_seconds ?? 0)) : null;
    $("kpiLag").textContent = maxLag == null ? (m?.replica_set ? "Unavailable" : "Standalone") : asNum(maxLag, "s");
    $("kpiConnections").textContent = asNum(m?.connections);
    $("kpiOps").textContent = asNum(m?.operations_per_second);
    const age = summary.rpo?.current_seconds;
    $("kpiBackupAge").textContent = formatAge(age);
    $("kpiRestore").textContent = summary.latest_restore_verification?.status || "Not verified";
    $("sampleSummary").textContent = m ? `Real sample captured ${formatTime(m.sampled_at)}${m.replica_set ? ` · replica set ${m.replica_set}` : " · standalone MongoDB"}.` : summary.monitoring_error ? `Live MongoDB sampling failed: ${summary.monitoring_error}` : "No sample has been recorded yet. MongoDB metrics are unavailable until the database is reachable.";
    const detail = $("sampleDetails"); detail.replaceChildren();
    [["Cache used", asNum(m?.cache_usage_mb, " MB")], ["Operations", m?.operations_per_type ? Object.entries(m.operations_per_type).map(([k, v]) => `${k} ${asNum(v)}/s`).join(" · ") : "Sampling"], ["Secondary members", m?.replication_lag_by_member?.length ?? (m?.replica_set ? "None reported" : "Not applicable")], ["Unacknowledged alerts", summary.unacknowledged_alert_count ?? 0]].forEach(([label, value]) => { const item = document.createElement("div"); const caption = document.createElement("span"); caption.textContent = label; const content = document.createElement("strong"); content.textContent = value; item.append(caption, content); detail.append(item); });
    $("rpoTarget").textContent = formatAge(summary.rpo?.target_seconds);
    $("rpoCurrent").textContent = age == null ? "No valid backup file recorded." : `Current backup age ${formatAge(age)} · ${summary.rpo.within_target ? "within target" : "outside target"}.`;
    $("rtoTarget").textContent = formatAge(summary.rto?.target_seconds);
    $("rtoCurrent").textContent = summary.rto?.last_verified_seconds == null ? "No successful restore verification recorded." : `Last verified in ${formatAge(summary.rto.last_verified_seconds)} · ${summary.rto.within_target ? "within target" : "outside target"}.`;
    $("backupSummary").textContent = summary.backup_configuration?.configured ? `Hourly schedule configured. ${summary.latest_backup ? `Newest file: ${summary.latest_backup.name} (${asNum(summary.latest_backup.size_mb)} MB).` : "No successful archive exists yet."}` : (summary.backup_configuration?.error || "Backup service configuration is incomplete.");
    const configurationIssues = [];
    if (summary.monitoring_error) configurationIssues.push(`Monitoring: ${summary.monitoring_error}`);
    if (!summary.backup_configuration?.configured) configurationIssues.push(`Backup: ${summary.backup_configuration?.error || "configuration incomplete"}`);
    if (!summary.restore_configuration?.configured) configurationIssues.push(`Restore verification: ${summary.restore_configuration?.error || "configuration incomplete"}`);
    if (configurationIssues.length) message("configurationMessage", configurationIssues.join(" "), "warning"); else $("configurationMessage").hidden = true;
    const restoreConfig = $("restoreConfigurationMessage");
    restoreConfig.textContent = summary.restore_configuration?.error || "";
    restoreConfig.hidden = !!summary.restore_configuration?.configured;
    const verification = summary.latest_restore_verification;
    $("verificationDetail").textContent = verification ? `${verification.status.toUpperCase()} · ${verification.collections_verified ?? 0} collections · ${verification.documents_verified ?? 0} documents · ${formatTime(verification.created_at)}${verification.error ? ` · ${verification.error}` : ""}` : "No restore verification has run.";
    $("rpoDetail").textContent = age == null ? `Target: ${formatAge(summary.rpo?.target_seconds)}. No successful backup is recorded, so current RPO cannot be measured.` : `Target: ${formatAge(summary.rpo?.target_seconds)} · current backup age: ${formatAge(age)} · ${summary.rpo.within_target ? "within target" : "outside target"}.`;
    $("rtoDetail").textContent = summary.rto?.last_verified_seconds == null ? `Target: ${formatAge(summary.rto?.target_seconds)}. RTO remains unmeasured until restore verification succeeds.` : `Target: ${formatAge(summary.rto?.target_seconds)} · last successful verification: ${formatAge(summary.rto.last_verified_seconds)} · ${summary.rto.within_target ? "within target" : "outside target"}.`;
    renderMetricsTable(m);
    renderBackups(summary.backup_history || []);
    renderAlerts(summary.alerts || [], summary.unacknowledged_alert_count);
    chartSvg($("overviewCacheChart"), [{ name: "Cache hit ratio", values: (state.monitoring.samples || []).map((s) => ({ time: s.sampled_at, value: s.cache_hit_ratio_percent })) }], { min: 0, max: 100, warning: 80, unit: "%", label: "Cache hit ratio history" });
    renderCharts();
  }

  function renderCharts() {
    const samples = state.monitoring.samples || [];
    const byMember = new Map();
    samples.forEach((sample) => (sample.replication_lag_by_member || []).forEach((entry) => {
      if (!byMember.has(entry.member)) byMember.set(entry.member, []);
      byMember.get(entry.member).push({ time: sample.sampled_at, value: entry.lag_seconds });
    }));
    const lagSets = Array.from(byMember, ([name, values]) => ({ name, values }));
    chartSvg($("cacheChart"), [{ name: "Cache hit ratio", values: samples.map((s) => ({ time: s.sampled_at, value: s.cache_hit_ratio_percent })) }], { min: 0, max: 100, warning: 80, unit: "%" });
    chartSvg($("replicationChart"), lagSets, { min: 0, warning: 10, unit: "s", empty: "No replica set lag samples available in this window." });
    chartSvg($("operationsChart"), [{ name: "Operations / sec", values: samples.map((s) => ({ time: s.sampled_at, value: s.operations_per_second })) }]);
    chartSvg($("connectionsChart"), [{ name: "Connections", values: samples.map((s) => ({ time: s.sampled_at, value: s.connections })) }]);
    const backups = (state.summary?.backup_history || []).filter((b) => b.status === "completed" && b.size_mb != null).slice().reverse();
    chartSvg($("backupChart"), [{ name: "Backup size", values: backups.map((b) => ({ time: b.created_at, value: b.size_mb })) }], { unit: " MB", empty: "No successful backup sizes are available." });
  }

  async function load() {
    if (window.location.pathname.startsWith("/moderation")) {
      try {
        const result = await api("/api/moderation/alerts?status=open");
        state.alerts = result.alerts || [];
        renderAlerts(state.alerts, result.unacknowledged_count);
        $("serviceState").textContent = "Alert moderation connected";
        $("serviceState").classList.add("online");
        $("accessMessage").hidden = true;
      } catch (error) {
        message("accessMessage", `${error.message} Sign in with an Aegis administrator or alert moderator account, then refresh.`, "warning");
        $("openAlertBadge").textContent = "—";
        $("alertsCountHeading").textContent = "—";
        $("alertSummary").textContent = "Alert queue unavailable until sign in.";
        const body = $("alertsTable");
        body.replaceChildren();
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 8;
        cell.className = "lab14-empty";
        cell.textContent = `${error.message} Sign in with an Aegis administrator or alert moderator account, then refresh.`;
      }
      return;
    }
    try {
      const [summaryResult, monitoringResult, alertsResult] = await Promise.allSettled([
        api("/api/services/lab14"),
        api(`/api/ops/metrics/monitoring?minutes=${$("metricsWindow").value}`),
        api("/api/moderation/alerts?status=open"),
      ]);
      if (summaryResult.status === "rejected") throw summaryResult.reason;
      const summary = summaryResult.value;
      const refreshIssues = [];
      if (monitoringResult.status === "fulfilled") state.monitoring = monitoringResult.value;
      else { state.monitoring = { samples: [], alerts: [] }; refreshIssues.push(`Metric history unavailable: ${monitoringResult.reason.message}`); }
      if (alertsResult.status === "fulfilled") state.alerts = alertsResult.value.alerts || [];
      else { state.alerts = summary.alerts || []; refreshIssues.push(`Alert queue unavailable: ${alertsResult.reason.message}`); }
      renderSummary({
        ...summary,
        alerts: state.alerts,
        unacknowledged_alert_count: alertsResult.status === "fulfilled" ? alertsResult.value.unacknowledged_count : summary.unacknowledged_alert_count,
      });
      if (refreshIssues.length) message("accessMessage", refreshIssues.join(" "), "warning");
      else $("accessMessage").hidden = true;
    } catch (error) {
      $("serviceState").textContent = "Unavailable";
      message("accessMessage", `${error.message} Sign in with an Aegis administrator or alert moderator account, then refresh.`, "warning");
      renderMetricsTable(null);
    }
  }

  async function runAction(action) {
    const isBackup = action === "backup";
    const button = document.querySelector(`[data-action="${action}"]`) || (isBackup ? $("backupNowButton") : $("verifyRestoreButton"));
    const prior = button?.textContent;
    if (button) { button.disabled = true; button.textContent = isBackup ? "Creating backup…" : "Verifying restore…"; }
    try {
      const result = await api(isBackup ? "/api/ops/lab14/backup" : "/api/ops/lab14/verify", { method: "POST", body: "{}" });
      const info = isBackup ? result.backup : result.verification;
      const status = isBackup ? `${info.name} created · ${asNum(info.size_mb)} MB · ${formatTime(info.created_at)}` : `${info.status} · ${info.collections_verified} collections and ${info.documents_verified} documents · ${formatTime(info.created_at)}`;
      message("actionMessage", status, "success");
      const resultBox = $("backupResult"); resultBox.textContent = status; resultBox.hidden = false;
      if (isBackup) {
        const history = state.summary?.backup_history || [];
        const updatedHistory = [info, ...history.filter((entry) => entry.backup_id !== info.backup_id)];
        if (state.summary) state.summary = { ...state.summary, backup_history: updatedHistory, latest_backup: info };
        renderBackups(updatedHistory);
        renderCharts();
      }
      await load();
    } catch (error) { message("actionMessage", error.message, "error"); }
    finally { if (button) { button.disabled = false; button.textContent = prior || (isBackup ? "Back up now" : "Verify restore"); } }
  }

  document.addEventListener("click", async (event) => {
    const viewButton = event.target.closest("[data-view]");
    if (viewButton) { switchView(viewButton.dataset.view); return; }
    const actionButton = event.target.closest("[data-action]");
    if (actionButton) { await runAction(actionButton.dataset.action); return; }
    const ackButton = event.target.closest("[data-alert-id]");
    if (ackButton) {
      ackButton.disabled = true;
      try {
        const result = await api("/api/moderation/alerts/ack", { method: "POST", body: JSON.stringify({ alert_id: ackButton.dataset.alertId }) });
        message("actionMessage", `Alert acknowledged by ${result.alert.acknowledged_by} at ${formatTime(result.alert.acknowledged_at)}.`, "success");
        await load();
      } catch (error) { ackButton.disabled = false; message("actionMessage", error.message, "error"); }
    }
  });
  $("backupNowButton").addEventListener("click", () => runAction("backup"));
  $("verifyRestoreButton").addEventListener("click", () => runAction("verify"));
  $("refreshButton").addEventListener("click", load);
  $("refreshAlerts").addEventListener("click", load);
  $("metricsWindow").addEventListener("change", load);
  if (window.location.pathname.startsWith("/moderation")) {
    // The moderation endpoint intentionally exposes alerts to moderators only;
    // keep admin-only metrics and operations out of this focused queue view.
    const kpis = document.querySelector(".lab14-kpis");
    if (kpis) kpis.hidden = true;
    document.querySelectorAll(".lab14-tabs [data-view]").forEach((button) => {
      if (button.dataset.view !== "alerts") button.hidden = true;
    });
  }
  switchView(currentView(), false);
  load();
  window.setInterval(load, 30000);
})();

(() => {
  const api = location.port === "8000" ? location.origin : "http://127.0.0.1:8000";
  const $ = id => document.getElementById(id);
  const token = () => localStorage.getItem("cti_auth_token");
  const conversation = $("conversation");
  const esc = value => String(value ?? "");
  async function call(path, options = {}) {
    const headers = { ...(options.headers || {}), ...(token() ? { Authorization: `Bearer ${token()}` } : {}) };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(`${api}${path}`, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  }
  function appendTextWithCitations(host, value, sources) {
    const pattern = /\[(\d+)\]/g;
    let offset = 0, match;
    while ((match = pattern.exec(value))) {
      host.append(document.createTextNode(value.slice(offset, match.index)));
      const source = sources.find(item => Number(item.source_number) === Number(match[1]));
      if (source) {
        const link = document.createElement("a");
        link.href = `#source-${source.source_number}`; link.textContent = match[0]; link.className = "l17-citation";
        host.append(link);
      } else host.append(document.createTextNode(match[0]));
      offset = pattern.lastIndex;
    }
    host.append(document.createTextNode(value.slice(offset)));
  }
  function renderItem(item) {
    const turn = document.createElement("article"); turn.className = "l17-turn";
    const question = document.createElement("div"); question.className = "l17-message user";
    const label = document.createElement("span"); label.className = "l17-message-label"; label.textContent = "YOU";
    const q = document.createElement("p"); q.textContent = esc(item.question); question.append(label, q);
    const answer = document.createElement("div"); answer.className = "l17-message assistant";
    const head = document.createElement("div"); head.className = "l17-answer-head";
    const answerLabel = document.createElement("span"); answerLabel.className = "l17-message-label"; answerLabel.textContent = "AEGIS · ANSWER";
    const mode = document.createElement("span"); mode.className = `l17-mode ${item.mode === "llm" ? "llm" : "extractive"}`; mode.textContent = item.mode === "llm" ? `LLM · ${item.model || "configured model"}` : "Extractive · no LLM";
    head.append(answerLabel, mode);
    const body = document.createElement("p"); body.className = "l17-answer-text"; appendTextWithCitations(body, esc(item.answer), item.sources || []);
    answer.append(head, body);
    const sources = item.sources || [];
    if (sources.length) {
      const sourceHeading = document.createElement("h3"); sourceHeading.className = "l17-sources-title"; sourceHeading.textContent = "Retrieved sources"; answer.append(sourceHeading);
      const grid = document.createElement("div"); grid.className = "l17-source-grid";
      for (const source of sources) {
        const card = document.createElement("article"); card.className = "l17-source"; card.id = `source-${source.source_number}`;
        const title = document.createElement("h4"); title.textContent = `[${source.source_number}] ${esc(source.report_title)}`;
        const meta = document.createElement("div"); meta.className = "l17-source-meta"; meta.textContent = `Page ${source.page_number ?? "—"} · Relevance ${Number(source.relevance_score || 0).toFixed(3)}`;
        const excerpt = document.createElement("p"); excerpt.textContent = esc(source.text);
        card.append(title, meta, excerpt); grid.append(card);
      }
      answer.append(grid);
    }
    turn.append(question, answer); conversation.append(turn);
  }
  async function loadHistory() {
    if (!token()) { $("askStatus").textContent = "Sign in to continue."; conversation.innerHTML = '<div class="l17-empty">Sign in through the Aegis dashboard before using Ask CTI.</div>'; return; }
    try {
      const result = await call("/api/ask/history"); conversation.replaceChildren();
      for (const item of result.items || []) renderItem(item);
      $("askStatus").textContent = result.items?.length ? `${result.items.length} saved question${result.items.length === 1 ? "" : "s"}` : "No questions yet · your history is private.";
      if (!result.items?.length) conversation.innerHTML = '<div class="l17-empty">Ask a question to search the report library. Retrieved evidence and citations will appear here.</div>';
      conversation.scrollTop = conversation.scrollHeight;
    } catch (error) { $("askStatus").textContent = error.message; conversation.innerHTML = `<div class="l17-empty">${esc(error.message)}</div>`; }
  }
  $("askForm").addEventListener("submit", async event => {
    event.preventDefault(); const button = $("sendQuestion"), input = $("question"), question = input.value.trim();
    if (!question) return; button.disabled = true; button.textContent = "Searching…"; $("askStatus").textContent = "Embedding question · searching indexed reports · preparing answer…";
    try { const result = await call("/api/ask", { method: "POST", body: JSON.stringify({ question }) }); input.value = ""; if (conversation.querySelector(".l17-empty")) conversation.replaceChildren(); renderItem(result); conversation.scrollTop = conversation.scrollHeight; $("askStatus").textContent = result.mode === "llm" ? `Answered with ${result.model}.` : "Extractive answer · generated from retrieved report content without an LLM."; }
    catch (error) { $("askStatus").textContent = error.message; }
    finally { button.disabled = false; button.innerHTML = 'Send <span aria-hidden="true">↗</span>'; }
  });
  $("forgetConversation").addEventListener("click", async () => {
    if (!token()) { $("askStatus").textContent = "Sign in before clearing conversation history."; return; }
    const button = $("forgetConversation"); button.disabled = true;
    try { const result = await call("/api/ask/history", { method: "DELETE" }); conversation.innerHTML = '<div class="l17-empty">Conversation forgotten. Start a new research question whenever you are ready.</div>'; $("askStatus").textContent = `${result.deleted} saved turn${result.deleted === 1 ? "" : "s"} removed.`; }
    catch (error) { $("askStatus").textContent = error.message; } finally { button.disabled = false; }
  });
  loadHistory();
})();

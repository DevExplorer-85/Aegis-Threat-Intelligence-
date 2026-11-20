(() => {
    const api = window.location.port === "8000"
        ? window.location.origin
        : "http://127.0.0.1:8000";

    /* ── Navigation categories & links ─────────────────────────────── */
    const categories = [
        {
            label: "THREAT INTELLIGENCE",
            links: [
                { icon: "》", title: "Live Threat Stream", href: "index.html" },
                { icon: "⊛", title: "Top Threats", href: "index.html#threats" },
                { icon: "☰", title: "Report Corpus", href: "index.html#reports" },
                { icon: "⌕", title: "Search & Enrich", href: "index.html#search" },
                { icon: "⊕", title: "Cross-Source Analysis", href: "cross-source.html" },
            ]
        },
        {
            label: "SYSTEM MONITORING",
            links: [
                { icon: "⚡", title: "Working Set Monitor", href: "experiment.html?lab=7.2-try" },
            ]
        },
        {
            label: "PERFORMANCE & RELIABILITY",
            links: [
                { icon: "◷", title: "Write Concern Latency", href: "experiment.html?lab=9.1" },
                { icon: "▣", title: "Network Reliability", href: "experiment.html?lab=9.1-try" },
            ]
        },
        {
            label: "BUSINESS OPERATIONS",
            links: [
                { icon: "◈", title: "Banking Operations", href: "experiment.html?lab=10.1", chapter: "10" },
                { icon: "◉", title: "Reliability & Inventory", href: "experiment.html?lab=10.2", chapter: "10" },
                { icon: "▤", title: "Sharding & Horizontal", href: "experiment.html?lab=11.1", chapter: "11" },
            ]
        },
        {
            label: "SECURITY & COMPLIANCE",
            links: [
                { icon: "🔒", title: "Zero-Trust RBAC", href: "experiment.html?lab=12.1", chapter: "12" },
                { icon: "🛡️", title: "TLS & Redaction", href: "experiment.html?lab=12.2", chapter: "12" },
            ]
        },
        {
            label: "INFRASTRUCTURE",
            links: [
                { icon: "☁️", title: "Cloud & Container Ops", href: "/extras/lab13", chapter: "13" },
                { icon: "📈", title: "Monitoring & Backup", href: "/extras/lab14", chapter: "14" },
            ]
        },
        {
            label: "ADVANCED MODULES",
            links: [
                { icon: "🗂️", title: "Case Management", href: "/cases", chapter: "15" },
                { icon: "🕸️", title: "Cassandra & Neo4j", href: "/extras/lab16", chapter: "16" },
                { icon: "🧠", title: "Vector Search & RAG", href: "/extras/lab17", chapter: "17" },
                { icon: "⚖️", title: "Comparative Capstone", href: "/extras/lab18", chapter: "18" },
            ]
        }
    ];

    /* Which link matches current page */
    function isActive(href) {
        const path = window.location.pathname;
        const search = window.location.search;
        const full = path + search;
        // Exact match first
        if (href === full) return true;
        if (href === path) return true;
        // Experiment page match
        if (path.includes("experiment.html") && href.includes("experiment.html")) {
            return href === `experiment.html${search}` || href === `${path}${search}`;
        }
        // Index page
        if ((path === "/" || path.endsWith("index.html")) && (href === "index.html" || href.startsWith("index.html#"))) return true;
        // Feature pages
        if (path.includes(href.replace(/^\//, ""))) return true;
        return false;
    }

    async function fetchCurrentUser() {
        const token = localStorage.getItem("cti_auth_token");
        try {
            const res = await fetch(`${api}/api/auth/me`, {
                headers: token ? { "Authorization": `Bearer ${token}` } : {}
            });
            if (res.ok) return await res.json();
        } catch (e) {}
        return {
            authenticated: false,
            user: {
                name: "Guest Analyst",
                role: "soc_analyst",
                role_display: "Tier-1 SOC Analyst",
                organization: "Enterprise Workspace"
            }
        };
    }

    async function installSidebar() {
        /* Don't double-install */
        if (document.querySelector(".sidebar")) return;

        const userInfo = await fetchCurrentUser();
        const user = userInfo.user;
        const initial = String(user.name || "A").trim().charAt(0).toUpperCase();

        /* Create sidebar */
        const sidebar = document.createElement("aside");
        sidebar.className = "sidebar";

        /* ─ Header ─ */
        sidebar.innerHTML = `
            <div class="sidebar-header">
                <a class="sidebar-brand" href="experiments.html">
                    <div class="sidebar-logo">🛡</div>
                    <span class="sidebar-title">Threat Intelligence<br>Platform</span>
                </a>
                <div class="sidebar-avatar" title="${user.name}">${initial}</div>
            </div>
            <nav class="sidebar-nav" aria-label="Platform Navigation"></nav>
            <div class="sidebar-footer">
                <div class="sidebar-role-badge">
                    <span class="sidebar-role-dot"></span>
                    <div>
                        <div class="sidebar-role-name">${user.name}</div>
                        <div class="sidebar-role-label">${user.role_display || user.role}</div>
                    </div>
                </div>
                <button class="role-switch-btn">Switch role</button>
            </div>
        `;

        const nav = sidebar.querySelector(".sidebar-nav");

        /* Hub link at top */
        const hubLink = document.createElement("a");
        hubLink.className = "sidebar-link" + (window.location.pathname.includes("experiments") ? " active" : "");
        hubLink.href = "experiments.html";
        hubLink.innerHTML = `<span class="sidebar-link-icon">⬡</span> All Modules`;
        hubLink.style.marginBottom = "6px";
        hubLink.style.fontWeight = "600";
        nav.append(hubLink);

        /* Build category sections */
        for (const cat of categories) {
            const catLabel = document.createElement("div");
            catLabel.className = "sidebar-category";
            catLabel.textContent = cat.label;
            nav.append(catLabel);

            for (const link of cat.links) {
                const a = document.createElement("a");
                a.className = "sidebar-link" + (isActive(link.href) ? " active" : "");
                a.href = link.href;
                a.innerHTML = `<span class="sidebar-link-icon">${link.icon}</span> ${link.title}`;
                nav.append(a);
            }
        }

        /* Role switch */
        const switchBtn = sidebar.querySelector(".role-switch-btn");
        switchBtn.addEventListener("click", async () => {
            const nextRole = user.role === "admin" ? "soc_analyst" : "admin";
            const creds = nextRole === "admin"
                ? { email: "admin@cti.platform", password: "admin123" }
                : { email: "analyst@cti.platform", password: "analyst123" };
            try {
                const loginRes = await fetch(`${api}/api/auth/login`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(creds)
                });
                if (loginRes.ok) {
                    const data = await loginRes.json();
                    localStorage.setItem("cti_auth_token", data.token);
                    window.location.reload();
                }
            } catch (err) {
                alert("Could not switch role: " + err.message);
            }
        });

        /* Wrap existing body content in .main-content */
        const mainContent = document.createElement("div");
        mainContent.className = "main-content";

        /* Move all existing body children into mainContent */
        while (document.body.firstChild) {
            mainContent.appendChild(document.body.firstChild);
        }

        /* Create app shell */
        const shell = document.createElement("div");
        shell.className = "app-shell";
        shell.append(sidebar, mainContent);
        document.body.appendChild(shell);
    }

    /* ── Cluster status (now a subtle banner inside main content) ──── */
    function installClusterStatus() {
        const mainContent = document.querySelector(".main-content");
        if (!mainContent || document.querySelector(".cluster-status-bar")) return;

        const bar = document.createElement("div");
        bar.className = "cluster-status-bar";
        bar.style.cssText = `
            padding: 8px 42px;
            font-size: 12px;
            color: #9e8a87;
            border-bottom: 1px solid #e8ddd7;
            background: #f7f1ee;
            display: flex;
            align-items: center;
            gap: 10px;
        `;
        bar.innerHTML = `<strong style="color:#4a2c2a">MongoDB</strong> <span>Connecting…</span>`;
        mainContent.prepend(bar);

        async function refresh() {
            try {
                const response = await fetch(`${api}/api/cluster`, { cache: "no-store" });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                const statusSpan = bar.querySelector("span");
                if (!data.connected) {
                    statusSpan.textContent = "DATABASE UNAVAILABLE";
                    statusSpan.style.color = "#c0392b";
                } else {
                    const memberText = (data.members || []).map(m =>
                        `${m.name}: ${m.state}${data.mongodb_version ? ` · v${data.mongodb_version}` : ""}`
                    ).join("  ·  ");
                    statusSpan.textContent = memberText || "Connected";
                    statusSpan.style.color = "#3a855d";
                }
            } catch (err) {
                const statusSpan = bar.querySelector("span");
                statusSpan.textContent = `Unavailable`;
                statusSpan.style.color = "#c0392b";
            }
        }
        refresh();
        setInterval(refresh, 3000);
    }

    document.addEventListener("DOMContentLoaded", () => {
        installSidebar();
        installClusterStatus();
    });
})();

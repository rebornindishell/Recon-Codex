const state = {
  assets: [],
  findings: [],
  summary: {},
  connectors: [],
};

const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  window.setTimeout(() => node.classList.remove("show"), 2600);
}

async function refresh() {
  const [summary, assets, findings, connectors] = await Promise.all([
    api("/api/summary"),
    api("/api/assets"),
    api("/api/findings"),
    api("/api/connectors"),
  ]);
  state.summary = summary;
  state.assets = assets.assets;
  state.findings = findings.findings;
  state.connectors = connectors.connectors;
  render();
}

function render() {
  renderMetrics();
  renderAssets();
  renderFindings();
  renderConnectors();
}

function renderMetrics() {
  const items = [
    ["Assets", state.summary.asset_count || 0],
    ["Exposed", state.summary.exposed_count || 0],
    ["Findings", state.summary.finding_count || 0],
    ["Critical Assets", state.summary.critical_count || 0],
  ];
  $("#metrics").innerHTML = items.map(([label, value]) => `
    <div class="metric">
      <strong>${escapeHtml(value)}</strong>
      <span>${escapeHtml(label)}</span>
    </div>
  `).join("");
}

function renderAssets() {
  const filter = ($("#assetFilter").value || "").toLowerCase();
  const rows = state.assets.filter((asset) => JSON.stringify(asset).toLowerCase().includes(filter));
  $("#assetRows").innerHTML = rows.map((asset) => `
    <tr>
      <td>
        <strong>${escapeHtml(asset.display_name || asset.value)}</strong>
        <div>${renderTags(asset.tags || [])}</div>
      </td>
      <td>${escapeHtml(asset.asset_type)}</td>
      <td><span class="pill ${escapeHtml(asset.criticality)}">${escapeHtml(asset.criticality)}</span></td>
      <td><span class="pill ${escapeHtml((asset.suggested_priority || asset.priority).toLowerCase())}">${escapeHtml(asset.suggested_priority || asset.priority)}</span></td>
      <td><strong>${escapeHtml(asset.risk_score || 0)}</strong></td>
      <td>${asset.exposed ? '<span class="pill high">exposed</span>' : '<span class="pill">tracked</span>'}</td>
      <td>${escapeHtml([asset.software_name, asset.software_version].filter(Boolean).join(" ") || "-")}</td>
      <td>${escapeHtml(asset.recommendation || "-")}</td>
    </tr>
  `).join("");
}

function renderFindings() {
  $("#findingCount").textContent = `${state.findings.length} open`;
  $("#findingRows").innerHTML = state.findings.length ? state.findings.map((finding) => `
    <article class="finding">
      <header>
        <div>
          <strong>${escapeHtml(finding.summary)}</strong>
          <p>${escapeHtml(finding.recommendation)}</p>
        </div>
        <span class="pill ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      </header>
      <small>Asset #${escapeHtml(finding.asset_id)} | ${escapeHtml(finding.source)} | Confidence ${Math.round((finding.confidence || 0) * 100)}%</small>
    </article>
  `).join("") : `<p>No findings yet.</p>`;
}

function renderConnectors() {
  $("#connectorRows").innerHTML = state.connectors.map((connector) => `
    <div class="connector">
      <div>
        <strong>${escapeHtml(connector.name)}</strong>
        <p>${escapeHtml(connector.details)}</p>
      </div>
      <span class="pill ${connector.configured ? "p3" : "p2"}">${connector.configured ? "ready" : "needs setup"}</span>
    </div>
  `).join("");
}

function renderTags(tags) {
  return tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join(" ");
}

function formToObject(form) {
  const data = new FormData(form);
  const payload = Object.fromEntries(data.entries());
  payload.exposed = data.has("exposed");
  if (payload.tags) {
    payload.tags = payload.tags.split(",").map((item) => item.trim()).filter(Boolean);
  }
  if (!payload.business_unit_id) {
    delete payload.business_unit_id;
  }
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

$("#refresh").addEventListener("click", () => refresh().catch((error) => toast(error.message)));
$("#assetFilter").addEventListener("input", renderAssets);

$("#assetForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/api/assets", { method: "POST", body: JSON.stringify(formToObject(event.currentTarget)) });
  event.currentTarget.reset();
  toast("Asset saved");
  await refresh();
});

$("#discoveryForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const domains = new FormData(event.currentTarget).get("domains");
  const result = await api("/api/discover", { method: "POST", body: JSON.stringify({ domains }) });
  toast(`Discovery added ${result.discovered} assets`);
  await refresh();
});

$("#vulnCheck").addEventListener("click", async () => {
  const result = await api("/api/vuln-check", { method: "POST", body: JSON.stringify({ organization_id: 1 }) });
  toast(`Checked ${result.assets_checked} assets`);
  await refresh();
});

$("#dailyMonitor").addEventListener("click", async () => {
  await api("/api/daily-monitor", { method: "POST", body: JSON.stringify({ organization_id: 1 }) });
  toast("Daily monitor completed");
  await refresh();
});

$("#csvForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const csv = new FormData(event.currentTarget).get("csv");
  const result = await api("/api/import/csv", { method: "POST", body: JSON.stringify({ csv }) });
  toast(`Imported ${result.imported} CSV assets`);
  await refresh();
});

$("#jsonForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const value = new FormData(event.currentTarget).get("json");
  const parsed = JSON.parse(value);
  const result = await api("/api/import/json", { method: "POST", body: JSON.stringify(parsed) });
  toast(`Imported ${result.imported} JSON assets`);
  await refresh();
});

refresh().catch((error) => toast(error.message));

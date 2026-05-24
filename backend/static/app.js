const els = {
  riskPanel: document.querySelector("#riskPanel"),
  modelStatus: document.querySelector("#modelStatus"),
  profileBadge: document.querySelector("#profileBadge"),
  statusText: document.querySelector("#statusText"),
  riskScore: document.querySelector("#riskScore"),
  threatText: document.querySelector("#threatText"),
  topReason: document.querySelector("#topReason"),
  modeChip: document.querySelector("#modeChip"),
  sensitivityChip: document.querySelector("#sensitivityChip"),
  sourceChip: document.querySelector("#sourceChip"),
  piStatus: document.querySelector("#piStatus"),
  modeSelect: document.querySelector("#modeSelect"),
  sensitivitySelect: document.querySelector("#sensitivitySelect"),
  reasonCount: document.querySelector("#reasonCount"),
  reasonList: document.querySelector("#reasonList"),
  metricGrid: document.querySelector("#metricGrid"),
  baselineSummary: document.querySelector("#baselineSummary"),
  apCount: document.querySelector("#apCount"),
  apRows: document.querySelector("#apRows"),
  eventCount: document.querySelector("#eventCount"),
  timeline: document.querySelector("#timeline"),
};

const featureLabels = {
  ap_count: "Visible APs",
  unknown_bssid_count: "Unknown BSSID",
  known_ssid_unknown_bssid_count: "SSID mismatch",
  duplicate_ssid_count: "Duplicate SSID",
  open_network_count: "Open AP",
  strong_unknown_count: "Strong unknown",
  deauth_count: "Deauth frames",
  probe_request_count: "Probe requests",
  unique_client_count: "Unique clients",
  privacy_probe_count: "Privacy probes",
  channel_switch_count: "Channel drift",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) throw new Error(`${path} failed (${response.status})`);
  return response.json();
}

function statusClass(status) {
  if (status === "ALERT") return "alert";
  if (status === "WATCH") return "watch";
  if (status === "SAFE") return "safe";
  return "ready";
}

function round(value) {
  return Number.isFinite(Number(value)) ? Math.round(Number(value)) : 0;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function render(data) {
  const state = data.state || {};
  const profile = data.profile_summary || {};
  const reasons = data.reasons || [];
  const features = data.features || {};
  const networks = data.networks || [];
  const events = data.events || [];

  els.riskPanel.dataset.state = statusClass(data.status);
  els.modelStatus.textContent = data.model_status || "rules-only";
  els.profileBadge.textContent = `Profile: ${profile.active_profile || state.active_profile || "lab"}`;
  els.statusText.textContent = data.status || "READY";
  els.riskScore.textContent = round(data.risk_score);
  els.threatText.textContent = data.threat || "Waiting for sensor input";
  els.topReason.textContent = data.top_reason || "No reason yet";
  els.modeChip.textContent = `mode: ${state.mode || "monitor"}`;
  els.sensitivityChip.textContent = `sensitivity: ${state.sensitivity || "normal"}`;
  els.sourceChip.textContent = `source: ${data.source || "system"}`;
  els.piStatus.textContent = `Pi: ${state.pi_sensor || "standby"}`;
  els.modeSelect.value = state.mode || "monitor";
  els.sensitivitySelect.value = state.sensitivity || "normal";
  els.baselineSummary.textContent = `${profile.known_bssid_count || 0} AP baseline`;

  renderReasons(reasons);
  renderMetrics(features);
  renderAps(networks);
  renderEvents(events);
}

function renderReasons(reasons) {
  els.reasonCount.textContent = `${reasons.length} reasons`;
  els.reasonList.innerHTML = "";
  if (!reasons.length) {
    els.reasonList.innerHTML = `<div class="empty">No risk reasons yet.</div>`;
    return;
  }
  reasons.forEach((reason) => {
    const item = document.createElement("div");
    item.className = "reason-card";
    item.innerHTML = `
      <div>
        <b>${escapeHtml(reason.title)}</b>
        <span>+${round(reason.points)} risk points</span>
      </div>
      <p>${escapeHtml(reason.detail)}</p>
      <small>Evidence: ${escapeHtml(reason.evidence)}</small>
      <small>Action: ${escapeHtml(reason.recommendation)}</small>
    `;
    els.reasonList.appendChild(item);
  });
}

function renderMetrics(features) {
  els.metricGrid.innerHTML = "";
  Object.entries(featureLabels).forEach(([key, label]) => {
    const metric = document.createElement("div");
    metric.className = "metric";
    metric.innerHTML = `<small>${label}</small><b>${round(features[key])}</b>`;
    els.metricGrid.appendChild(metric);
  });
}

function renderAps(networks) {
  els.apCount.textContent = `${networks.length} APs`;
  els.apRows.innerHTML = "";
  networks.forEach((net) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(net.ssid)}</td>
      <td><code>${escapeHtml(net.bssid)}</code></td>
      <td>${round(net.rssi)}</td>
      <td>${round(net.channel)}</td>
      <td>${escapeHtml(net.encryption)}</td>
    `;
    els.apRows.appendChild(row);
  });
}

function renderEvents(events) {
  els.eventCount.textContent = `${events.length} latest`;
  els.timeline.innerHTML = "";
  if (!events.length) {
    els.timeline.innerHTML = `<div class="empty">No events stored yet.</div>`;
    return;
  }
  events.forEach((event) => {
    const item = document.createElement("div");
    item.className = `event ${statusClass(event.status)}`;
    const time = new Date(event.created_at).toLocaleTimeString();
    item.innerHTML = `
      <b>${escapeHtml(event.status)} · ${round(event.risk_score)}%</b>
      <span>${escapeHtml(event.threat)}</span>
      <small>${time} · ${escapeHtml(event.summary)}</small>
    `;
    els.timeline.appendChild(item);
  });
}

async function refresh() {
  try {
    render(await api("/api/status"));
  } catch (error) {
    els.modelStatus.textContent = error.message;
  }
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", async () => {
    await api("/api/control", {
      method: "POST",
      body: JSON.stringify({ action: button.dataset.action }),
    });
    await refresh();
  });
});

document.querySelectorAll("[data-demo]").forEach((button) => {
  button.addEventListener("click", async () => {
    render(await api(`/api/demo/${button.dataset.demo}`, { method: "POST" }));
  });
});

els.modeSelect.addEventListener("change", async () => {
  await api("/api/control", { method: "POST", body: JSON.stringify({ mode: els.modeSelect.value }) });
  await refresh();
});

els.sensitivitySelect.addEventListener("change", async () => {
  await api("/api/control", { method: "POST", body: JSON.stringify({ sensitivity: els.sensitivitySelect.value }) });
  await refresh();
});

refresh();
setInterval(refresh, 2500);

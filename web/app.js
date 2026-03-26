


let devices = [];
let alerts = [];
let currentFilter = "all";
let currentTab = "dashboard";

const byId = (id) => document.getElementById(id);

async function api(url, options = {}) {
  const res = await fetch(`.${url}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      message = data.detail || message;
    } catch (_) {}
    throw new Error(message);
  }

  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return await res.json();
  }
  return null;
}

function toast(message, isError = false) {
  const el = byId("toast");
  el.textContent = message;
  el.className = `toast show ${isError ? "error" : ""}`;
  setTimeout(() => {
    el.className = "toast";
  }, 2600);
}

function setHealth(text, ok = true) {
  byId("health-text").textContent = text;
  document.querySelector(".dot").className = `dot ${ok ? "online" : "offline"}`;
}

function statusLabel(device) {
  if (device.approved === 0) return "new";
  return device.status || "offline";
}

function badgeHtml(device) {
  const status = statusLabel(device);
  return `<span class="badge badge-${status}">${status.toUpperCase()}</span>`;
}

function deviceMatchesFilter(device) {
  const status = statusLabel(device);

  if (currentFilter === "all") return true;
  if (currentFilter === "online") return status === "online";
  if (currentFilter === "offline") return status === "offline";
  if (currentFilter === "new") return status === "new";
  if (currentFilter === "critical") return Number(device.critical) === 1;
  if (currentFilter === "pinned") return Number(device.pinned) === 1;
  return true;
}

function deviceMatchesSearch(device) {
  const q = byId("search-input")?.value?.trim()?.toLowerCase() || "";
  if (!q) return true;
  return (
    (device.name || "").toLowerCase().includes(q) ||
    (device.ip || "").toLowerCase().includes(q) ||
    (device.category || "").toLowerCase().includes(q)
  );
}

function renderStats() {
  const total = devices.length;
  const online = devices.filter((d) => statusLabel(d) === "online").length;
  const offline = devices.filter((d) => statusLabel(d) === "offline").length;
  const isNew = devices.filter((d) => statusLabel(d) === "new").length;

  byId("stat-total").textContent = total;
  byId("stat-online").textContent = online;
  byId("stat-offline").textContent = offline;
  byId("stat-new").textContent = isNew;
}

function deviceCard(device) {
  const pinned = Number(device.pinned) === 1;
  const critical = Number(device.critical) === 1;

  return `
    <div class="device-card ${pinned ? "pinned" : ""}">
      <div class="device-card-head">
        <div>
          <div class="device-name-row">
            <h3>${escapeHtml(device.name || device.ip)}</h3>
            ${device.flag ? `<span class="flag-pill">${escapeHtml(device.flag)}</span>` : ""}
          </div>
          <div class="device-ip">${escapeHtml(device.ip)}</div>
        </div>
        ${badgeHtml(device)}
      </div>

      <div class="device-meta">
        <div><span class="meta-label">Category:</span> ${escapeHtml(device.category || "-")}</div>
        <div><span class="meta-label">Source:</span> ${escapeHtml(device.source || "-")}</div>
        <div><span class="meta-label">Last seen:</span> ${escapeHtml(device.last_seen || "-")}</div>
      </div>

      ${device.notes ? `<div class="device-notes">${escapeHtml(device.notes)}</div>` : ""}

      <div class="device-actions">
        ${device.approved === 0 ? `<button class="btn btn-small" onclick="approveDevice(${device.id})">Approve</button>` : ""}
        <button class="btn btn-small" onclick="togglePinned(${device.id}, ${pinned ? "false" : "true"})">${pinned ? "Unpin" : "Pin"}</button>
        <button class="btn btn-small" onclick="toggleCritical(${device.id}, ${critical ? "false" : "true"})">${critical ? "Unmark critical" : "Mark critical"}</button>
        <button class="btn btn-small" onclick="editDevice(${device.id})">Edit</button>
        <button class="btn btn-small btn-danger" onclick="deleteDevice(${device.id})">Delete</button>
      </div>
    </div>
  `;
}

function renderRecentDevices() {
  const target = byId("recent-devices");
  const recent = [...devices].slice(0, 6);
  target.innerHTML = recent.map(deviceCard).join("") || `<div class="empty">No devices yet</div>`;
}

function renderDevices() {
  const target = byId("devices-grid");
  const filtered = devices.filter(deviceMatchesFilter).filter(deviceMatchesSearch);
  target.innerHTML = filtered.map(deviceCard).join("") || `<div class="empty">No devices match this filter</div>`;
}

function renderAlerts() {
  const target = byId("alerts-list");
  if (!alerts.length) {
    target.innerHTML = `<div class="empty">No alerts yet</div>`;
    return;
  }

  target.innerHTML = alerts.map((a) => `
    <div class="alert-item ${a.resolved ? "resolved" : ""}">
      <div>
        <div class="alert-message">${escapeHtml(a.message || a.ip || "Alert")}</div>
        <div class="alert-meta">${escapeHtml(a.created_at || "")} · ${escapeHtml(a.severity || "warning")}</div>
      </div>
      <div class="badge badge-${a.resolved ? "online" : "offline"}">${a.resolved ? "RESOLVED" : "OPEN"}</div>
    </div>
  `).join("");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadHealth() {
  try {
    const data = await api("/api/health");
    setHealth(`DB: ${data.db_path}`, true);
  } catch (e) {
    setHealth("Disconnected", false);
  }
}

async function loadSettings() {
  try {
    const settings = await api("/api/settings");
    byId("networks-input").value = settings.networks || "";
  } catch (e) {
    toast(e.message, true);
  }
}

async function loadDevices() {
  devices = await api("/api/devices");
  renderStats();
  renderRecentDevices();
  renderDevices();
}

async function loadAlerts() {
  alerts = await api("/api/alerts");
  renderAlerts();
}

async function fullRefresh() {
  try {
    await loadHealth();
    await loadSettings();
    await loadDevices();
    await loadAlerts();
  } catch (e) {
    toast(e.message, true);
  }
}

async function runScan() {
  try {
    toast("Scanning networks...");
    await api("/api/scan", { method: "POST" });
    await fullRefresh();
    toast("Scan completed");
  } catch (e) {
    toast(e.message, true);
  }
}

async function approveAll() {
  try {
    const res = await api("/api/devices/approve_all", { method: "POST" });
    await fullRefresh();
    toast(`Approved ${res.count} device(s)`);
  } catch (e) {
    toast(e.message, true);
  }
}

async function approveDevice(id) {
  try {
    await api(`/api/devices/${id}/approve`, { method: "POST" });
    await fullRefresh();
    toast("Device approved");
  } catch (e) {
    toast(e.message, true);
  }
}

async function togglePinned(id, value) {
  try {
    await api(`/api/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ pinned: value === "true" }),
    });
    await fullRefresh();
  } catch (e) {
    toast(e.message, true);
  }
}

async function toggleCritical(id, value) {
  try {
    await api(`/api/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ critical: value === "true" }),
    });
    await fullRefresh();
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteDevice(id) {
  if (!confirm("Delete this device?")) return;
  try {
    await api(`/api/devices/${id}`, { method: "DELETE" });
    await fullRefresh();
    toast("Device deleted");
  } catch (e) {
    toast(e.message, true);
  }
}

async function editDevice(id) {
  const device = devices.find((d) => d.id === id);
  if (!device) return;

  const name = prompt("Device name:", device.name || "") ?? device.name;
  if (name === null) return;
  const category = prompt("Category:", device.category || "") ?? device.category;
  if (category === null) return;
  const flag = prompt("Flag:", device.flag || "") ?? device.flag;
  if (flag === null) return;
  const notes = prompt("Notes:", device.notes || "") ?? device.notes;
  if (notes === null) return;

  try {
    await api(`/api/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ name, category, flag, notes }),
    });
    await fullRefresh();
    toast("Device updated");
  } catch (e) {
    toast(e.message, true);
  }
}

async function saveSettings() {
  try {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ networks: byId("networks-input").value }),
    });
    toast("Settings saved");
  } catch (e) {
    toast(e.message, true);
  }
}

async function addManualDevice() {
  const ip = byId("manual-ip").value.trim();
  const name = byId("manual-name").value.trim();

  if (!ip) {
    toast("IP address is required", true);
    return;
  }

  try {
    await api("/api/add_device", {
      method: "POST",
      body: JSON.stringify({ ip, name }),
    });
    byId("manual-ip").value = "";
    byId("manual-name").value = "";
    await fullRefresh();
    toast("Manual device added");
  } catch (e) {
    toast(e.message, true);
  }
}

function switchTab(tabName) {
  currentTab = tabName;

  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.remove("active");
  });

  const el = byId(`${tabName}-tab`);
  if (el) el.classList.add("active");

  byId("page-title").textContent = tabName.charAt(0).toUpperCase() + tabName.slice(1);
}

function bindEvents() {
  byId("scan-btn").addEventListener("click", runScan);
  byId("approve-all-btn").addEventListener("click", approveAll);
  byId("save-settings-btn").addEventListener("click", saveSettings);
  byId("add-device-btn").addEventListener("click", addManualDevice);
  byId("search-input").addEventListener("input", renderDevices);

  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      currentFilter = btn.dataset.filter;
      document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderDevices();
    });
  });
}

window.approveDevice = approveDevice;
window.togglePinned = togglePinned;
window.toggleCritical = toggleCritical;
window.deleteDevice = deleteDevice;
window.editDevice = editDevice;

bindEvents();
fullRefresh();
setInterval(loadDevices, 15000);
setInterval(loadAlerts, 20000);

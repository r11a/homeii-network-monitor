class HomeiiDynamicBoardCard extends HTMLElement {
  static getStubConfig() {
    return {
      title: "HOMEii Network Board",
      offline_entity: "sensor.homeii_network_monitor_disconnected_devices",
      offline_details_entity: "sensor.homeii_network_monitor_disconnected_devices_details",
      unstable_entity: "sensor.homeii_network_monitor_unstable_devices",
      unstable_details_entity: "sensor.homeii_network_monitor_unstable_devices_details",
      new_entity: "sensor.homeii_network_monitor_new_devices",
      new_details_entity: "sensor.homeii_network_monitor_new_devices_details",
      alerts_entity: "sensor.homeii_network_monitor_open_alerts",
      alerts_details_entity: "sensor.homeii_network_monitor_open_alerts_details",
      online_entity: "sensor.homeii_network_monitor_connected_devices",
      online_details_entity: "sensor.homeii_network_monitor_connected_devices_details",
      critical_entity: "sensor.homeii_network_monitor_critical_devices",
      critical_details_entity: "sensor.homeii_network_monitor_critical_devices_details",
      pinned_entity: "sensor.homeii_network_monitor_pinned_devices",
      pinned_details_entity: "sensor.homeii_network_monitor_pinned_devices_details",
      default_view: "offline",
      max_items: 10,
    };
  }

  setConfig(config) {
    this._config = { ...HomeiiDynamicBoardCard.getStubConfig(), ...config };
    if (!this.shadowRoot) {
      this.attachShadow({ mode: "open" });
    }
    this._activeKey = this._config.default_view || "offline";
    this._renderSkeleton();
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._config || !this.shadowRoot) {
      return;
    }
    this._render();
  }

  getCardSize() {
    return 6;
  }

  _lang() {
    return this._hass?.locale?.language || this._hass?.language || "en";
  }

  _isHebrew() {
    return String(this._lang()).startsWith("he");
  }

  _t(en, he) {
    return this._isHebrew() ? he : en;
  }

  _state(entityId, fallback = "0") {
    return this._hass?.states?.[entityId]?.state ?? fallback;
  }

  _attr(entityId, key, fallback = null) {
    return this._hass?.states?.[entityId]?.attributes?.[key] ?? fallback;
  }

  _filters() {
    return [
      {
        key: "offline",
        label: this._t("Offline", "מנותקים"),
        entity: this._config.offline_entity,
        details: this._config.offline_details_entity,
        tone: "offline",
      },
      {
        key: "unstable",
        label: this._t("Unstable", "לא יציבים"),
        entity: this._config.unstable_entity,
        details: this._config.unstable_details_entity,
        tone: "unstable",
      },
      {
        key: "new",
        label: this._t("New", "חדשים"),
        entity: this._config.new_entity,
        details: this._config.new_details_entity,
        tone: "new",
      },
      {
        key: "alerts",
        label: this._t("Alerts", "התראות"),
        entity: this._config.alerts_entity,
        details: this._config.alerts_details_entity,
        tone: "alert",
      },
      {
        key: "online",
        label: this._t("Online", "מחוברים"),
        entity: this._config.online_entity,
        details: this._config.online_details_entity,
        tone: "online",
      },
      {
        key: "critical",
        label: this._t("Critical", "קריטיים"),
        entity: this._config.critical_entity,
        details: this._config.critical_details_entity,
        tone: "critical",
      },
      {
        key: "pinned",
        label: this._t("Pinned", "נעוצים"),
        entity: this._config.pinned_entity,
        details: this._config.pinned_details_entity,
        tone: "pinned",
      },
    ];
  }

  _renderSkeleton() {
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }
        ha-card {
          overflow: hidden;
          border-radius: 28px;
          padding: 20px;
          background:
            radial-gradient(circle at top left, rgba(117, 186, 255, 0.18), transparent 30%),
            radial-gradient(circle at bottom right, rgba(89, 122, 255, 0.16), transparent 26%),
            linear-gradient(180deg, rgba(18, 27, 47, 0.98), rgba(10, 14, 28, 0.98));
          color: #eef4ff;
          border: 1px solid rgba(150, 190, 255, 0.16);
          box-shadow: 0 28px 54px rgba(4, 10, 22, 0.34);
        }
        .header {
          display: flex;
          justify-content: space-between;
          gap: 16px;
          align-items: flex-start;
          margin-bottom: 16px;
        }
        .title {
          margin: 0;
          font-size: 1.35rem;
          font-weight: 800;
          letter-spacing: 0.02em;
        }
        .subtitle {
          margin-top: 6px;
          color: rgba(226, 234, 255, 0.72);
          font-size: 0.92rem;
        }
        .badge {
          padding: 8px 14px;
          border-radius: 999px;
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.08);
          color: rgba(239,244,255,0.88);
          font-size: 0.82rem;
          font-weight: 700;
          white-space: nowrap;
        }
        .toolbar {
          display: grid;
          grid-template-columns: repeat(7, minmax(0, 1fr));
          gap: 12px;
          margin-bottom: 18px;
        }
        .stat {
          position: relative;
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 22px;
          padding: 16px 14px 14px;
          background: rgba(255,255,255,0.05);
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.07);
          cursor: pointer;
          transition: transform .18s ease, border-color .18s ease, background .18s ease;
        }
        .stat:hover {
          transform: translateY(-2px);
        }
        .stat.active {
          border-color: rgba(255,255,255,0.18);
          background: rgba(255,255,255,0.10);
        }
        .stat::after {
          content: "";
          position: absolute;
          inset-inline: 14px;
          bottom: 0;
          height: 3px;
          border-radius: 999px;
          background: var(--tone, rgba(117,186,255,0.9));
        }
        .stat-label {
          color: rgba(226, 234, 255, 0.74);
          font-size: 0.83rem;
          margin-bottom: 10px;
        }
        .stat-value {
          font-size: 1.95rem;
          font-weight: 800;
          line-height: 1;
        }
        .panel {
          border-radius: 24px;
          padding: 16px;
          background: rgba(255,255,255,0.04);
          border: 1px solid rgba(255,255,255,0.08);
        }
        .panel-head {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          margin-bottom: 14px;
        }
        .panel-title {
          font-size: 1.1rem;
          font-weight: 800;
        }
        .panel-meta {
          color: rgba(226,234,255,0.72);
          font-size: 0.86rem;
        }
        .list {
          display: grid;
          gap: 10px;
        }
        .row {
          border-radius: 18px;
          padding: 14px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          display: flex;
          justify-content: space-between;
          gap: 14px;
          align-items: flex-start;
        }
        .main {
          min-width: 0;
          flex: 1;
        }
        .name {
          font-size: 1rem;
          font-weight: 800;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .meta {
          margin-top: 7px;
          color: rgba(226,234,255,0.72);
          font-size: 0.84rem;
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .chip {
          display: inline-flex;
          align-items: center;
          border-radius: 999px;
          padding: 7px 12px;
          font-size: 0.79rem;
          font-weight: 800;
          white-space: nowrap;
          border: 1px solid transparent;
        }
        .chip.offline {
          color: #ffb3b3;
          background: rgba(255, 92, 92, 0.12);
          border-color: rgba(255, 92, 92, 0.26);
        }
        .chip.unstable {
          color: #ffd998;
          background: rgba(255, 193, 74, 0.12);
          border-color: rgba(255, 193, 74, 0.24);
        }
        .chip.new {
          color: #dce4ff;
          background: rgba(112, 138, 255, 0.14);
          border-color: rgba(112, 138, 255, 0.24);
        }
        .chip.alert, .chip.critical {
          color: #ffb3cc;
          background: rgba(255, 92, 160, 0.12);
          border-color: rgba(255, 92, 160, 0.24);
        }
        .chip.online {
          color: #c6f5d7;
          background: rgba(64, 196, 129, 0.14);
          border-color: rgba(64, 196, 129, 0.26);
        }
        .chip.pinned {
          color: #ffe2a8;
          background: rgba(255, 202, 86, 0.12);
          border-color: rgba(255, 202, 86, 0.24);
        }
        .empty {
          border-radius: 18px;
          padding: 18px;
          text-align: center;
          color: rgba(226,234,255,0.72);
          background: rgba(255,255,255,0.04);
          border: 1px dashed rgba(255,255,255,0.14);
        }
        .offline { --tone: rgba(255, 92, 92, 0.9); }
        .unstable { --tone: rgba(255, 193, 74, 0.9); }
        .new { --tone: rgba(112, 138, 255, 0.9); }
        .alert { --tone: rgba(255, 92, 160, 0.9); }
        .online { --tone: rgba(64, 196, 129, 0.9); }
        .critical { --tone: rgba(255, 131, 131, 0.9); }
        .pinned { --tone: rgba(255, 202, 86, 0.9); }
        @media (max-width: 1100px) {
          .toolbar {
            grid-template-columns: repeat(3, minmax(0, 1fr));
          }
        }
        @media (max-width: 760px) {
          .toolbar {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
          .row {
            flex-direction: column;
          }
        }
      </style>
      <ha-card><div id="root"></div></ha-card>
    `;
  }

  _toneClass(item) {
    const status = String(item?.status || "").toLowerCase();
    if (status === "offline") return "offline";
    if (status === "unstable") return "unstable";
    if (status === "new") return "new";
    if (item?.severity) return "alert";
    if (item?.critical) return "critical";
    if (item?.pinned) return "pinned";
    return "online";
  }

  _statusLabel(item) {
    const status = String(item?.status || "").toLowerCase();
    if (item?.severity) return String(item.severity).toUpperCase();
    if (status === "offline") return this._t("Offline", "מנותק");
    if (status === "unstable") return this._t("Unstable", "לא יציב");
    if (status === "new") return this._t("New", "חדש");
    if (item?.critical) return this._t("Critical", "קריטי");
    if (item?.pinned) return this._t("Pinned", "נעוץ");
    return this._t("Online", "מחובר");
  }

  _itemsForFilter(filter) {
    return (this._attr(filter.details, "items", []) || []).slice(0, this._config.max_items || 10);
  }

  _selectFilter(key) {
    this._activeKey = key;
    this._render();
  }

  _render() {
    const root = this.shadowRoot.getElementById("root");
    const filters = this._filters();
    const active = filters.find((item) => item.key === this._activeKey) || filters[0];
    const items = this._itemsForFilter(active);
    const totalVisible = Number(this._state(active.entity, "0") || 0);
    root.innerHTML = `
      <div class="header">
        <div>
          <div class="title">${this._config.title || this._t("HOMEii Dynamic Board", "לוח דינמי של HOMEii")}</div>
          <div class="subtitle">${this._t("Clickable live counters with focused device lists", "מונים חיים לחיצים עם רשימות התקנים ממוקדות")}</div>
        </div>
        <div class="badge">${active.label}: ${totalVisible}</div>
      </div>
      <div class="toolbar">
        ${filters.map((filter) => `
          <div
            class="stat ${filter.tone} ${filter.key === active.key ? "active" : ""}"
            role="button"
            tabindex="0"
            data-filter="${filter.key}"
          >
            <div class="stat-label">${filter.label}</div>
            <div class="stat-value">${this._state(filter.entity, "0")}</div>
          </div>
        `).join("")}
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">${active.label}</div>
          <div class="panel-meta">${this._t("Showing", "מוצגים")} ${items.length} / ${totalVisible}</div>
        </div>
        ${
          items.length
            ? `<div class="list">${items.map((item) => `
                <div class="row">
                  <div class="main">
                    <div class="name">${item.name || item.title || item.category || item.label || item.ip || this._t("Unknown item", "פריט לא מזוהה")}</div>
                    <div class="meta">
                      ${item.ip ? `<span>${item.ip}</span>` : ""}
                      ${item.vendor ? `<span>${item.vendor}</span>` : ""}
                      ${item.category ? `<span>${item.category}</span>` : ""}
                      ${item.network ? `<span>${item.network}</span>` : ""}
                      ${item.message ? `<span>${item.message}</span>` : ""}
                    </div>
                  </div>
                  <div class="chip ${this._toneClass(item)}">${this._statusLabel(item)}</div>
                </div>
              `).join("")}</div>`
            : `<div class="empty">${this._t("Nothing to show in this view", "אין כרגע פריטים בתצוגה הזאת")}</div>`
        }
      </div>
    `;

    root.querySelectorAll("[data-filter]").forEach((el) => {
      el.addEventListener("click", () => this._selectFilter(el.dataset.filter));
      el.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          this._selectFilter(el.dataset.filter);
        }
      });
    });
  }
}

customElements.define("homeii-dynamic-board-card", HomeiiDynamicBoardCard);

class HomeiiOverviewCard extends HTMLElement {
  static getStubConfig() {
    return {
      title: "HOMEii Overview",
      total_entity: "sensor.homeii_network_monitor_total_devices",
      online_entity: "sensor.homeii_network_monitor_connected_devices",
      offline_entity: "sensor.homeii_network_monitor_disconnected_devices",
      unstable_entity: "sensor.homeii_network_monitor_unstable_devices",
      new_entity: "sensor.homeii_network_monitor_new_devices",
      alerts_entity: "sensor.homeii_network_monitor_open_alerts",
      critical_entity: "sensor.homeii_network_monitor_critical_devices",
      pinned_entity: "sensor.homeii_network_monitor_pinned_devices",
      last_scan_entity: "sensor.homeii_network_monitor_last_scan_finished",
      category_summary_entity: "sensor.homeii_network_monitor_category_summary",
    };
  }

  setConfig(config) {
    if (!config.total_entity) {
      throw new Error("total_entity is required");
    }
    this._config = config;
    if (!this.shadowRoot) {
      this.attachShadow({ mode: "open" });
    }
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
    return 4;
  }

  _t(en, he) {
    const lang = this._hass?.locale?.language || this._hass?.language || "en";
    return String(lang).startsWith("he") ? he : en;
  }

  _state(entityId, fallback = "0") {
    return this._hass?.states?.[entityId]?.state ?? fallback;
  }

  _attr(entityId, key, fallback = null) {
    return this._hass?.states?.[entityId]?.attributes?.[key] ?? fallback;
  }

  _renderSkeleton() {
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }
        ha-card {
          overflow: hidden;
          border-radius: 24px;
          padding: 20px;
          background:
            radial-gradient(circle at top left, rgba(103, 187, 255, 0.16), transparent 32%),
            linear-gradient(180deg, rgba(18, 26, 45, 0.98), rgba(10, 14, 28, 0.98));
          color: #eef4ff;
          border: 1px solid rgba(150, 190, 255, 0.18);
          box-shadow: 0 24px 44px rgba(4, 10, 22, 0.32);
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 16px;
          margin-bottom: 18px;
        }
        .title {
          font-size: 1.4rem;
          font-weight: 800;
          letter-spacing: 0.02em;
          margin: 0;
        }
        .subtitle {
          margin-top: 6px;
          color: rgba(222, 231, 255, 0.72);
          font-size: 0.94rem;
        }
        .scan {
          text-align: end;
          color: rgba(222, 231, 255, 0.78);
          font-size: 0.9rem;
          white-space: nowrap;
        }
        .kpis {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 12px;
        }
        .kpi {
          border-radius: 20px;
          padding: 16px 16px 14px;
          background: rgba(255, 255, 255, 0.06);
          border: 1px solid rgba(255, 255, 255, 0.08);
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
        }
        .kpi.alert {
          background: rgba(255, 92, 92, 0.12);
          border-color: rgba(255, 92, 92, 0.28);
        }
        .kpi.good {
          background: rgba(64, 196, 129, 0.12);
          border-color: rgba(64, 196, 129, 0.26);
        }
        .kpi.warn {
          background: rgba(255, 193, 74, 0.12);
          border-color: rgba(255, 193, 74, 0.24);
        }
        .label {
          color: rgba(222, 231, 255, 0.72);
          font-size: 0.84rem;
          margin-bottom: 8px;
        }
        .value {
          font-size: 2rem;
          font-weight: 800;
          line-height: 1;
        }
        .categories {
          margin-top: 18px;
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 12px;
        }
        .category {
          border-radius: 18px;
          padding: 14px;
          background: rgba(255, 255, 255, 0.04);
          border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .category-top {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: baseline;
        }
        .category-name {
          font-size: 1rem;
          font-weight: 700;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .category-total {
          font-size: 1.3rem;
          font-weight: 800;
        }
        .category-meta {
          margin-top: 10px;
          color: rgba(222, 231, 255, 0.74);
          font-size: 0.84rem;
          display: flex;
          justify-content: space-between;
          gap: 8px;
        }
        .empty {
          margin-top: 16px;
          border-radius: 18px;
          padding: 18px;
          text-align: center;
          color: rgba(222, 231, 255, 0.72);
          background: rgba(255, 255, 255, 0.04);
          border: 1px dashed rgba(255, 255, 255, 0.14);
        }
        @media (max-width: 900px) {
          .kpis, .categories {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }
      </style>
      <ha-card>
        <div id="root"></div>
      </ha-card>
    `;
  }

  _render() {
    const cfg = this._config;
    const categories = (this._attr(cfg.category_summary_entity, "items", []) || []).slice(0, 6);
    const root = this.shadowRoot.getElementById("root");
    const lastScanRaw = this._state(cfg.last_scan_entity, "");
    const hasAlerts = Number(this._state(cfg.alerts_entity, "0")) > 0;
    root.innerHTML = `
      <div class="header">
        <div>
          <div class="title">${cfg.title || "HOMEii Overview"}</div>
          <div class="subtitle">${this._t("Live network posture for Home Assistant", "תמונת מצב חיה של הרשת בתוך Home Assistant")}</div>
        </div>
        <div class="scan">
          <div>${this._t("Last scan", "סריקה אחרונה")}</div>
          <strong>${lastScanRaw || this._t("Unknown", "לא ידוע")}</strong>
        </div>
      </div>
      <div class="kpis">
        ${this._kpi(this._t("Total", "סה\"כ"), this._state(cfg.total_entity), "")}
        ${this._kpi(this._t("Online", "מחוברים"), this._state(cfg.online_entity), "good")}
        ${this._kpi(this._t("Offline", "מנותקים"), this._state(cfg.offline_entity), hasAlerts ? "alert" : "")}
        ${this._kpi(this._t("Unstable", "לא יציבים"), this._state(cfg.unstable_entity), "warn")}
        ${this._kpi(this._t("New", "חדשים"), this._state(cfg.new_entity), "")}
        ${this._kpi(this._t("Alerts", "התראות"), this._state(cfg.alerts_entity), hasAlerts ? "alert" : "")}
        ${this._kpi(this._t("Critical", "קריטיים"), this._state(cfg.critical_entity), "alert")}
        ${this._kpi(this._t("Pinned", "נעוצים"), this._state(cfg.pinned_entity), "")}
      </div>
      ${
        categories.length
          ? `<div class="categories">
              ${categories
                .map(
                  (item) => `
                    <div class="category">
                      <div class="category-top">
                        <div class="category-name">${item.category || this._t("Uncategorized", "ללא קטגוריה")}</div>
                        <div class="category-total">${item.total ?? 0}</div>
                      </div>
                      <div class="category-meta">
                        <span>${this._t("Online", "מחוברים")}: ${item.online ?? 0}</span>
                        <span>${this._t("Offline", "מנותקים")}: ${item.offline ?? 0}</span>
                      </div>
                    </div>`
                )
                .join("")}
            </div>`
          : `<div class="empty">${this._t("No categories available yet", "עדיין אין קטגוריות זמינות")}</div>`
      }
    `;
  }

  _kpi(label, value, cls) {
    return `
      <div class="kpi ${cls}">
        <div class="label">${label}</div>
        <div class="value">${value ?? 0}</div>
      </div>
    `;
  }
}

customElements.define("homeii-overview-card", HomeiiOverviewCard);

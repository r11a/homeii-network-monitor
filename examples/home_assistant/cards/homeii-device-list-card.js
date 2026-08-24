class HomeiiDeviceListCard extends HTMLElement {
  static getStubConfig() {
    return {
      title: "Disconnected Devices",
      entity: "sensor.homeii_network_monitor_disconnected_devices_details",
      empty_text: "No devices in this list",
      max_items: 8,
    };
  }

  setConfig(config) {
    if (!config.entity) {
      throw new Error("entity is required");
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

  _renderSkeleton() {
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }
        ha-card {
          overflow: hidden;
          border-radius: 24px;
          padding: 18px;
          background:
            radial-gradient(circle at top left, rgba(255, 123, 123, 0.14), transparent 30%),
            linear-gradient(180deg, rgba(18, 26, 45, 0.98), rgba(10, 14, 28, 0.98));
          color: #eef4ff;
          border: 1px solid rgba(150, 190, 255, 0.14);
          box-shadow: 0 24px 44px rgba(4, 10, 22, 0.28);
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          margin-bottom: 14px;
        }
        .title {
          font-size: 1.25rem;
          font-weight: 800;
        }
        .count {
          min-width: 42px;
          height: 42px;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border-radius: 999px;
          background: rgba(255,255,255,0.08);
          border: 1px solid rgba(255,255,255,0.12);
          font-weight: 800;
        }
        .rows {
          display: grid;
          gap: 10px;
        }
        .row {
          border-radius: 18px;
          padding: 14px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
        }
        .row-top {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: flex-start;
        }
        .name {
          font-size: 1rem;
          font-weight: 700;
        }
        .meta {
          color: rgba(222, 231, 255, 0.72);
          font-size: 0.84rem;
          margin-top: 6px;
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .chip {
          display: inline-flex;
          align-items: center;
          padding: 5px 10px;
          border-radius: 999px;
          font-size: 0.78rem;
          font-weight: 700;
        }
        .chip.offline {
          background: rgba(255, 92, 92, 0.14);
          color: #ffb0b0;
          border: 1px solid rgba(255, 92, 92, 0.28);
        }
        .chip.unstable {
          background: rgba(255, 193, 74, 0.14);
          color: #ffd892;
          border: 1px solid rgba(255, 193, 74, 0.26);
        }
        .chip.new {
          background: rgba(103, 138, 255, 0.14);
          color: #d7e1ff;
          border: 1px solid rgba(103, 138, 255, 0.26);
        }
        .chip.good {
          background: rgba(64, 196, 129, 0.14);
          color: #bff2d4;
          border: 1px solid rgba(64, 196, 129, 0.26);
        }
        .empty {
          border-radius: 18px;
          padding: 18px;
          text-align: center;
          color: rgba(222, 231, 255, 0.72);
          background: rgba(255,255,255,0.04);
          border: 1px dashed rgba(255,255,255,0.14);
        }
      </style>
      <ha-card>
        <div id="root"></div>
      </ha-card>
    `;
  }

  _render() {
    const stateObj = this._hass?.states?.[this._config.entity];
    const items = (stateObj?.attributes?.items || []).slice(0, this._config.max_items || 8);
    const count = Number(stateObj?.state || 0);
    const root = this.shadowRoot.getElementById("root");
    root.innerHTML = `
      <div class="header">
        <div class="title">${this._config.title || this._t("Device List", "רשימת התקנים")}</div>
        <div class="count">${count}</div>
      </div>
      ${
        items.length
          ? `<div class="rows">${items.map((item) => this._row(item)).join("")}</div>`
          : `<div class="empty">${this._config.empty_text || this._t("No devices in this list", "אין התקנים ברשימה הזאת")}</div>`
      }
    `;
  }

  _row(item) {
    const status = String(item.status || "").toLowerCase();
    const chipClass =
      status === "offline" ? "offline" :
      status === "unstable" ? "unstable" :
      status === "new" ? "new" : "good";
    const statusLabel =
      status === "offline" ? this._t("Offline", "מנותק") :
      status === "unstable" ? this._t("Unstable", "לא יציב") :
      status === "new" ? this._t("New", "חדש") :
      this._t("Online", "מחובר");
    return `
      <div class="row">
        <div class="row-top">
          <div>
            <div class="name">${item.name || item.ip || this._t("Unknown device", "התקן לא מזוהה")}</div>
            <div class="meta">
              ${item.ip ? `<span>${item.ip}</span>` : ""}
              ${item.vendor ? `<span>${item.vendor}</span>` : ""}
              ${item.category ? `<span>${item.category}</span>` : ""}
              ${item.network ? `<span>${item.network}</span>` : ""}
            </div>
          </div>
          <div class="chip ${chipClass}">${statusLabel}</div>
        </div>
      </div>
    `;
  }
}

customElements.define("homeii-device-list-card", HomeiiDeviceListCard);

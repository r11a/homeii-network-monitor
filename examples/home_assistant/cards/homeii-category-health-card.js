class HomeiiCategoryHealthCard extends HTMLElement {
  static getStubConfig() {
    return {
      title: "Category Health",
      entity: "sensor.homeii_network_monitor_category_summary",
      max_items: 6,
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
        :host { display: block; }
        ha-card {
          overflow: hidden;
          border-radius: 24px;
          padding: 18px;
          background:
            radial-gradient(circle at top right, rgba(83, 162, 255, 0.14), transparent 28%),
            linear-gradient(180deg, rgba(18, 26, 45, 0.98), rgba(10, 14, 28, 0.98));
          color: #eef4ff;
          border: 1px solid rgba(150, 190, 255, 0.14);
          box-shadow: 0 24px 44px rgba(4, 10, 22, 0.28);
        }
        .title {
          font-size: 1.25rem;
          font-weight: 800;
          margin-bottom: 14px;
        }
        .grid {
          display: grid;
          gap: 10px;
        }
        .row {
          border-radius: 18px;
          padding: 14px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
        }
        .top {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: baseline;
        }
        .name {
          font-size: 1rem;
          font-weight: 700;
        }
        .total {
          font-size: 1.1rem;
          font-weight: 800;
        }
        .meta {
          margin-top: 8px;
          color: rgba(222, 231, 255, 0.76);
          font-size: 0.84rem;
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
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
      <ha-card><div id="root"></div></ha-card>
    `;
  }

  _render() {
    const stateObj = this._hass?.states?.[this._config.entity];
    const items = (stateObj?.attributes?.items || []).slice(0, this._config.max_items || 6);
    const root = this.shadowRoot.getElementById("root");
    root.innerHTML = `
      <div class="title">${this._config.title || this._t("Category Health", "בריאות קטגוריות")}</div>
      ${
        items.length
          ? `<div class="grid">${items.map((item) => `
              <div class="row">
                <div class="top">
                  <div class="name">${item.category || this._t("Uncategorized", "ללא קטגוריה")}</div>
                  <div class="total">${item.total ?? 0}</div>
                </div>
                <div class="meta">
                  <span>${this._t("Online", "מחוברים")}: ${item.online ?? 0}</span>
                  <span>${this._t("Offline", "מנותקים")}: ${item.offline ?? 0}</span>
                  <span>${this._t("Unstable", "לא יציבים")}: ${item.unstable ?? 0}</span>
                  <span>${this._t("New", "חדשים")}: ${item.new ?? 0}</span>
                </div>
              </div>
            `).join("")}</div>`
          : `<div class="empty">${this._t("No category data available yet", "עדיין אין נתוני קטגוריות זמינים")}</div>`
      }
    `;
  }
}

customElements.define("homeii-category-health-card", HomeiiCategoryHealthCard);

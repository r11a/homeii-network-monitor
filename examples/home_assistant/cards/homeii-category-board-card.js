class HomeiiCategoryBoardCard extends HTMLElement {
  static getStubConfig() {
    return {
      title: "HOMEii Category Board",
      summary_entity: "sensor.homeii_network_monitor_category_summary",
      devices_entity: "sensor.homeii_network_monitor_all_devices_details",
      max_categories: 8,
      max_items: 10,
      default_category: "",
    };
  }

  setConfig(config) {
    this._config = { ...HomeiiCategoryBoardCard.getStubConfig(), ...config };
    if (!this.shadowRoot) {
      this.attachShadow({ mode: "open" });
    }
    this._activeCategory = this._config.default_category || "";
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

  _attr(entityId, key, fallback = null) {
    return this._hass?.states?.[entityId]?.attributes?.[key] ?? fallback;
  }

  _renderSkeleton() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        ha-card {
          overflow: hidden;
          border-radius: 28px;
          padding: 20px;
          background:
            radial-gradient(circle at top right, rgba(91, 179, 255, 0.18), transparent 28%),
            radial-gradient(circle at bottom left, rgba(64, 196, 129, 0.12), transparent 28%),
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
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 12px;
          margin-bottom: 18px;
        }
        .category {
          position: relative;
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 22px;
          padding: 16px 14px 14px;
          background: rgba(255,255,255,0.05);
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.07);
          cursor: pointer;
          transition: transform .18s ease, border-color .18s ease, background .18s ease;
        }
        .category:hover { transform: translateY(-2px); }
        .category.active {
          border-color: rgba(255,255,255,0.18);
          background: rgba(255,255,255,0.10);
        }
        .category::after {
          content: "";
          position: absolute;
          inset-inline: 14px;
          bottom: 0;
          height: 3px;
          border-radius: 999px;
          background: var(--tone, rgba(64, 196, 129, 0.9));
        }
        .category.offline { --tone: rgba(255, 92, 92, 0.9); }
        .category.unstable { --tone: rgba(255, 193, 74, 0.9); }
        .category.good { --tone: rgba(64, 196, 129, 0.9); }
        .category-name {
          font-size: 0.98rem;
          font-weight: 800;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          margin-bottom: 10px;
        }
        .category-total {
          font-size: 1.9rem;
          font-weight: 800;
          line-height: 1;
        }
        .category-meta {
          margin-top: 10px;
          color: rgba(226,234,255,0.72);
          font-size: 0.82rem;
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
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
        .chip.online {
          color: #c6f5d7;
          background: rgba(64, 196, 129, 0.14);
          border-color: rgba(64, 196, 129, 0.26);
        }
        .empty {
          border-radius: 18px;
          padding: 18px;
          text-align: center;
          color: rgba(226,234,255,0.72);
          background: rgba(255,255,255,0.04);
          border: 1px dashed rgba(255,255,255,0.14);
        }
        @media (max-width: 1100px) {
          .toolbar { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        }
        @media (max-width: 760px) {
          .toolbar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          .row { flex-direction: column; }
        }
      </style>
      <ha-card><div id="root"></div></ha-card>
    `;
  }

  _toneClass(item) {
    if ((item.offline || 0) > 0) return "offline";
    if ((item.unstable || 0) > 0) return "unstable";
    return "good";
  }

  _deviceTone(item) {
    const status = String(item?.status || "").toLowerCase();
    if (status === "offline") return "offline";
    if (status === "unstable") return "unstable";
    if (status === "new") return "new";
    return "online";
  }

  _deviceLabel(item) {
    const status = String(item?.status || "").toLowerCase();
    if (status === "offline") return this._t("Offline", "מנותק");
    if (status === "unstable") return this._t("Unstable", "לא יציב");
    if (status === "new") return this._t("New", "חדש");
    return this._t("Online", "מחובר");
  }

  _selectCategory(category) {
    this._activeCategory = category;
    this._render();
  }

  _render() {
    const categories = (this._attr(this._config.summary_entity, "items", []) || []).slice(0, this._config.max_categories || 8);
    const devices = this._attr(this._config.devices_entity, "items", []) || [];
    const active = categories.find((item) => item.category === this._activeCategory) || categories[0] || null;
    const activeCategory = active?.category || "";
    const filtered = devices
      .filter((item) => ((item.category || "").trim() || "Uncategorized") === activeCategory)
      .slice(0, this._config.max_items || 10);

    const root = this.shadowRoot.getElementById("root");
    root.innerHTML = `
      <div class="header">
        <div>
          <div class="title">${this._config.title || this._t("HOMEii Category Board", "לוח קטגוריות של HOMEii")}</div>
          <div class="subtitle">${this._t("Clickable category cards with live device lists", "כרטיסי קטגוריות לחיצים עם רשימות התקנים חיות")}</div>
        </div>
        <div class="badge">${activeCategory || this._t("No category", "אין קטגוריה")}</div>
      </div>
      ${
        categories.length
          ? `<div class="toolbar">
              ${categories.map((item) => `
                <div
                  class="category ${this._toneClass(item)} ${item.category === activeCategory ? "active" : ""}"
                  role="button"
                  tabindex="0"
                  data-category="${item.category}"
                >
                  <div class="category-name">${item.category || this._t("Uncategorized", "ללא קטגוריה")}</div>
                  <div class="category-total">${item.total ?? 0}</div>
                  <div class="category-meta">
                    <span>${this._t("Online", "מחוברים")}: ${item.online ?? 0}</span>
                    <span>${this._t("Offline", "מנותקים")}: ${item.offline ?? 0}</span>
                  </div>
                </div>
              `).join("")}
            </div>`
          : `<div class="empty">${this._t("No categories available", "אין כרגע קטגוריות זמינות")}</div>`
      }
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">${activeCategory || this._t("Category devices", "התקני הקטגוריה")}</div>
          <div class="panel-meta">${this._t("Showing", "מוצגים")} ${filtered.length}</div>
        </div>
        ${
          filtered.length
            ? `<div class="list">${filtered.map((item) => `
                <div class="row">
                  <div class="main">
                    <div class="name">${item.name || item.ip || this._t("Unknown device", "התקן לא מזוהה")}</div>
                    <div class="meta">
                      ${item.ip ? `<span>${item.ip}</span>` : ""}
                      ${item.vendor ? `<span>${item.vendor}</span>` : ""}
                      ${item.network ? `<span>${item.network}</span>` : ""}
                    </div>
                  </div>
                  <div class="chip ${this._deviceTone(item)}">${this._deviceLabel(item)}</div>
                </div>
              `).join("")}</div>`
            : `<div class="empty">${this._t("No devices in this category", "אין כרגע התקנים בקטגוריה הזאת")}</div>`
        }
      </div>
    `;

    root.querySelectorAll("[data-category]").forEach((el) => {
      el.addEventListener("click", () => this._selectCategory(el.dataset.category));
      el.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          this._selectCategory(el.dataset.category);
        }
      });
    });
  }
}

customElements.define("homeii-category-board-card", HomeiiCategoryBoardCard);

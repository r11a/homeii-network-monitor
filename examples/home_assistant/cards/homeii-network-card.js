const HOMEII_DEFAULTS = {
  title: "HOMEii Network",
  devices_entity: "sensor.homeii_network_monitor_all_devices_details",
  category_entity: "sensor.homeii_network_monitor_category_summary",
  history_entity: "sensor.homeii_network_monitor_availability_history",
  total_entity: "sensor.homeii_network_monitor_total_devices",
  online_entity: "sensor.homeii_network_monitor_connected_devices",
  offline_entity: "sensor.homeii_network_monitor_disconnected_devices",
  unstable_entity: "sensor.homeii_network_monitor_unstable_devices",
  new_entity: "sensor.homeii_network_monitor_new_devices",
  default_view: "overview",
  show_summary: true,
  show_categories: true,
  show_graph: true,
  show_history: true,
  statuses: ["online", "offline", "unstable", "new"],
  max_items: 12,
};

class HomeiiNetworkCard extends HTMLElement {
  static getStubConfig() { return { ...HOMEII_DEFAULTS }; }

  static getConfigElement() { return document.createElement("homeii-network-card-editor"); }

  setConfig(config) {
    if (!config.devices_entity) throw new Error("devices_entity is required");
    this._config = { ...HOMEII_DEFAULTS, ...config };
    this._view = this._config.default_view;
    this._category = "";
    if (!this.shadowRoot) this.attachShadow({ mode: "open" });
    this._shell();
  }

  set hass(hass) { this._hass = hass; if (this._config) this._render(); }
  getCardSize() { return 8; }

  _he() { return String(this._hass?.locale?.language || this._hass?.language || "en").startsWith("he"); }
  _t(en, he) { return this._he() ? he : en; }
  _state(id, fallback = "0") { return this._hass?.states?.[id]?.state ?? fallback; }
  _attr(id, key, fallback = null) { return this._hass?.states?.[id]?.attributes?.[key] ?? fallback; }
  _esc(value) { const node = document.createElement("span"); node.textContent = String(value ?? ""); return node.innerHTML; }
  _devices() { return this._attr(this._config.devices_entity, "items", []) || []; }
  _categories() { return this._attr(this._config.category_entity, "items", []) || []; }

  _shell() {
    this.shadowRoot.innerHTML = `<style>
      :host{display:block;--hn-green:#4de1a8;--hn-red:#ff6b7a;--hn-amber:#ffca68;--hn-blue:#72a7ff}
      ha-card{overflow:hidden;border-radius:28px;padding:22px;color:var(--primary-text-color,#eef5ff);background:radial-gradient(circle at 8% 0%,rgba(65,180,255,.18),transparent 30%),radial-gradient(circle at 92% 100%,rgba(95,83,255,.15),transparent 34%),linear-gradient(145deg,var(--ha-card-background,#111a2b),rgba(8,13,25,.98));border:1px solid rgba(140,185,255,.18);box-shadow:0 26px 60px rgba(2,8,20,.28)}
      .head,.row,.device-head,.cat-head{display:flex;align-items:center;justify-content:space-between;gap:14px}.eyebrow{color:var(--primary-color,#72a7ff);font-size:.72rem;font-weight:900;letter-spacing:.16em;text-transform:uppercase}.title{font-size:1.45rem;font-weight:850;margin-top:4px}.live{display:flex;align-items:center;gap:8px;font-size:.8rem;opacity:.75}.dot{width:8px;height:8px;border-radius:50%;background:var(--hn-green);box-shadow:0 0 0 5px rgba(77,225,168,.12)}
      .tabs{display:flex;gap:8px;overflow:auto;margin:20px 0 16px;padding-bottom:2px}.tab,.stat,.cat{font:inherit;color:inherit;cursor:pointer}.tab{border:1px solid rgba(255,255,255,.09);background:rgba(255,255,255,.045);border-radius:999px;padding:9px 14px;white-space:nowrap}.tab.active{background:var(--primary-color,#4f86ec);border-color:transparent;color:#fff}
      .stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.stat{border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045);border-radius:20px;padding:15px;text-align:start;position:relative;overflow:hidden}.stat:after{content:"";position:absolute;inset-inline:0;bottom:0;height:3px;background:var(--tone)}.stat.active{border-color:var(--tone);background:rgba(255,255,255,.085)}.num{font-size:1.8rem;font-weight:850}.label{font-size:.8rem;opacity:.7;margin-top:5px}
      .content{margin-top:14px}.panel{border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035);border-radius:22px;padding:16px}.section-title{font-size:1rem;font-weight:800;margin-bottom:12px}.categories{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.cat{border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.045);border-radius:17px;padding:13px;text-align:start}.cat.active{border-color:var(--primary-color,#72a7ff);background:rgba(114,167,255,.12)}.cat-name{font-weight:750;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cat-meta{font-size:.76rem;opacity:.68;margin-top:7px}
      .chart{height:170px;width:100%;display:block}.gridline{stroke:rgba(255,255,255,.08);stroke-width:1}.area{fill:url(#area)}.line{fill:none;stroke:var(--hn-green);stroke-width:3;stroke-linejoin:round;stroke-linecap:round}.axis{display:flex;justify-content:space-between;font-size:.72rem;opacity:.58;margin-top:5px}.chart-value{font-size:1.8rem;font-weight:850}.muted{font-size:.78rem;opacity:.65}
      .list{display:grid;gap:9px}.device{border:1px solid rgba(255,255,255,.075);background:rgba(255,255,255,.04);border-radius:17px;padding:13px}.name{font-weight:780}.meta{display:flex;flex-wrap:wrap;gap:6px 12px;font-size:.78rem;opacity:.68;margin-top:7px}.pill{padding:6px 10px;border-radius:999px;font-size:.72rem;font-weight:850;background:color-mix(in srgb,var(--tone) 17%,transparent);color:var(--tone)}.empty{text-align:center;padding:26px;opacity:.65}.spacer{height:12px}
      @media(max-width:750px){ha-card{padding:16px;border-radius:22px}.stats{grid-template-columns:repeat(2,1fr)}.categories{grid-template-columns:repeat(2,1fr)}.head{align-items:flex-start}.live{display:none}}
    </style><ha-card><div id="root"></div></ha-card>`;
  }

  _statusMeta(key) {
    return {
      online: [this._t("Connected","מחוברים"), this._config.online_entity, "var(--hn-green)"],
      offline: [this._t("Disconnected","מנותקים"), this._config.offline_entity, "var(--hn-red)"],
      unstable: [this._t("Unstable","לא יציבים"), this._config.unstable_entity, "var(--hn-amber)"],
      new: [this._t("New","חדשים"), this._config.new_entity, "var(--hn-blue)"],
    }[key];
  }

  _filtered() {
    let rows = this._devices();
    if (["online","offline","unstable","new"].includes(this._view)) rows = rows.filter(d => d.status === this._view);
    if (this._category) rows = rows.filter(d => (d.category || this._t("Uncategorized","ללא קטגוריה")) === this._category);
    if (this._view === "history") rows = rows.filter(d => d.offline_since || d.status === "offline").sort((a,b) => (b.offline_since||0)-(a.offline_since||0));
    return rows.slice(0, Number(this._config.max_items) || 12);
  }

  _formatTime(ts) {
    if (!Number(ts)) return this._t("Unknown","לא ידוע");
    return new Intl.DateTimeFormat(this._he() ? "he-IL" : undefined,{dateStyle:"short",timeStyle:"short"}).format(new Date(Number(ts)*1000));
  }

  _relative(ts) {
    if (!Number(ts)) return "";
    const mins = Math.max(0, Math.floor((Date.now()/1000-Number(ts))/60));
    if (mins < 60) return this._t(`${mins} min ago`,`לפני ${mins} דק׳`);
    const hours = Math.floor(mins/60); if (hours < 48) return this._t(`${hours}h ago`,`לפני ${hours} שעות`);
    const days = Math.floor(hours/24); return this._t(`${days}d ago`,`לפני ${days} ימים`);
  }

  _graph() {
    const history = this._attr(this._config.history_entity, "items", []) || [];
    if (!history.length) return `<div class="empty">${this._t("History will appear after monitoring samples are collected","הגרף יוצג לאחר איסוף נתוני ניטור")}</div>`;
    const points = history.map(p => ({ts:p.ts,value:Number(p.availability_pct||0)}));
    const w=700,h=150,pad=8; const coords=points.map((p,i)=>[pad+i*(w-pad*2)/Math.max(1,points.length-1),h-pad-(p.value/100)*(h-pad*2)]);
    const line=coords.map(p=>p.join(",")).join(" "); const area=`${pad},${h-pad} ${line} ${w-pad},${h-pad}`;
    const avg=Math.round(points.reduce((s,p)=>s+p.value,0)/points.length*10)/10;
    return `<div class="row"><div><div class="chart-value">${avg}%</div><div class="muted">${this._t("Average availability · 24 hours","זמינות ממוצעת · 24 שעות")}</div></div></div><svg class="chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img"><defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4de1a8" stop-opacity=".3"/><stop offset="1" stop-color="#4de1a8" stop-opacity="0"/></linearGradient></defs><line class="gridline" x1="0" y1="8" x2="700" y2="8"/><line class="gridline" x1="0" y1="75" x2="700" y2="75"/><line class="gridline" x1="0" y1="142" x2="700" y2="142"/><polygon class="area" points="${area}"/><polyline class="line" points="${line}"/></svg><div class="axis"><span>${this._t("24 hours ago","לפני 24 שעות")}</span><span>${this._t("Now","עכשיו")}</span></div>`;
  }

  _list() {
    const items=this._filtered();
    if (!items.length) return `<div class="empty">${this._t("No devices in this view","אין מכשירים בתצוגה זו")}</div>`;
    return `<div class="list">${items.map(d=>{const meta=this._statusMeta(d.status)||[d.status,null,"var(--hn-blue)"];const since=d.status==="offline"?(d.offline_since||d.last_seen):0;return `<div class="device"><div class="device-head"><div><div class="name">${this._esc(d.name||d.ip)}</div><div class="meta"><span>${this._esc(d.ip)}</span>${d.vendor?`<span>${this._esc(d.vendor)}</span>`:""}${d.category?`<span>${this._esc(d.category)}</span>`:""}${d.availability_24h!=null?`<span>${this._esc(d.availability_24h)}% ${this._t("availability","זמינות")}</span>`:""}${since?`<span>${this._t("Disconnected","נותק")}: ${this._esc(this._formatTime(since))} · ${this._esc(this._relative(since))}</span>`:""}</div></div><span class="pill" style="--tone:${meta[2]}">${meta[0]}</span></div></div>`}).join("")}</div>`;
  }

  _render() {
    const views=[["overview",this._t("Overview","סקירה")],["categories",this._t("Categories","קטגוריות")],["history",this._t("History","היסטוריה")]];
    const statuses=(Array.isArray(this._config.statuses)?this._config.statuses:String(this._config.statuses).split(",")).filter(k=>this._statusMeta(k));
    const categories=this._categories(); const showCats=this._config.show_categories && (this._view==="categories"||this._view==="overview");
    const root=this.shadowRoot.getElementById("root"); root.dir=this._he()?"rtl":"ltr";
    root.innerHTML=`<div class="head"><div><div class="eyebrow">Network intelligence</div><div class="title">${this._esc(this._config.title)}</div></div><div class="live"><span class="dot"></span>${this._t("Live from HOMEii","חי מ־HOMEii")}</div></div>
      <div class="tabs">${views.filter(([k])=>k!=="categories"||this._config.show_categories).filter(([k])=>k!=="history"||this._config.show_history).map(([k,l])=>`<button class="tab ${this._view===k?"active":""}" data-view="${k}">${l}</button>`).join("")}</div>
      ${this._config.show_summary?`<div class="stats">${statuses.map(k=>{const m=this._statusMeta(k);return `<button class="stat ${this._view===k?"active":""}" data-view="${k}" style="--tone:${m[2]}"><div class="num">${this._esc(this._state(m[1]))}</div><div class="label">${m[0]}</div></button>`}).join("")}</div>`:""}
      <div class="content">${showCats?`<div class="panel"><div class="section-title">${this._t("Choose a category","בחירת קטגוריה")}</div><div class="categories"><button class="cat ${!this._category?"active":""}" data-category=""><div class="cat-head"><span class="cat-name">${this._t("All devices","כל המכשירים")}</span><b>${this._esc(this._state(this._config.total_entity))}</b></div></button>${categories.map(c=>`<button class="cat ${this._category===c.category?"active":""}" data-category="${this._esc(c.category)}"><div class="cat-head"><span class="cat-name">${this._esc(c.category||this._t("Uncategorized","ללא קטגוריה"))}</span><b>${c.total||0}</b></div><div class="cat-meta">${c.online||0} ${this._t("connected","מחוברים")} · ${c.offline||0} ${this._t("offline","מנותקים")}</div></button>`).join("")}</div></div><div class="spacer"></div>`:""}
      ${this._config.show_graph && (this._view==="overview"||this._view==="history")?`<div class="panel"><div class="section-title">${this._t("Network availability","זמינות הרשת")}</div>${this._graph()}</div><div class="spacer"></div>`:""}<div class="panel"><div class="section-title">${this._view==="history"?this._t("Disconnection history","היסטוריית ניתוקים"):this._t("Devices","מכשירים")}</div>${this._list()}</div></div>`;
    root.querySelectorAll("[data-view]").forEach(el=>el.onclick=()=>{this._view=el.dataset.view;this._render()});
    root.querySelectorAll("[data-category]").forEach(el=>el.onclick=()=>{this._category=el.dataset.category;this._view="categories";this._render()});
  }
}

class HomeiiNetworkCardEditor extends HTMLElement {
  setConfig(config){this._config={...HOMEII_DEFAULTS,...config};this._render()}
  set hass(hass){this._hass=hass;this._render()}
  _render(){if(!this._config)return;this.innerHTML=`<div style="display:grid;gap:12px;padding:8px"><ha-textfield label="Title" data-key="title" value="${this._config.title||""}"></ha-textfield><ha-entity-picker label="Devices entity" data-key="devices_entity" value="${this._config.devices_entity||""}" allow-custom-entity></ha-entity-picker><ha-entity-picker label="Category entity" data-key="category_entity" value="${this._config.category_entity||""}" allow-custom-entity></ha-entity-picker><ha-entity-picker label="History entity" data-key="history_entity" value="${this._config.history_entity||""}" allow-custom-entity></ha-entity-picker>${["show_summary","show_categories","show_graph","show_history"].map(k=>`<ha-formfield label="${k.replaceAll("_"," ")}"><ha-switch data-key="${k}" ${this._config[k]!==false?"checked":""}></ha-switch></ha-formfield>`).join("")}</div>`;this.querySelectorAll("[data-key]").forEach(el=>{el.hass=this._hass;el.addEventListener("change",()=>{const key=el.dataset.key;this._config={...this._config,[key]:el.tagName==="HA-SWITCH"?el.checked:el.value};this.dispatchEvent(new CustomEvent("config-changed",{detail:{config:this._config},bubbles:true,composed:true}))})})}
}

if (!customElements.get("homeii-network-card")) customElements.define("homeii-network-card",HomeiiNetworkCard);
if (!customElements.get("homeii-network-card-editor")) customElements.define("homeii-network-card-editor",HomeiiNetworkCardEditor);
window.customCards=window.customCards||[];window.customCards.push({type:"homeii-network-card",name:"HOMEii Network Card",description:"Interactive network status, categories and history"});

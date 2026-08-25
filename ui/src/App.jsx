import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  Boxes,
  ChevronLeft,
  CircleGauge,
  Clock3,
  Command,
  Cpu,
  Gauge,
  Globe2,
  History,
  Languages,
  LayoutDashboard,
  Menu,
  Network,
  Pin,
  Play,
  Radar,
  RefreshCw,
  Route,
  Search,
  Server,
  Settings,
  ShieldAlert,
  Sparkles,
  Terminal,
  Wifi,
  WifiOff,
  Wrench,
  X,
  Zap,
  CheckCircle2,
  TrendingUp,
  Eye,
  UserCog,
  MonitorUp,
  Database,
  SlidersHorizontal,
  ArrowUpRight,
  Upload,
  Download,
  FileJson,
  FileSpreadsheet,
  LogOut,
  LockKeyhole,
  UserPlus,
  Users,
  TableProperties,
  Grid2X2,
  Plus,
  ArrowUpDown,
  Copy,
  Volume2,
  VolumeX,
  Tag,
  Trash2,
  Pencil,
  Camera,
  Laptop,
  Smartphone,
  Printer,
  Router,
  HardDrive,
  Cloud,
  Tv,
  Radio,
  Lightbulb,
  Thermometer,
  Lock,
  Video,
  Headphones,
  Gamepad2,
  Building2,
  PlugZap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Bar,
  BarChart,
  Pie,
  PieChart,
  Cell,
} from "recharts";
import { api, query } from "./api";
import { translator } from "./i18n";

const navItems = [
  ["dashboard", LayoutDashboard],
  ["viewer", CircleGauge],
  ["devices", Server],
  ["alerts", Bell],
  ["history", History],
  ["tools", Wrench],
  ["settings", Settings],
];
const statusIcons = {
  online: Wifi,
  offline: WifiOff,
  unstable: Activity,
  new: Sparkles,
  critical: ShieldAlert,
  pinned: Pin,
  total: Boxes,
};
const categoryIcons = {
  boxes: Boxes,
  server: Server,
  camera: Eye,
  wifi: Wifi,
  shield: ShieldAlert,
  tag: Tag,
  laptop: Laptop,
  phone: Smartphone,
  printer: Printer,
  router: Router,
  storage: HardDrive,
  cloud: Cloud,
  tv: Tv,
  radio: Radio,
  light: Lightbulb,
  sensor: Thermometer,
  lock: Lock,
  video: Video,
  audio: Headphones,
  gaming: Gamepad2,
  building: Building2,
  power: PlugZap,
};
const categoryIconOptions = Object.keys(categoryIcons);
const statusOrder = [
  "offline",
  "unstable",
  "new",
  "critical",
  "online",
  "total",
];

function useRoute() {
  const getRoute = () =>
    (location.hash.replace("#/", "") || "dashboard").split("/");
  const [[route, detail], setRoute] = useState(getRoute);
  useEffect(() => {
    const onChange = () => setRoute(getRoute());
    addEventListener("hashchange", onChange);
    return () => removeEventListener("hashchange", onChange);
  }, []);
  return [
    route,
    (next) => {
      location.hash = `#/${next}`;
    },
    detail || "",
  ];
}

function Logo() {
  return (
    <div className="brand-lockup">
      <div className="brand-mark">
        <img src="./icons/homeii-192.png" alt="" />
      </div>
      <div>
        <strong>
          HOME<span>ii</span>
        </strong>
        <small>NETWORK INTELLIGENCE</small>
      </div>
    </div>
  );
}

function StatusDot({ status }) {
  return <span className={`status-dot ${status}`} aria-label={status} />;
}
function CategoryIcon({ name, size = 20 }) {
  const Icon = categoryIcons[name] || Boxes;
  return <Icon size={size} />;
}

function TimeAgo({ timestamp, language }) {
  if (!timestamp) return <span>—</span>;
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp));
  const units =
    language === "he"
      ? [
          [86400, "ימים"],
          [3600, "שעות"],
          [60, "דקות"],
          [1, "שניות"],
        ]
      : [
          [86400, "days"],
          [3600, "hours"],
          [60, "minutes"],
          [1, "seconds"],
        ];
  const [size, label] = units.find(([size]) => seconds >= size) || units.at(-1);
  return (
    <span>
      {Math.floor(seconds / size)} {label}
    </span>
  );
}

function KpiCard({ type, value, label, onClick }) {
  const Icon = statusIcons[type] || Gauge;
  return (
    <button className={`kpi-card tone-${type}`} onClick={onClick}>
      <div className="kpi-head">
        <span className="icon-box">
          <Icon size={18} />
        </span>
        <span className="micro-label">{label}</span>
      </div>
      <div className="kpi-value">{value ?? 0}</div>
      <div className="kpi-foot">
        <span className="pulse-line" />
        <ChevronLeft size={16} />
      </div>
    </button>
  );
}

function Empty({ t }) {
  return (
    <div className="empty">
      <Radar size={38} />
      <p>{t("noData")}</p>
    </div>
  );
}

function AvailabilityStrip({ series = [], t }) {
  const values = series.length
    ? series.slice(-24)
    : Array.from({ length: 24 }, () => ({ availability_pct: null }));
  return (
    <div
      className="availability-strip"
      title={t ? t("availability24h") : "24h availability"}
    >
      {values.map((item, index) => {
        const raw = item.availability_pct ?? item.availability;
        const pct = raw === null || raw === undefined ? null : Number(raw);
        const hour = item.ts
          ? new Date(Number(item.ts) * 1000).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })
          : `${String(index).padStart(2, "0")}:00`;
        const incidents = Number(item.offline_events || 0);
        return (
          <span
            key={item.ts || index}
            title={`${hour} · ${pct === null ? "—" : `${Math.round(pct)}%`} · ${incidents}`}
            className={
              pct === null
                ? "unknown"
                : pct >= 99
                  ? "good"
                  : pct >= 60
                    ? "warn"
                    : "bad"
            }
          />
        );
      })}
    </div>
  );
}

function Dashboard({ data, t, setRoute, language }) {
  const { status, alerts, events, viewer } = data;
  const chartData =
    viewer?.summary?.series?.map((point, index) => ({
      name: `${index}:00`,
      availability: Number(point.availability_pct || 0),
    })) || [];
  const attention = (data.devices || [])
    .filter((d) => ["offline", "unstable", "new"].includes(d.status))
    .slice(0, 5);
  const healthData = [
    { key: "online", value: Number(status?.online || 0), color: "#35d49a" },
    { key: "offline", value: Number(status?.offline || 0), color: "#ff5d73" },
    { key: "unstable", value: Number(status?.unstable || 0), color: "#ffb547" },
    { key: "anomalies", value: Number(status?.new || 0), color: "#5da9ff" },
  ];
  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div>
          <span className="eyebrow">
            <Zap size={14} /> {t("monitorLive")}
          </span>
          <h1>{t("networkPulse")}</h1>
          <p>
            {t("last24h")} · {status?.networks?.length || 0} {t("network")}
          </p>
        </div>
        <div className={`health-orb ${status?.offline ? "danger" : "healthy"}`}>
          <Activity size={32} />
          <strong>{status?.offline ? status.offline : "OK"}</strong>
          <small>{status?.offline ? t("offline") : t("systemHealthy")}</small>
        </div>
      </section>
      <section className="kpi-grid">
        {statusOrder.map((type) => (
          <KpiCard
            key={type}
            type={type}
            value={status?.[type]}
            label={t(type)}
            onClick={() =>
              setRoute(`devices/${type === "total" ? "all" : type}`)
            }
          />
        ))}
      </section>
      <section className="panel fleet-overview">
        <div className="fleet-chart">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={healthData}
                dataKey="value"
                nameKey="key"
                innerRadius="64%"
                outerRadius="88%"
                paddingAngle={3}
                stroke="none"
                onClick={(entry) =>
                  setRoute(
                    `devices/${entry.key === "anomalies" ? "new" : entry.key}`,
                  )
                }
              >
                {healthData.map((item) => (
                  <Cell key={item.key} fill={item.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "var(--chart-tooltip)",
                  border: "1px solid var(--line-strong)",
                  borderRadius: 14,
                }}
                formatter={(value, key) => [value, t(key)]}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="fleet-total">
            <strong>{status?.total || 0}</strong>
            <span>{t("monitored")}</span>
          </div>
        </div>
        <div className="fleet-summary">
          <span className="eyebrow">{t("fleetHealth")}</span>
          <h2>{t("operationalSnapshot")}</h2>
          <p>{t("fleetHealthHelp")}</p>
          <div className="fleet-legend">
            {healthData.map((item) => (
              <button
                key={item.key}
                onClick={() =>
                  setRoute(
                    `devices/${item.key === "anomalies" ? "new" : item.key}`,
                  )
                }
                style={{ "--legend-color": item.color }}
              >
                <i />
                <span>{t(item.key)}</span>
                <strong>{item.value}</strong>
                <ChevronLeft />
              </button>
            ))}
          </div>
        </div>
      </section>
      <section className="dashboard-grid">
        <article className="panel chart-panel wide">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("sla24h")}</span>
              <h2>{t("uptimeTrend")}</h2>
            </div>
            <span className="score">
              {viewer?.summary?.availability_24h ?? 0}%
            </span>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="availability" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stopColor="#27e6a4" stopOpacity=".52" />
                    <stop offset=".58" stopColor="#27e6a4" stopOpacity=".13" />
                    <stop offset="1" stopColor="#27e6a4" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis
                  dataKey="name"
                  stroke="var(--chart-axis)"
                  tickLine={false}
                />
                <YAxis domain={[0, 100]} hide />
                <Tooltip
                  contentStyle={{
                    background: "var(--chart-tooltip)",
                    border: "1px solid var(--line-strong)",
                    borderRadius: 14,
                    boxShadow: "0 18px 45px #000a",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="availability"
                  stroke="#27e6a4"
                  strokeWidth={3}
                  fill="url(#availability)"
                  activeDot={{
                    r: 5,
                    fill: "#27e6a4",
                    stroke: "#07130f",
                    strokeWidth: 3,
                  }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>
        <article className="panel attention-panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("liveQueue")}</span>
              <h2>{t("attention")}</h2>
            </div>
            <AlertTriangle size={21} />
          </div>
          <div className="compact-list">
            {attention.length ? (
              attention.map((device) => (
                <div className="compact-row" key={device.ip}>
                  <StatusDot status={device.status} />
                  <div>
                    <strong>
                      {device.display_name || device.name || device.ip}
                    </strong>
                    <small>
                      {device.ip} · {device.vendor || "Unknown"}
                    </small>
                  </div>
                  <TimeAgo timestamp={device.last_seen} language={language} />
                </div>
              ))
            ) : (
              <Empty t={t} />
            )}
          </div>
        </article>
        <article className="panel events-panel">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("systemLog")}</span>
              <h2>{t("recentEvents")}</h2>
            </div>
            <Command size={21} />
          </div>
          <div className="event-grid">
            {(events || []).slice(0, 6).map((event, index) => (
              <div
                className={`event-tile ${event.level}`}
                key={event.id || index}
              >
                <span>{event.event_type || event.type}</span>
                <strong>{event.message}</strong>
                <TimeAgo timestamp={event.ts} language={language} />
              </div>
            ))}
          </div>
        </article>
        <article className="panel alerts-mini">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("alertCenter")}</span>
              <h2>{t("openAlerts")}</h2>
            </div>
            <span className="score danger-text">
              {(alerts || []).filter((a) => a.status === "open").length}
            </span>
          </div>
          <AvailabilityStrip
            series={chartData.map((x) => ({
              availability_pct: x.availability,
            }))}
          />
        </article>
      </section>
    </div>
  );
}

function Viewer({
  data,
  t,
  language,
  refresh,
  alertSound,
  setAlertSound,
  currentUser,
}) {
  const categories = data.viewer?.categories || [];
  const [selected, setSelected] = useState(null);
  const [categoryCheck, setCategoryCheck] = useState(null);
  const devices = (data.devices || []).filter(
    (device) => !device.quarantined && !device.trashed_at,
  );
  const activeAlerts = (data.alerts || []).filter(
    (alert) => alert.status === "open",
  );
  const unacknowledged = activeAlerts.filter((alert) => !alert.acknowledged_at);
  const problemDevices = devices
    .filter((device) => ["offline", "unstable"].includes(device.status))
    .sort(
      (left, right) =>
        Number(right.critical) - Number(left.critical) ||
        Number(left.last_seen || 0) - Number(right.last_seen || 0),
    );
  const priorityDevices = problemDevices.slice(0, 8);
  const canManageAlerts =
    currentUser?.role === "admin" ||
    (currentUser?.role === "user" && Boolean(currentUser?.can_manage_alerts));
  const fleetSeries = (data.viewer?.summary?.series || []).map((point) => ({
    hour: new Date(Number(point.ts) * 1000).toLocaleTimeString(
      language === "he" ? "he-IL" : "en-US",
      { hour: "2-digit", minute: "2-digit" },
    ),
    availability: Number(point.availability_pct || 0),
    incidents:
      Number(point.offline_events || 0) + Number(point.unstable_events || 0),
  }));
  const overallAvailability = Number(
    data.viewer?.summary?.availability_24h || 0,
  );
  const acknowledgeAlert = async (id) => {
    await api(`/acknowledge_alert/${id}`, { method: "POST" });
    await refresh();
  };
  const selectedDevices = selected
    ? data.viewer?.devices?.[selected] ||
      data.devices?.filter((device) => (device.category || "") === selected) ||
      []
    : [];
  const selectedCategory = categories.find(
    (item) => item.category === selected,
  );
  const categoryTrend = (selectedCategory?.series || []).map(
    (point, index) => ({
      hour: `${String(index).padStart(2, "0")}:00`,
      availability: Number(point.availability_pct || 0),
      disconnects: Number(point.offline_events || 0),
    }),
  );
  const categoryRanking = selectedDevices
    .map((device) => ({
      ...device,
      disconnects: (device.availability_series || []).reduce(
        (sum, point) => sum + Number(point.offline_events || 0),
        0,
      ),
      availability: Number(device.availability_24h ?? 0),
    }))
    .sort(
      (a, b) =>
        b.disconnects - a.disconnects || a.availability - b.availability,
    )
    .slice(0, 5);
  const lastCategoryCheck = Math.max(
    0,
    ...selectedDevices.map((device) =>
      Number(device.updated_at || device.last_seen || 0),
    ),
  );
  const checkCategory = async () => {
    if (!selected) return;
    setCategoryCheck({ running: true });
    await api(`/categories/${encodeURIComponent(selected)}/check`, {
      method: "POST",
    });
    const poll = setInterval(async () => {
      const result = await api(
        `/categories/${encodeURIComponent(selected)}/check`,
      );
      setCategoryCheck(result.state);
      if (!result.state?.running) clearInterval(poll);
    }, 1200);
  };
  return (
    <div className="page-stack noc-page">
      <div className="page-heading noc-heading">
        <div>
          <span className="eyebrow">{t("liveOperations")}</span>
          <h1>{t("viewer")}</h1>
          <p>{t("controlRoomHelp")}</p>
        </div>
        <div className="noc-heading-actions">
          <button
            className={`button ${alertSound ? "sound-active" : ""}`}
            onClick={() => {
              const enabled = !alertSound;
              setAlertSound(enabled);
              localStorage.setItem(
                "homeii-alert-sound",
                enabled ? "on" : "off",
              );
            }}
          >
            {alertSound ? <Volume2 /> : <VolumeX />}
            {t(alertSound ? "soundOn" : "soundOff")}
          </button>
          <div className="live-badge">
            <span className="live-dot" />
            {t("monitorLive")}
          </div>
        </div>
      </div>
      <section className="noc-command-grid">
        <article
          className={`noc-health-card ${problemDevices.some((device) => device.status === "offline") ? "danger" : "healthy"}`}
        >
          <div>
            <span className="eyebrow">{t("fleetHealth")}</span>
            <strong>{overallAvailability}%</strong>
            <p>
              {devices.length} {t("monitored")} · {problemDevices.length}{" "}
              {t("attention")}
            </p>
          </div>
          <CircleGauge />
          <AvailabilityStrip series={data.viewer?.summary?.series} t={t} />
        </article>
        <article
          className={`noc-alert-card ${unacknowledged.length ? "urgent" : ""}`}
        >
          <div className="noc-alert-count">
            <Bell />
            <strong>{unacknowledged.length}</strong>
          </div>
          <div>
            <span className="eyebrow">{t("awaitingAction")}</span>
            <h2>
              {t(unacknowledged.length ? "operatorActionRequired" : "noIssues")}
            </h2>
            <p>
              {activeAlerts.length} {t("openAlerts")}
            </p>
          </div>
        </article>
      </section>
      <section className="noc-live-grid">
        <article className="panel noc-trend">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("last24h")}</span>
              <h2>{t("healthTimeline")}</h2>
            </div>
            <span className="score">{overallAvailability}%</span>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={fleetSeries}>
                <defs>
                  <linearGradient id="nocHealth" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0" stopColor="#32e6a1" stopOpacity=".58" />
                    <stop offset="1" stopColor="#32e6a1" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis
                  dataKey="hour"
                  stroke="var(--chart-axis)"
                  tickLine={false}
                  minTickGap={28}
                />
                <YAxis domain={[0, 100]} hide />
                <Tooltip
                  contentStyle={{
                    background: "var(--chart-tooltip)",
                    border: "1px solid var(--line-strong)",
                    borderRadius: 14,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="availability"
                  stroke="#32e6a1"
                  fill="url(#nocHealth)"
                  strokeWidth={3}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>
        <article className="panel noc-priority">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("priorityQueue")}</span>
              <h2>{t("offlineAndUnstable")}</h2>
            </div>
            <strong className="danger-text">{priorityDevices.length}</strong>
          </div>
          <div className="noc-priority-list">
            {priorityDevices.map((device) => {
              const offlineSeconds = Math.max(
                0,
                Math.floor(
                  Date.now() / 1000 -
                    Number(device.last_seen || Date.now() / 1000),
                ),
              );
              return (
                <div
                  className={`noc-priority-row ${device.status} ${device.critical ? "critical" : ""}`}
                  key={device.ip}
                >
                  <StatusDot status={device.status} />
                  <div>
                    <strong>
                      {device.display_name || device.name || device.ip}
                    </strong>
                    <small>
                      {device.ip} · {device.category || t("uncategorized")}
                    </small>
                  </div>
                  <span>
                    <TimeAgo timestamp={device.last_seen} language={language} />
                    {offlineSeconds >= 3600 && <em>{t("prolongedOutage")}</em>}
                  </span>
                </div>
              );
            })}
            {!priorityDevices.length && <Empty t={t} />}
          </div>
        </article>
      </section>
      <section className="panel noc-journal">
        <div className="panel-title">
          <div>
            <span className="eyebrow">{t("liveJournal")}</span>
            <h2>{t("operatorJournal")}</h2>
          </div>
          <span>
            {unacknowledged.length} {t("unacknowledged")}
          </span>
        </div>
        <div className="noc-journal-grid">
          {activeAlerts.slice(0, 6).map((alert) => (
            <article
              className={`noc-journal-item severity-${alert.severity} ${alert.acknowledged_at ? "acknowledged" : ""}`}
              key={alert.id}
            >
              <i />
              <div>
                <span>{t(alert.severity)}</span>
                <strong>{alert.title || alert.ip}</strong>
                <p>{alert.message}</p>
                <small>
                  <TimeAgo timestamp={alert.created_at} language={language} /> ·{" "}
                  {alert.ip}
                </small>
              </div>
              {canManageAlerts && !alert.acknowledged_at && (
                <button
                  className="button"
                  onClick={() => acknowledgeAlert(alert.id)}
                >
                  {t("acknowledge")}
                </button>
              )}
            </article>
          ))}
          {!activeAlerts.length &&
            (data.events || []).slice(0, 4).map((event, index) => (
              <article
                className={`noc-journal-item severity-${event.level}`}
                key={event.id || index}
              >
                <i />
                <div>
                  <span>{event.event_type}</span>
                  <strong>{event.message}</strong>
                  <small>
                    <TimeAgo timestamp={event.ts} language={language} />
                  </small>
                </div>
              </article>
            ))}
        </div>
      </section>
      <div className="noc-section-heading">
        <div>
          <span className="eyebrow">{t("categoryHealth")}</span>
          <h2>{t("categories")}</h2>
        </div>
        <p>{t("selectCategory")}</p>
      </div>
      <section className="category-grid">
        {categories.map((item) => (
          <button
            className={`category-card ${item.offline ? "has-alert" : ""} ${selected === item.category ? "selected" : ""}`}
            style={{ "--category-color": item.color || "#5da9ff" }}
            key={item.category}
            onClick={() =>
              setSelected(selected === item.category ? null : item.category)
            }
          >
            <div className="category-top">
              <span className="icon-box category-icon">
                <CategoryIcon name={item.icon} />
              </span>
              <span className="availability-score">
                {item.availability_24h ?? 0}%
              </span>
            </div>
            <h2>{item.category || t("uncategorized")}</h2>
            <strong className="category-count">
              {item.total ?? item.count ?? 0}
            </strong>
            <div className="category-tags">
              <span className="category-ratio">
                {t("availableCount")} <strong>{item.online || 0}</strong>{" "}
                {t("outOf")} <strong>{item.total ?? item.count ?? 0}</strong>
              </span>
              {item.offline > 0 && (
                <span className="danger-tag">
                  {item.offline} {t("offline")}
                </span>
              )}
            </div>
            <AvailabilityStrip series={item.series} />
          </button>
        ))}
      </section>
      {selected && (
        <section className="panel category-detail">
          <div className="panel-title">
            <div>
              <span className="eyebrow">{t("deviceHealth")}</span>
              <h2>{selected}</h2>
              <small>
                {t("lastCheck")}:{" "}
                <TimeAgo
                  timestamp={categoryCheck?.finished_at || lastCategoryCheck}
                  language={language}
                />
              </small>
            </div>
            <div className="category-actions">
              <button
                className="button"
                disabled={categoryCheck?.running}
                onClick={checkCategory}
              >
                <Radar className={categoryCheck?.running ? "spin" : ""} />
                {categoryCheck?.running
                  ? t("checkingCategory")
                  : t("checkCategory")}
              </button>
              <button className="icon-button" onClick={() => setSelected(null)}>
                <X size={17} />
              </button>
            </div>
          </div>
          {categoryCheck && !categoryCheck.running && (
            <div className="category-check-result">
              <CheckCircle2 />
              <strong>
                {categoryCheck.online || 0} {t("online")}
              </strong>
              <span>
                {categoryCheck.offline || 0} {t("offline")}
              </span>
            </div>
          )}
          <div className="category-insights">
            <article className="category-health-chart">
              <div>
                <span>{t("healthScore")}</span>
                <strong>{selectedCategory?.availability_24h ?? 0}%</strong>
              </div>
              <div className="chart-wrap">
                <ResponsiveContainer>
                  <AreaChart data={categoryTrend}>
                    <defs>
                      <linearGradient
                        id="categoryHealth"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop offset="0" stopColor="#35d49a" stopOpacity=".5" />
                        <stop offset="1" stopColor="#35d49a" stopOpacity="0" />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      stroke="var(--chart-grid)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="hour"
                      stroke="var(--chart-axis)"
                      tickLine={false}
                    />
                    <YAxis domain={[0, 100]} hide />
                    <Tooltip
                      contentStyle={{
                        background: "var(--chart-tooltip)",
                        border: "1px solid var(--line-strong)",
                        borderRadius: 14,
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="availability"
                      stroke="#35d49a"
                      strokeWidth={3}
                      fill="url(#categoryHealth)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </article>
            <article className="category-ranking">
              <div className="panel-title">
                <h3>{t("mostDisconnected")}</h3>
                <WifiOff />
              </div>
              {categoryRanking.map((device, index) => (
                <div key={device.ip}>
                  <b>{index + 1}</b>
                  <span>
                    <strong>
                      {device.display_name || device.name || device.ip}
                    </strong>
                    <small>{device.ip}</small>
                  </span>
                  <em>
                    {device.disconnects} {t("disconnects")}
                  </em>
                </div>
              ))}
              {!categoryRanking.length && <Empty t={t} />}
            </article>
          </div>
          <div className="noc-device-grid">
            {selectedDevices.map((device) => (
              <article
                className={`noc-device state-${device.status}`}
                key={device.ip}
              >
                <div>
                  <StatusDot status={device.status} />
                  <strong>
                    {device.display_name || device.name || device.ip}
                  </strong>
                </div>
                <small>
                  {device.ip} · {device.vendor || "—"} · {t("lastCheck")}{" "}
                  <TimeAgo
                    timestamp={device.updated_at || device.last_seen}
                    language={language}
                  />
                </small>
                <AvailabilityStrip series={device.availability_series} />
              </article>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function Devices({
  data,
  t,
  language,
  refresh,
  role,
  setRoute,
  initialFilter = "",
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [editing, setEditing] = useState(null);
  const [pingState, setPingState] = useState("idle");
  const [notice, setNotice] = useState("");
  const [visibleCount, setVisibleCount] = useState(48);
  const [viewMode, setViewMode] = useState(
    data.settings?.default_view === "table" ? "table" : "grid",
  );
  const [sortBy, setSortBy] = useState("priority");
  const [manualDevice, setManualDevice] = useState(null);
  const [cloneDevice, setCloneDevice] = useState(null);
  const [newTagDraft, setNewTagDraft] = useState({ name: "", color: "#5da9ff" });
  const [newCategoryDraft, setNewCategoryDraft] = useState({ name: "", color: "#5da9ff" });
  useEffect(() => {
    if (!initialFilter) return;
    const selected = (data.devices || []).find((device) => device.ip === decodeURIComponent(initialFilter));
    if (selected) setEditing(selected);
    else setFilter(initialFilter);
  }, [initialFilter, data.devices]);
  useEffect(() => setVisibleCount(48), [search, filter]);
  const devices = useMemo(
    () =>
      (data.devices || [])
        .filter((device) => {
          const text =
            `${device.display_name} ${device.name} ${device.ip} ${device.vendor} ${device.category} ${device.mac}`.toLowerCase();
          const matchesFilter =
            filter === "all" ||
            (filter === "quarantined"
              ? device.quarantined
              : filter === "critical"
                ? device.critical
                : filter === "pinned"
                  ? device.pinned
                  : device.status === filter);
          return (
            (!search || text.includes(search.toLowerCase())) && matchesFilter
          );
        })
        .sort((left, right) => {
          if (sortBy === "name")
            return (left.display_name || left.name || left.ip).localeCompare(
              right.display_name || right.name || right.ip,
            );
          if (sortBy === "ip")
            return left.ip.localeCompare(right.ip, undefined, {
              numeric: true,
            });
          if (sortBy === "lastSeen")
            return Number(right.last_seen || 0) - Number(left.last_seen || 0);
          const rank = { offline: 0, unstable: 1, new: 2, online: 3 };
          return (
            (rank[left.status] ?? 4) - (rank[right.status] ?? 4) ||
            Number(right.critical) - Number(left.critical)
          );
        }),
    [data.devices, search, filter, sortBy],
  );
  const action = async (path) => {
    await api(path);
    await refresh();
    setNotice(t("actionCompleted"));
    setTimeout(() => setNotice(""), 2500);
  };
  const saveDevice = async () => {
    await query("/update", {
      ip: editing.ip,
      name: editing.display_name || editing.name || "",
      category: editing.category || "",
      tags: editing.tags_text ?? (editing.tags || []).join(","),
      assigned_network: editing.assigned_network || "",
      scan_profile: editing.scan_profile || "normal",
      device_profile: editing.device_profile || "generic",
      maintenance: editing.maintenance ? 1 : 0,
      mute_alerts: editing.mute_alerts ? 1 : 0,
      pinned: editing.pinned ? 1 : 0,
      critical: editing.critical ? 1 : 0,
      notes: editing.notes || "",
    });
    await refresh();
    setEditing(null);
    setNotice(t("deviceSaved"));
    setTimeout(() => setNotice(""), 2500);
  };
  const selectedEditingTags = editing
    ? editing.tags_text !== undefined
      ? editing.tags_text.split(",").map((tag) => tag.trim()).filter(Boolean)
      : Array.isArray(editing.tags)
        ? editing.tags.map((tag) => (typeof tag === "string" ? tag : tag.name)).filter(Boolean)
        : []
    : [];
  const toggleEditingTag = (name) => {
    const next = selectedEditingTags.includes(name)
      ? selectedEditingTags.filter((tag) => tag !== name)
      : [...selectedEditingTags, name];
    setEditing({ ...editing, tags: next, tags_text: next.join(",") });
  };
  const createEditingTag = async () => {
    const name = newTagDraft.name.trim();
    if (!name) return;
    await api("/labels", {
      method: "POST",
      body: JSON.stringify({
        kind: "tag",
        name,
        color: newTagDraft.color,
        icon: "tag",
      }),
    });
    const next = [...new Set([...selectedEditingTags, name])];
    setEditing({ ...editing, tags: next, tags_text: next.join(",") });
    setNewTagDraft({ name: "", color: "#5da9ff" });
    await refresh();
  };
  const createEditingCategory = async () => {
    const name = newCategoryDraft.name.trim();
    if (!name) return;
    await api("/labels", {
      method: "POST",
      body: JSON.stringify({ kind: "category", name, color: newCategoryDraft.color, icon: "boxes" }),
    });
    setEditing({ ...editing, category: name });
    setNewCategoryDraft({ name: "", color: "#5da9ff" });
    await refresh();
  };
  const pingDevice = async () => {
    setPingState("running");
    try {
      const response = await api(`/ping_now/${encodeURIComponent(editing.ip)}`);
      setPingState(
        response.status === "online" || response.ok ? "success" : "failed",
      );
      setEditing((current) =>
        current
          ? {
              ...current,
              status: response.status || current.status,
              updated_at: response.checked_at || current.updated_at,
              last_seen: response.ok
                ? response.checked_at || current.last_seen
                : current.last_seen,
            }
          : current,
      );
    } catch {
      setPingState("failed");
    }
  };
  const addManualDevice = async () => {
    await api("/add_manual", {
      method: "POST",
      body: JSON.stringify(manualDevice),
    });
    await refresh();
    setManualDevice(null);
    setNotice(t("manualDeviceAdded"));
    setTimeout(() => setNotice(""), 2500);
  };
  const saveClone = async () => {
    await api(`/devices/${encodeURIComponent(cloneDevice.source_ip)}/clone`, {
      method: "POST",
      body: JSON.stringify({ ip: cloneDevice.ip, name: cloneDevice.name }),
    });
    await refresh();
    setCloneDevice(null);
    setEditing(null);
    setNotice(t("deviceCloned"));
    setTimeout(() => setNotice(""), 2500);
  };
  const editingTrend = (editing?.availability_series || []).map(
    (point, index) => ({
      hour: `${String(index).padStart(2, "0")}:00`,
      availability: Number(point.availability_pct || 0),
      disconnects: Number(point.offline_events || 0),
    }),
  );
  const editingDisconnects = editingTrend.reduce(
    (sum, point) => sum + point.disconnects,
    0,
  );
  const editingAvailability = editingTrend.length
    ? Math.round(
        editingTrend.reduce((sum, point) => sum + point.availability, 0) /
          editingTrend.length,
      )
    : editing?.status === "online"
      ? 100
      : 0;
  return (
    <div className="page-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">{t("assetInventory")}</span>
          <h1>{t("devices")}</h1>
          <p>
            {devices.length} {t("of")} {data.devices?.length || 0}
          </p>
        </div>
        <div className="page-actions">
          {role === "admin" && (
            <button
              className="button primary"
              onClick={() =>
                setManualDevice({ ip: "", name: "", category: "", notes: "" })
              }
            >
              <Plus />
              {t("addDevice")}
            </button>
          )}
        </div>
      </div>
      {notice && (
        <div className="success-banner">
          <CheckCircle2 />
          {notice}
        </div>
      )}
      <section className="toolbar panel device-toolbar">
        <div className="search-box">
          <Search size={18} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("search")}
          />
          {search && (
            <button className="clear-search" onClick={() => setSearch("")}>
              <X size={15} />
            </button>
          )}
        </div>
        <div className="inventory-controls">
          <label>
            <ArrowUpDown size={16} />
            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
              <option value="priority">{t("sortPriority")}</option>
              <option value="name">{t("sortName")}</option>
              <option value="ip">IP</option>
              <option value="lastSeen">{t("lastSeen")}</option>
            </select>
          </label>
          <div className="view-switch">
            <button
              className={viewMode === "grid" ? "active" : ""}
              onClick={() => setViewMode("grid")}
              title={t("grid")}
            >
              <Grid2X2 />
            </button>
            <button
              className={viewMode === "table" ? "active" : ""}
              onClick={() => setViewMode("table")}
              title={t("table")}
            >
              <TableProperties />
            </button>
          </div>
        </div>
        <div className="filter-pills">
          {[
            "all",
            "online",
            "offline",
            "unstable",
            "new",
            "critical",
            "pinned",
            "quarantined",
          ].map((item) => (
            <button
              className={filter === item ? "active" : ""}
              onClick={() => setFilter(item)}
              key={item}
            >
              {t(item)}
            </button>
          ))}
        </div>
      </section>
      {viewMode === "grid" ? (
        <section className="device-grid inventory-grid">
          {devices.slice(0, visibleCount).map((device) => {
            const health = Math.max(
              0,
              Math.min(
                100,
                Math.round(
                  Number(
                    device.availability_24h ??
                      (device.status === "online"
                        ? 100
                        : device.status === "unstable"
                          ? 62
                          : device.status === "new"
                            ? 78
                            : 0),
                  ),
                ),
              ),
            );
            return (
              <article
                className={`device-card premium-device-card state-${device.status}`}
                key={device.ip}
                onClick={() => {
                  setEditing({ ...device });
                  setPingState("idle");
                }}
              >
                <div className="device-accent" />
                <div className="device-card-head">
                  <div className="live-state">
                    <StatusDot status={device.status} />
                    <span>{t(device.status)}</span>
                  </div>
                  <div className="device-flags">
                    {device.critical && (
                      <span className="flag critical">
                        <ShieldAlert /> {t("critical")}
                      </span>
                    )}
                    {device.pinned && (
                      <span className="flag">
                        <Pin /> {t("pinned")}
                      </span>
                    )}
                    <button
                      className="icon-button"
                      onClick={(event) => {
                        event.stopPropagation();
                        setEditing({ ...device });
                        setPingState("idle");
                      }}
                    >
                      <Settings size={17} />
                    </button>
                  </div>
                </div>
                <div className="device-identity">
                  <div className={`device-glyph ${device.status}`}>
                    <Server />
                  </div>
                  <div>
                    <h2>{device.display_name || device.name || device.ip}</h2>
                    <p>{device.vendor || t("unavailable")}</p>
                    <code>{device.ip}</code>
                  </div>
                  <div
                    className={`health-score score-${device.status}`}
                    title={t("healthScore")}
                  >
                    <strong>
                      {health}
                      <sup>%</sup>
                    </strong>
                  </div>
                </div>
                <div className="device-facts">
                  <span>
                    <Boxes />
                    {device.category || t("uncategorized")}
                  </span>
                  <span>
                    <Network />
                    {device.assigned_network || "—"}
                  </span>
                  <span>
                    <Clock3 />
                    <TimeAgo timestamp={device.last_seen} language={language} />
                  </span>
                  <span>
                    <Radar />
                    {t(device.scan_profile || "normal")}
                  </span>
                </div>
                <div className="device-availability">
                  <div>
                    <span>24H</span>
                    <small>
                      {device.availability_series?.length
                        ? `${t("availability")} · ${health}%`
                        : t("noData")}
                    </small>
                  </div>
                  <AvailabilityStrip
                    series={device.availability_series}
                    t={t}
                  />
                </div>
              </article>
            );
          })}
          {!devices.length && <Empty t={t} />}
        </section>
      ) : (
        <section className="device-table-wrap panel">
          <table className="device-table">
            <thead>
              <tr>
                <th>{t("status")}</th>
                <th>{t("name")}</th>
                <th>IP</th>
                <th>{t("vendor")}</th>
                <th>{t("category")}</th>
                <th>{t("network")}</th>
                <th>{t("lastSeen")}</th>
                <th>{t("actions")}</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr key={device.ip} className={`state-${device.status}`}>
                  <td>
                    <span className="table-status">
                      <StatusDot status={device.status} />
                      {t(device.status)}
                    </span>
                  </td>
                  <td>
                    <strong>
                      {device.display_name || device.name || device.ip}
                    </strong>
                  </td>
                  <td>
                    <code>{device.ip}</code>
                  </td>
                  <td>{device.vendor || "—"}</td>
                  <td>{device.category || "—"}</td>
                  <td>{device.assigned_network || "—"}</td>
                  <td>
                    <TimeAgo timestamp={device.last_seen} language={language} />
                  </td>
                  <td>
                    <button
                      className="icon-button"
                      onClick={() => {
                        setEditing({ ...device });
                        setPingState("idle");
                      }}
                    >
                      <Settings size={17} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!devices.length && <Empty t={t} />}
        </section>
      )}
      {viewMode === "grid" && devices.length > visibleCount && (
        <button
          className="button load-more"
          onClick={() => setVisibleCount((count) => count + 48)}
        >
          {t("showMore")} · {devices.length - visibleCount}
        </button>
      )}
      {manualDevice && (
        <div
          className="modal-backdrop"
          onMouseDown={(e) =>
            e.target === e.currentTarget && setManualDevice(null)
          }
        >
          <div className="modal-card manual-device-modal">
            <button
              className="modal-close"
              onClick={() => setManualDevice(null)}
            >
              <X />
            </button>
            <span className="eyebrow">{t("manualDevice")}</span>
            <h1>{t("addDevice")}</h1>
            <p className="modal-intro">{t("manualDeviceHelp")}</p>
            <div className="detail-grid">
              <label>
                {t("ip")}
                <input
                  autoFocus
                  value={manualDevice.ip}
                  onChange={(e) =>
                    setManualDevice({ ...manualDevice, ip: e.target.value })
                  }
                  placeholder="192.168.1.50"
                />
              </label>
              <label>
                {t("name")}
                <input
                  value={manualDevice.name}
                  onChange={(e) =>
                    setManualDevice({ ...manualDevice, name: e.target.value })
                  }
                />
              </label>
              <label>
                {t("category")}
                <select
                  value={manualDevice.category}
                  onChange={(e) =>
                    setManualDevice({
                      ...manualDevice,
                      category: e.target.value,
                    })
                  }
                >
                  <option value="">{t("autoDetect")}</option>
                  {(data.labels?.categories || []).map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {t("notes")}
                <input
                  value={manualDevice.notes}
                  onChange={(e) =>
                    setManualDevice({ ...manualDevice, notes: e.target.value })
                  }
                />
              </label>
            </div>
            <div className="modal-actions">
              <button className="button" onClick={() => setManualDevice(null)}>
                {t("cancel")}
              </button>
              <button
                className="button primary"
                disabled={!manualDevice.ip.trim()}
                onClick={addManualDevice}
              >
                <Plus />
                {t("addAndMonitor")}
              </button>
            </div>
          </div>
        </div>
      )}
      {cloneDevice && (
        <div
          className="modal-backdrop"
          onMouseDown={(e) =>
            e.target === e.currentTarget && setCloneDevice(null)
          }
        >
          <div className="modal-card manual-device-modal">
            <button
              className="modal-close"
              onClick={() => setCloneDevice(null)}
            >
              <X />
            </button>
            <span className="eyebrow">{t("cloneDevice")}</span>
            <h1>{cloneDevice.source_name}</h1>
            <p className="modal-intro">{t("cloneDeviceHelp")}</p>
            <div className="detail-grid">
              <label>
                {t("newIp")}
                <input
                  autoFocus
                  value={cloneDevice.ip}
                  onChange={(e) =>
                    setCloneDevice({ ...cloneDevice, ip: e.target.value })
                  }
                  placeholder="192.168.1.51"
                />
              </label>
              <label>
                {t("newName")}
                <input
                  value={cloneDevice.name}
                  onChange={(e) =>
                    setCloneDevice({ ...cloneDevice, name: e.target.value })
                  }
                />
              </label>
            </div>
            <div className="modal-actions">
              <button className="button" onClick={() => setCloneDevice(null)}>
                {t("cancel")}
              </button>
              <button
                className="button primary"
                disabled={!cloneDevice.ip.trim()}
                onClick={saveClone}
              >
                <Copy />
                {t("cloneAndMonitor")}
              </button>
            </div>
          </div>
        </div>
      )}
      {editing && (
        <div
          className="modal-backdrop"
          onMouseDown={(e) => e.target === e.currentTarget && setEditing(null)}
        >
          <div className={`modal-card device-editor state-${editing.status || "unknown"}`}>
            <button className="modal-close" onClick={() => setEditing(null)}>
              <X />
            </button>
            <section className="device-editor-hero">
              <div className={`device-editor-icon state-${editing.status || "unknown"}`}>
                <Server />
              </div>
              <div className="device-editor-title">
                <span className="eyebrow">{t("deviceControl")} · {editing.ip}</span>
                <h1>{editing.display_name || editing.name || editing.ip}</h1>
                <p>{editing.vendor || t("unavailable")} · {editing.mac || "—"}</p>
              </div>
              <div className={`device-editor-status state-${editing.status || "unknown"}`}>
                <StatusDot status={editing.status} />
                <strong>{t(editing.status || "unavailable")}</strong>
              </div>
            </section>
            <section className="device-insight-strip device-editor-metrics">
              <div>
                <span>{t("healthScore")}</span>
                <strong>{editingAvailability}%</strong>
              </div>
              <div>
                <span>{t("disconnects")}</span>
                <strong>{editingDisconnects}</strong>
              </div>
              <div>
                <span>{t("lastCheck")}</span>
                <strong>
                  <TimeAgo
                    timestamp={editing.updated_at || editing.last_seen}
                    language={language}
                  />
                </strong>
              </div>
              <div className="device-mini-chart">
                <ResponsiveContainer>
                  <AreaChart data={editingTrend}>
                    <Area
                      type="monotone"
                      dataKey="availability"
                      stroke="#35d49a"
                      strokeWidth={2}
                      fill="#35d49a18"
                    />
                    <YAxis domain={[0, 100]} hide />
                    <Tooltip
                      contentStyle={{
                        background: "var(--chart-tooltip)",
                        border: "1px solid var(--line-strong)",
                        borderRadius: 12,
                      }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
            <div className="device-editor-body">
              <section className="device-editor-section">
                <div className="device-editor-section-title">
                  <div><Pencil /><strong>{t("deviceControl")}</strong></div>
                  <small>{editing.ip} · {editing.assigned_network || "—"}</small>
                </div>
                <div className="detail-grid">
                  <label>
                    {t("name")}
                    <input
                      value={editing.display_name || editing.name || ""}
                      onChange={(e) => setEditing({ ...editing, display_name: e.target.value, name: e.target.value })}
                    />
                  </label>
                  <label>
                    {t("category")}
                    <select value={editing.category || ""} onChange={(e) => setEditing({ ...editing, category: e.target.value })}>
                      <option value="">{t("uncategorized")}</option>
                      {(data.labels?.categories || []).map((item) => (
                        <option key={item.name} value={item.name}>{item.name}</option>
                      ))}
                    </select>
                  </label>
                  <div className="device-new-tag device-new-category">
                    <input value={newCategoryDraft.name} onChange={(e) => setNewCategoryDraft({ ...newCategoryDraft, name: e.target.value })} placeholder={t("newCategory")} />
                    <input type="color" value={newCategoryDraft.color} onChange={(e) => setNewCategoryDraft({ ...newCategoryDraft, color: e.target.value })} aria-label={t("color")} />
                    <button type="button" className="button" disabled={!newCategoryDraft.name.trim()} onClick={createEditingCategory}><Plus />{t("add")}</button>
                  </div>
                  <label>
                    {t("network")}
                    <select value={editing.assigned_network || ""} onChange={(e) => setEditing({ ...editing, assigned_network: e.target.value })}>
                      <option value="">—</option>
                      {(data.settingsPayload?.networks || data.status?.networks || []).map((network) => (
                        <option value={network} key={network}>{network}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    {t("scanProfile")}
                    <select value={editing.scan_profile || "normal"} onChange={(e) => setEditing({ ...editing, scan_profile: e.target.value })}>
                      <option value="slow">{t("slow")}</option>
                      <option value="normal">{t("normal")}</option>
                      <option value="fast">{t("fast")}</option>
                    </select>
                  </label>
                  <label>
                    {t("deviceProfile")}
                    <select value={editing.device_profile || "generic"} onChange={(e) => setEditing({ ...editing, device_profile: e.target.value })}>
                      <option value="generic">{t("generic")}</option>
                      <option value="iot">IoT</option>
                      <option value="mobile">{t("mobile")}</option>
                      <option value="infrastructure">{t("infrastructure")}</option>
                    </select>
                  </label>
                </div>
              </section>
              <section className="device-editor-section device-editor-labels">
                <div className="device-editor-section-title">
                  <div><Tag /><strong>{t("tags")}</strong></div>
                  <small>{selectedEditingTags.length}</small>
                </div>
                <div className="device-tag-library">
                  {(data.labels?.tags || []).map((item) => (
                    <button
                      type="button"
                      key={item.name}
                      className={selectedEditingTags.includes(item.name) ? "selected" : ""}
                      style={{ "--tag-color": item.color || "#5da9ff" }}
                      onClick={() => toggleEditingTag(item.name)}
                    >
                      <i /> {item.name}
                    </button>
                  ))}
                  {!data.labels?.tags?.length && <span className="device-tags-empty">{t("noData")}</span>}
                </div>
                <div className="device-new-tag">
                  <input
                    value={newTagDraft.name}
                    onChange={(e) => setNewTagDraft({ ...newTagDraft, name: e.target.value })}
                    placeholder={t("newLabel")}
                  />
                  <input
                    type="color"
                    value={newTagDraft.color}
                    onChange={(e) => setNewTagDraft({ ...newTagDraft, color: e.target.value })}
                    aria-label={t("color")}
                  />
                  <button type="button" className="button" disabled={!newTagDraft.name.trim()} onClick={createEditingTag}>
                    <Plus /> {t("add")}
                  </button>
                </div>
              </section>
            </div>
            <div className="editor-toggles device-editor-flags">
              {[
                ["critical", "critical"],
                ["pinned", "pinned"],
                ["maintenance", "maintenance"],
                ["mute_alerts", "muteAlerts"],
              ].map(([field, label]) => (
                <button
                  type="button"
                  className={editing[field] ? "active" : ""}
                  onClick={() =>
                    setEditing({ ...editing, [field]: !editing[field] })
                  }
                  key={field}
                >
                  <span />
                  <strong>{t(label)}</strong>
                </button>
              ))}
            </div>
            <label className="notes-field">
              {t("notes")}
              <textarea
                value={editing.notes || ""}
                onChange={(e) =>
                  setEditing({ ...editing, notes: e.target.value })
                }
              />
            </label>
            {pingState !== "idle" && (
              <div className={`ping-feedback ${pingState}`}>
                {pingState === "running" ? (
                  <RefreshCw className="spin" />
                ) : pingState === "success" ? (
                  <CheckCircle2 />
                ) : (
                  <AlertTriangle />
                )}
                <strong>
                  {t(
                    pingState === "running"
                      ? "pingRunning"
                      : pingState === "success"
                        ? "pingSuccess"
                        : "pingFailed",
                  )}
                </strong>
              </div>
            )}
            <div className="modal-actions">
              <button
                className="button"
                onClick={() =>
                  setCloneDevice({
                    source_ip: editing.ip,
                    source_name:
                      editing.display_name || editing.name || editing.ip,
                    ip: "",
                    name: `${editing.display_name || editing.name || editing.ip} copy`,
                  })
                }
              >
                <Copy />
                {t("cloneDevice")}
              </button>
              <button
                className="button danger"
                onClick={() =>
                  action(
                    `/${editing.quarantined ? "restore" : "remove"}/${encodeURIComponent(editing.ip)}`,
                  ).then(() => setEditing(null))
                }
              >
                {t(editing.quarantined ? "restore" : "quarantine")}
              </button>
              <button
                className="button"
                onClick={() => {
                  setEditing(null);
                  setRoute(`tools/${editing.ip}`);
                }}
              >
                <Wrench />
                {t("advancedChecks")}
              </button>
              <button
                className={`button ping-button ${pingState}`}
                onClick={pingDevice}
              >
                {t("ping")}
              </button>
              <button className="button" onClick={() => setEditing(null)}>
                {t("close")}
              </button>
              <button className="button primary" onClick={saveDevice}>
                {t("saveChanges")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Alerts({ data, t, language, refresh, alertSound, setAlertSound }) {
  const alerts = data.alerts || [];
  const [filter, setFilter] = useState("open");
  const visible = alerts.filter(
    (alert) =>
      filter === "all" || alert.status === filter || alert.severity === filter,
  );
  const deviceNames = Object.fromEntries(
    (data.devices || []).map((device) => [
      device.ip,
      device.display_name || device.name || device.ip,
    ]),
  );
  const summary = [
    [
      "critical",
      alerts.filter((a) => a.status === "open" && a.severity === "critical")
        .length,
    ],
    [
      "high",
      alerts.filter((a) => a.status === "open" && a.severity === "high").length,
    ],
    [
      "unacknowledged",
      alerts.filter((a) => a.status === "open" && !a.acknowledged_at).length,
    ],
    ["resolved", alerts.filter((a) => a.status === "resolved").length],
  ];
  return (
    <div className="page-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">{t("incidentCenter")}</span>
          <h1>{t("alerts")}</h1>
          <p>
            {alerts.filter((a) => a.status === "open").length} {t("openAlerts")}
          </p>
        </div>
        <button
          className={`button ${alertSound ? "sound-active" : ""}`}
          onClick={() => {
            const enabled = !alertSound;
            setAlertSound(enabled);
            localStorage.setItem("homeii-alert-sound", enabled ? "on" : "off");
          }}
        >
          {alertSound ? <Volume2 /> : <VolumeX />}
          {t(alertSound ? "soundOn" : "soundOff")}
        </button>
      </div>
      <section className="incident-summary">
        {summary.map(([key, value]) => (
          <button
            className={`incident-kpi ${key}`}
            key={key}
            onClick={() => setFilter(key === "unacknowledged" ? "open" : key)}
          >
            <span className="incident-symbol">
              {key === "critical" ? (
                <ShieldAlert />
              ) : key === "high" ? (
                <AlertTriangle />
              ) : key === "unacknowledged" ? (
                <Bell />
              ) : (
                <CheckCircle2 />
              )}
            </span>
            <div>
              <small>{t(key)}</small>
              <strong>{value}</strong>
            </div>
            <ChevronLeft />
          </button>
        ))}
      </section>
      <section className="toolbar panel">
        <div className="filter-pills">
          {["open", "criticalSeverity", "high", "resolved", "all"].map(
            (item) => {
              const value = item === "criticalSeverity" ? "critical" : item;
              return (
                <button
                  className={filter === value ? "active" : ""}
                  onClick={() => setFilter(value)}
                  key={item}
                >
                  {t(item)}
                </button>
              );
            },
          )}
        </div>
      </section>
      <section className="alert-list incident-list">
        {visible.length ? (
          visible.map((alert) => (
            <article
              className={`alert-card incident-card severity-${alert.severity} ${alert.acknowledged_at ? "acknowledged" : ""} ${alert.status}`}
              key={alert.id}
            >
              <i className="severity-rail" />
              <div className="alert-icon">
                <AlertTriangle />
              </div>
              <div className="incident-copy">
                <div className="incident-meta">
                  <span className={`severity-badge ${alert.severity}`}>
                    {t(alert.severity)}
                  </span>
                  <span>
                    {alert.status === "open"
                      ? t("activeIncident")
                      : t("resolved")}
                  </span>
                  <TimeAgo timestamp={alert.created_at} language={language} />
                </div>
                <h2>{deviceNames[alert.ip] || alert.title}</h2>
                <p>{alert.message}</p>
                <div className="incident-device">
                  <Server />
                  <strong>{alert.ip}</strong>
                  <span>{alert.title}</span>
                </div>
                {alert.acknowledged_at && (
                  <div className="acknowledged-label">
                    <CheckCircle2 />
                    {t("acknowledgedBy")} {alert.acknowledged_by}
                  </div>
                )}
              </div>
              <div className="alert-side">
                {alert.status === "open" && !alert.acknowledged_at && (
                  <button
                    className="button primary"
                    onClick={async () => {
                      await api(`/acknowledge_alert/${alert.id}`, {
                        method: "POST",
                      });
                      refresh();
                    }}
                  >
                    {t("acknowledge")}
                  </button>
                )}
                {alert.status === "open" && (
                  <button
                    className="button"
                    onClick={async () => {
                      await api(`/resolve_alert/${alert.id}`);
                      refresh();
                    }}
                  >
                    {t("resolve")}
                  </button>
                )}
              </div>
            </article>
          ))
        ) : (
          <Empty t={t} />
        )}
      </section>
    </div>
  );
}

function HistoryPage({ history, t, language }) {
  const [days, setDays] = useState(14);
  const [report, setReport] = useState(history);
  useEffect(() => {
    const toTs = Math.floor(Date.now() / 1000);
    query("/history/summary", { from_ts: toTs - days * 86400, to_ts: toTs })
      .then(setReport)
      .catch(() => setReport(history));
  }, [days, history]);
  const normalized = (report?.daily_series || []).map((item, index) => ({
    name:
      item.label ||
      item.date ||
      new Date((item.ts || 0) * 1000).toLocaleDateString(
        language === "he" ? "he-IL" : "en-US",
        { day: "2-digit", month: "2-digit" },
      ) ||
      index,
    availability: Number(item.availability_pct || 0),
    disconnects: Number(item.disconnects || 0),
  }));
  const summary = report?.summary || {};
  const rankings = report?.rankings || {};
  const formatDate = (ts) =>
    new Date((ts || 0) * 1000).toLocaleString(
      language === "he" ? "he-IL" : "en-US",
      { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" },
    );
  return (
    <div className="page-stack history-page">
      <div className="page-heading history-heading">
        <div>
          <span className="eyebrow">HISTORICAL INTELLIGENCE</span>
          <h1>{t("history")}</h1>
          <p>{t("uptimeTrend")}</p>
        </div>
        <div className="range-pills">
          {[
            [1, "day"],
            [7, "week"],
            [30, "month"],
            [90, "quarter"],
            [180, "halfYear"],
            [365, "year"],
          ].map(([value, label]) => (
            <button
              className={days === value ? "active" : ""}
              onClick={() => setDays(value)}
              key={value}
            >
              {t(label)}
            </button>
          ))}
        </div>
      </div>
      <section className="history-summary">
        {[
          ["availability", `${summary.availability_pct ?? 0}%`, TrendingUp],
          ["disconnects", summary.disconnects || 0, WifiOff],
          ["recoveries", summary.recoveries || 0, CheckCircle2],
          ["affectedDevices", summary.devices_affected || 0, AlertTriangle],
        ].map(([key, value, Icon]) => (
          <article className="history-stat" key={key}>
            <Icon />
            <span>{t(key)}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </section>
      <section className="history-grid">
        <article className="panel chart-panel wide">
          <div className="panel-title">
            <h2>{t("availability")}</h2>
            <span className="score">{summary.availability_pct ?? 0}%</span>
          </div>
          <div className="chart-wrap tall">
            <ResponsiveContainer>
              <AreaChart data={normalized}>
                <defs>
                  <linearGradient
                    id="historyAvailability"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="0" stopColor="#35d7ef" stopOpacity=".52" />
                    <stop offset="1" stopColor="#35d7ef" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis
                  dataKey="name"
                  stroke="var(--chart-axis)"
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke="var(--chart-axis)"
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--chart-tooltip)",
                    border: "1px solid var(--line-strong)",
                    borderRadius: 14,
                  }}
                />
                <Area
                  dataKey="availability"
                  stroke="#35d7ef"
                  fill="url(#historyAvailability)"
                  strokeWidth={3}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>
        <article className="panel chart-panel">
          <div className="panel-title">
            <h2>{t("disconnects")}</h2>
            <span className="score danger-text">
              {summary.disconnects || 0}
            </span>
          </div>
          <div className="chart-wrap tall">
            <ResponsiveContainer>
              <BarChart data={normalized}>
                <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                <XAxis dataKey="name" hide />
                <YAxis hide />
                <Tooltip
                  contentStyle={{
                    background: "var(--chart-tooltip)",
                    border: "1px solid var(--line-strong)",
                    borderRadius: 14,
                  }}
                />
                <Bar
                  dataKey="disconnects"
                  fill="#ff5c70"
                  radius={[8, 8, 2, 2]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>
      </section>
      <section className="history-lower">
        <article className="panel ranking-panel">
          <div className="panel-title">
            <h2>{t("stableDevices")}</h2>
            <CheckCircle2 />
          </div>
          <div className="rank-list">
            {(rankings.stable || []).map((item, index) => (
              <div key={item.ip}>
                <b>{index + 1}</b>
                <span>
                  <strong>{item.name}</strong>
                  <small>{item.ip}</small>
                </span>
                <em>{item.availability_pct ?? item.value}%</em>
              </div>
            ))}
          </div>
        </article>
        <article className="panel ranking-panel">
          <div className="panel-title">
            <h2>{t("unstableDevices")}</h2>
            <AlertTriangle />
          </div>
          <div className="rank-list">
            {(rankings.unstable || []).map((item, index) => (
              <div key={item.ip}>
                <b>{index + 1}</b>
                <span>
                  <strong>{item.name}</strong>
                  <small>
                    {item.offline_count || 0} {t("disconnects")}
                  </small>
                </span>
                <em>{item.availability_pct}%</em>
              </div>
            ))}
          </div>
        </article>
        <article className="panel changes-panel">
          <div className="panel-title">
            <h2>{t("recentChanges")}</h2>
            <History />
          </div>
          <div className="change-list">
            {(report?.recent_changes || []).slice(0, 8).map((item, index) => (
              <div key={`${item.ip}-${item.ts}-${index}`}>
                <StatusDot status={item.new_status} />
                <span>
                  <strong>{item.name}</strong>
                  <small>
                    {item.old_status} → {item.new_status}
                  </small>
                </span>
                <time>{formatDate(item.ts)}</time>
              </div>
            ))}
          </div>
        </article>
      </section>
    </div>
  );
}

function Tools({ data, t, initialTarget = "" }) {
  const [target, setTarget] = useState(initialTarget);
  const [selected, setSelected] = useState("ping");
  const [ports, setPorts] = useState("80,443,554,8000,8080,22");
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const tools = [
    ["ping", Activity],
    ["trace", Route],
    ["ports", ShieldAlert],
    ["dns", Globe2],
    ["speed", Gauge],
    ["free_ips", Network],
  ];
  const run = async () => {
    setRunning(true);
    setResult(null);
    try {
      setResult(
        await api("/tools/run", {
          method: "POST",
          body: JSON.stringify({ target, tools: [selected], ports }),
        }),
      );
    } catch (error) {
      setResult({ ok: false, error: error.message });
    } finally {
      setRunning(false);
    }
  };
  const toolResult = result?.tools?.[selected];
  const status = result?.overall_status || (result?.error ? "down" : "idle");
  const resultItems =
    toolResult?.items ||
    toolResult?.ports ||
    toolResult?.hops ||
    toolResult?.addresses ||
    [];
  const targetDevice = (data.devices || []).find(
    (device) => device.ip === target,
  );
  const assessmentKey = !toolResult
    ? ""
    : selected === "ping"
      ? Number(toolResult.loss_pct) === 0
        ? Number(toolResult.latency_avg_ms) < 40
          ? "pingExcellent"
          : Number(toolResult.latency_avg_ms) < 100
            ? "pingGood"
            : "pingSlow"
        : Number(toolResult.loss_pct) < 30
          ? "pingPacketLoss"
          : "pingUnavailable"
      : selected === "ports"
        ? Number(toolResult.open_ports)
          ? "portsFound"
          : "noOpenPorts"
        : selected === "trace"
          ? toolResult.hop_count
            ? "routeFound"
            : "routeUnavailable"
          : selected === "dns"
            ? toolResult.reverse_host
              ? "dnsResolved"
              : "dnsNotResolved"
            : selected === "speed"
              ? toolResult.ok
                ? "speedCompleted"
                : "speedFailed"
              : selected === "free_ips"
                ? "freeIpsFound"
                : status;
  const metrics = Object.entries(toolResult || {})
    .filter(
      ([key, value]) =>
        !["ok", "status", "output", "target", "command"].includes(key) &&
        ["string", "number", "boolean"].includes(typeof value),
    )
    .slice(0, 8);
  const metricLabels = {
    transmitted: t("transmittedPackets"),
    received: t("receivedPackets"),
    loss_pct: t("packetLoss"),
    latency_min_ms: t("minimumLatency"),
    latency_avg_ms: t("averageLatency"),
    latency_max_ms: t("maximumLatency"),
    open_ports: t("openPorts"),
    checked_ports: t("checkedPorts"),
    hop_count: t("hopCount"),
    download_mbps: t("downloadSpeed"),
    upload_mbps: t("uploadSpeed"),
    ping_ms: t("latency"),
    available: t("availableAddresses"),
    checked: t("checkedAddresses"),
    reverse_host: t("reverseHost"),
  };
  const chartData = !toolResult
    ? []
    : selected === "ping"
      ? [
          { name: t("minimum"), value: Number(toolResult.latency_min_ms || 0) },
          { name: t("average"), value: Number(toolResult.latency_avg_ms || 0) },
          { name: t("maximum"), value: Number(toolResult.latency_max_ms || 0) },
        ]
      : selected === "trace"
        ? (toolResult.hops || []).map((hop) => ({
            name: String(hop.hop),
            value: Number(hop.latency_ms || 0),
          }))
        : selected === "ports"
          ? [
              { name: t("open"), value: Number(toolResult.open_ports || 0) },
              {
                name: t("closed"),
                value: Math.max(
                  0,
                  Number(toolResult.checked_ports || 0) -
                    Number(toolResult.open_ports || 0),
                ),
              },
            ]
          : selected === "speed"
            ? [
                {
                  name: t("download"),
                  value: Number(toolResult.download_mbps || 0),
                },
                {
                  name: t("upload"),
                  value: Number(toolResult.upload_mbps || 0),
                },
              ]
            : selected === "free_ips"
              ? [
                  {
                    name: t("available"),
                    value: Number(toolResult.available || 0),
                  },
                  {
                    name: t("used"),
                    value: Math.max(
                      0,
                      Number(toolResult.checked || 0) -
                        Number(toolResult.available || 0),
                    ),
                  },
                ]
              : [
                  {
                    name: "DNS",
                    value:
                      (toolResult.addresses || []).length +
                      (toolResult.reverse_host ? 1 : 0),
                  },
                ];
  return (
    <div className="page-stack tools-page">
      <div className="page-heading tools-heading">
        <div>
          <span className="eyebrow">{t("diagnosticsLab")}</span>
          <h1>{t("tools")}</h1>
          <p>{t("toolsDescription")}</p>
        </div>
        <span className={`result-status ${status}`}>
          {running ? t("scanning") : t(status)}
        </span>
      </div>
      <section className="tool-workbench">
        <article className="panel tool-command-card">
          <div className="tool-selector">
            {tools.map(([key, Icon]) => (
              <button
                className={selected === key ? "active" : ""}
                onClick={() => {
                  setSelected(key);
                  setResult(null);
                }}
                key={key}
              >
                <Icon />
                <span>{key === "free_ips" ? t("freeIps") : t(key)}</span>
              </button>
            ))}
          </div>
          <div className="tool-target-card">
            <label>
              <span>{t("target")}</span>
              <div className="tool-target-input">
                <Search />
                <input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="192.168.1.100"
                  list="device-ips"
                />
              </div>
              <datalist id="device-ips">
                {(data.devices || []).map((device) => (
                  <option value={device.ip} key={device.ip}>
                    {device.display_name}
                  </option>
                ))}
              </datalist>
            </label>
            {targetDevice && (
              <div className="target-device-chip">
                <StatusDot status={targetDevice.status} />
                <div>
                  <strong>
                    {targetDevice.display_name ||
                      targetDevice.name ||
                      targetDevice.ip}
                  </strong>
                  <small>
                    {targetDevice.category || t("uncategorized")} ·{" "}
                    {targetDevice.vendor || "—"}
                  </small>
                </div>
              </div>
            )}
            {selected === "ports" && (
              <label className="ports-field">
                <span>{t("ports")}</span>
                <input
                  value={ports}
                  onChange={(event) => setPorts(event.target.value)}
                  placeholder="80,443 or 1-1024"
                />
              </label>
            )}
            <button
              className="button primary tool-run"
              onClick={run}
              disabled={
                running ||
                (!target && !["speed", "free_ips"].includes(selected))
              }
            >
              {running ? <RefreshCw className="spin" /> : <Play />}
              {running ? t("scanning") : t("run")}
            </button>
          </div>
        </article>
        <article className={`panel diagnostic-result visual-result ${status}`}>
          {!result ? (
            <div className="diagnostic-empty">
              <span className="result-orb idle">
                <Activity />
              </span>
              <strong>{t("readyForTest")}</strong>
              <p>{t("selectAndRunTest")}</p>
            </div>
          ) : result.error ? (
            <div className="diagnostic-error">
              <AlertTriangle />
              <strong>{t("testFailed")}</strong>
              <p>{result.error}</p>
            </div>
          ) : (
            <div className="result-body">
              <div className="result-hero">
                <span className={`result-orb ${status}`}>
                  {status === "healthy" ? <CheckCircle2 /> : <AlertTriangle />}
                </span>
                <div>
                  <small>{t("diagnosticResult")}</small>
                  <h2>{t(assessmentKey)}</h2>
                  <p>{result.target}</p>
                </div>
                <span className={`result-status ${status}`}>{t(status)}</span>
              </div>
              <p className="result-explanation">{t(`${assessmentKey}Help`)}</p>
              <div className="visual-result-grid">
                <div className="result-chart">
                  <div className="panel-title">
                    <h3>{t("visualSummary")}</h3>
                    <TrendingUp />
                  </div>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData}>
                      <CartesianGrid
                        stroke="var(--chart-grid)"
                        vertical={false}
                      />
                      <XAxis
                        dataKey="name"
                        stroke="var(--chart-axis)"
                        tickLine={false}
                      />
                      <YAxis hide />
                      <Tooltip
                        contentStyle={{
                          background: "var(--chart-tooltip)",
                          border: "1px solid var(--line-strong)",
                          borderRadius: 12,
                        }}
                      />
                      <Bar
                        dataKey="value"
                        fill={
                          status === "down"
                            ? "#ff5d73"
                            : status === "degraded"
                              ? "#ffb52e"
                              : "#35d49a"
                        }
                        radius={[8, 8, 3, 3]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="result-metrics">
                  {metrics.slice(0, 6).map(([key, value]) => (
                    <div key={key}>
                      <span>
                        {metricLabels[key] || key.replaceAll("_", " ")}
                      </span>
                      <strong>{String(value)}</strong>
                    </div>
                  ))}
                </div>
              </div>
              <details className="advanced-result">
                <summary>{t("advancedDetails")}</summary>
                {resultItems.length > 0 && (
                  <div className="result-list">
                    {resultItems.slice(0, 50).map((item, index) => {
                      const value =
                        typeof item === "string"
                          ? item
                          : item.ip ||
                            item.port ||
                            item.address ||
                            item.hop ||
                            index + 1;
                      const detail =
                        typeof item === "string"
                          ? t("ready")
                          : item.open === true
                            ? t("open")
                            : item.open === false
                              ? t("closed")
                              : item.status || item.name || item.service || "—";
                      return (
                        <div key={index}>
                          <code>{value}</code>
                          <span>{detail}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
                {toolResult?.output && <pre>{toolResult.output}</pre>}
              </details>
            </div>
          )}
        </article>
      </section>
    </div>
  );
}

function AuthScreen({ setupRequired, onAuthenticated }) {
  const [form, setForm] = useState({
    username: "",
    password: "",
    display_name: "",
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api(setupRequired ? "/auth/setup" : "/auth/login", {
        method: "POST",
        body: JSON.stringify(form),
      });
      await onAuthenticated();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="auth-screen">
      <section className="auth-card">
        <Logo />
        <div className="auth-intro">
          <span className="eyebrow">SECURE NETWORK INTELLIGENCE</span>
          <h1>{setupRequired ? "יצירת מנהל ראשי" : "כניסה מאובטחת"}</h1>
          <p>
            {setupRequired
              ? "הגדר את חשבון המנהל הראשון. הסיסמה חייבת להכיל לפחות 8 תווים."
              : "הזן שם משתמש וסיסמה כדי להיכנס למערכת."}
          </p>
        </div>
        <form onSubmit={submit}>
          {setupRequired && (
            <label>
              שם תצוגה
              <input
                autoComplete="name"
                value={form.display_name}
                onChange={(e) =>
                  setForm({ ...form, display_name: e.target.value })
                }
              />
            </label>
          )}
          <label>
            שם משתמש
            <input
              autoFocus
              autoComplete="username"
              required
              minLength="3"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
            />
          </label>
          <label>
            סיסמה
            <input
              type="password"
              autoComplete={setupRequired ? "new-password" : "current-password"}
              required
              minLength="8"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
          </label>
          {error && (
            <div className="auth-error">
              <AlertTriangle />
              {error}
            </div>
          )}
          <button className="button primary auth-submit" disabled={busy}>
            {busy ? <RefreshCw className="spin" /> : <LockKeyhole />}
            {setupRequired ? "צור חשבון מנהל" : "כניסה"}
          </button>
        </form>
        <small className="auth-note">
          HOMEii protects the web console with an encrypted session.
        </small>
      </section>
    </main>
  );
}

function UserManagement({ t, currentUser }) {
  const [users, setUsers] = useState([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [draft, setDraft] = useState({
    username: "",
    display_name: "",
    password: "",
    role: "user",
    viewer_edge_to_edge: false,
    can_manage_alerts: false,
  });
  const [message, setMessage] = useState("");
  const load = () =>
    api("/admin/users")
      .then((result) => setUsers(result.users || []))
      .catch((error) => setMessage(error.message));
  useEffect(() => {
    load();
  }, []);
  const create = async () => {
    await api("/admin/users", { method: "POST", body: JSON.stringify(draft) });
    setDraft({
      username: "",
      display_name: "",
      password: "",
      role: "user",
      viewer_edge_to_edge: false,
      can_manage_alerts: false,
    });
    setMessage(t("userCreated"));
    setCreateOpen(false);
    load();
  };
  const update = async (user, next) => {
    await api(`/admin/users/${user.id}`, {
      method: "PATCH",
      body: JSON.stringify({ ...user, ...next }),
    });
    load();
  };
  return (
    <div className="users-panel">
      <div className="settings-title">
        <Users />
        <div>
          <h2>{t("userManagement")}</h2>
          <p>{t("userManagementHelp")}</p>
        </div>
        <button className="button primary settings-title-action" onClick={() => setCreateOpen(true)}>
          <UserPlus /> {t("addUser")}
        </button>
      </div>
      {createOpen && <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setCreateOpen(false)}>
      <div className="modal-card admin-form-modal">
        <button className="modal-close" onClick={() => setCreateOpen(false)}><X /></button>
        <span className="eyebrow">{t("userManagement")}</span>
        <h1>{t("addUser")}</h1>
        <div className="user-create-card">
        <div className="form-grid">
          <label>
            {t("username")}
            <input
              value={draft.username}
              onChange={(e) => setDraft({ ...draft, username: e.target.value })}
            />
          </label>
          <label>
            {t("displayName")}
            <input
              value={draft.display_name}
              onChange={(e) =>
                setDraft({ ...draft, display_name: e.target.value })
              }
            />
          </label>
          <label>
            {t("password")}
            <input
              type="password"
              value={draft.password}
              onChange={(e) => setDraft({ ...draft, password: e.target.value })}
            />
          </label>
          <label>
            {t("role")}
            <select
              value={draft.role}
              onChange={(e) => setDraft({ ...draft, role: e.target.value })}
            >
              <option value="admin">Admin</option>
              <option value="user">User</option>
              <option value="viewer">Viewer</option>
            </select>
          </label>
        </div>
        <button
          type="button"
          className={`setting-toggle ${draft.viewer_edge_to_edge ? "active" : ""}`}
          onClick={() =>
            setDraft({
              ...draft,
              viewer_edge_to_edge: !draft.viewer_edge_to_edge,
            })
          }
        >
          <span />
          <div>
            <strong>{t("edgeToEdge")}</strong>
            <small>{t("edgeToEdgeHelp")}</small>
          </div>
        </button>
        <button
          type="button"
          className={`setting-toggle ${draft.can_manage_alerts ? "active" : ""}`}
          onClick={() =>
            setDraft({ ...draft, can_manage_alerts: !draft.can_manage_alerts })
          }
        >
          <span />
          <div>
            <strong>{t("manageAlertsPermission")}</strong>
            <small>{t("manageAlertsPermissionHelp")}</small>
          </div>
        </button>
        <button
          className="button primary"
          onClick={create}
          disabled={draft.username.length < 3 || draft.password.length < 8}
        >
          <UserPlus />
          {t("addUser")}
        </button>
      </div>
      </div></div>}
      {message && <div className="success-banner">{message}</div>}
      <div className="user-list">
        {users.map((user) => (
          <article key={user.id}>
            <div className="user-avatar">
              {(user.display_name || user.username).slice(0, 1).toUpperCase()}
            </div>
            <div>
              <strong>{user.display_name || user.username}</strong>
              <small>
                @{user.username} · {user.role}
              </small>
            </div>
            <select
              value={user.role}
              disabled={user.id === currentUser?.id}
              onChange={(e) => update(user, { role: e.target.value })}
            >
              <option value="admin">Admin</option>
              <option value="user">User</option>
              <option value="viewer">Viewer</option>
            </select>
            <button
              className={`mini-toggle ${user.viewer_edge_to_edge ? "active" : ""}`}
              onClick={() =>
                update(user, { viewer_edge_to_edge: !user.viewer_edge_to_edge })
              }
            >
              {t("edgeToEdge")}
            </button>
            <button
              className={`mini-toggle ${user.can_manage_alerts ? "active" : ""}`}
              onClick={() =>
                update(user, { can_manage_alerts: !user.can_manage_alerts })
              }
            >
              {t("manageAlertsPermission")}
            </button>
            <button
              className={`mini-toggle ${user.active ? "active" : ""}`}
              disabled={user.id === currentUser?.id}
              onClick={() => update(user, { active: !user.active })}
            >
              {user.active ? t("active") : t("disabled")}
            </button>
          </article>
        ))}
      </div>
    </div>
  );
}

function OperationsManagement({ t, refresh }) {
  const [labels, setLabels] = useState({ categories: [], tags: [] });
  const [recycled, setRecycled] = useState([]);
  const [audit, setAudit] = useState([]);
  const [draft, setDraft] = useState({
    kind: "category",
    name: "",
    color: "#5da9ff",
    icon: "boxes",
  });
  const [cleanupResult, setCleanupResult] = useState(null);
  const load = async () => {
    const [labelData, recycleData, auditData] = await Promise.all([
      api("/labels"),
      api("/recycle-bin"),
      api("/audit?limit=100"),
    ]);
    setLabels(labelData);
    setRecycled(recycleData.devices || []);
    setAudit(auditData.records || []);
  };
  useEffect(() => {
    load();
  }, []);
  const saveLabel = async () => {
    await api("/labels", { method: "POST", body: JSON.stringify(draft) });
    setDraft({ ...draft, name: "" });
    load();
    refresh();
  };
  const cleanupInventory = async () => {
    if (!confirm(t("cleanupInventoryConfirm"))) return;
    const result = await api("/admin/inventory/cleanup", { method: "POST" });
    setCleanupResult(result);
    await load();
    await refresh();
  };
  return (
    <div className="operations-admin">
      <div className="settings-title">
        <Tag />
        <div>
          <h2>{t("operationsManagement")}</h2>
          <p>{t("operationsManagementHelp")}</p>
        </div>
      </div>
      <div className="operations-actions">
        <button
          className="button danger"
          onClick={async () => {
            if (!confirm(t("trashOfflineConfirm"))) return;
            await api("/recycle-bin/trash-offline", { method: "POST" });
            load();
            refresh();
          }}
        >
          <WifiOff />
          {t("trashAllOffline")}
        </button>
        <button className="button danger" onClick={cleanupInventory}>
          <ShieldAlert />
          {t("cleanupInventory")}
        </button>
        <button
          className="button"
          onClick={async () => {
            await api("/admin/backup-now", { method: "POST" });
            load();
          }}
        >
          <Database />
          {t("backupNow")}
        </button>
      </div>
      {cleanupResult && (
        <div className="cleanup-result">
          <CheckCircle2 />
          <strong>{t("cleanupComplete")}</strong>
          <span>
            {cleanupResult.offline || 0} {t("offline")} ·{" "}
            {cleanupResult.duplicates || 0} {t("duplicates")}
          </span>
        </div>
      )}
      <section className="admin-grid">
        <article className="admin-card">
          <h3>{t("categoriesAndTags")}</h3>
          <div className="label-builder">
            <select
              value={draft.kind}
              onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
            >
              <option value="category">{t("category")}</option>
              <option value="tag">{t("tags")}</option>
            </select>
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder={t("name")}
            />
            <input
              type="color"
              value={draft.color}
              onChange={(e) => setDraft({ ...draft, color: e.target.value })}
            />
            <select
              value={draft.icon}
              onChange={(e) => setDraft({ ...draft, icon: e.target.value })}
            >
              <option value="boxes">Boxes</option>
              <option value="server">Server</option>
              <option value="camera">Camera</option>
              <option value="wifi">Wi-Fi</option>
              <option value="shield">Shield</option>
              <option value="tag">Tag</option>
            </select>
            <button
              className="button primary"
              disabled={!draft.name.trim()}
              onClick={saveLabel}
            >
              <Plus />
              {t("add")}
            </button>
          </div>
          <div className="label-cloud">
            {[...(labels.categories || []), ...(labels.tags || [])].map(
              (item) => (
                <span
                  style={{ "--label-color": item.color }}
                  key={`${item.kind}-${item.name}`}
                >
                  <i />
                  {item.name}
                  <small>{t(item.kind)}</small>
                </span>
              ),
            )}
          </div>
        </article>
        <article className="admin-card">
          <h3>{t("recycleBin")}</h3>
          <p>{t("recycleBinHelp")}</p>
          <div className="admin-list">
            {recycled.map((device) => (
              <div key={device.ip}>
                <StatusDot status="offline" />
                <span>
                  <strong>
                    {device.display_name || device.name || device.ip}
                  </strong>
                  <small>{device.ip}</small>
                </span>
                <button
                  className="button"
                  onClick={async () => {
                    await api(`/recycle-bin/${device.ip}/restore`, {
                      method: "POST",
                    });
                    load();
                    refresh();
                  }}
                >
                  {t("restore")}
                </button>
                <button
                  className="icon-button danger-text"
                  onClick={async () => {
                    await api(`/recycle-bin/${device.ip}`, {
                      method: "DELETE",
                    });
                    load();
                  }}
                >
                  <X />
                </button>
              </div>
            ))}
            {!recycled.length && <Empty t={t} />}
          </div>
        </article>
      </section>
      <article className="admin-card audit-card">
        <div className="panel-title">
          <div>
            <h3>{t("auditLog")}</h3>
            <p>{t("auditLogHelp")}</p>
          </div>
          <button
            className="button danger"
            onClick={async () => {
              await api("/alerts?scope=resolved", { method: "DELETE" });
              refresh();
            }}
          >
            {t("clearResolvedAlerts")}
          </button>
        </div>
        <div className="audit-table">
          {audit.map((record) => (
            <div key={record.id}>
              <time>{new Date(record.ts * 1000).toLocaleString()}</time>
              <strong>{record.actor}</strong>
              <code>{record.action}</code>
              <span className={record.outcome}>{record.outcome}</span>
            </div>
          ))}
        </div>
      </article>
    </div>
  );
}

function LabelManager({ data, t, refresh }) {
  const empty = {
    id: 0,
    kind: "category",
    name: "",
    color: "#5da9ff",
    icon: "boxes",
  };
  const [draft, setDraft] = useState(empty);
  const [message, setMessage] = useState("");
  const items = [
    ...(data.labels?.categories || []),
    ...(data.labels?.tags || []),
  ].filter((item) => item.id);
  const PreviewIcon = categoryIcons[draft.icon] || Tag;
  const save = async () => {
    if (draft.id) {
      await api(`/labels/${draft.id}`, {
        method: "PATCH",
        body: JSON.stringify(draft),
      });
    } else {
      await api("/labels", { method: "POST", body: JSON.stringify(draft) });
    }
    setDraft(empty);
    setMessage(t("labelSaved"));
    await refresh();
  };
  const remove = async (item) => {
    if (!confirm(t("deleteLabelConfirm"))) return;
    await api(`/labels/${item.id}`, { method: "DELETE" });
    if (draft.id === item.id) setDraft(empty);
    await refresh();
  };
  return (
    <div className="label-manager">
      <div className="settings-title">
        <Tag />
        <div>
          <h2>{t("categoriesAndTags")}</h2>
          <p>{t("labelManagerHelp")}</p>
        </div>
      </div>
      <section className="label-editor">
        <div className="label-preview" style={{ "--label-color": draft.color }}>
          <span>
            <PreviewIcon />
          </span>
          <div>
            <small>{t(draft.kind === "category" ? "category" : "tags")}</small>
            <strong>{draft.name || t("newLabel")}</strong>
          </div>
        </div>
        <div className="form-grid">
          <label>
            {t("type")}
            <select
              disabled={Boolean(draft.id)}
              value={draft.kind}
              onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
            >
              <option value="category">{t("category")}</option>
              <option value="tag">{t("tags")}</option>
            </select>
          </label>
          <label>
            {t("name")}
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </label>
          <label>
            {t("color")}
            <input
              type="color"
              value={draft.color}
              onChange={(e) => setDraft({ ...draft, color: e.target.value })}
            />
          </label>
          <label>
            {t("icon")}
            <select
              value={draft.icon}
              onChange={(e) => setDraft({ ...draft, icon: e.target.value })}
            >
              {categoryIconOptions.map(
                (icon) => (
                  <option value={icon} key={icon}>
                    {t(icon)}
                  </option>
                ),
              )}
            </select>
          </label>
        </div>
        <div className="label-editor-actions">
          {Boolean(draft.id) && (
            <button className="button" onClick={() => setDraft(empty)}>
              {t("cancel")}
            </button>
          )}
          <button
            className="button primary"
            disabled={!draft.name.trim()}
            onClick={save}
          >
            {draft.id ? <Pencil /> : <Plus />}
            {t(draft.id ? "saveChanges" : "add")}
          </button>
        </div>
      </section>
      {message && (
        <div className="success-banner">
          <CheckCircle2 />
          {message}
        </div>
      )}
      <section className="label-library">
        <div className="panel-title">
          <div>
            <h3>{t("labelLibrary")}</h3>
            <p>{t("labelLibraryHelp")}</p>
          </div>
          <strong>{items.length}</strong>
        </div>
        <div>
          {items.map((item) => (
            <article key={item.id} style={{ "--label-color": item.color }}>
              <span className="label-swatch">
                <Tag />
              </span>
              <div>
                <strong>{item.name}</strong>
                <small>
                  {t(item.kind === "category" ? "category" : "tags")} ·{" "}
                  {item.icon}
                </small>
              </div>
              <button
                className="icon-button"
                onClick={() => setDraft({ ...item })}
              >
                <Pencil />
              </button>
              <button
                className="icon-button danger-text"
                onClick={() => remove(item)}
              >
                <Trash2 />
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function NotificationManagement({ t, enableNotifications }) {
  const [rules, setRules] = useState([]);
  const [audit, setAudit] = useState([]);
  const [filters, setFilters] = useState({ actor: "", action: "", outcome: "", date_from: "", date_to: "" });
  const [ruleOpen, setRuleOpen] = useState(false);
  const [draft, setDraft] = useState({ name: "", trigger_type: "device_offline", severity: "high", category: "", tag: "", critical_only: false, sound: true, toast: true, pwa: true });
  const loadRules = () => api("/alert-rules").then((result) => setRules(result.rules || []));
  const loadAudit = () => {
    const params = new URLSearchParams({ limit: "250" });
    Object.entries(filters).forEach(([key, value]) => {
      if (!value) return;
      params.set(key, key.startsWith("date_") ? String(Math.floor(new Date(value).getTime() / 1000)) : value);
    });
    return api(`/audit?${params}`).then((result) => setAudit(result.records || []));
  };
  useEffect(() => { loadRules(); loadAudit(); }, []);
  const saveRule = async () => {
    await api("/alert-rules", { method: "POST", body: JSON.stringify({
      name: draft.name,
      trigger_type: draft.trigger_type,
      severity: draft.severity,
      condition: { category: draft.category, tag: draft.tag, critical: draft.critical_only || undefined },
      action: { sound: draft.sound, toast: draft.toast, pwa: draft.pwa },
      enabled: true,
    }) });
    setRuleOpen(false);
    setDraft({ name: "", trigger_type: "device_offline", severity: "high", category: "", tag: "", critical_only: false, sound: true, toast: true, pwa: true });
    loadRules();
  };
  const toggleRule = async (rule) => {
    await api(`/alert-rules/${rule.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !rule.enabled }) });
    loadRules();
  };
  return <div className="notification-management">
    <div className="settings-title"><Bell /><div><h2>{t("notification")}</h2><p>{t("notificationCenterHelp")}</p></div><button className="button primary settings-title-action" onClick={() => setRuleOpen(true)}><Plus />{t("addRule")}</button></div>
    <section className="notification-channels">
      <article><Bell /><div><strong>PWA / Browser</strong><small>{t("notificationChannelHelp")}</small></div><button className="button" onClick={enableNotifications}>{t("enableNotifications")}</button></article>
      <article><Volume2 /><div><strong>{t("disconnectSound")}</strong><small>{t("disconnectSoundHelp")}</small></div><span className="healthy-label">{t("ready")}</span></article>
    </section>
    <section className="rules-panel"><div className="panel-title"><div><h3>{t("systemRules")}</h3><p>{t("triggerConditionAction")}</p></div><strong>{rules.length}</strong></div>
      <div className="rules-list">{rules.map((rule) => <article key={rule.id}><i className={`severity-dot ${rule.severity}`} /><div><strong>{rule.name}</strong><small>{rule.trigger_type} · {rule.severity}</small></div><button className={`mini-toggle ${rule.enabled ? "active" : ""}`} onClick={() => toggleRule(rule)}>{rule.enabled ? t("active") : t("disabled")}</button><button className="icon-button danger-text" onClick={async () => { await api(`/alert-rules/${rule.id}`, { method: "DELETE" }); loadRules(); }}><Trash2 /></button></article>)}</div>
    </section>
    <section className="audit-panel"><div className="panel-title"><div><h3>{t("auditLog")}</h3><p>{t("auditLogHelp")}</p></div></div>
      <div className="audit-filters"><input placeholder={t("username")} value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })}/><input placeholder={t("actions")} value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}/><select value={filters.outcome} onChange={(e) => setFilters({ ...filters, outcome: e.target.value })}><option value="">{t("all")}</option><option value="success">Success</option><option value="failed">Failed</option></select><input type="date" value={filters.date_from} onChange={(e) => setFilters({ ...filters, date_from: e.target.value })}/><input type="date" value={filters.date_to} onChange={(e) => setFilters({ ...filters, date_to: e.target.value })}/><button className="button" onClick={loadAudit}><Search />{t("search")}</button></div>
      <div className="audit-table">{audit.map((record) => <article key={record.id}><time>{new Date(Number(record.ts) * 1000).toLocaleString()}</time><strong>{record.action}</strong><span>{record.actor || "system"}</span><code>{record.target || "—"}</code><em className={record.outcome === "success" ? "healthy-label" : "danger-text"}>{record.outcome}</em></article>)}</div>
    </section>
    {ruleOpen && <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setRuleOpen(false)}><section className="modal-card admin-form-modal"><button className="modal-close" onClick={() => setRuleOpen(false)}><X /></button><span className="eyebrow">{t("triggerConditionAction")}</span><h1>{t("addRule")}</h1><div className="form-grid"><label>{t("name")}<input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })}/></label><label>{t("trigger")}<select value={draft.trigger_type} onChange={(e) => setDraft({ ...draft, trigger_type: e.target.value })}><option value="device_offline">{t("deviceOffline")}</option><option value="critical_offline">{t("criticalOffline")}</option><option value="device_unstable">{t("deviceUnstable")}</option><option value="device_recovered">{t("recoveries")}</option><option value="new_device">{t("newDevices")}</option></select></label><label>{t("severity")}<select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}><option value="info">Info</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label><label>{t("category")}<input value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })}/></label><label>{t("tags")}<input value={draft.tag} onChange={(e) => setDraft({ ...draft, tag: e.target.value })}/></label></div><div className="rule-actions">{[["sound", t("sound")],["toast", "Toast"],["pwa", "PWA"]].map(([key,label]) => <button key={key} className={`mini-toggle ${draft[key] ? "active" : ""}`} onClick={() => setDraft({ ...draft, [key]: !draft[key] })}>{label}</button>)}</div><div className="modal-actions"><button className="button" onClick={() => setRuleOpen(false)}>{t("cancel")}</button><button className="button primary" disabled={!draft.name.trim()} onClick={saveRule}><Plus />{t("addRule")}</button></div></section></div>}
  </div>;
}

function BackupManagement({ t }) {
  const [state, setState] = useState({ target: "data", retention: 3, enabled: true, backups: [] });
  const [busy, setBusy] = useState(false);
  const load = () => api("/admin/backups").then(setState);
  useEffect(() => { load(); }, []);
  const save = async () => { setBusy(true); try { setState(await api("/admin/backups/settings", { method: "POST", body: JSON.stringify(state) })); } finally { setBusy(false); } };
  const backupNow = async () => { setBusy(true); try { await api("/admin/backup-now", { method: "POST" }); await load(); } finally { setBusy(false); } };
  return <section className="backup-management"><div className="panel-title"><div><h3>{t("backups")}</h3><p>{t("backupsHelp")}</p></div><Database /></div><div className="backup-settings"><button className={`setting-toggle ${state.enabled ? "active" : ""}`} onClick={() => setState({ ...state, enabled: !state.enabled })}><span/><div><strong>{t("automaticBackup")}</strong><small>{t("automaticBackupHelp")}</small></div></button><label>{t("backupLocation")}<select value={state.target || "data"} onChange={(e) => setState({ ...state, target: e.target.value })}><option value="data">/data</option><option value="share">/share</option></select></label><label>{t("retention")}<input type="number" min="1" max="10" value={state.retention || 3} onChange={(e) => setState({ ...state, retention: Number(e.target.value) })}/></label><button className="button" disabled={busy} onClick={save}>{t("save")}</button><button className="button primary" disabled={busy} onClick={backupNow}><Database />{t("backupNow")}</button></div><div className="backup-list">{(state.backups || []).map((item) => <article key={item.name}><Database/><div><strong>{item.name}</strong><small>{item.size_human || item.size || ""}</small></div><time>{item.modified ? new Date(item.modified * 1000).toLocaleString() : ""}</time></article>)}</div></section>;
}

function SettingsDevices({ data, t, refresh }) {
  const [addOpen, setAddOpen] = useState(false);
  const [draft, setDraft] = useState({
    ip: "",
    mac: "",
    name: "",
    category: "",
    tags: [],
    scan_profile: "normal",
    critical: false,
  });
  const [result, setResult] = useState(null);
  const [preflight, setPreflight] = useState(null);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState({});
  const [edits, setEdits] = useState({});
  const [joinReport, setJoinReport] = useState(null);
  const [pendingEdits, setPendingEdits] = useState({});
  const [selected, setSelected] = useState([]);
  const [customLabel, setCustomLabel] = useState({ kind: "category", name: "", color: "#5da9ff" });
  const grouped = useMemo(() => {
    const groups = {};
    for (const device of data.devices || []) {
      if (device.ignored || device.quarantined || device.trashed_at) continue;
      const category = device.category || t("uncategorized");
      (groups[category] ||= []).push(device);
    }
    return groups;
  }, [data.devices, t]);
  const pending = (data.devices || []).filter((device) => device.status === "new" && !device.approved && !device.quarantined && !device.ignored);
  const runPreflight = async () => {
    setBusy(true);
    setResult(null);
    try {
      const checked = await api("/devices/preflight", { method: "POST", body: JSON.stringify({ ip: draft.ip, mac: draft.mac }) });
      setPreflight(checked);
    } catch (error) {
      setResult({ ok: false, error: error.message, ip: draft.ip });
    } finally {
      setBusy(false);
    }
  };
  const add = async () => {
    setBusy(true);
    setResult(null);
    try {
      const checked = preflight?.ip === draft.ip ? preflight : await api("/devices/preflight", { method: "POST", body: JSON.stringify({ ip: draft.ip, mac: draft.mac }) });
      if (!checked.can_add) throw new Error("device_identity_conflict");
      await api("/add_manual", { method: "POST", body: JSON.stringify(draft) });
      await query("/update", {
        ip: draft.ip,
        name: draft.name,
        category: draft.category,
        scan_profile: draft.scan_profile,
        critical: draft.critical ? 1 : 0,
        tags: draft.tags.join(","),
      });
      const probe = await api(`/ping_now/${encodeURIComponent(draft.ip)}`);
      setResult({
        ok: Boolean(probe.ok),
        ip: draft.ip,
        name: draft.name || draft.ip,
      });
      setDraft({ ip: "", mac: "", name: "", category: "", tags: [], scan_profile: "normal", critical: false });
      setPreflight(null);
      setAddOpen(false);
      await refresh();
    } catch (error) {
      setResult({ ok: false, error: error.message, ip: draft.ip });
    } finally {
      setBusy(false);
    }
  };
  const saveInline = async (device) => {
    const edit = edits[device.ip] || {};
    await query("/update", {
      ip: device.ip,
      name: edit.name ?? device.display_name ?? device.name ?? "",
      category: edit.category ?? device.category ?? "",
      tags: edit.tags ?? (device.tags || []).join(","),
      critical: edit.critical === undefined ? (device.critical ? 1 : 0) : (edit.critical ? 1 : 0),
      pinned: edit.pinned === undefined ? (device.pinned ? 1 : 0) : (edit.pinned ? 1 : 0),
    });
    await refresh();
  };
  const joinOne = async (device) => {
    try {
      const response = await api(`/accept/${encodeURIComponent(device.ip)}`);
      const edit = pendingEdits[device.ip] || {};
      if (response.ok) {
        await query("/update", {
          ip: device.ip,
          name: edit.name ?? device.display_name ?? device.name ?? "",
          category: edit.category ?? "",
          tags: edit.tags ?? (device.tags || []).join(","),
        });
        await api(`/ping_now/${encodeURIComponent(device.ip)}`);
      }
      setJoinReport({ accepted: response.ok ? [device.ip] : [], conflicts: [] });
    } catch (error) {
      setJoinReport({ accepted: [], conflicts: [{ ip: device.ip, error: error.message }] });
    }
    await refresh();
  };
  const joinAll = async () => {
    setJoinReport(await api("/accept_all"));
    await api("/scan?mode=accept_all");
    await refresh();
  };
  const toggleSelected = (ip) => setSelected((current) => current.includes(ip) ? current.filter((item) => item !== ip) : [...current, ip]);
  const deleteSelected = async (ips = selected) => {
    if (!ips.length || !window.confirm(`${t("delete")} · ${ips.length}`)) return;
    await api("/admin/devices/delete", { method: "POST", body: JSON.stringify({ ips }) });
    setSelected((current) => current.filter((ip) => !ips.includes(ip)));
    await refresh();
  };
  const createCustomLabel = async () => {
    const name = customLabel.name.trim();
    if (!name) return;
    await api("/labels", { method: "POST", body: JSON.stringify({ ...customLabel, name, icon: customLabel.kind === "category" ? "boxes" : "tag" }) });
    setDraft((current) => customLabel.kind === "category" ? { ...current, category: name } : { ...current, tags: [...new Set([...current.tags, name])] });
    setCustomLabel({ ...customLabel, name: "" });
    await refresh();
  };
  return (
    <div className="settings-devices">
      <div className="settings-title">
        <Server />
        <div>
          <h2>{t("deviceSetup")}</h2>
          <p>{t("deviceSetupHelp")}</p>
        </div>
        <button className="button primary settings-title-action" onClick={() => { setAddOpen(true); setResult(null); setPreflight(null); }}><Plus />{t("addDevice")}</button>
      </div>
      {addOpen && <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && setAddOpen(false)}>
      <section className="modal-card admin-form-modal device-onboarding-modal">
        <button className="modal-close" onClick={() => setAddOpen(false)}><X /></button>
        <span className="eyebrow">{t("manualDevice")}</span><h1>{t("addDevice")}</h1>
        <p className="modal-intro">{t("manualDeviceHelp")}</p>
        <div className="device-entry-card">
        <div className="form-grid">
          <label>
            {t("ip")}
            <input
              autoFocus
              value={draft.ip}
              onChange={(e) => setDraft({ ...draft, ip: e.target.value })}
              placeholder="192.168.1.50"
            />
          </label>
          <label>MAC
            <input value={draft.mac} onChange={(e) => { setDraft({ ...draft, mac: e.target.value }); setPreflight(null); }} placeholder="AA:BB:CC:DD:EE:FF" />
          </label>
          <label>
            {t("name")}
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder={t("optionalName")}
            />
          </label>
          <label>
            {t("category")}
            <select
              value={draft.category}
              onChange={(e) => setDraft({ ...draft, category: e.target.value })}
            >
              <option value="">{t("uncategorized")}</option>
              {(data.labels?.categories || []).map((item) => (
                <option value={item.name} key={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t("scanProfile")}
            <select
              value={draft.scan_profile}
              onChange={(e) =>
                setDraft({ ...draft, scan_profile: e.target.value })
              }
            >
              <option value="slow">{t("slow")}</option>
              <option value="normal">{t("normal")}</option>
              <option value="fast">{t("fast")}</option>
            </select>
          </label>
        </div>
        <div className="device-tag-library onboarding-tags">
          {(data.labels?.tags || []).map((item) => <button type="button" key={item.name} className={draft.tags.includes(item.name) ? "selected" : ""} style={{ "--tag-color": item.color }} onClick={() => setDraft({ ...draft, tags: draft.tags.includes(item.name) ? draft.tags.filter((tag) => tag !== item.name) : [...draft.tags, item.name] })}><i />{item.name}</button>)}
        </div>
        <div className="device-new-tag onboarding-custom-label">
          <select value={customLabel.kind} onChange={(e) => setCustomLabel({ ...customLabel, kind: e.target.value })}><option value="category">{t("category")}</option><option value="tag">{t("tags")}</option></select>
          <input value={customLabel.name} onChange={(e) => setCustomLabel({ ...customLabel, name: e.target.value })} placeholder={t("newLabel")} />
          <input type="color" value={customLabel.color} onChange={(e) => setCustomLabel({ ...customLabel, color: e.target.value })} />
          <button type="button" className="button" disabled={!customLabel.name.trim()} onClick={createCustomLabel}><Plus />{t("add")}</button>
        </div>
        <button
          type="button"
          className={`setting-toggle ${draft.critical ? "active" : ""}`}
          onClick={() => setDraft({ ...draft, critical: !draft.critical })}
        >
          <span />
          <div>
            <strong>{t("critical")}</strong>
            <small>{t("criticalDeviceHelp")}</small>
          </div>
        </button>
        {preflight && <div className={`device-add-result ${preflight.reachable ? "healthy" : "failed"}`}><Radar /><div><strong>{preflight.reachable ? t("deviceReachable") : t("deviceNotReachable")}</strong><span>{preflight.mac || "MAC —"} · {preflight.vendor || "—"}</span>{preflight.conflicts?.map((item) => <small key={item.ip}>{item.ip} · {item.reasons.join(", ")}</small>)}</div></div>}
        <div className="modal-actions"><button className="button" onClick={() => setAddOpen(false)}>{t("cancel")}</button><button className="button" disabled={busy || !draft.ip.trim()} onClick={runPreflight}><Radar />{t("ping")}</button><button className="button primary" disabled={busy || !draft.ip.trim() || !preflight?.can_add} onClick={add}>{busy ? <RefreshCw className="spin" /> : <Plus />}{t("addAndMonitor")}</button></div>
        </div>
      </section></div>}
      {result && (
        <div
          className={`device-add-result ${result.ok ? "healthy" : "failed"}`}
        >
          {result.ok ? <CheckCircle2 /> : <AlertTriangle />}
          <div>
            <strong>
              {result.ok ? t("deviceReachable") : t("deviceNotReachable")}
            </strong>
            <span>
              {result.name || result.error} · {result.ip}
            </span>
          </div>
        </div>
      )}
      {pending.length > 0 && <section className="settings-pending-devices">
        <div className="panel-title"><div><h3>{t("newDevices")}</h3><small>{pending.length}</small></div><button className="button primary" onClick={joinAll}>{t("acceptAllNew")}</button></div>
        {pending.map((device) => { const edit = pendingEdits[device.ip] || {}; return <article className="pending-device-editor" key={device.ip}><StatusDot status="new"/><div><strong>{device.display_name || device.name || device.ip}</strong><small>{device.ip} · {device.mac || "—"}</small></div><input value={edit.name ?? device.display_name ?? device.name ?? ""} onChange={(e) => setPendingEdits({ ...pendingEdits, [device.ip]: { ...edit, name: e.target.value } })} placeholder={t("name")}/><select value={edit.category ?? ""} onChange={(e) => setPendingEdits({ ...pendingEdits, [device.ip]: { ...edit, category: e.target.value } })}><option value="">{t("uncategorized")}</option>{(data.labels?.categories || []).map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}</select><input value={edit.tags ?? (device.tags || []).join(", ")} onChange={(e) => setPendingEdits({ ...pendingEdits, [device.ip]: { ...edit, tags: e.target.value } })} placeholder={t("tags")}/><button className="button primary" onClick={() => joinOne(device)}><CheckCircle2 />{t("save")} · {t("accept")}</button></article>})}
        {joinReport && <div className={joinReport.conflicts?.length ? "error-banner" : "success-banner"}>{joinReport.accepted?.length || 0} {t("accepted")} · {joinReport.conflicts?.length || 0} {t("duplicates")}</div>}
      </section>}
      <section className="settings-device-groups">
        <div className="panel-title">
          <h3>{t("devices")}</h3>
          <div className="settings-device-bulk"><span>{data.devices?.length || 0}</span><button className="button danger" disabled={!selected.length} onClick={() => deleteSelected()}><Trash2 />{t("delete")} ({selected.length})</button></div>
        </div>
        {Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, devices]) => <div className="settings-device-group" key={category}>
          <button className="settings-device-group-head" onClick={() => setExpanded({ ...expanded, [category]: !expanded[category] })}><span><Boxes /> <strong>{category}</strong></span><span>{devices.filter((item) => item.status === "online").length}/{devices.length} <ChevronLeft className={expanded[category] ? "expanded" : ""}/></span></button>
          {expanded[category] && <div className="settings-device-rows">{devices.map((device) => { const edit = edits[device.ip] || {}; return <article key={device.ip}><input type="checkbox" checked={selected.includes(device.ip)} onChange={() => toggleSelected(device.ip)} aria-label={`${t("select")} ${device.ip}`}/><StatusDot status={device.status}/><input value={edit.name ?? device.display_name ?? device.name ?? ""} onChange={(e) => setEdits({ ...edits, [device.ip]: { ...edit, name: e.target.value } })}/><code>{device.ip}</code><select value={edit.category ?? device.category ?? ""} onChange={(e) => setEdits({ ...edits, [device.ip]: { ...edit, category: e.target.value } })}><option value="">{t("uncategorized")}</option>{(data.labels?.categories || []).map((item) => <option key={item.name}>{item.name}</option>)}</select><input value={edit.tags ?? (device.tags || []).join(", ")} onChange={(e) => setEdits({ ...edits, [device.ip]: { ...edit, tags: e.target.value } })} placeholder={t("tags")}/><button className="button" onClick={() => saveInline(device)}>{t("save")}</button><button className="icon-button" onClick={() => location.hash = `#/devices/${encodeURIComponent(device.ip)}`}><ArrowUpRight /></button><button className="icon-button danger" onClick={() => deleteSelected([device.ip])}><Trash2 /></button></article>})}</div>}
        </div>)}
      </section>
    </div>
  );
}

function SettingsPage({
  data,
  t,
  language,
  refresh,
  enableNotifications,
  currentUser,
  onExit,
}) {
  const settings = data.settings || {};
  const [form, setForm] = useState({
    language: settings.language || language,
    theme: settings.theme || "granite",
    auto_refresh: settings.auto_refresh || "30",
    history_retention_days: settings.history_retention_days || "30",
    alert_profile: settings.alert_profile || "normal",
    auto_restore_quarantined: settings.auto_restore_quarantined || "1",
    default_view: settings.default_view || "table",
    dashboard_style: settings.dashboard_style || "advanced",
    status_animation: settings.status_animation || "blink",
    discovery_mode: data.settingsPayload?.discovery_mode || "auto_manual",
    discovery_protocols: data.settingsPayload?.discovery_protocols || [
      "ping",
      "arp",
      "dns",
      "special",
      "vendor",
    ],
  });
  const [section, setSection] = useState("general");
  const [transfer, setTransfer] = useState({ type: "", message: "" });
  const [reconcile, setReconcile] = useState(null);
  const [networksText, setNetworksText] = useState("");
  const importRef = useRef(null);
  useEffect(
    () =>
      setForm((f) => ({
        ...f,
        language: settings.language || f.language,
        theme: settings.theme || f.theme,
        auto_refresh: settings.auto_refresh || f.auto_refresh,
        history_retention_days:
          settings.history_retention_days || f.history_retention_days,
        alert_profile: settings.alert_profile || f.alert_profile,
        auto_restore_quarantined:
          settings.auto_restore_quarantined || f.auto_restore_quarantined,
        default_view: settings.default_view || f.default_view,
        dashboard_style: settings.dashboard_style || f.dashboard_style,
        status_animation: settings.status_animation || f.status_animation,
        discovery_mode:
          data.settingsPayload?.discovery_mode || f.discovery_mode,
        discovery_protocols:
          data.settingsPayload?.discovery_protocols || f.discovery_protocols,
      })),
    [
      settings,
      data.settingsPayload?.discovery_mode,
      data.settingsPayload?.discovery_protocols,
    ],
  );
  useEffect(
    () =>
      setNetworksText(
        (data.settingsPayload?.networks || data.status?.networks || []).join(
          "\n",
        ),
      ),
    [data.settingsPayload?.networks, data.status?.networks],
  );
  const saveForm = async (next = form) => {
    await api("/save_settings", {
      method: "POST",
      body: JSON.stringify({
        ...settings,
        ...next,
        networks: data.settingsPayload?.networks || data.status?.networks || [],
        network_names: data.settingsPayload?.network_names || {},
      }),
    });
    await refresh();
  };
  const save = () => saveForm(form);
  const saveNetworks = async () => {
    await api("/save_networks", {
      method: "POST",
      body: JSON.stringify({
        networks: networksText,
        network_names: data.settingsPayload?.network_names || {},
      }),
    });
    await refresh();
    setTransfer({ type: "success", message: t("networksSaved") });
  };
  const runReconciliation = async () => {
    if (!window.confirm(t("reconcileConfirm"))) return;
    setReconcile({ running: true });
    try {
      await api("/admin/reconcile-inventory", { method: "POST" });
      const poll = async () => {
        const result = await api("/admin/reconcile-inventory");
        const state = result.reconciliation || {};
        setReconcile(state);
        if (state.running) setTimeout(poll, 1500);
        else await refresh();
      };
      setTimeout(poll, 1000);
    } catch (error) {
      setReconcile({ running: false, error: error.message });
    }
  };
  const importFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const kind = file.name.toLowerCase().endsWith(".csv")
      ? "devices"
      : "settings";
    const body = new FormData();
    body.append("file", file);
    try {
      const result = await api(`/import/${kind}`, { method: "POST", body });
      await refresh();
      setTransfer({
        type: "success",
        message:
          kind === "devices"
            ? `${t("imported")} ${result.imported || 0}`
            : t("settingsImported"),
      });
    } catch (error) {
      setTransfer({ type: "error", message: error.message });
    } finally {
      event.target.value = "";
    }
  };
  const sections = [
    ["general", SlidersHorizontal],
    ["devices", Server],
    ["labels", Tag],
    ["appearance", Eye],
    ["discovery", Radar],
    ["networks", Network],
    ["notification", Bell],
    ["operationsManagement", ShieldAlert],
    ["users", Users],
    ["system", Database],
    ["dataManagement", FileJson],
  ];
  const deferredSaveSections = new Set(["general", "appearance", "discovery"]);
  return (
    <div className="settings-workspace">
      <aside className="settings-sidebar">
        <div className="settings-brand">
          <Logo />
          <button className="settings-exit" onClick={onExit}>
            <ChevronLeft />
            <span>{t("backToApplication")}</span>
          </button>
        </div>
        <nav className="settings-nav">
          {sections.map(([key, Icon]) => (
            <button
              className={section === key ? "active" : ""}
              onClick={() => setSection(key)}
              key={key}
            >
              <Icon />
              <span>{t(key)}</span>
              <ChevronLeft />
            </button>
          ))}
        </nav>
        <div className="settings-version">
          <span className="live-dot" />
          <div>
            <strong>{t("monitorLive")}</strong>
            <small>v{data.status?.version}</small>
          </div>
        </div>
      </aside>
      <main className="settings-main">
        <div className="settings-workspace-heading">
          <div>
            <span className="eyebrow">{t("systemConfiguration")}</span>
            <h1>{t("settings")}</h1>
            <p>{t("controlPlane")}</p>
          </div>
          <button className="icon-button settings-mobile-exit" onClick={onExit}>
            <X />
          </button>
        </div>
        {transfer.message && (
          <div
            className={
              transfer.type === "error" ? "error-banner" : "success-banner"
            }
          >
            {transfer.type === "error" ? <AlertTriangle /> : <CheckCircle2 />}
            {transfer.message}
            <button onClick={() => setTransfer({ type: "", message: "" })}>
              <X />
            </button>
          </div>
        )}
        <section
          className={`settings-content settings-surface section-${section}`}
        >
          {section === "general" && (
            <>
              <div className="settings-title">
                <SlidersHorizontal />
                <div>
                  <h2>{t("general")}</h2>
                  <p>{t("generalHelp")}</p>
                </div>
              </div>
              <div className="form-grid">
                <label>
                  {t("autoRefresh")}
                  <input
                    type="number"
                    min="10"
                    max="3600"
                    value={form.auto_refresh}
                    onChange={(e) =>
                      setForm({ ...form, auto_refresh: e.target.value })
                    }
                  />
                  <small>10–3600 {t("seconds")}</small>
                </label>
                <label>
                  {t("historyDays")}
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={form.history_retention_days}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        history_retention_days: e.target.value,
                      })
                    }
                  />
                  <small>1–365 {t("days")}</small>
                </label>
              </div>
            </>
          )}
          {section === "devices" && (
            <SettingsDevices data={data} t={t} refresh={refresh} />
          )}
          {section === "labels" && (
            <LabelManager data={data} t={t} refresh={refresh} />
          )}
          {section === "appearance" && (
            <>
              <div className="settings-title">
                <Eye />
                <div>
                  <h2>{t("appearance")}</h2>
                  <p>
                    {t("language")} · {t("theme")}
                  </p>
                </div>
              </div>
              <div className="choice-grid">
                <button
                  className={form.language === "he" ? "selected" : ""}
                  onClick={() => {
                    const next = { ...form, language: "he" };
                    setForm(next);
                    saveForm(next);
                  }}
                >
                  <Languages />
                  <strong>עברית</strong>
                  <span>RTL</span>
                </button>
                <button
                  className={form.language === "en" ? "selected" : ""}
                  onClick={() => {
                    const next = { ...form, language: "en" };
                    setForm(next);
                    saveForm(next);
                  }}
                >
                  <Languages />
                  <strong>English</strong>
                  <span>LTR</span>
                </button>
                <button
                  className={
                    ["granite", "dark"].includes(form.theme) ? "selected" : ""
                  }
                  onClick={() => {
                    const next = { ...form, theme: "granite" };
                    setForm(next);
                    document.documentElement.dataset.theme = "granite";
                    saveForm(next);
                  }}
                >
                  <MonitorUp />
                  <strong>{t("granite")}</strong>
                  <span>Charcoal</span>
                </button>
                <button
                  className={form.theme === "navy" ? "selected" : ""}
                  onClick={() => {
                    const next = { ...form, theme: "navy" };
                    setForm(next);
                    document.documentElement.dataset.theme = "navy";
                    saveForm(next);
                  }}
                >
                  <MonitorUp />
                  <strong>{t("navy")}</strong>
                  <span>Midnight</span>
                </button>
                <button
                  className={form.theme === "light" ? "selected" : ""}
                  onClick={() => {
                    const next = { ...form, theme: "light" };
                    setForm(next);
                    document.documentElement.dataset.theme = "light";
                    saveForm(next);
                  }}
                >
                  <MonitorUp />
                  <strong>{t("light")}</strong>
                  <span>Porcelain</span>
                </button>
              </div>
            </>
          )}
          {section === "discovery" && (
            <>
              <div className="settings-title">
                <Radar />
                <div>
                  <h2>{t("discovery")}</h2>
                  <p>{t("discoveryHelp")}</p>
                </div>
              </div>
              <div className="form-grid">
                <label>
                  {t("discoveryMode")}
                  <select
                    value={form.discovery_mode}
                    onChange={(e) =>
                      setForm({ ...form, discovery_mode: e.target.value })
                    }
                  >
                    <option value="auto_manual">{t("autoManual")}</option>
                    <option value="auto_only">{t("autoOnly")}</option>
                    <option value="manual_only">{t("manualOnly")}</option>
                  </select>
                  <small>{t("discoveryModeHelp")}</small>
                </label>
              </div>
              <div className="protocol-grid">
                {["ping", "arp", "dns", "special", "vendor"].map((protocol) => (
                  <button
                    type="button"
                    className={
                      (form.discovery_protocols || []).includes(protocol)
                        ? "active"
                        : ""
                    }
                    onClick={() =>
                      setForm({
                        ...form,
                        discovery_protocols: (
                          form.discovery_protocols || []
                        ).includes(protocol)
                          ? form.discovery_protocols.filter(
                              (item) => item !== protocol,
                            )
                          : [...(form.discovery_protocols || []), protocol],
                      })
                    }
                    key={protocol}
                  >
                    <span />
                    <div>
                      <strong>{t(`protocol_${protocol}`)}</strong>
                      <small>{t(`protocol_${protocol}_help`)}</small>
                    </div>
                  </button>
                ))}
              </div>
              <div className="admin-reconcile-card">
                <div className="admin-reconcile-head">
                  <ShieldAlert />
                  <div>
                    <span className="eyebrow">{t("adminOnly")}</span>
                    <h3>{t("reconcileTitle")}</h3>
                    <p>{t("reconcileHelp")}</p>
                  </div>
                </div>
                <button
                  type="button"
                  className={`setting-toggle ${form.auto_restore_quarantined === "1" ? "active" : ""}`}
                  onClick={() =>
                    setForm({
                      ...form,
                      auto_restore_quarantined:
                        form.auto_restore_quarantined === "1" ? "0" : "1",
                    })
                  }
                >
                  <span />
                  <div>
                    <strong>{t("autoRestore")}</strong>
                    <small>{t("autoRestoreHelp")}</small>
                  </div>
                </button>
                {reconcile && (
                  <div
                    className={`reconcile-status ${reconcile.error ? "failed" : reconcile.running ? "running" : "complete"}`}
                  >
                    {reconcile.running ? (
                      <>
                        <RefreshCw className="spin" />
                        <strong>{t("reconcileRunning")}</strong>
                      </>
                    ) : reconcile.error ? (
                      <>
                        <AlertTriangle />
                        <strong>{reconcile.error}</strong>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 />
                        <div>
                          <strong>{t("reconcileComplete")}</strong>
                          <span>
                            {reconcile.online || 0} {t("online")} ·{" "}
                            {reconcile.quarantined || 0} {t("quarantined")} ·{" "}
                            {reconcile.restored || 0} {t("restored")}
                          </span>
                        </div>
                      </>
                    )}
                  </div>
                )}
                <button
                  type="button"
                  className="button danger"
                  disabled={reconcile?.running}
                  onClick={runReconciliation}
                >
                  <Radar />
                  {reconcile?.running ? t("scanning") : t("runReconcile")}
                </button>
              </div>
            </>
          )}{" "}
          {section === "networks" && (
            <>
              <div className="settings-title">
                <Network />
                <div>
                  <h2>{t("networks")}</h2>
                  <p>{t("networksHelp")}</p>
                </div>
              </div>
              <label className="notes-field">
                {t("networkRanges")}
                <textarea
                  value={networksText}
                  onChange={(e) => setNetworksText(e.target.value)}
                  placeholder={"192.168.1.0/24\n10.0.0.0/24"}
                />
                <small>{t("oneNetworkPerLine")}</small>
              </label>
              <div className="settings-actions inline">
                <button className="button primary" onClick={saveNetworks}>
                  {t("saveNetworks")}
                </button>
              </div>
              <div className="network-list">
                {(
                  data.settingsPayload?.networks ||
                  data.status?.networks ||
                  []
                ).map((network, index) => (
                  <div key={network}>
                    <span className="icon-box">
                      <Network />
                    </span>
                    <div>
                      <strong>
                        {data.settingsPayload?.network_names?.[network] ||
                          `${t("network")} ${index + 1}`}
                      </strong>
                      <code>{network}</code>
                    </div>
                    <span className="healthy-label">{t("monitorLive")}</span>
                  </div>
                ))}
              </div>
            </>
          )}
          {section === "notification" && (
            <NotificationManagement t={t} enableNotifications={enableNotifications} />
          )}
          {section === "operationsManagement" && (
            <OperationsManagement t={t} refresh={refresh} />
          )}
          {section === "users" && (
            <UserManagement t={t} currentUser={currentUser} />
          )}
          {section === "system" && (
            <>
              <div className="settings-title">
                <DatabaseIcon />
                <div>
                  <h2>{t("system")}</h2>
                  <p>{t("systemWorkers")}</p>
                </div>
              </div>
              <dl className="system-dl">
                <div>
                  <dt>{t("version")}</dt>
                  <dd>{data.status?.version}</dd>
                </div>
                <div>
                  <dt>{t("database")}</dt>
                  <dd
                    className={
                      data.status?.db_ok ? "healthy-label" : "danger-text"
                    }
                  >
                    {data.status?.db_ok ? t("ready") : t("unavailable")}
                  </dd>
                </div>
                <div>
                  <dt>{t("networks")}</dt>
                  <dd>{data.status?.networks?.length || 0}</dd>
                </div>
                <div>
                  <dt>PWA</dt>
                  <dd>
                    {"serviceWorker" in navigator
                      ? t("ready")
                      : t("unavailable")}
                  </dd>
                </div>
              </dl>
            </>
          )}
          {section === "dataManagement" && (
            <>
              <div className="settings-title">
                <FileJson />
                <div>
                  <h2>{t("dataManagement")}</h2>
                  <p>{t("dataManagementHelp")}</p>
                </div>
              </div>
              <div className="transfer-grid">
                <a
                  className="transfer-card"
                  href="./api/export/devices.csv"
                  download
                >
                  <FileSpreadsheet />
                  <div>
                    <strong>{t("exportDevices")}</strong>
                    <span>CSV · Excel</span>
                  </div>
                  <Download />
                </a>
                <a
                  className="transfer-card"
                  href="./api/export/settings.json"
                  download
                >
                  <FileJson />
                  <div>
                    <strong>{t("exportSettings")}</strong>
                    <span>JSON</span>
                  </div>
                  <Download />
                </a>
                <button
                  className="transfer-card"
                  onClick={() => importRef.current?.click()}
                >
                  <Upload />
                  <div>
                    <strong>{t("importData")}</strong>
                    <span>CSV / JSON</span>
                  </div>
                  <ArrowUpRight />
                </button>
                <input
                  ref={importRef}
                  className="visually-hidden"
                  type="file"
                  accept=".csv,.json,text/csv,application/json"
                  onChange={importFile}
                />
              </div>
              <BackupManagement t={t} />
            </>
          )}
          {deferredSaveSections.has(section) && (
            <div className="settings-actions settings-savebar">
              <button className="button primary" onClick={save}>
                {t("save")}
              </button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

function DatabaseIcon() {
  return (
    <div className="db-icon">
      <span />
      <span />
      <span />
    </div>
  );
}

export default function App() {
  const [route, setRoute, routeDetail] = useRoute();
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [auth, setAuth] = useState({
    loading: true,
    authenticated: false,
    setup_required: false,
    user: null,
  });
  const notificationReady = useRef(false);
  const refreshInFlight = useRef(false);
  const audioContext = useRef(null);
  const knownOfflineAlerts = useRef(null);
  const [alertSound, setAlertSound] = useState(
    () => localStorage.getItem("homeii-alert-sound") !== "off",
  );
  const [offlineToast, setOfflineToast] = useState(null);
  const language = data.settings?.language || "he";
  const t = useMemo(() => translator(language), [language]);
  const showAlertNotifications = async (alerts = []) => {
    if (!("Notification" in window) || Notification.permission !== "granted")
      return;
    const open = alerts.filter((a) => a.status === "open");
    const ids = open.map((a) => String(a.id));
    const previous = JSON.parse(
      localStorage.getItem("homeii-notified-alerts") || "null",
    );
    localStorage.setItem("homeii-notified-alerts", JSON.stringify(ids));
    if (!notificationReady.current || !previous) {
      notificationReady.current = true;
      return;
    }
    const fresh = open.filter((a) => !previous.includes(String(a.id)));
    if (!fresh.length) return;
    const registration = await navigator.serviceWorker?.ready;
    fresh.slice(0, 3).forEach((alert) =>
      registration?.showNotification(alert.title || "HOMEii Network Alert", {
        body: alert.message || alert.ip || "",
        icon: "./icons/homeii-192.png",
        badge: "./icons/homeii-192.png",
        tag: `homeii-alert-${alert.id}`,
        data: { route: "#/alerts" },
      }),
    );
  };
  const enableNotifications = async () => {
    if (!("Notification" in window)) {
      setError(t("notificationsUnsupported"));
      return;
    }
    const permission = await Notification.requestPermission();
    if (permission === "granted") {
      notificationReady.current = true;
      setError("");
    } else setError(t("notificationsDenied"));
  };
  const loadAuth = async () => {
    try {
      const result = await api("/auth/session");
      setAuth({ ...result, loading: false });
      if (result.authenticated) {
        if (result.user?.role === "viewer") setRoute("viewer");
        await refresh();
      }
    } catch {
      setAuth({
        loading: false,
        authenticated: false,
        setup_required: false,
        user: null,
      });
    }
  };
  const refresh = async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    try {
      setError("");
      const [
        status,
        devices,
        alerts,
        events,
        settingsPayload,
        viewer,
        history,
        labels,
      ] = await Promise.all([
        api("/status"),
        api("/devices"),
        api("/alerts?limit=100"),
        api("/events?limit=100"),
        api("/settings"),
        api("/viewer/categories"),
        api("/history/summary"),
        api("/labels"),
      ]);
      const alertItems = alerts.alerts || [];
      setData({
        status,
        devices: (devices.devices || []).map((device) => ({
          ...device,
          availability_series: device.availability_series?.length ? device.availability_series : viewer.devices?.[String(device.ip || "").trim()]?.series || [],
          availability_24h: device.availability_24h ?? viewer.devices?.[String(device.ip || "").trim()]?.availability_24h,
        })),
        alerts: alertItems,
        events: events.events || [],
        settings: settingsPayload.settings || {},
        settingsPayload,
        viewer,
        history,
        labels,
      });
      showAlertNotifications(alertItems);
    } catch (e) {
      setError(e.message);
    } finally {
      refreshInFlight.current = false;
      setLoading(false);
    }
  };
  useEffect(() => {
    loadAuth();
  }, []);
  useEffect(() => {
    if (!auth.authenticated) return;
    const interval =
      Math.max(10, Number(data.settings?.auto_refresh || 30)) * 1000;
    const id = setInterval(refresh, interval);
    return () => clearInterval(id);
  }, [auth.authenticated, data.settings?.auto_refresh]);
  useEffect(() => {
    if (!auth.authenticated) return;
    const stream = new EventSource("./api/stream");
    stream.addEventListener("update", refresh);
    return () => stream.close();
  }, [auth.authenticated]);
  useEffect(() => {
    const unlock = () => {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext && !audioContext.current)
        audioContext.current = new AudioContext();
      audioContext.current?.resume?.();
    };
    addEventListener("pointerdown", unlock, { once: true });
    return () => removeEventListener("pointerdown", unlock);
  }, []);
  useEffect(() => {
    if (!auth.authenticated || !data.status) return;
    const offlineAlerts = (data.alerts || []).filter(
      (alert) => alert.status === "open" && alert.title === "Device offline",
    );
    const currentIds = new Set(offlineAlerts.map((alert) => String(alert.id)));
    if (knownOfflineAlerts.current === null) {
      knownOfflineAlerts.current = currentIds;
      return;
    }
    const fresh = offlineAlerts.find(
      (alert) => !knownOfflineAlerts.current.has(String(alert.id)),
    );
    knownOfflineAlerts.current = currentIds;
    if (!fresh) return;
    const device = (data.devices || []).find((item) => item.ip === fresh.ip);
    setOfflineToast({
      id: fresh.id,
      name: device?.display_name || device?.name || fresh.ip,
      ip: fresh.ip,
      category: device?.category || t("uncategorized"),
      critical: Boolean(device?.critical),
      createdAt: fresh.created_at,
    });
    if (alertSound && audioContext.current) {
      const ctx = audioContext.current;
      const oscillator = ctx.createOscillator();
      const gain = ctx.createGain();
      oscillator.frequency.setValueAtTime(760, ctx.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(
        390,
        ctx.currentTime + 0.52,
      );
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.17, ctx.currentTime + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.58);
      oscillator.connect(gain).connect(ctx.destination);
      oscillator.start();
      oscillator.stop(ctx.currentTime + 0.6);
    }
  }, [auth.authenticated, alertSound, data.alerts, data.devices, t]);
  useEffect(() => {
    if (!offlineToast) return;
    const timer = setTimeout(() => setOfflineToast(null), 20000);
    return () => clearTimeout(timer);
  }, [offlineToast]);
  useEffect(() => {
    document.documentElement.lang = language;
    document.documentElement.dir = language === "he" ? "rtl" : "ltr";
    document.documentElement.dataset.theme = data.settings?.theme || "dark";
  }, [language, data.settings?.theme]);
  if (auth.loading)
    return (
      <div className="loading-screen">
        <Logo />
        <div className="loader" />
      </div>
    );
  if (!auth.authenticated)
    return (
      <AuthScreen
        setupRequired={auth.setup_required}
        onAuthenticated={loadAuth}
      />
    );
  const role = auth.user?.role || "viewer";
  const edgeViewer = role === "viewer" && auth.user?.viewer_edge_to_edge;
  const pages = {
    dashboard: (
      <Dashboard data={data} t={t} setRoute={setRoute} language={language} />
    ),
    viewer: (
      <Viewer
        data={data}
        t={t}
        language={language}
        refresh={refresh}
        alertSound={alertSound}
        setAlertSound={setAlertSound}
        currentUser={auth.user}
      />
    ),
    devices: (
      <Devices
        data={data}
        t={t}
        language={language}
        refresh={refresh}
        role={role}
        setRoute={setRoute}
        initialFilter={routeDetail}
      />
    ),
    alerts: (
      <Alerts
        data={data}
        t={t}
        language={language}
        refresh={refresh}
        alertSound={alertSound}
        setAlertSound={setAlertSound}
      />
    ),
    history: <HistoryPage history={data.history} t={t} language={language} />,
    tools: <Tools data={data} t={t} initialTarget={routeDetail} />,
  };
  const allowed =
    {
      admin: navItems,
      user: navItems.filter(([key]) => !["tools", "settings"].includes(key)),
      viewer: navItems.filter(([key]) => key === "viewer"),
    }[role] || [];
  const logout = async () => {
    await api("/auth/logout", { method: "POST" });
    setData({});
    setAuth({
      loading: false,
      authenticated: false,
      setup_required: false,
      user: null,
    });
  };
  if (route === "settings" && role === "admin")
    return (
      <SettingsPage
        data={data}
        t={t}
        language={language}
        refresh={refresh}
        enableNotifications={enableNotifications}
        currentUser={auth.user}
        onExit={() => setRoute("dashboard")}
      />
    );
  return (
    <div
      className={`app-shell role-${role} ${edgeViewer ? "edge-viewer" : ""}`}
    >
      <aside className={menuOpen ? "open" : ""}>
        <Logo />
        <details className="account-menu">
          <summary className="account-chip">
            <span>
              {(auth.user.display_name || auth.user.username)
                .slice(0, 1)
                .toUpperCase()}
            </span>
            <div>
              <strong>{auth.user.display_name || auth.user.username}</strong>
              <small>{t(`${role}Mode`)}</small>
            </div>
            <ChevronLeft />
          </summary>
          <div className="account-popover">
            <button onClick={logout}>
              <LogOut />
              <span>{t("logout")}</span>
            </button>
          </div>
        </details>
        <nav>
          {allowed.map(([key, Icon]) => (
            <button
              key={key}
              className={route === key ? "active" : ""}
              onClick={() => {
                setRoute(key);
                setMenuOpen(false);
              }}
            >
              <Icon />
              <span>{t(key)}</span>
              {route === key && <i />}
            </button>
          ))}
        </nav>
        <div className="sidebar-health">
          <span className="live-dot" />
          <div>
            <strong>{t("monitorLive")}</strong>
            <small>v{data.status?.version || "6.8.1"}</small>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header>
          <button
            className="mobile-menu icon-button"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            <Menu />
          </button>
          <div>
            <span className="eyebrow">HOMEii / {t(route)}</span>
            <h2>
              {new Date().toLocaleDateString(
                language === "he" ? "he-IL" : "en-US",
                { weekday: "long", day: "numeric", month: "long" },
              )}
            </h2>
          </div>
          <div className="header-actions">
            <button className="button subtle" onClick={refresh}>
              <RefreshCw className={loading ? "spin" : ""} />
              <span>{t("refresh")}</span>
            </button>
            {role === "admin" && (
              <button
                className="button primary"
                onClick={async () => {
                  await api("/scan?mode=manual");
                  refresh();
                }}
              >
                <Radar />
                <span>{t("scanNow")}</span>
              </button>
            )}
          </div>
        </header>
        {error && (
          <div className="error-banner">
            <AlertTriangle />
            {error}
            <button onClick={() => setError("")}>
              <X />
            </button>
          </div>
        )}
        <main>
          {loading && !data.status ? (
            <div className="loading-screen">
              <Logo />
              <div className="loader" />
            </div>
          ) : (
            pages[route] || pages[allowed[0]?.[0]]
          )}
        </main>
      </div>
      {offlineToast && (
        <aside
          className={`offline-toast ${offlineToast.critical ? "critical" : ""}`}
          role="alert"
          aria-live="assertive"
        >
          <div className="offline-toast-icon">
            <WifiOff />
          </div>
          <div>
            <span>{t("deviceDisconnected")}</span>
            <strong>{offlineToast.name}</strong>
            <p>
              {offlineToast.ip} · {offlineToast.category}
            </p>
            <small>
              {new Date(Number(offlineToast.createdAt) * 1000).toLocaleString(
                language === "he" ? "he-IL" : "en-US",
              )}
            </small>
          </div>
          <button
            className="icon-button"
            onClick={() => setOfflineToast(null)}
            aria-label={t("close")}
          >
            <X />
          </button>
        </aside>
      )}
      {menuOpen && (
        <button className="scrim" onClick={() => setMenuOpen(false)} />
      )}
    </div>
  );
}

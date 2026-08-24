import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, Bell, Boxes, ChevronLeft, CircleGauge, Clock3, Command,
  Cpu, Gauge, Globe2, History, Languages, LayoutDashboard, Menu, Network, Pin,
  Play, Radar, RefreshCw, Route, Search, Server, Settings, ShieldAlert, Sparkles,
  Terminal, Wifi, WifiOff, Wrench, X, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
  Bar, BarChart,
} from 'recharts'
import { api, query } from './api'
import { translator } from './i18n'

const navItems = [
  ['dashboard', LayoutDashboard], ['viewer', CircleGauge], ['devices', Server],
  ['alerts', Bell], ['history', History], ['tools', Wrench], ['settings', Settings],
]
const statusIcons = { online: Wifi, offline: WifiOff, unstable: Activity, new: Sparkles, critical: ShieldAlert, pinned: Pin, total: Boxes }
const statusOrder = ['offline', 'unstable', 'new', 'critical', 'online', 'total']

function useRoute() {
  const getRoute = () => (location.hash.replace('#/', '') || 'dashboard').split('/')[0]
  const [route, setRoute] = useState(getRoute)
  useEffect(() => {
    const onChange = () => setRoute(getRoute())
    addEventListener('hashchange', onChange)
    return () => removeEventListener('hashchange', onChange)
  }, [])
  return [route, (next) => { location.hash = `#/${next}` }]
}

function Logo() {
  return <div className="brand-lockup">
    <div className="brand-mark"><img src="./icons/homeii-192.png" alt="" /></div>
    <div><strong>HOME<span>ii</span></strong><small>NETWORK INTELLIGENCE</small></div>
  </div>
}

function StatusDot({ status }) { return <span className={`status-dot ${status}`} aria-label={status} /> }

function TimeAgo({ timestamp, language }) {
  if (!timestamp) return <span>—</span>
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp))
  const units = language === 'he'
    ? [[86400, 'ימים'], [3600, 'שעות'], [60, 'דקות'], [1, 'שניות']]
    : [[86400, 'days'], [3600, 'hours'], [60, 'minutes'], [1, 'seconds']]
  const [size, label] = units.find(([size]) => seconds >= size) || units.at(-1)
  return <span>{Math.floor(seconds / size)} {label}</span>
}

function KpiCard({ type, value, label, onClick }) {
  const Icon = statusIcons[type] || Gauge
  return <button className={`kpi-card tone-${type}`} onClick={onClick}>
    <div className="kpi-head"><span className="icon-box"><Icon size={18} /></span><span className="micro-label">{label}</span></div>
    <div className="kpi-value">{value ?? 0}</div>
    <div className="kpi-foot"><span className="pulse-line" /><ChevronLeft size={16} /></div>
  </button>
}

function Empty({ t }) { return <div className="empty"><Radar size={38} /><p>{t('noData')}</p></div> }

function AvailabilityStrip({ series = [] }) {
  const values = series.length ? series.slice(-24) : Array.from({ length: 24 }, () => ({ availability_pct: 100 }))
  return <div className="availability-strip" title="24h availability">
    {values.map((item, index) => {
      const pct = Number(item.availability_pct ?? item.availability ?? 100)
      return <span key={index} className={pct >= 99 ? 'good' : pct >= 60 ? 'warn' : 'bad'} />
    })}
  </div>
}

function Dashboard({ data, t, setRoute, language }) {
  const { status, alerts, events, viewer } = data
  const chartData = viewer?.summary?.series?.map((point, index) => ({
    name: `${index}:00`, availability: Number(point.availability_pct || 0),
  })) || []
  const attention = (data.devices || []).filter((d) => ['offline', 'unstable', 'new'].includes(d.status)).slice(0, 5)
  return <div className="page-stack">
    <section className="hero-panel">
      <div><span className="eyebrow"><Zap size={14} /> {t('monitorLive')}</span><h1>{t('networkPulse')}</h1><p>{t('last24h')} · {status?.networks?.length || 0} {t('network')}</p></div>
      <div className={`health-orb ${status?.offline ? 'danger' : 'healthy'}`}><Activity size={32} /><strong>{status?.offline ? status.offline : 'OK'}</strong><small>{status?.offline ? t('offline') : t('systemHealthy')}</small></div>
    </section>
    <section className="kpi-grid">
      {statusOrder.map((type) => <KpiCard key={type} type={type} value={status?.[type]} label={t(type)} onClick={() => setRoute('devices')} />)}
    </section>
    <section className="dashboard-grid">
      <article className="panel chart-panel wide">
        <div className="panel-title"><div><span className="eyebrow">SLA · 24H</span><h2>{t('uptimeTrend')}</h2></div><span className="score">{viewer?.summary?.availability_24h ?? 0}%</span></div>
        <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData}><defs><linearGradient id="availability" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#27e6a4" stopOpacity=".52"/><stop offset=".58" stopColor="#27e6a4" stopOpacity=".13"/><stop offset="1" stopColor="#27e6a4" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" stroke="var(--chart-axis)" tickLine={false}/><YAxis domain={[0,100]} hide/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14,boxShadow:'0 18px 45px #000a'}}/><Area type="monotone" dataKey="availability" stroke="#27e6a4" strokeWidth={3} fill="url(#availability)" activeDot={{r:5,fill:'#27e6a4',stroke:'#07130f',strokeWidth:3}} /></AreaChart></ResponsiveContainer></div>
      </article>
      <article className="panel attention-panel">
        <div className="panel-title"><div><span className="eyebrow">LIVE QUEUE</span><h2>{t('attention')}</h2></div><AlertTriangle size={21} /></div>
        <div className="compact-list">{attention.length ? attention.map((device) => <div className="compact-row" key={device.ip}><StatusDot status={device.status}/><div><strong>{device.display_name || device.name || device.ip}</strong><small>{device.ip} · {device.vendor || 'Unknown'}</small></div><TimeAgo timestamp={device.last_seen} language={language}/></div>) : <Empty t={t}/>}</div>
      </article>
      <article className="panel events-panel">
        <div className="panel-title"><div><span className="eyebrow">SYSTEM LOG</span><h2>{t('recentEvents')}</h2></div><Command size={21}/></div>
        <div className="event-grid">{(events || []).slice(0, 6).map((event, index) => <div className={`event-tile ${event.level}`} key={event.id || index}><span>{event.event_type || event.type}</span><strong>{event.message}</strong><TimeAgo timestamp={event.ts} language={language}/></div>)}</div>
      </article>
      <article className="panel alerts-mini">
        <div className="panel-title"><div><span className="eyebrow">ALERT CENTER</span><h2>{t('openAlerts')}</h2></div><span className="score danger-text">{(alerts || []).filter(a => a.status === 'open').length}</span></div>
        <AvailabilityStrip series={chartData.map(x => ({availability_pct:x.availability}))}/>
      </article>
    </section>
  </div>
}

function Viewer({ data, t }) {
  const categories = data.viewer?.categories || []
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">NOC VIEW</span><h1>{t('viewer')}</h1><p>{t('deviceHealth')}</p></div></div>
    <section className="category-grid">{categories.map((item) => <article className={`category-card ${item.offline ? 'has-alert' : ''}`} key={item.category}>
      <div className="category-top"><span className="icon-box"><Cpu size={20}/></span><span className="availability-score">{item.availability_24h ?? 0}%</span></div>
      <h2>{item.category || 'Uncategorized'}</h2><strong className="category-count">{item.total ?? item.count ?? 0}</strong>
      <div className="category-tags"><span>{item.online || 0} {t('online')}</span>{item.offline > 0 && <span className="danger-tag">{item.offline} {t('offline')}</span>}</div>
      <AvailabilityStrip series={item.series}/>
    </article>)}</section>
  </div>
}

function Devices({ data, t, language, refresh }) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [editing, setEditing] = useState(null)
  const devices = useMemo(() => (data.devices || []).filter((device) => {
    const text = `${device.display_name} ${device.name} ${device.ip} ${device.vendor}`.toLowerCase()
    return (!search || text.includes(search.toLowerCase())) && (filter === 'all' || device.status === filter)
  }), [data.devices, search, filter])
  const action = async (path) => { await api(path); await refresh() }
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">ASSET INVENTORY</span><h1>{t('devices')}</h1><p>{devices.length} / {data.devices?.length || 0}</p></div></div>
    <section className="toolbar panel"><div className="search-box"><Search size={18}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder={t('search')}/></div><div className="filter-pills">{['all','online','offline','unstable','new'].map(item=><button className={filter===item?'active':''} onClick={()=>setFilter(item)} key={item}>{t(item)}</button>)}</div></section>
    <section className="device-grid">{devices.map(device => <article className={`device-card state-${device.status}`} key={device.ip}>
      <div className="device-card-head"><div><StatusDot status={device.status}/><span>{t(device.status)}</span></div><button className="icon-button" onClick={()=>setEditing(device)}><Settings size={17}/></button></div>
      <h2>{device.display_name || device.name || device.ip}</h2><p>{device.vendor || 'Unknown vendor'}</p><code>{device.ip}</code>
      <div className="device-meta"><span><Network size={14}/>{device.assigned_network || '—'}</span><span><Clock3 size={14}/><TimeAgo timestamp={device.last_seen} language={language}/></span></div>
      <AvailabilityStrip series={device.availability_series}/>
    </article>)}</section>
    {editing && <div className="modal-backdrop" onMouseDown={e=>e.target===e.currentTarget&&setEditing(null)}><div className="modal-card"><button className="modal-close" onClick={()=>setEditing(null)}><X/></button><span className="eyebrow">DEVICE CONTROL</span><h1>{editing.display_name || editing.ip}</h1><div className="detail-grid"><label>{t('name')}<input defaultValue={editing.display_name || editing.name}/></label><label>{t('category')}<input defaultValue={editing.category}/></label><label>{t('network')}<input value={editing.assigned_network || ''} readOnly/></label><label>{t('vendor')}<input value={editing.vendor || ''} readOnly/></label></div><div className="modal-actions"><button className="button danger" onClick={()=>action(`/${editing.quarantined?'restore':'remove'}/${encodeURIComponent(editing.ip)}`).then(()=>setEditing(null))}>{t(editing.quarantined?'restore':'quarantine')}</button><button className="button" onClick={()=>api(`/ping_now/${encodeURIComponent(editing.ip)}`)}>{t('ping')}</button><button className="button primary" onClick={()=>setEditing(null)}>{t('close')}</button></div></div></div>}
  </div>
}

function Alerts({ data, t, language, refresh }) {
  const alerts = data.alerts || []
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">INCIDENT CENTER</span><h1>{t('alerts')}</h1><p>{alerts.filter(a=>a.status==='open').length} {t('openAlerts')}</p></div></div>
    <section className="alert-list">{alerts.length ? alerts.map(alert=><article className={`alert-card severity-${alert.severity}`} key={alert.id}><div className="alert-icon"><AlertTriangle/></div><div><span className="eyebrow">{alert.severity} · {alert.ip}</span><h2>{alert.title}</h2><p>{alert.message}</p></div><div className="alert-side"><TimeAgo timestamp={alert.created_at} language={language}/>{alert.status==='open'&&<button className="button" onClick={async()=>{await api(`/resolve_alert/${alert.id}`);refresh()}}>{t('resolve')}</button>}</div></article>) : <Empty t={t}/>}</section>
  </div>
}

function HistoryPage({ history, t }) {
  const series = history?.daily_series || history?.series || history?.daily || history?.availability || []
  const normalized = series.map((item,index)=>({name:item.label||item.date||index, availability:Number(item.availability_pct??item.availability??0), disconnects:Number(item.disconnects??item.offline_count??0)}))
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">HISTORICAL INTELLIGENCE</span><h1>{t('history')}</h1><p>{t('uptimeTrend')}</p></div></div><section className="history-grid"><article className="panel chart-panel wide"><div className="panel-title"><h2>{t('availability')}</h2><span className="score">{history?.availability_pct ?? history?.summary?.availability_pct ?? 0}%</span></div><div className="chart-wrap tall"><ResponsiveContainer><AreaChart data={normalized}><defs><linearGradient id="historyAvailability" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#3d8bff" stopOpacity=".5"/><stop offset="1" stopColor="#3d8bff" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" stroke="var(--chart-axis)" tickLine={false}/><YAxis stroke="var(--chart-axis)" tickLine={false}/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14}}/><Area dataKey="availability" stroke="#3d8bff" fill="url(#historyAvailability)" strokeWidth={3}/></AreaChart></ResponsiveContainer></div></article><article className="panel chart-panel"><div className="panel-title"><h2>{t('offline')}</h2></div><div className="chart-wrap tall"><ResponsiveContainer><BarChart data={normalized}><defs><linearGradient id="disconnectBars" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ff5c70"/><stop offset="1" stopColor="#9f2639"/></linearGradient></defs><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" hide/><YAxis hide/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14}}/><Bar dataKey="disconnects" fill="url(#disconnectBars)" radius={[8,8,2,2]}/></BarChart></ResponsiveContainer></div></article></section></div>
}

function Tools({ data, t }) {
  const [target,setTarget]=useState(''); const [selected,setSelected]=useState('ping'); const [result,setResult]=useState(null); const [running,setRunning]=useState(false)
  const run=async()=>{setRunning(true);setResult(null);try{setResult(await api('/tools/run',{method:'POST',body:JSON.stringify({target,tools:[selected]})}))}catch(error){setResult({error:error.message})}finally{setRunning(false)}}
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">DIAGNOSTICS LAB</span><h1>{t('tools')}</h1><p>Ping · Trace · Ports · DNS · Speed</p></div></div><section className="tools-layout"><article className="panel tool-console"><div className="target-row"><label>{t('target')}<input value={target} onChange={e=>setTarget(e.target.value)} placeholder="192.168.1.100" list="device-ips"/><datalist id="device-ips">{(data.devices||[]).map(d=><option value={d.ip} key={d.ip}>{d.display_name}</option>)}</datalist></label><button className="button primary" onClick={run} disabled={running||(!target&&selected!=='speed')}><Play size={17}/>{running?t('scanning'):t('run')}</button></div><div className="tool-selector">{[['ping',Activity],['trace',Route],['ports',ShieldAlert],['dns',Globe2],['speed',Gauge]].map(([key,Icon])=><button className={selected===key?'active':''} onClick={()=>setSelected(key)} key={key}><Icon/><span>{t(key)}</span></button>)}</div></article><article className="panel terminal-panel"><div className="terminal-head"><Terminal size={17}/><span>HOMEii diagnostics</span><i className={running?'running':''}/></div><pre>{result?JSON.stringify(result,null,2):'Select a diagnostic and run the test.'}</pre></article></section></div>
}

function SettingsPage({ data, t, language, refresh, enableNotifications }) {
  const settings=data.settings||{}; const [form,setForm]=useState({language:settings.language||language,theme:settings.theme||'dark',auto_refresh:settings.auto_refresh||'30',history_retention_days:settings.history_retention_days||'30',alert_profile:settings.alert_profile||'normal'})
  useEffect(()=>setForm(f=>({...f,language:settings.language||f.language,theme:settings.theme||f.theme,auto_refresh:settings.auto_refresh||f.auto_refresh,history_retention_days:settings.history_retention_days||f.history_retention_days,alert_profile:settings.alert_profile||f.alert_profile})),[settings])
  const save=async()=>{await api('/save_settings',{method:'POST',body:JSON.stringify({...settings,...form,networks:data.settingsPayload?.networks||data.status?.networks||[],network_names:data.settingsPayload?.network_names||{}})});await refresh()}
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">SYSTEM CONFIGURATION</span><h1>{t('settings')}</h1><p>HOMEii 6 control plane</p></div></div><section className="settings-grid"><article className="panel settings-card"><div className="settings-title"><Languages/><div><h2>{t('general')}</h2><p>{t('language')} · {t('appearance')}</p></div></div><div className="form-grid"><label>{t('language')}<select value={form.language} onChange={e=>setForm({...form,language:e.target.value})}><option value="he">עברית</option><option value="en">English</option></select></label><label>{t('theme')}<select value={form.theme} onChange={e=>setForm({...form,theme:e.target.value})}><option value="dark">{t('dark')}</option><option value="light">{t('light')}</option></select></label><label>{t('autoRefresh')}<input type="number" value={form.auto_refresh} onChange={e=>setForm({...form,auto_refresh:e.target.value})}/></label><label>{t('historyDays')}<input type="number" min="1" max="365" value={form.history_retention_days} onChange={e=>setForm({...form,history_retention_days:e.target.value})}/></label></div><div className="settings-actions"><button className="button primary" onClick={save}>{t('save')}</button><button className="button" onClick={enableNotifications}><Bell size={17}/>{t('enableNotifications')}</button></div></article><article className="panel system-card"><div className="settings-title"><DatabaseIcon/><div><h2>System</h2><p>Database & workers</p></div></div><dl><div><dt>Version</dt><dd>{data.status?.version}</dd></div><div><dt>Database</dt><dd>{data.status?.db_ok?'Healthy':'Unavailable'}</dd></div><div><dt>Networks</dt><dd>{data.status?.networks?.length||0}</dd></div><div><dt>PWA</dt><dd>{'serviceWorker' in navigator ? t('ready') : t('unavailable')}</dd></div></dl></article></section></div>
}

function DatabaseIcon(){return <div className="db-icon"><span/><span/><span/></div>}

export default function App() {
  const [route,setRoute]=useRoute(); const [data,setData]=useState({}); const [loading,setLoading]=useState(true); const [error,setError]=useState(''); const [menuOpen,setMenuOpen]=useState(false)
  const notificationReady=useRef(false)
  const language=data.settings?.language||'he'; const t=useMemo(()=>translator(language),[language])
  const showAlertNotifications=async(alerts=[])=>{if(!('Notification' in window)||Notification.permission!=='granted')return;const open=alerts.filter(a=>a.status==='open');const ids=open.map(a=>String(a.id));const previous=JSON.parse(localStorage.getItem('homeii-notified-alerts')||'null');localStorage.setItem('homeii-notified-alerts',JSON.stringify(ids));if(!notificationReady.current||!previous){notificationReady.current=true;return}const fresh=open.filter(a=>!previous.includes(String(a.id)));if(!fresh.length)return;const registration=await navigator.serviceWorker?.ready;fresh.slice(0,3).forEach(alert=>registration?.showNotification(alert.title||'HOMEii Network Alert',{body:alert.message||alert.ip||'',icon:'./icons/homeii-192.png',badge:'./icons/homeii-192.png',tag:`homeii-alert-${alert.id}`,data:{route:'#/alerts'}}))}
  const enableNotifications=async()=>{if(!('Notification' in window)){setError(t('notificationsUnsupported'));return}const permission=await Notification.requestPermission();if(permission==='granted'){notificationReady.current=true;setError('')}else setError(t('notificationsDenied'))}
  const refresh=async()=>{try{setError('');const [status,devices,alerts,events,settingsPayload,viewer,history]=await Promise.all([api('/status'),api('/devices'),api('/alerts?limit=100'),api('/events?limit=100'),api('/settings'),api('/viewer/categories'),api('/history/summary')]);const alertItems=alerts.alerts||[];setData({status,devices:devices.devices||[],alerts:alertItems,events:events.events||[],settings:settingsPayload.settings||{},settingsPayload,viewer,history});showAlertNotifications(alertItems)}catch(e){setError(e.message)}finally{setLoading(false)}}
  useEffect(()=>{refresh()},[])
  useEffect(()=>{const interval=Math.max(10,Number(data.settings?.auto_refresh||30))*1000;const id=setInterval(refresh,interval);return()=>clearInterval(id)},[data.settings?.auto_refresh])
  useEffect(()=>{document.documentElement.lang=language;document.documentElement.dir=language==='he'?'rtl':'ltr';document.documentElement.dataset.theme=data.settings?.theme||'dark'},[language,data.settings?.theme])
  const pages={dashboard:<Dashboard data={data} t={t} setRoute={setRoute} language={language}/>,viewer:<Viewer data={data} t={t}/>,devices:<Devices data={data} t={t} language={language} refresh={refresh}/>,alerts:<Alerts data={data} t={t} language={language} refresh={refresh}/>,history:<HistoryPage history={data.history} t={t}/>,tools:<Tools data={data} t={t}/>,settings:<SettingsPage data={data} t={t} language={language} refresh={refresh} enableNotifications={enableNotifications}/>}
  return <div className="app-shell"><aside className={menuOpen?'open':''}><Logo/><nav>{navItems.map(([key,Icon])=><button key={key} className={route===key?'active':''} onClick={()=>{setRoute(key);setMenuOpen(false)}}><Icon/><span>{t(key)}</span>{route===key&&<i/>}</button>)}</nav><div className="sidebar-health"><span className="live-dot"/><div><strong>{t('monitorLive')}</strong><small>v{data.status?.version||'6.0.1'}</small></div></div></aside><div className="main-shell"><header><button className="mobile-menu icon-button" onClick={()=>setMenuOpen(!menuOpen)}><Menu/></button><div><span className="eyebrow">HOMEii / {t(route)}</span><h2>{new Date().toLocaleDateString(language==='he'?'he-IL':'en-US',{weekday:'long',day:'numeric',month:'long'})}</h2></div><div className="header-actions"><button className="button subtle" onClick={refresh}><RefreshCw className={loading?'spin':''}/><span>{t('refresh')}</span></button><button className="button primary" onClick={async()=>{await api('/scan?mode=manual');refresh()}}><Radar/><span>{t('scanNow')}</span></button></div></header>{error&&<div className="error-banner"><AlertTriangle/>{error}<button onClick={()=>setError('')}><X/></button></div>}<main>{loading&&!data.status?<div className="loading-screen"><Logo/><div className="loader"/></div>:pages[route]||pages.dashboard}</main></div>{menuOpen&&<button className="scrim" onClick={()=>setMenuOpen(false)}/>}</div>
}
